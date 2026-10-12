/*
 * Forked from fw/test/src/ez_sd.c (bench-validated on V1). Added for the
 * production card check (IMPL-ENG-010): ez_sd_status() (CMD13) and
 * ez_sd_read_cid() (CMD10 re-read).
 */
/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-FW-004, SEC-HW-002 -- see ez_guard.c for the enforcement points.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/gpio.h"

#include "board.h"
#include "ez_sd.h"

#define CMD0   0
#define CMD8   8
#define CMD9   9
#define CMD10  10
#define CMD12  12
#define CMD16  16
#define CMD17  17
#define CMD18  18
#define CMD24  24
#define CMD55  55
#define CMD58  58
#define CMD59  59
#define ACMD41 41

#define R1_IDLE            0x01
#define R1_ILLEGAL_CMD     0x04
#define DATA_START_BLOCK   0xfe

static bool s_block_addressed = false;
static bool s_initialised = false;

static uint8_t sd_xfer(uint8_t b);
static inline void sd_cs(bool low);
static char s_err[48] = "none";
static uint32_t s_write_timeout_ms = 10000;
/* Formatting raises this: after a large ERASE, the card's first writes can
 * stay busy for minutes while it works in the background (TR-07). */
void ez_sd_set_write_timeout_ms(uint32_t ms) { s_write_timeout_ms = ms; }
const char *ez_sd_last_error(void) { return s_err; }
static void set_err(const char *what, unsigned v) { snprintf(s_err, sizeof s_err, "%s 0x%02x", what, v); }

/* Wait until the card releases DO (0xFF): a card still programming holds
 * it low, and a command sent then can leave some cards unresponsive until
 * power is cut (seen on V1, TR-07). */
/* Called about once a second while the driver waits on a busy card, so
 * a long wait is visible (TR-07: silence could not be told from a crash). */
void (*ez_sd_wait_hook)(const char *what, uint32_t s);
static void waited(const char *what, uint64_t t0, uint64_t *last)
{
    uint64_t now = time_us_64();
    if (ez_sd_wait_hook && now - *last >= 1000000u) {
        *last = now;
        ez_sd_wait_hook(what, (uint32_t)((now - t0) / 1000000u));
    }
}

/*
 * Poll a busy card gently. For the first 2 ms poll continuously (a normal
 * write finishes in that time); after that release the card between
 * checks -- deselect, 8 clocks, 1 ms, reselect, one byte. A Transcend card
 * on V1 (TR-07) never finished its periodic internal work (every ~1,565
 * single-block writes) while clocked continuously with CS low; Linux,
 * which polls with status commands, wrote the same pattern without a stall.
 * Returns the last byte read (0x00 while busy).
 */
static uint8_t busy_poll(uint64_t t0)
{
    if (time_us_64() - t0 < 2000u) return sd_xfer(0xff);
    sd_cs(false);
    sd_xfer(0xff);
    sleep_us(1000);
    sd_cs(true);
    return sd_xfer(0xff);
}

static bool sd_wait_ready(uint32_t ms)
{
    absolute_time_t deadline = make_timeout_time_ms(ms);
    uint64_t t0 = time_us_64(), last = t0;
    while (busy_poll(t0) != 0xff) {
        waited("before a command", t0, &last);
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) return false;
    }
    return true;
}


/* --- low level ---------------------------------------------------------- */

static inline void sd_cs(bool low)
{
    __asm__ volatile("nop \n nop \n nop");
    gpio_put(SD_CSN_PIN, low ? 0 : 1);
    __asm__ volatile("nop \n nop \n nop");
}

static uint8_t sd_xfer(uint8_t v)
{
    uint8_t rx = 0xff;
    spi_write_read_blocking(SD_SPI, &v, &rx, 1);
    return rx;
}

static void sd_clocks(int bytes)
{
    for (int i = 0; i < bytes; i++) sd_xfer(0xff);
}

void ez_sd_deselect(void)
{
    sd_cs(false);
    sd_xfer(0xff);      /* release DO */
}

uint32_t ez_sd_set_baud(uint32_t baud)
{
    return spi_set_baudrate(SD_SPI, baud);
}

static void sd_bus_init(uint32_t baud)
{
    spi_init(SD_SPI, baud);
    spi_set_format(SD_SPI, 8, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);

    gpio_set_function(SD_SCLK_PIN, GPIO_FUNC_SPI);
    gpio_set_function(SD_MOSI_PIN, GPIO_FUNC_SPI);
    gpio_set_function(SD_MISO_PIN, GPIO_FUNC_SPI);

    gpio_init(SD_CSN_PIN);
    gpio_set_dir(SD_CSN_PIN, GPIO_OUT);
    gpio_put(SD_CSN_PIN, 1);

    gpio_init(SD_DET_PIN);
    gpio_set_dir(SD_DET_PIN, GPIO_IN);
    gpio_pull_up(SD_DET_PIN);
}

static ez_sd_det_mode_t s_det_mode =
#if SD_DET_ACTIVE_LOW
    EZ_SD_DET_ACTIVE_LOW;
#else
    EZ_SD_DET_ACTIVE_HIGH;
#endif

void ez_sd_set_det_mode(ez_sd_det_mode_t m) { s_det_mode = m; }
ez_sd_det_mode_t ez_sd_get_det_mode(void)   { return s_det_mode; }

const char *ez_sd_det_mode_name(ez_sd_det_mode_t m)
{
    switch (m) {
    case EZ_SD_DET_ACTIVE_LOW:  return "active-low";
    case EZ_SD_DET_ACTIVE_HIGH: return "active-high";
    default:                    return "ignored";
    }
}

int ez_sd_det_raw(void)
{
    gpio_init(SD_DET_PIN);
    gpio_set_dir(SD_DET_PIN, GPIO_IN);
    /* V1: the switch drives the pin high with a card present (OI-03). */
    gpio_pull_down(SD_DET_PIN);
    /* The internal pull-up is 50-80 kOhm. Against socket and trace
     * capacitance 20 us was optimistic; 500 us costs nothing here. */
    sleep_us(500);
    return gpio_get(SD_DET_PIN) ? 1 : 0;
}

void ez_sd_det_probe(int *with_pullup, int *with_pulldown)
{
    gpio_init(SD_DET_PIN);
    gpio_set_dir(SD_DET_PIN, GPIO_IN);

    gpio_pull_up(SD_DET_PIN);
    sleep_us(500);
    *with_pullup = gpio_get(SD_DET_PIN) ? 1 : 0;

    gpio_pull_down(SD_DET_PIN);
    sleep_us(500);
    *with_pulldown = gpio_get(SD_DET_PIN) ? 1 : 0;

    gpio_pull_down(SD_DET_PIN); /* leave it biased as V1 needs (OI-03) */
    sleep_us(500);
}

bool ez_sd_card_detected(void)
{
    if (s_det_mode == EZ_SD_DET_IGNORE) return true;
    int v = ez_sd_det_raw();
    return (s_det_mode == EZ_SD_DET_ACTIVE_LOW) ? (v == 0) : (v == 1);
}

static uint8_t crc7(const uint8_t *data, int len)
{
    uint8_t crc = 0;
    for (int i = 0; i < len; i++) {
        uint8_t d = data[i];
        for (int b = 0; b < 8; b++) {
            crc <<= 1;
            if ((d & 0x80) ^ (crc & 0x80)) crc ^= 0x09;
            d <<= 1;
        }
    }
    return (uint8_t)((crc << 1) | 1);
}

static uint16_t crc16_ccitt(const uint8_t *data, int len)
{
    uint16_t crc = 0;
    for (int i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

/* Sends a command and returns R1. CS must already be low. */
static uint8_t sd_cmd_r1(uint8_t cmd, uint32_t arg)
{
    uint8_t frame[6];
    frame[0] = (uint8_t)(0x40 | cmd);
    frame[1] = (uint8_t)(arg >> 24);
    frame[2] = (uint8_t)(arg >> 16);
    frame[3] = (uint8_t)(arg >> 8);
    frame[4] = (uint8_t)(arg);
    frame[5] = crc7(frame, 5);

    /* Never send a command to a busy card (except CMD0 during init). */
    if (cmd != 0 && !sd_wait_ready(10000)) set_err("busy before CMD", cmd);
    sd_xfer(0xff);
    spi_write_blocking(SD_SPI, frame, 6);

    /* CMD12 emits a stuff byte before its response. */
    if (cmd == CMD12) sd_xfer(0xff);

    uint8_t r1 = 0xff;
    for (int i = 0; i < 16; i++) {
        r1 = sd_xfer(0xff);
        if (!(r1 & 0x80)) break;
    }
    return r1;
}

static uint8_t sd_cmd_r37(uint8_t cmd, uint32_t arg, uint32_t *trailing)
{
    uint8_t r1 = sd_cmd_r1(cmd, arg);
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | sd_xfer(0xff);
    if (trailing) *trailing = v;
    return r1;
}

static uint8_t sd_acmd(uint8_t cmd, uint32_t arg)
{
    sd_cmd_r1(CMD55, 0);
    return sd_cmd_r1(cmd, arg);
}

/* Waits for the data start token and reads len bytes plus the CRC-16. */
static bool sd_read_data(uint8_t *buf, int len, bool *crc_ok, uint32_t timeout_ms)
{
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    uint8_t tok;
    for (;;) {
        tok = sd_xfer(0xff);
        if (tok == DATA_START_BLOCK) break;
        if ((tok & 0xf0) == 0x00 && tok != 0xff) return false;  /* error token */
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) return false;
    }

    memset(buf, 0xff, len);
    spi_read_blocking(SD_SPI, 0xff, buf, len);

    uint16_t got = (uint16_t)((sd_xfer(0xff) << 8) | sd_xfer(0xff));
    if (crc_ok) *crc_ok = (got == crc16_ccitt(buf, len));
    return true;
}

/* --- init --------------------------------------------------------------- */

static void decode_cid(ez_sd_card_t *c)
{
    const uint8_t *p = c->cid;
    c->mid = p[0];
    c->oid[0] = (char)p[1]; c->oid[1] = (char)p[2]; c->oid[2] = 0;
    for (int i = 0; i < 5; i++) c->pnm[i] = (char)p[3 + i];
    c->pnm[5] = 0;
    c->prv_major = (uint8_t)(p[8] >> 4);
    c->prv_minor = (uint8_t)(p[8] & 0x0f);
    c->psn = ((uint32_t)p[9] << 24) | ((uint32_t)p[10] << 16) |
             ((uint32_t)p[11] << 8) | p[12];
    uint16_t mdt = (uint16_t)(((p[13] & 0x0f) << 8) | p[14]);
    c->mdt_year = (uint16_t)(2000 + (mdt >> 4));
    c->mdt_month = (uint8_t)(mdt & 0x0f);
}

static void decode_csd(ez_sd_card_t *c)
{
    const uint8_t *p = c->csd;
    c->csd_structure = (uint8_t)(p[0] >> 6);
    c->tran_speed = p[3];

    if (c->csd_structure == 0) {
        uint32_t read_bl_len = p[5] & 0x0f;
        uint32_t c_size = (uint32_t)(((p[6] & 0x03) << 10) | (p[7] << 2) | (p[8] >> 6));
        uint32_t c_size_mult = (uint32_t)(((p[9] & 0x03) << 1) | (p[10] >> 7));
        uint64_t blocknr = (uint64_t)(c_size + 1) * (1u << (c_size_mult + 2));
        uint64_t block_len = 1u << read_bl_len;
        c->capacity_bytes = blocknr * block_len;
    } else {
        uint32_t c_size = (uint32_t)(((p[7] & 0x3f) << 16) | (p[8] << 8) | p[9]);
        c->capacity_bytes = (uint64_t)(c_size + 1) * 512ull * 1024ull;
    }
    c->block_count = (uint32_t)(c->capacity_bytes / 512ull);
}

bool ez_sd_init(ez_sd_card_t *card, ez_sd_initlog_t *log)
{
    memset(card, 0, sizeof(*card));
    memset(log, 0, sizeof(*log));
    s_initialised = false;
    uint64_t t0 = time_us_64();

#define STEP(n, name) do { log->step = (n); log->step_name = (name); } while (0)

    STEP(0, "bus setup");
    sd_bus_init(SD_BAUD_INIT);

    /* 74+ clocks with CS and DI high puts the card into native SPI mode. */
    STEP(1, "power-on clocks");
    sd_cs(false);
    sd_clocks(16);

    STEP(2, "CMD0 GO_IDLE_STATE");
    /* Recovering a card that was running (not just powered up): let it
     * finish any programming, resynchronise the bus, then reset with the
     * card reselected for every attempt (TR-07: a card reset while busy
     * stayed unresponsive until power was cut). */
    sd_cs(true);
    sd_wait_ready(3000);
    ez_sd_deselect();
    sd_clocks(10);
    uint8_t r1 = 0xff;
    for (int i = 0; i < 50; i++) {
        sd_cs(true);
        r1 = sd_cmd_r1(CMD0, 0);
        if (r1 == R1_IDLE) break;
        ez_sd_deselect();
        sd_clocks(2);
        sleep_ms(10);
    }
    log->last_r1 = r1;
    if (r1 != R1_IDLE) { set_err("init: CMD0 r1", r1); ez_sd_deselect(); return false; }

    STEP(3, "CMD8 SEND_IF_COND");
    uint32_t r7 = 0;
    r1 = sd_cmd_r37(CMD8, 0x000001aa, &r7);
    log->last_r1 = r1;

    bool v2 = false;
    if (!(r1 & R1_ILLEGAL_CMD)) {
        if ((r7 & 0xfff) != 0x1aa) { ez_sd_deselect(); return false; }  /* voltage mismatch */
        v2 = true;
    }

    STEP(4, "ACMD41 SD_SEND_OP_COND");
    absolute_time_t deadline = make_timeout_time_ms(2000);
    for (;;) {
        r1 = sd_acmd(ACMD41, v2 ? 0x40000000u : 0);
        log->acmd41_iterations++;
        if (r1 == 0) break;
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) {
            log->last_r1 = r1;
            ez_sd_deselect();
            return false;
        }
        sleep_ms(2);
    }
    log->last_r1 = r1;

    STEP(5, "CMD58 READ_OCR");
    r1 = sd_cmd_r37(CMD58, 0, &card->ocr);
    s_block_addressed = v2 && ((card->ocr & 0x40000000u) != 0);
    card->block_addressed = s_block_addressed;
    card->type = s_block_addressed ? SD_TYPE_SDHC : (v2 ? SD_TYPE_SDSC_V2 : SD_TYPE_SDSC_V1);

    if (!s_block_addressed) {
        STEP(6, "CMD16 SET_BLOCKLEN");
        sd_cmd_r1(CMD16, 512);
    }

    STEP(7, "CMD9 SEND_CSD");
    r1 = sd_cmd_r1(CMD9, 0);
    bool crc_ok = false;
    if (r1 != 0 || !sd_read_data(card->csd, 16, &crc_ok, 500)) { ez_sd_deselect(); return false; }

    STEP(8, "CMD10 SEND_CID");
    r1 = sd_cmd_r1(CMD10, 0);
    if (r1 != 0 || !sd_read_data(card->cid, 16, &crc_ok, 500)) { ez_sd_deselect(); return false; }

    decode_csd(card);
    decode_cid(card);

    STEP(9, "ready");
    ez_sd_deselect();
    ez_sd_set_baud(SD_BAUD_DEFAULT);
    s_initialised = true;
    log->elapsed_ms = (uint32_t)((time_us_64() - t0) / 1000u);
    return true;
#undef STEP
}

/* --- block I/O ----------------------------------------------------------- */

bool ez_sd_read_block(uint32_t lba, uint8_t *buf, bool *crc_ok)
{
    if (!s_initialised) return false;
    uint32_t arg = s_block_addressed ? lba : (lba * 512u);

    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD17, arg);
    if (r1 != 0) { ez_sd_deselect(); return false; }
    bool ok = sd_read_data(buf, 512, crc_ok, 500);
    ez_sd_deselect();
    return ok;
}

bool ez_sd_write_block(uint32_t lba, const uint8_t *buf)
{
    if (!s_initialised) return false;
    uint32_t arg = s_block_addressed ? lba : (lba * 512u);

    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD24, arg);
    if (r1 != 0) { set_err("CMD24 r1", r1); ez_sd_deselect(); return false; }

    sd_xfer(0xff);
    sd_xfer(DATA_START_BLOCK);
    spi_write_blocking(SD_SPI, buf, 512);
    uint16_t crc = crc16_ccitt(buf, 512);
    sd_xfer((uint8_t)(crc >> 8));
    sd_xfer((uint8_t)(crc & 0xff));

    uint8_t resp = sd_xfer(0xff);
    if ((resp & 0x1f) != 0x05) { set_err("CMD24 data response", resp); ez_sd_deselect(); return false; }

    /* Busy while programming: consumer cards can exceed the nominal 250 ms
     * during internal housekeeping. */
    /* After a large ERASE, cards finish much of the work in the background
     * and later writes can stay busy for seconds (TR-07). */
    absolute_time_t deadline = make_timeout_time_ms(s_write_timeout_ms);
    uint64_t t0 = time_us_64(), last = t0;
    while (busy_poll(t0) == 0x00) {
        waited("CMD24 write", t0, &last);
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) {
            set_err("CMD24 busy timeout", 0);
            ez_sd_deselect();
            return false;
        }
    }
    ez_sd_deselect();
    return true;
}

bool ez_sd_bench_read(uint32_t lba, uint32_t blocks, uint8_t *scratch,
                      uint32_t *bytes_per_sec, uint32_t *crc_errors)
{
    if (!s_initialised) return false;
    *crc_errors = 0;

    uint32_t arg = s_block_addressed ? lba : (lba * 512u);
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD18, arg);       /* multi-block read */
    if (r1 != 0) { ez_sd_deselect(); return false; }

    uint64_t t0 = time_us_64();
    for (uint32_t i = 0; i < blocks; i++) {
        bool crc_ok = false;
        if (!sd_read_data(scratch, 512, &crc_ok, 500)) {
            sd_cmd_r1(CMD12, 0);
            ez_sd_deselect();
            return false;
        }
        if (!crc_ok) (*crc_errors)++;
    }
    uint64_t t1 = time_us_64();

    sd_cmd_r1(CMD12, 0);
    ez_sd_deselect();

    *bytes_per_sec = (t1 > t0) ? (uint32_t)((uint64_t)blocks * 512ull * 1000000ull / (t1 - t0)) : 0;
    return true;
}

const char *ez_sd_type_name(ez_sd_type_t t)
{
    switch (t) {
    case SD_TYPE_SDHC:    return "SDHC/SDXC";
    case SD_TYPE_SDSC_V2: return "SDSC v2";
    case SD_TYPE_SDSC_V1: return "SDSC v1";
    case SD_TYPE_MMC:     return "MMC";
    default:              return "none";
    }
}

/* ---- production additions (IMPL-ENG-010) --------------------------------- */

#define CMD13 13

/* CMD13 SEND_STATUS: true if the card answers with no error bits. */
bool ez_sd_status(void)
{
    if (!s_initialised) return false;
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD13, 0);
    uint8_t r2 = sd_xfer(0xff);
    ez_sd_deselect();
    return r1 == 0 && r2 == 0;
}

/* CMD10 SEND_CID: read the card's identity again. */
bool ez_sd_read_cid(uint8_t cid[16])
{
    if (!s_initialised) return false;
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD10, 0);
    bool crc_ok = false;
    bool ok = r1 == 0 && sd_read_data(cid, 16, &crc_ok, 500) && crc_ok;
    ez_sd_deselect();
    return ok;
}

/* ---- CSD (TR-05: temporary write protection) ------------------------------ */

#define CMD27 27

bool ez_sd_read_csd(uint8_t csd[16])
{
    if (!s_initialised) return false;
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD9, 0);
    bool crc_ok = false;
    bool ok = r1 == 0 && sd_read_data(csd, 16, &crc_ok, 500) && crc_ok;
    ez_sd_deselect();
    return ok;
}

/* PROGRAM_CSD with only TMP_WRITE_PROTECT (CSD bit 12) changed from the
 * card's current CSD. PERM_WRITE_PROTECT (bit 13) is never touched. */
bool ez_sd_set_tmp_write_protect(bool on)
{
    uint8_t csd[16];
    if (!ez_sd_read_csd(csd)) return false;
    if (on) csd[14] |= 0x10; else csd[14] &= (uint8_t)~0x10;
    csd[15] = (uint8_t)((crc7(csd, 15) << 1) | 1);
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD27, 0);
    if (r1 != 0) { ez_sd_deselect(); return false; }
    sd_xfer(0xff);
    sd_xfer(DATA_START_BLOCK);
    spi_write_blocking(SD_SPI, csd, 16);
    uint16_t crc = crc16_ccitt(csd, 16);
    sd_xfer((uint8_t)(crc >> 8));
    sd_xfer((uint8_t)(crc & 0xff));
    uint8_t resp = sd_xfer(0xff);
    bool ok = (resp & 0x1f) == 0x05;
    absolute_time_t deadline = make_timeout_time_ms(1000);
    while (sd_xfer(0xff) == 0x00)
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) { ok = false; break; }
    ez_sd_deselect();
    return ok;
}

/* ---- erase (IMPL-AV-007: card format) ------------------------------------ */

#define CMD32 32
#define CMD33 33
#define CMD38 38

/* Erase blocks [first, last]; waits for the card (up to 30 s). */
bool ez_sd_erase(uint32_t first, uint32_t last)
{
    if (!s_initialised) return false;
    uint32_t a = s_block_addressed ? first : first * 512u, b = s_block_addressed ? last : last * 512u;
    uint8_t r;
    sd_cs(true);
    bool ok = (r = sd_cmd_r1(CMD32, a)) == 0;
    if (!ok) set_err("CMD32 r1", r);
    ez_sd_deselect();
    sd_cs(true);
    ok = ok && ((r = sd_cmd_r1(CMD33, b)) == 0 || (set_err("CMD33 r1", r), false));
    ez_sd_deselect();
    sd_cs(true);
    ok = ok && ((r = sd_cmd_r1(CMD38, 0)) == 0 || (set_err("CMD38 r1", r), false));
    absolute_time_t deadline = make_timeout_time_ms(30000);
    uint64_t te = time_us_64();
    while (ok && busy_poll(te) == 0x00)
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) { ok = false; break; }
    ez_sd_deselect();
    return ok;
}

/* Presence, not health: any valid reply to SEND_STATUS (R1 bit 7 clear)
 * means a card is there; error flags in the reply are card errors. */
bool ez_sd_alive(void)
{
    if (!s_initialised) return false;
    sd_cs(true);
    uint8_t r1 = sd_cmd_r1(CMD13, 0);
    sd_xfer(0xff);
    ez_sd_deselect();
    return !(r1 & 0x80);
}

void ez_sd_note_init(const ez_sd_initlog_t *log)
{
    if (strncmp(s_err, "init:", 5) != 0)
        snprintf(s_err, sizeof s_err, "init: %s r1 0x%02x", log->step_name ? log->step_name : "?", log->last_r1);
}

/* Wait (up to ms) for the card to finish background work. */
bool ez_sd_settle(uint32_t ms)
{
    if (!s_initialised) return false;
    sd_cs(true);
    bool ok = sd_wait_ready(ms);
    ez_sd_deselect();
    return ok;
}

/* One byte, no waiting: is the card holding DO low (busy)? */
bool ez_sd_busy_now(void)
{
    if (!s_initialised) return false;
    sd_cs(true);
    uint8_t r = sd_xfer(0xff);
    ez_sd_deselect();
    return r == 0x00;
}
