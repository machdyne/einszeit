/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-PTR-002, SEC-META-003, SEC-UI-005 -- all callers gated by ez_guard.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <string.h>

#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/gpio.h"

#include "board.h"
#include "ez_fram.h"

static ez_fram_geom_t g_geom = { .present = false, .size_bytes = 32768,
                                 .size_confirmed = false, .addr_bytes = 2 };

void ez_fram_geom_defaults(ez_fram_geom_t *g) { *g = g_geom; }

static inline void cs_lo(void) { asm volatile("nop \n nop \n nop");
                                 gpio_put(FRAM_SS_PIN, 0);
                                 asm volatile("nop \n nop \n nop"); }
static inline void cs_hi(void) { asm volatile("nop \n nop \n nop");
                                 gpio_put(FRAM_SS_PIN, 1);
                                 asm volatile("nop \n nop \n nop"); }

void ez_fram_init(uint32_t baud)
{
    spi_init(FRAM_SPI, baud);
    spi_set_format(FRAM_SPI, 8, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);

    gpio_set_function(FRAM_SCLK_PIN, GPIO_FUNC_SPI);
    gpio_set_function(FRAM_MOSI_PIN, GPIO_FUNC_SPI);
    gpio_set_function(FRAM_MISO_PIN, GPIO_FUNC_SPI);

    /* CS is bit-banged so a transaction can span several SPI calls. */
    gpio_init(FRAM_SS_PIN);
    gpio_set_dir(FRAM_SS_PIN, GPIO_OUT);
    gpio_put(FRAM_SS_PIN, 1);
}

uint32_t ez_fram_set_baud(uint32_t baud)
{
    return spi_set_baudrate(FRAM_SPI, baud);
}

static void addr_bytes(uint32_t addr, uint8_t *out, uint8_t n)
{
    if (n == 3) {
        out[0] = (uint8_t)(addr >> 16);
        out[1] = (uint8_t)(addr >> 8);
        out[2] = (uint8_t)(addr);
    } else {
        out[0] = (uint8_t)(addr >> 8);
        out[1] = (uint8_t)(addr);
    }
}

static void cmd_only(uint8_t op)
{
    cs_lo();
    spi_write_blocking(FRAM_SPI, &op, 1);
    cs_hi();
}

uint8_t ez_fram_read_status(void)
{
    uint8_t tx[2] = { FRAM_OP_RDSR, 0xff };
    uint8_t rx[2] = { 0, 0 };
    cs_lo();
    spi_write_read_blocking(FRAM_SPI, tx, rx, 2);
    cs_hi();
    return rx[1];
}

bool ez_fram_write_status(uint8_t v)
{
    cmd_only(FRAM_OP_WREN);
    uint8_t tx[2] = { FRAM_OP_WRSR, v };
    cs_lo();
    spi_write_blocking(FRAM_SPI, tx, 2);
    cs_hi();
    return true;
}

/* --- JEDEC ID ----------------------------------------------------------- */

struct fram_id_entry {
    uint8_t  mfr;
    uint8_t  cont;      /* continuation code count is folded into the match */
    uint16_t product;
    const char *vendor;
    const char *part;
    uint32_t density;
};

/*
 * Only the parts likely to be on a small security dongle. Anything not listed
 * still reports its raw ID bytes; `fram size` measures the real density
 * regardless of whether the part is in this table.
 *
 * Parts that do NOT implement RDID (0x9F) at all, and so can never appear
 * here no matter how healthy they are:
 *
 *   MB85RS64, MB85RS64PNF   64 Kbit,   8 KB, 2-byte addressing, 20 MHz max
 *   MB85RS128, MB85RS256A   older A/no-suffix Fujitsu parts
 *
 * The Device ID command was introduced with the "V" generation. On a part
 * without it, 0x9F clocks out nothing and the host reads all zeroes. Use
 * ez_fram_probe() for presence and `fram size` for density on those.
 */
static const struct fram_id_entry id_table[] = {
    { 0x04, 0x7f, 0x0302, "Fujitsu",          "MB85RS64V",   8u * 1024 },
    { 0x04, 0x7f, 0x0101, "Fujitsu",          "MB85RS128B",  16u * 1024 },
    { 0x04, 0x7f, 0x2503, "Fujitsu",          "MB85RS256B",  32u * 1024 },
    { 0x04, 0x7f, 0x2703, "Fujitsu",          "MB85RS512T",  64u * 1024 },
    { 0x04, 0x7f, 0x2803, "Fujitsu",          "MB85RS1MT",  128u * 1024 },
    { 0x04, 0x7f, 0x4803, "Fujitsu",          "MB85RS2MTA", 256u * 1024 },
    { 0x04, 0x7f, 0x4903, "Fujitsu",          "MB85RS4MT",  512u * 1024 },
    { 0xc2, 0x7f, 0x2200, "Infineon/Cypress", "FM25V02A",    32u * 1024 },
    { 0xc2, 0x7f, 0x2300, "Infineon/Cypress", "FM25V05",     64u * 1024 },
    { 0xc2, 0x7f, 0x2400, "Infineon/Cypress", "FM25V10",    128u * 1024 },
    { 0xc2, 0x7f, 0x2500, "Infineon/Cypress", "FM25V20A",   256u * 1024 },
};

static const char *vendor_name(uint8_t mfr)
{
    switch (mfr) {
    case 0x04: return "Fujitsu";
    case 0xc2: return "Infineon/Cypress";
    case 0xef: return "Winbond";
    case 0x0b: return "Ramtron";
    default:   return "unknown";
    }
}

bool ez_fram_read_id(ez_fram_id_t *id)
{
    uint8_t tx[10], rx[10];
    memset(tx, 0xff, sizeof(tx));
    tx[0] = FRAM_OP_RDID;

    cs_lo();
    spi_write_read_blocking(FRAM_SPI, tx, rx, 10);
    cs_hi();

    memcpy(id->id, &rx[1], 9);
    id->id_len = 9;
    id->vendor = "unknown";
    id->part = "unknown";
    id->density_bytes = 0;

    /* Skip 0x7F continuation codes to find the manufacturer byte. */
    int i = 0;
    while (i < 8 && id->id[i] == 0x7f) i++;
    uint8_t mfr = id->id[i];

    if (mfr == 0x00 || mfr == 0xff) return false;   /* bus stuck or no device */

    id->vendor = vendor_name(mfr);
    uint16_t product = (uint16_t)((id->id[i + 1] << 8) | id->id[i + 2]);
    for (size_t k = 0; k < count_of(id_table); k++) {
        if (id_table[k].mfr == mfr && id_table[k].product == product) {
            id->vendor = id_table[k].vendor;
            id->part = id_table[k].part;
            id->density_bytes = id_table[k].density;
            break;
        }
    }
    return true;
}

/*
 * Non-destructive liveness probe. See ez_fram_probe_t in the header for why
 * this exists rather than trusting RDID.
 */
bool ez_fram_probe(ez_fram_probe_t *pr)
{
    memset(pr, 0, sizeof(*pr));

    ez_fram_id_t id;
    pr->rdid_supported = ez_fram_read_id(&id);

    pr->sr_idle = ez_fram_read_status();
    cmd_only(FRAM_OP_WREN);
    pr->sr_wren = ez_fram_read_status();
    cmd_only(FRAM_OP_WRDI);
    pr->sr_wrdi = ez_fram_read_status();

    /* A stuck MISO reads the same value for every transfer. */
    pr->miso_alive = !(pr->sr_idle == pr->sr_wren && pr->sr_wren == pr->sr_wrdi
                       && (pr->sr_idle == 0x00 || pr->sr_idle == 0xff));

    pr->wel_toggles = ((pr->sr_wren & FRAM_SR_WEL) != 0)
                   && ((pr->sr_wrdi & FRAM_SR_WEL) == 0);

    pr->present = pr->wel_toggles;
    return pr->present;
}

/* --- data access -------------------------------------------------------- */

void ez_fram_read(uint32_t addr, uint8_t *buf, size_t len)
{
    uint8_t hdr[4];
    hdr[0] = FRAM_OP_READ;
    addr_bytes(addr, &hdr[1], g_geom.addr_bytes);

    cs_lo();
    spi_write_blocking(FRAM_SPI, hdr, 1u + g_geom.addr_bytes);
    spi_read_blocking(FRAM_SPI, 0xff, buf, len);
    cs_hi();
}

void ez_fram_write(uint32_t addr, const uint8_t *buf, size_t len)
{
    uint8_t hdr[4];
    hdr[0] = FRAM_OP_WRITE;
    addr_bytes(addr, &hdr[1], g_geom.addr_bytes);

    cmd_only(FRAM_OP_WREN);
    cs_lo();
    spi_write_blocking(FRAM_SPI, hdr, 1u + g_geom.addr_bytes);
    spi_write_blocking(FRAM_SPI, buf, len);
    cs_hi();
}

/* --- density detection --------------------------------------------------- */
/*
 * FRAM ignores the high address bits it does not implement, so writing a
 * distinct marker at 0, 1, 2, 4, ... 2^n and then checking which of them
 * corrupted address 0 tells us where the address space wraps. Tries 3-byte
 * addressing first: on a 2-byte part the extra byte is consumed as data, which
 * shows up as a failed readback and we fall back.
 */
bool ez_fram_detect_size(ez_fram_geom_t *g)
{
    static const uint8_t marker0[8] = { 0x45, 0x5a, 0x53, 0x49, 0x5a, 0x45, 0x30, 0x00 };
    uint8_t probe[8], back[8];

    for (int ab = 2; ab <= 3; ab++) {
        g_geom.addr_bytes = (uint8_t)ab;

        /* Sanity: a plain write/read at 0 must work before we trust anything. */
        ez_fram_write(0, marker0, 8);
        ez_fram_read(0, back, 8);
        if (memcmp(back, marker0, 8) != 0) continue;

        uint32_t size = 0;
        for (int bit = 6; bit <= 23; bit++) {      /* 64 B .. 8 MB */
            uint32_t a = 1u << bit;
            memcpy(probe, marker0, 8);
            probe[7] = (uint8_t)bit;

            ez_fram_write(a, probe, 8);
            ez_fram_read(0, back, 8);

            if (memcmp(back, marker0, 8) != 0) {
                /* Address a aliased onto 0 -> device is 2^bit bytes. */
                size = a;
                /* Restore address 0 for tidiness. */
                ez_fram_write(0, marker0, 8);
                break;
            }
            /* Confirm the marker actually landed where we put it. */
            ez_fram_read(a, back, 8);
            if (memcmp(back, probe, 8) != 0) { size = 0; break; }
        }

        if (size) {
            g_geom.present = true;
            g_geom.size_bytes = size;
            g_geom.size_confirmed = true;
            g_geom.addr_bytes = (uint8_t)ab;
            /* Parts over 512 Kbit need 3 address bytes; if we found a big
             * device using 2-byte addressing the result is not trustworthy. */
            if (ab == 2 && size > 65536u) { g_geom.size_confirmed = false; }
            *g = g_geom;
            return true;
        }
    }

    g_geom.present = false;
    g_geom.size_confirmed = false;
    *g = g_geom;
    return false;
}

/* --- tests --------------------------------------------------------------- */

static uint32_t xorshift32(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *s = x;
}

static void note_error(ez_fram_result_t *r, uint32_t addr, uint8_t exp, uint8_t got)
{
    if (r->error_count == 0) {
        r->first_error_addr = addr;
        r->first_error_expected = exp;
        r->first_error_got = got;
    }
    r->error_count++;
}

bool ez_fram_test_region(uint32_t addr, uint32_t len, ez_fram_result_t *r,
                         uint8_t *scratch, size_t scratch_len)
{
    memset(r, 0, sizeof(*r));
    if (len > scratch_len / 2) len = (uint32_t)(scratch_len / 2);

    uint8_t *saved = scratch;
    uint8_t *work  = scratch + len;

    ez_fram_read(addr, saved, len);

    /* A device that is absent or has a stuck MISO returns all 0x00 or 0xFF
     * for every read; catch that before interpreting any pattern result. */
    ez_fram_id_t id;
    r->id_ok = ez_fram_read_id(&id);

    uint8_t sr_before = ez_fram_read_status();
    cmd_only(FRAM_OP_WREN);
    uint8_t sr_wren = ez_fram_read_status();
    cmd_only(FRAM_OP_WRDI);
    uint8_t sr_wrdi = ez_fram_read_status();
    r->sr_ok = ((sr_wren & FRAM_SR_WEL) != 0) && ((sr_wrdi & FRAM_SR_WEL) == 0);
    (void)sr_before;

    static const uint8_t pats[] = { 0x00, 0xff, 0x55, 0xaa, 0x0f, 0xf0 };
    r->patterns_ok = true;
    for (size_t p = 0; p < count_of(pats); p++) {
        memset(work, pats[p], len);
        ez_fram_write(addr, work, len);
        memset(work, (uint8_t)~pats[p], len);
        ez_fram_read(addr, work, len);
        for (uint32_t i = 0; i < len; i++) {
            if (work[i] != pats[p]) {
                note_error(r, addr + i, pats[p], work[i]);
                r->patterns_ok = false;
            }
        }
        r->bytes_tested += len;
    }

    /* Address-unique pattern: catches shorted or swapped address lines, which
     * a uniform pattern cannot see. */
    for (uint32_t i = 0; i < len; i++)
        work[i] = (uint8_t)((addr + i) ^ ((addr + i) >> 8) ^ 0x5a);
    ez_fram_write(addr, work, len);
    uint8_t *check = work;   /* reuse: recompute expected on the fly */
    ez_fram_read(addr, check, len);
    r->addressing_ok = true;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t exp = (uint8_t)((addr + i) ^ ((addr + i) >> 8) ^ 0x5a);
        if (check[i] != exp) {
            note_error(r, addr + i, exp, check[i]);
            r->addressing_ok = false;
        }
    }
    r->bytes_tested += len;

    /* Stuck-bus detection: if every byte we ever read back was 0x00 or 0xFF
     * while we wrote varied data, MISO is not moving. */
    bool all_same = true;
    for (uint32_t i = 1; i < len; i++) if (check[i] != check[0]) { all_same = false; break; }
    r->bus_ok = !(all_same && (check[0] == 0x00 || check[0] == 0xff));

    ez_fram_write(addr, saved, len);   /* restore */
    return r->patterns_ok && r->addressing_ok && r->bus_ok;
}

bool ez_fram_test_full(uint32_t size_bytes, ez_fram_result_t *r,
                       void (*progress)(uint32_t, uint32_t))
{
    memset(r, 0, sizeof(*r));
    r->bus_ok = true;
    r->patterns_ok = true;
    r->addressing_ok = true;

    uint8_t buf[256];

    /* Pass 1: address-unique pattern over the whole device. */
    for (uint32_t a = 0; a < size_bytes; a += sizeof(buf)) {
        uint32_t n = size_bytes - a;
        if (n > sizeof(buf)) n = sizeof(buf);
        for (uint32_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((a + i) ^ ((a + i) >> 8) ^ ((a + i) >> 16));
        ez_fram_write(a, buf, n);
        if (progress && (a % 4096 == 0)) progress(a, size_bytes * 2);
    }
    for (uint32_t a = 0; a < size_bytes; a += sizeof(buf)) {
        uint32_t n = size_bytes - a;
        if (n > sizeof(buf)) n = sizeof(buf);
        ez_fram_read(a, buf, n);
        for (uint32_t i = 0; i < n; i++) {
            uint8_t exp = (uint8_t)((a + i) ^ ((a + i) >> 8) ^ ((a + i) >> 16));
            if (buf[i] != exp) { note_error(r, a + i, exp, buf[i]); r->addressing_ok = false; }
        }
        r->bytes_tested += n;
        if (progress && (a % 4096 == 0)) progress(size_bytes + a, size_bytes * 2);
    }

    /* Pass 2: pseudorandom fill, verified with the same seed. */
    uint32_t s = 0x13579bdfu;
    for (uint32_t a = 0; a < size_bytes; a += sizeof(buf)) {
        uint32_t n = size_bytes - a;
        if (n > sizeof(buf)) n = sizeof(buf);
        for (uint32_t i = 0; i < n; i++) buf[i] = (uint8_t)xorshift32(&s);
        ez_fram_write(a, buf, n);
    }
    s = 0x13579bdfu;
    for (uint32_t a = 0; a < size_bytes; a += sizeof(buf)) {
        uint32_t n = size_bytes - a;
        if (n > sizeof(buf)) n = sizeof(buf);
        ez_fram_read(a, buf, n);
        for (uint32_t i = 0; i < n; i++) {
            uint8_t exp = (uint8_t)xorshift32(&s);
            if (buf[i] != exp) { note_error(r, a + i, exp, buf[i]); r->patterns_ok = false; }
        }
        r->bytes_tested += n;
    }

    ez_fram_id_t id;
    r->id_ok = ez_fram_read_id(&id);
    return r->error_count == 0;
}

void ez_fram_bench(uint32_t addr, uint32_t len, uint8_t *scratch,
                   uint32_t *write_bps, uint32_t *read_bps, bool *verify_ok)
{
    uint32_t s = 0xc0ffee11u;
    for (uint32_t i = 0; i < len; i++) scratch[i] = (uint8_t)xorshift32(&s);

    uint64_t t0 = time_us_64();
    ez_fram_write(addr, scratch, len);
    uint64_t t1 = time_us_64();

    uint8_t *rd = scratch + len;
    ez_fram_read(addr, rd, len);
    uint64_t t2 = time_us_64();

    *verify_ok = (memcmp(scratch, rd, len) == 0);
    *write_bps = (t1 > t0) ? (uint32_t)((uint64_t)len * 1000000u / (t1 - t0)) : 0;
    *read_bps  = (t2 > t1) ? (uint32_t)((uint64_t)len * 1000000u / (t2 - t1)) : 0;
}
