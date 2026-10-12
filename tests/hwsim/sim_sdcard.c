/* sim_sdcard.c -- see sim_sdcard.h. Also implements pico_shim.h. */
#include "sim_sdcard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "board.h"
#include "pico_shim.h"

spi_inst_t sim_spi0 = { 0 }, sim_spi1 = { 1 };
static uint64_t now;

/* ---- sparse storage ------------------------------------------------------- */
#define HCAP (1u << 18)
static uint32_t *hkey;
static uint8_t **hval;
static uint8_t **slot(uint32_t lba, bool create)
{
	uint32_t h = (lba * 2654435761u) & (HCAP - 1);
	for (;;) {
		if (hkey[h] == lba + 1) return &hval[h];
		if (!hkey[h]) {
			if (!create) return NULL;
			hkey[h] = lba + 1;
			return &hval[h];
		}
		h = (h + 1) & (HCAP - 1);
	}
}

/* ---- card state ------------------------------------------------------------- */
static sim_sd_cfg_t cfg;
static struct {
	bool inserted, powered, spi_mode, ready, app, wedged, cs_low, tmp_wp;
	int acmd41;
	uint8_t frame[6]; int flen;
	uint8_t out[600]; int out_n, out_i;
	int rx;                         /* 0 none, 24 write block, 27 program CSD */
	bool rx_started; int rx_n; uint8_t rx_buf[514];
	uint32_t rx_lba, er_start, er_end;
	uint64_t busy_until, bg_until;
	uint64_t held_left;             /* internal work that progresses only while CS is high */
	uint8_t r2;                     /* status error bits for CMD13 */
	unsigned long writes;
	int det_pull;                   /* 1 up, 0 down */
} c;

static uint16_t crc16(const uint8_t *p, int n)
{
	uint16_t x = 0;
	for (int i = 0; i < n; i++) {
		x ^= (uint16_t)(p[i] << 8);
		for (int b = 0; b < 8; b++) x = (x & 0x8000) ? (uint16_t)((x << 1) ^ 0x1021) : (uint16_t)(x << 1);
	}
	return x;
}
static uint8_t crc7(const uint8_t *p, int n)
{
	uint8_t x = 0;
	for (int i = 0; i < n; i++)
		for (int b = 7; b >= 0; b--) {
			int in = (p[i] >> b) & 1, top = (x >> 6) & 1;
			x = (uint8_t)((x << 1) & 0x7F);
			if (in ^ top) x ^= 0x09;
		}
	return x;
}

static void q(uint8_t b) { if (c.out_n < (int)sizeof c.out) c.out[c.out_n++] = b; }
static void q_block(const uint8_t *d, int n)
{
	q(0xFF); q(0xFE);
	for (int i = 0; i < n; i++) q(d[i]);
	uint16_t x = crc16(d, n);
	q((uint8_t)(x >> 8)); q((uint8_t)x);
}

static void csd(uint8_t o[16])
{
	memset(o, 0, 16);
	o[0] = 0x40;                                     /* CSD v2 */
	o[3] = 0x32; o[4] = 0x5B; o[5] = 0x59;
	uint32_t cs = cfg.blocks / 1024u - 1u;           /* C_SIZE */
	o[7] = (uint8_t)((cs >> 16) & 0x3F); o[8] = (uint8_t)(cs >> 8); o[9] = (uint8_t)cs;
	o[10] = 0x7F; o[11] = 0x80; o[12] = 0x0A; o[13] = 0x40;
	o[14] = c.tmp_wp ? 0x10 : 0x00;
	o[15] = (uint8_t)((crc7(o, 15) << 1) | 1);
}

static int trace = -1;
static void command(void)
{
	if (trace < 0) trace = getenv("SDTRACE") != NULL;
	uint8_t cmd = c.frame[0] & 0x3F;
	uint32_t arg = (uint32_t)c.frame[1] << 24 | (uint32_t)c.frame[2] << 16 | (uint32_t)c.frame[3] << 8 | c.frame[4];
	bool app = c.app;
	c.app = false;
	c.out_n = c.out_i = 0;
	q(0xFF);                                         /* NCR */
	if (now < c.busy_until) {                        /* a command while busy */
		if (cmd == 0 && cfg.wedge_on_busy_reset) c.wedged = true;
		c.out_n = 0;
		return;
	}
	if (!c.spi_mode) {
		if (cmd == 0) { c.spi_mode = true; c.ready = false; c.acmd41 = 0; q(0x01); }
		return;
	}
	uint8_t idle = c.ready ? 0x00 : 0x01;
	switch (app ? 100 + cmd : cmd) {
	case 0: c.ready = false; c.acmd41 = 0; q(0x01); break;
	case 8: q(idle); q(0); q(0); q(0x01); q((uint8_t)arg); break;
	case 55: c.app = true; q(idle); break;
	case 141: if (++c.acmd41 >= 3) c.ready = true; q(c.ready ? 0x00 : 0x01); break;
	case 58: q(idle); q(0xC0); q(0xFF); q(0x80); q(0x00); break;
	case 59: case 16: case 12: q(idle); break;
	case 9: { uint8_t o[16]; csd(o); q(0x00); q_block(o, 16); break; }
	case 10: { uint8_t o[16] = { 0x1B, 'S', 'M', 'E', 'Z', 'S', 'I', 'M', 0x10, 1, 2, 3, 4, 0x01, 0x23, 0 };
	           o[15] = (uint8_t)((crc7(o, 15) << 1) | 1); q(0x00); q_block(o, 16); break; }
	case 13: q(c.ready ? 0x00 : 0x01); q(c.r2); c.r2 = 0; break;
	case 17:
		if (!c.ready) { q(0x05); break; }
		if (arg >= cfg.blocks) { q(0x20); c.r2 |= 0x80; break; }   /* ADDRESS_ERROR, OUT_OF_RANGE */
		{ uint8_t d[512]; sim_sd_raw_read(arg, d); q(0x00); q_block(d, 512); }
		break;
	case 24:
		if (!c.ready) { q(0x05); break; }
		if (arg >= cfg.blocks) { q(0x20); c.r2 |= 0x80; break; }
		q(0x00); c.rx = 24; c.rx_lba = arg; c.rx_started = false; c.rx_n = 0;
		break;
	case 27: q(0x00); c.rx = 27; c.rx_started = false; c.rx_n = 0; break;
	case 32: c.er_start = arg; q(arg < cfg.blocks ? 0x00 : 0x20); break;
	case 33: c.er_end = arg; q(arg < cfg.blocks ? 0x00 : 0x20); break;
	case 38: {
		q(0x00);
		uint64_t mib = ((uint64_t)c.er_end - c.er_start + 1u) / 2048u + 1u;
		for (uint32_t b = c.er_start; b <= c.er_end && b < cfg.blocks; b++) {
			uint8_t **s = slot(b, false);
			if (s && *s) { free(*s); *s = NULL; }
		}
		c.busy_until = now + 20 + cfg.erase_busy_us_per_mib * mib;
		/* background work continues for erase_bg_us after the last erase */
		c.bg_until = c.busy_until + cfg.erase_bg_us;
		break;
	}
	default: q(0x04); break;                       /* illegal command */
	}
	if (trace) fprintf(stderr, "sd: %sCMD%u arg %08x -> r1 %02x (t=%llu)\n", app ? "A" : "", cmd, arg,
	                   c.out_n > 1 ? c.out[1] : 0xFF, (unsigned long long)now);
}

static uint8_t xfer(uint8_t in)
{
	now += 1;                                       /* about 1 us per byte */
	if (!c.cs_low && c.held_left) c.held_left = c.held_left > 1 ? c.held_left - 1 : 0;
	if (!c.inserted || !c.powered || !c.cs_low || c.wedged) return 0xFF;
	if (c.held_left && c.out_i >= c.out_n && !c.rx) return 0x00;      /* busy until released long enough */
	if (c.out_i < c.out_n) return c.out[c.out_i++];  /* a pending response first */
	if (c.rx) {                                     /* receiving a data block */
		if (!c.rx_started) {
			if (in == 0xFE) c.rx_started = true;
			return 0xFF;
		}
		int need = c.rx == 24 ? 514 : 18;
		c.rx_buf[c.rx_n++] = in;
		if (c.rx_n < need) return 0xFF;
		int kind = c.rx;
		c.rx = 0;
		c.out_n = c.out_i = 0;
		if (kind == 24) {
			if (cfg.cut_after_writes == 0) { c.powered = false; return 0xFF; }
			if (cfg.cut_after_writes > 0) cfg.cut_after_writes--;
			if (c.tmp_wp) { q(0x0D); return 0xFF; }
			sim_sd_raw_write(c.rx_lba, c.rx_buf);
			c.writes++;
			if (cfg.stall_every && c.writes % cfg.stall_every == 0) c.held_left = cfg.stall_us;
			uint64_t sim_sd_slow_take(void);
			uint64_t busy = cfg.write_busy_us, slow = sim_sd_slow_take();
			if (slow > busy) busy = slow;
			if (c.bg_until > now && c.bg_until - now > busy) busy = c.bg_until - now;
			c.busy_until = now + busy;
		} else {
			c.tmp_wp = (c.rx_buf[14] & 0x10) != 0;
			c.busy_until = now + 1000;
		}
		q(0x05);
		return 0xFF;
	}
	if (c.out_i < c.out_n) return c.out[c.out_i++];
	if (now < c.busy_until && c.flen == 0 && (in == 0xFF)) return 0x00;    /* holding DO low */
	if (c.flen == 0 && (in & 0xC0) != 0x40) return now < c.busy_until ? 0x00 : 0xFF;
	c.frame[c.flen++] = in;
	if (c.flen == 6) { c.flen = 0; command(); }
	return 0xFF;
}

/* ---- pico shim ---------------------------------------------------------------- */
uint32_t spi_init(spi_inst_t *s, uint32_t baud) { (void)s; return baud; }
uint32_t spi_set_baudrate(spi_inst_t *s, uint32_t baud) { (void)s; return baud; }
void spi_set_format(spi_inst_t *s, unsigned b, unsigned p, unsigned h, unsigned o) { (void)s; (void)b; (void)p; (void)h; (void)o; }
int spi_write_blocking(spi_inst_t *s, const uint8_t *src, size_t len) { (void)s; for (size_t i = 0; i < len; i++) xfer(src[i]); return (int)len; }
int spi_read_blocking(spi_inst_t *s, uint8_t tx, uint8_t *dst, size_t len) { (void)s; for (size_t i = 0; i < len; i++) dst[i] = xfer(tx); return (int)len; }
int spi_write_read_blocking(spi_inst_t *s, const uint8_t *src, uint8_t *dst, size_t len) { (void)s; for (size_t i = 0; i < len; i++) dst[i] = xfer(src[i]); return (int)len; }

void gpio_init(unsigned p) { (void)p; }
void gpio_set_dir(unsigned p, bool o) { (void)p; (void)o; }
void gpio_set_function(unsigned p, unsigned f) { (void)p; (void)f; }
void gpio_put(unsigned p, bool v)
{
	if (p == SD_CSN_PIN) {
		bool low = !v;
		if (!low) { c.flen = 0; c.out_n = c.out_i = 0; }
		c.cs_low = low;
	}
}
void gpio_pull_up(unsigned p) { if (p == SD_DET_PIN) c.det_pull = 1; }
void gpio_pull_down(unsigned p) { if (p == SD_DET_PIN) c.det_pull = 0; }
bool gpio_get(unsigned p)
{
	if (p == SD_DET_PIN) return c.inserted ? true : c.det_pull == 1;   /* V1: switch to 3.3 V */
	return false;
}

uint64_t time_us_64(void) { return now; }
uint64_t sim_now_us(void) { return now; }
static void pass(uint64_t us)
{
	now += us;
	if (!c.cs_low && c.held_left) c.held_left = c.held_left > us ? c.held_left - us : 0;
}
void sleep_ms(uint32_t ms) { pass((uint64_t)ms * 1000u); }
void sleep_us(uint64_t us) { pass(us); }
void busy_wait_us(uint64_t us) { now += us; }
absolute_time_t get_absolute_time(void) { return now; }
absolute_time_t make_timeout_time_ms(uint32_t ms) { return now + (uint64_t)ms * 1000u; }
absolute_time_t make_timeout_time_us(uint64_t us) { return now + us; }
int64_t absolute_time_diff_us(absolute_time_t a, absolute_time_t b) { return (int64_t)(b - a); }

/* ---- control ----------------------------------------------------------------------- */
void sim_sd_init(const sim_sd_cfg_t *x)
{
	sim_sd_free();
	cfg = *x;
	hkey = calloc(HCAP, sizeof *hkey);
	hval = calloc(HCAP, sizeof *hval);
	memset(&c, 0, sizeof c);
	c.inserted = c.powered = true;
	c.det_pull = 1;
}
void sim_sd_free(void)
{
	if (!hkey) return;
	for (uint32_t i = 0; i < HCAP; i++) free(hval[i]);
	free(hkey); free(hval);
	hkey = NULL; hval = NULL;
}
void sim_sd_power_cycle(void)
{
	c.powered = true; c.spi_mode = c.ready = c.wedged = c.app = false;
	c.busy_until = c.bg_until = 0; c.rx = 0; c.flen = 0; c.out_n = c.out_i = 0;
	if (cfg.cut_after_writes == 0) cfg.cut_after_writes = -1;
}
void sim_sd_remove(void) { c.inserted = false; }
void sim_sd_insert(void) { c.inserted = true; sim_sd_power_cycle(); }
bool sim_sd_wedged(void) { return c.wedged; }
bool sim_sd_tmp_wp(void) { return c.tmp_wp; }
unsigned long sim_sd_writes(void) { return c.writes; }
void sim_sd_raw_read(uint32_t lba, uint8_t out[512])
{
	uint8_t **s = slot(lba, false);
	if (s && *s) memcpy(out, *s, 512); else memset(out, 0, 512);
}
void sim_sd_raw_write(uint32_t lba, const uint8_t in[512])
{
	uint8_t **s = slot(lba, true);
	if (!*s) *s = malloc(512);
	memcpy(*s, in, 512);
}
void sim_sd_set_write_busy_us(uint64_t us) { cfg.write_busy_us = us; }
/* The card is busy (DO low) for us from now, as after a write the
 * driver gave up on. */
void sim_sd_make_busy(uint64_t us) { c.busy_until = now + us; }
static long slow_n; static uint64_t slow_us;
void sim_sd_slow_next_writes(long n, uint64_t us) { slow_n = n; slow_us = us; }
uint64_t sim_sd_slow_take(void) { if (slow_n > 0) { slow_n--; return slow_us; } return 0; }
void sim_sd_cut_after(long n) { cfg.cut_after_writes = n; }
