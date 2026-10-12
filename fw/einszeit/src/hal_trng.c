/*
 * hal_trng.c -- ez_hal_trng_t over the RP2350 TRNG, production profile.
 *
 * IMPL-ENT-001: SAMPLE_CNT1 = 16384 (the ent001 operating point), inverter
 * chain 0, and NO bypass bits: the Von Neumann balancer, the continuous RNG
 * test and the autocorrelation test are always on. There is no code path
 * that sets TRNG_DEBUG_CONTROL (unlike fw/test). Register sequence from
 * fw/test/src/ez_trng.c.
 *
 * IMPL-ENT-002 / SEC-ENTROPY-004: a collection that raised a health flag is
 * discarded, never used. An autocorrelation failure (fatal in hardware), a
 * timeout, or more than 4 flagged collections within one read() resets the
 * block, discards everything buffered, and returns EZ_ERR_ENTROPY. There is
 * no fallback source.
 *
 * Bytes left over from a 24-byte collection are kept for the next call and
 * cleared as they are used (SEC-GEN-001, SEC-FW-003).
 */
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/structs/trng.h"
#include "hardware/regs/trng.h"
#include "hardware/clocks.h"

#include "ez_secure.h"
#include "hal_rp2350.h"

static hal_trng_stats_t st;
static uint8_t pool[24];
static uint32_t pool_n;
static bool running;

void hal_trng_get_stats(hal_trng_stats_t *s) { *s = st; }

static void trng_reset(void)
{
	trng_hw->rnd_source_enable = 0;
	trng_hw->trng_sw_reset = 1;
	busy_wait_us(50);
	trng_hw->rnd_source_enable = 0;
	trng_hw->trng_config = 0;                    /* inverter chain 0 */
	trng_hw->sample_cnt1 = TRNG_SAMPLE_CNT1;
	trng_hw->rng_imr = 0xffffffffu;              /* polled */
	trng_hw->rng_icr = 0xffffffffu;
	trng_hw->autocorr_statistic = 0;
	trng_hw->rst_bits_counter = 1;
	running = false;
	ez_secure_zero(pool, sizeof pool);
	pool_n = 0;
}

static uint32_t timeout_us(void)
{
	uint64_t clk = clock_get_hz(clk_sys);
	if (clk == 0) clk = 150000000u;
	uint64_t us = ((uint64_t)(TRNG_SAMPLE_CNT1 + 1u) * 192u * 16u * 1000000u) / clk;
	return us < 50000u ? 50000u : (uint32_t)us;
}

/* One 192-bit collection into pool. -1 fault, 0 flagged (discarded), 1 ok. */
static int collect(void)
{
	if (!running) {
		trng_hw->rng_icr = 0xffffffffu;
		trng_hw->rnd_source_enable = TRNG_RND_SOURCE_ENABLE_RND_SRC_EN_BITS;
		running = true;
	}
	absolute_time_t deadline = make_timeout_time_us(timeout_us());
	uint32_t isr;
	for (;;) {
		isr = trng_hw->rng_isr;
		if (isr & (TRNG_RNG_ISR_EHR_VALID_BITS | TRNG_RNG_ISR_AUTOCORR_ERR_BITS)) break;
		if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) { st.timeouts++; return -1; }
		tight_loop_contents();
	}
	if (isr & TRNG_RNG_ISR_AUTOCORR_ERR_BITS) { st.autocorr_err++; return -1; }
	uint32_t w[6];
	for (int i = 0; i < 6; i++) w[i] = trng_hw->ehr_data[i];   /* releases the EHR */
	trng_hw->rng_icr = 0xffffffffu;
	bool flagged = false;
	if (isr & TRNG_RNG_ISR_VN_ERR_BITS)    { st.vn_err++; flagged = true; }
	if (isr & TRNG_RNG_ISR_CRNGT_ERR_BITS) { st.crngt_err++; flagged = true; }
	if (!flagged) {
		for (int i = 0; i < 6; i++)
			for (int k = 0; k < 4; k++) pool[4 * i + k] = (uint8_t)(w[i] >> (8 * k));
		pool_n = 24;
		st.collections++;
	}
	ez_secure_zero(w, sizeof w);
	return flagged ? 0 : 1;
}

static ez_status_t t_read(void *ctx, void *buf, uint32_t len)
{
	(void)ctx;
	uint8_t *p = buf;
	int flagged = 0;
	while (len) {
		if (pool_n == 0) {
			int r = collect();
			if (r < 0 || (r == 0 && ++flagged > 4)) {
				st.faults++;
				trng_reset();
				ez_secure_zero(buf, (size_t)(p - (uint8_t *)buf));
				return EZ_ERR_ENTROPY;
			}
			if (r == 0) continue;
		}
		uint32_t n = pool_n < len ? pool_n : len;
		memcpy(p, pool + (24 - pool_n), n);
		ez_secure_zero(pool + (24 - pool_n), n);
		pool_n -= n; p += n; len -= n;
	}
	return EZ_OK;
}

static uint8_t init_done;
static ez_status_t t_read_init(void *ctx, void *buf, uint32_t len)
{
	if (!init_done) { trng_reset(); init_done = 1; }
	return t_read(ctx, buf, len);
}

const ez_hal_trng_t hal_trng = { NULL, TRNG_PROFILE_ID, t_read_init };

uint32_t hal_uptime_s(void) { return (uint32_t)(time_us_64() / 1000000u); }
