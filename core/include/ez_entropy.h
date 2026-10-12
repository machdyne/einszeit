/*
 * ez_entropy.h -- online entropy monitoring and per-key acceptance tests
 * (EZ-IMPL-001 §7.2, §7.3)
 *
 * Both work on a stream, one byte at a time, so no copy of key material is
 * kept: the only retained data are counters and a 16-bit history used by
 * the autocorrelation test, which ez_mon_clear() wipes (SEC-FW-003).
 * Bits are taken most significant first.
 *
 * Online monitor (§2.3, SEC-ENTROPY-004): consecutive 4,096-bit windows.
 *   monobit     ones in window within 2048 +/- 200       (6.25 sigma)
 *   runs        number of runs within 2048.5 +/- 200     (6.25 sigma)
 *   longest run fewer than 44 identical bits
 *   autocorr    for lags 1..16, agreements within pairs/2 +/- 200
 * False-alarm probability for an ideal source: about 7.5e-9 per window,
 * 1.5e-5 per MiB generated. A false alarm halts generation (retry), it does
 * not accept bad data.
 *
 * Acceptance tests (SEC-ENTROPY-002), over the whole key as read back:
 *   FIPS 140-2 §4.9.1 monobit, poker, runs and long run on every complete
 *   20,000-bit block. An ideal source fails each test in roughly 1e-4 of
 *   blocks, so a key is rejected only when the number of failing blocks
 *   for a test exceeds a Poisson bound: P(false rejection) <= 1e-9 per
 *   test per key. Per-block rates used (upper 99.9% bounds, ppm):
 *   monobit 110, poker 105, runs 450, long run 520 (full
 *   derivation: docs/einszeit-entropy-thresholds.md and
 *   tests/tools/derive_thresholds.py).
 *   Whole-key monobit within 7 sigma, and byte-frequency chi-square
 *   (255 dof) within [136, 426], each <= 1e-10 for an ideal source.
 *   The lower chi-square bound rejects output that is too uniform (for
 *   example a counter).
 *
 * EZ-SEC-001 traceability: SEC-ENTROPY-002, SEC-ENTROPY-004, §2.3,
 * SEC-TEST-ENT-002.
 */
#ifndef EZ_ENTROPY_H
#define EZ_ENTROPY_H

#include <stdbool.h>
#include <stdint.h>

/* Failure bits; also the "detail" byte of key generation events. */
#define EZ_EF_MON_MONOBIT   0x01
#define EZ_EF_MON_RUNS      0x02   /* runs count or longest run */
#define EZ_EF_MON_AUTOCORR  0x04
#define EZ_EF_ACC_MONOBIT   0x08
#define EZ_EF_ACC_POKER     0x10
#define EZ_EF_ACC_RUNS      0x20   /* FIPS runs or long run */
#define EZ_EF_ACC_WHOLE     0x40   /* whole-key monobit or chi-square */
#define EZ_EF_OTHER         0x80   /* media, read-back, hardware fault, cancel */

#define EZ_MON_WINDOW_BITS  4096u
#define EZ_FIPS_BLOCK_BITS  20000u

typedef struct {
	uint32_t bits;          /* bits seen in the current window */
	uint32_t total_bits;    /* bits seen overall (history validity) */
	uint32_t ones;
	uint32_t runs;
	uint32_t run_len, longest;
	uint32_t agree[16];
	uint32_t pairs[16];
	uint16_t hist;          /* previous 16 bits, newest in bit 0 */
	uint32_t windows;       /* completed windows */
	uint8_t  fail;
} ez_monitor_t;

void    ez_mon_init(ez_monitor_t *m);
/* Feed bytes; returns failure bits (0 = healthy). Evaluated at every
 * window boundary; once failed, stays failed. */
uint8_t ez_mon_feed(ez_monitor_t *m, const uint8_t *p, uint32_t n);
void    ez_mon_clear(ez_monitor_t *m);

typedef struct {
	/* current FIPS block */
	uint32_t bits;
	uint32_t ones;
	uint16_t nib[16];
	uint8_t  nibv, nibn;
	int      cur;            /* current run bit value, -1 at block start */
	uint32_t run_len;
	uint32_t runs[2][6];
	bool     longrun;
	/* failing-block counts per test: monobit, poker, runs, long run */
	uint32_t blocks;
	uint32_t fails[4];
	/* whole key */
	uint64_t total_bits;
	uint64_t total_ones;
	uint32_t bytefreq[256];
} ez_accept_t;

void    ez_acc_init(ez_accept_t *a);
void    ez_acc_feed(ez_accept_t *a, const uint8_t *p, uint32_t n);
/* Evaluate; returns failure bits (0 = accept). Clears the state. */
uint8_t ez_acc_finish(ez_accept_t *a);

/* Exposed for tests: smallest number of failing blocks that rejects a key,
 * for `blocks` blocks at `ppm` false failures per block. */
uint32_t ez_acc_reject_threshold(uint32_t blocks, uint32_t ppm);

/* Per-block false-failure rates (ppm) used by the acceptance rule. */
#define EZ_FIPS_PPM_MONOBIT 110u
#define EZ_FIPS_PPM_POKER   105u
#define EZ_FIPS_PPM_RUNS    450u
#define EZ_FIPS_PPM_LONGRUN 520u

#endif /* EZ_ENTROPY_H */
