/*
 * test_entropy.c -- online monitor and per-key acceptance tests.
 *
 * EZ-SEC-001:
 *   SEC-TEST-ENT-002  a known-bad stream triggers a halt within one window
 *   SEC-ENTROPY-002   acceptance tests reject bad keys and accept good ones
 *   §2.3              monobit, runs and autocorrelation monitoring
 */
#include <stdlib.h>
#include <string.h>

#include "ez_entropy.h"
#include "ez_secure.h"
#include "ez_test.h"
#include "sim_trng.h"

#define WIN_BYTES (EZ_MON_WINDOW_BITS / 8)

static uint8_t buf[1 << 20];

static void gen(sim_trng_mode_t mode, uint32_t param, uint64_t seed, uint32_t n)
{
	sim_trng_t t;
	sim_trng_init(&t, seed);
	sim_trng_mode(&t, mode, param);
	EZ_CHECK_EQ(t.hal.read(t.hal.ctx, buf, n), EZ_OK);
}

/* Feed exactly one window: the halt must come within it. */
static uint8_t one_window(sim_trng_mode_t mode, uint32_t param)
{
	gen(mode, param, 99, WIN_BYTES);
	ez_monitor_t m;
	ez_mon_init(&m);
	uint8_t f = ez_mon_feed(&m, buf, WIN_BYTES);
	EZ_CHECK_EQ(m.windows, 1);
	return f;
}

static void t_monitor_good(void)
{
	/* 256 windows (128 KiB) from a good source: no false alarm. Over
	 * 64 seeds, 16,384 windows; expected false alarms ~1.2e-4. */
	for (uint64_t seed = 1; seed <= 64; seed++) {
		gen(SIM_TRNG_GOOD, 0, seed, 256 * WIN_BYTES);
		ez_monitor_t m;
		ez_mon_init(&m);
		EZ_CHECK_EQ(ez_mon_feed(&m, buf, 256 * WIN_BYTES), 0);
		EZ_CHECK_EQ(m.windows, 256);
		ez_mon_clear(&m);
		EZ_CHECK(ez_is_zero(&m, sizeof m));
	}
}

/* SEC-TEST-ENT-002 */
static void t_monitor_halts_within_one_window(void)
{
	EZ_CHECK(one_window(SIM_TRNG_BIASED, 154) & EZ_EF_MON_MONOBIT);   /* P(1) = 0.60 */
	EZ_CHECK(one_window(SIM_TRNG_BIASED, 102) & EZ_EF_MON_MONOBIT);   /* P(1) = 0.40 */
	EZ_CHECK(one_window(SIM_TRNG_STUCK, 0x00) != 0);
	EZ_CHECK(one_window(SIM_TRNG_STUCK, 0xFF) != 0);
	EZ_CHECK(one_window(SIM_TRNG_STUCK, 0xA7) & EZ_EF_MON_AUTOCORR);   /* period 8 */
	EZ_CHECK(one_window(SIM_TRNG_ALTERNATING, 0) & EZ_EF_MON_RUNS);
	EZ_CHECK(one_window(SIM_TRNG_ALTERNATING, 0) & EZ_EF_MON_AUTOCORR);
	EZ_CHECK(one_window(SIM_TRNG_CORRELATED, 128) & EZ_EF_MON_RUNS);   /* repeat p=0.5 */
	EZ_CHECK(one_window(SIM_TRNG_COUNTER, 0) != 0);
}

/* A failure in a later window is caught in that window. */
static void t_monitor_late_failure(void)
{
	gen(SIM_TRNG_GOOD, 0, 5, 10 * WIN_BYTES);
	memset(buf + 7 * WIN_BYTES, 0x00, WIN_BYTES);
	ez_monitor_t m;
	ez_mon_init(&m);
	EZ_CHECK_EQ(ez_mon_feed(&m, buf, 7 * WIN_BYTES), 0);
	EZ_CHECK(ez_mon_feed(&m, buf + 7 * WIN_BYTES, WIN_BYTES) != 0);
	EZ_CHECK_EQ(m.windows, 8);
}

static uint8_t accept(const uint8_t *p, uint32_t n, uint32_t piece)
{
	ez_accept_t a;
	ez_acc_init(&a);
	for (uint32_t i = 0; i < n; i += piece)
		ez_acc_feed(&a, p + i, n - i < piece ? n - i : piece);
	return ez_acc_finish(&a);
}

static void t_accept_good(void)
{
	for (uint64_t seed = 1; seed <= 20; seed++) {
		gen(SIM_TRNG_GOOD, 0, seed, 1 << 20);
		EZ_CHECK_EQ(accept(buf, 1 << 20, 512), 0);
	}
	gen(SIM_TRNG_GOOD, 0, 3, 8192);           /* minimum generated size */
	EZ_CHECK_EQ(accept(buf, 8192, 512), 0);
	/* Feeding in different piece sizes gives the same verdict. */
	gen(SIM_TRNG_GOOD, 0, 4, 65536);
	EZ_CHECK_EQ(accept(buf, 65536, 1), 0);
	EZ_CHECK_EQ(accept(buf, 65536, 7), 0);
}

static void t_accept_rejects_sources(void)
{
	uint32_t n = 1 << 18;
	gen(SIM_TRNG_BIASED, 133, 1, n);          /* P(1) = 0.52: subtle */
	EZ_CHECK(accept(buf, n, 512) & (EZ_EF_ACC_WHOLE | EZ_EF_ACC_MONOBIT));
	gen(SIM_TRNG_CORRELATED, 26, 1, n);       /* repeat p ~ 0.1 extra */
	EZ_CHECK(accept(buf, n, 512) & EZ_EF_ACC_RUNS);
	gen(SIM_TRNG_COUNTER, 0, 1, n);           /* uniform but not random */
	EZ_CHECK(accept(buf, n, 512) & EZ_EF_ACC_WHOLE);
	gen(SIM_TRNG_STUCK, 0x00, 1, n);
	EZ_CHECK(accept(buf, n, 512) != 0);
	gen(SIM_TRNG_ALTERNATING, 0, 1, n);
	EZ_CHECK(accept(buf, n, 512) != 0);
}

/* Each FIPS test individually: plant a defect in good data. */
static void t_accept_each_test(void)
{
	uint32_t n = 2500 * 8;                    /* 8 FIPS blocks */
	/* Long run: 32 zero bits in each of 6 blocks. */
	gen(SIM_TRNG_GOOD, 0, 11, n);
	for (int b = 0; b < 6; b++) memset(buf + b * 2500 + 100, 0x00, 4);
	EZ_CHECK(accept(buf, n, 512) & EZ_EF_ACC_RUNS);
	/* Poker: blocks of a repeated nibble pattern breaks poker and runs. */
	gen(SIM_TRNG_GOOD, 0, 12, n);
	for (int b = 0; b < 6; b++)
		for (int i = 0; i < 2500; i++) buf[b * 2500 + i] = (uint8_t)(i % 3 == 0 ? 0x5A : buf[b * 2500 + i]);
	EZ_CHECK(accept(buf, n, 512) & EZ_EF_ACC_POKER);
	/* Monobit: force ones in six blocks. */
	gen(SIM_TRNG_GOOD, 0, 13, n);
	for (int b = 0; b < 6; b++)
		for (int i = 0; i < 2500; i += 6) buf[b * 2500 + i] |= 0xF0;
	EZ_CHECK(accept(buf, n, 512) & EZ_EF_ACC_MONOBIT);
}

/* The Poisson threshold: tiny lambda tolerates exactly one failing block,
 * larger lambda proportionally more, and the table never runs out within
 * EZ_KEYGEN_MAX_LEN (64 MiB = 26,843 blocks). */
static void t_reject_threshold(void)
{
	EZ_CHECK_EQ(ez_acc_reject_threshold(0, 520), 1);
	EZ_CHECK_EQ(ez_acc_reject_threshold(3, 110), 3);       /* lam 3.3e-4: 3 fails reject */
	EZ_CHECK(ez_acc_reject_threshold(419, 520) >= 4);      /* 1 MiB */
	uint32_t blocks = (uint32_t)((64ull * 1024 * 1024 * 8) / EZ_FIPS_BLOCK_BITS);
	EZ_CHECK(ez_acc_reject_threshold(blocks, 520) > 0);
	EZ_CHECK(ez_acc_reject_threshold(blocks, 520) < 64);
	/* Monotonic in lambda. */
	uint32_t prev = 0;
	for (uint32_t b = 0; b <= blocks; b += 97) {
		uint32_t t = ez_acc_reject_threshold(b, 520);
		EZ_CHECK(t >= prev);
		prev = t;
	}
}

static void t_acc_clears_state(void)
{
	gen(SIM_TRNG_GOOD, 0, 21, 4096);
	ez_accept_t a;
	ez_acc_init(&a);
	ez_acc_feed(&a, buf, 4096);
	ez_acc_finish(&a);
	EZ_CHECK(ez_is_zero(&a, sizeof a));
}

static const ez_test_case_t cases[] = {
	{ "monitor_good",                    "§2.3", t_monitor_good },
	{ "monitor_halts_within_one_window", "SEC-TEST-ENT-002, SEC-ENTROPY-004, §2.3", t_monitor_halts_within_one_window },
	{ "monitor_late_failure",            "SEC-TEST-ENT-002", t_monitor_late_failure },
	{ "accept_good",                     "SEC-ENTROPY-002", t_accept_good },
	{ "accept_rejects_sources",          "SEC-ENTROPY-002", t_accept_rejects_sources },
	{ "accept_each_test",                "SEC-ENTROPY-002", t_accept_each_test },
	{ "reject_threshold",                "SEC-ENTROPY-002", t_reject_threshold },
	{ "acc_clears_state",                "SEC-FW-003", t_acc_clears_state },
};
EZ_TEST_MAIN(cases)
