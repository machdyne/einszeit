/*
 * test_meta_bitflip.c -- bit-flip injection into metadata storage.
 *
 * EZ-SEC-001:
 *   SEC-TEST-PTR-002  a corrupt session record is detected on power-on and
 *                     quarantined rather than silently used
 *   SEC-META-003      all records verified before any session operation
 *   SEC-PTR-001       a corrupt offset is never treated as a default value
 *
 * Exhaustive: every single bit of the 2 KB F-RAM is flipped in turn.
 * Sampled: 2- and 3-bit flips confined to one session record, where the
 * codes are designed to detect them (CRC-16/CCITT detects all 1-, 2- and
 * 3-bit errors in a slot; status codes have Hamming distance 4; selector
 * codes 8; CRC-32 has distance >= 4 at this length).
 *
 * The property checked for every session after every flip:
 *   - it is quarantined, OR it is exactly as before the flip;
 *   - it is never silently EMPTY if it was not before;
 *   - its offsets are never lower than before.
 */
#include <stdlib.h>
#include <string.h>

#include "meta_fixture.h"

static fx_t fx;
static uint8_t base_mem[EZ_META_SIZE];
static ez_meta_t base_m;

/* A representative state: several sessions with committed offsets, one
 * of them right after a torn commit (non-selected slot larger), one with
 * a persisted quarantine, one exhausted, one quarantined while its key is
 * being erased (must never become resolvable), and some log entries. */
static void build_state(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0x11111111, 8192, EZ_ROLE_ALICE, "alice");
	int b = fx_create(&fx, 0x22222222, 8192, EZ_ROLE_BOB, "bob");
	int c = fx_create(&fx, 0x33333333, 512, EZ_ROLE_ALICE, "quar");
	int d = fx_create(&fx, 0x44444444, 512, EZ_ROLE_BOB, "torn");
	int e = fx_create(&fx, 0x55555555, 100, EZ_ROLE_ALICE, "exh");
	int g = fx_create(&fx, 0x66666666, 512, EZ_ROLE_ALICE, "erasing");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 1000), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 1500), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 5000), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, b, 6000), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, b, 10), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, b, 20), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, c, 30), EZ_OK);
	EZ_CHECK_EQ(ez_meta_quarantine(&fx.m, c, EZ_Q_KEY_MISSING), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, d, 300), EZ_OK);
	sim_fram_arm_cut(&fx.fram, EZ_SLOT_SIZE);           /* torn: slot only */
	ez_meta_commit_tx(&fx.m, d, 400);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[d].tx_off, 400);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, e, 50), EZ_OK);
	EZ_CHECK_EQ(ez_meta_quarantine(&fx.m, g, EZ_Q_KEY_ERASING), EZ_OK);
	for (uint32_t i = 0; i < 6; i++)
		EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 0x100 + i, 512), EZ_OK);
	memcpy(base_mem, fx.fram.mem, EZ_META_SIZE);
	/* The reference: what a clean boot of the base state yields. */
	fx_reboot(&fx);
	base_m = fx.m;
}

static void check_against_base(void)
{
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *was = &base_m.s[i], *now = &fx.m.s[i];
		if (was->state == EZ_SS_EMPTY) {
			EZ_CHECK_MSG(now->state == EZ_SS_EMPTY || now->state == EZ_SS_QUARANTINED,
			             "garbage in an empty slot is quarantined, never usable");
			continue;
		}
		EZ_CHECK_MSG(now->state != EZ_SS_EMPTY, "a session never silently disappears");
		if (now->state == EZ_SS_QUARANTINED && now->qreason >= 0x80)
			continue;                              /* detected */
		/* A damaged reason code is read as the strictest reason. */
		if (was->state == EZ_SS_QUARANTINED && now->state == EZ_SS_QUARANTINED &&
		    now->qreason == EZ_Q_KEY_ERASING) {
			ez_session_t w = *was;
			w.qreason = EZ_Q_KEY_ERASING;
			EZ_CHECK_MSG(fx_session_same(now, &w), "undetected change to a session");
			continue;
		}
		EZ_CHECK_MSG(fx_session_same(now, was), "undetected change to a session");
	}
	EZ_CHECK_MSG(!(fx.m.drive0_enabled && !base_m.drive0_enabled),
	             "drive 0 never becomes enabled by corruption");
	/* Boot counter: corruption of the newer slot can expose the older one,
	 * which is at most one lower; the counter is advisory (IMPL §3.3). */
	if (fx.m.dev == EZ_DEV_VALID)
		EZ_CHECK(fx.m.boot_count + 1 >= base_m.boot_count);
}

static void boot_flipped(const uint32_t *bits, int n)
{
	memcpy(fx.fram.mem, base_mem, EZ_META_SIZE);
	for (int i = 0; i < n; i++)
		sim_fram_flip(&fx.fram, bits[i]);
	fx_reboot(&fx);
}

static void t_single_bit_exhaustive(void)
{
	build_state();
	unsigned long detected = 0, harmless = 0;
	for (uint32_t bit = 0; bit < EZ_META_SIZE * 8; bit++) {
		boot_flipped(&bit, 1);
		check_against_base();
		int q = 0;
		for (int i = 0; i < EZ_META_SESSIONS; i++)
			if (fx.m.s[i].state == EZ_SS_QUARANTINED && fx.m.s[i].qreason >= 0x80) q = 1;
		if (q || fx.m.dev == EZ_DEV_FAULT) detected++; else harmless++;
	}
	ez_test_note("%u single-bit flips: %lu detected, %lu without effect on any session",
	             EZ_META_SIZE * 8, detected, harmless);
}

static void flips_in_records(int nbits, int iters)
{
	build_state();
	srand(4242 + nbits);
	for (int it = 0; it < iters; it++) {
		int slot = rand() % 6;     /* the six occupied slots */
		uint32_t base = (EZ_META_SESSION_ADDR + (uint32_t)slot * EZ_META_SESSION_SIZE) * 8;
		uint32_t bits[3];
		for (int k = 0; k < nbits; k++) {
			int dup;
			do {
				bits[k] = base + (uint32_t)(rand() % (int)(EZ_META_SESSION_SIZE * 8));
				dup = 0;
				for (int j = 0; j < k; j++) if (bits[j] == bits[k]) dup = 1;
			} while (dup);
		}
		boot_flipped(bits, nbits);
		check_against_base();
	}
}

static void t_two_bit_sampled(void)   { flips_in_records(2, 100000); }
static void t_three_bit_sampled(void) { flips_in_records(3, 100000); }

/* A torn commit at rest (power lost between the slot write and the
 * selector flip), hit by a single bit flip before the next boot. The
 * result must be the pre-update value (300), the post-update value (400),
 * or a quarantine -- never lower, and never anything else. */
static void t_torn_state_flips(void)
{
	fx_init(&fx);
	int d = fx_create(&fx, 0x44, 512, EZ_ROLE_BOB, "torn");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, d, 300), EZ_OK);
	sim_fram_arm_cut(&fx.fram, EZ_SLOT_SIZE);
	ez_meta_commit_tx(&fx.m, d, 400);
	sim_fram_power_on(&fx.fram);
	memcpy(base_mem, fx.fram.mem, EZ_META_SIZE);
	uint32_t first = (EZ_META_SESSION_ADDR + (uint32_t)d * EZ_META_SESSION_SIZE) * 8;
	for (uint32_t bit = first; bit < first + EZ_META_SESSION_SIZE * 8; bit++) {
		boot_flipped(&bit, 1);
		const ez_session_t *s = &fx.m.s[d];
		if (s->state == EZ_SS_QUARANTINED && s->qreason >= 0x80) continue;
		EZ_CHECK_EQ(s->state, EZ_SS_VALID);
		EZ_CHECK_MSG(s->tx_off == 300 || s->tx_off == 400, "pre or post only");
		EZ_CHECK_EQ(s->rx_off, 0);
	}
}

/* Spot checks that the expected quarantine reason is reported. */
static void t_reasons(void)
{
	build_state();
	uint32_t s0 = EZ_META_SESSION_ADDR * 8;
	struct { uint32_t byte; uint8_t reason; } c[] = {
		{ 0, EZ_Q_FORMAT },                  /* magic */
		{ EZ_SR_OFF_KEY_ID, EZ_Q_STATIC_CRC },
		{ EZ_SR_OFF_LABEL + 2, EZ_Q_STATIC_CRC },
		{ EZ_SR_OFF_ROLE, EZ_Q_STATIC_CRC },
		{ EZ_SR_OFF_STATUS, EZ_Q_STATUS_CODE },
		{ EZ_SR_OFF_TX_SEL, EZ_Q_SELECTOR },
		{ EZ_SR_OFF_RX_SEL, EZ_Q_SELECTOR },
	};
	for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
		uint32_t bit = s0 + c[i].byte * 8;
		boot_flipped(&bit, 1);
		EZ_CHECK_EQ(fx.m.s[0].state, EZ_SS_QUARANTINED);
		EZ_CHECK_EQ(fx.m.s[0].qreason, c[i].reason);
	}
	/* Flip in the selected TX slot of session 0 -> slot check. */
	int sel = base_m.s[0].sel[0];
	uint32_t bit = s0 + (sel ? EZ_SR_OFF_TX_B : EZ_SR_OFF_TX_A) * 8 + 3;
	boot_flipped(&bit, 1);
	EZ_CHECK_EQ(fx.m.s[0].qreason, EZ_Q_SLOT_CHECK);
	/* Flip in the non-selected TX slot -> ignored, offset unchanged. */
	bit = s0 + (sel ? EZ_SR_OFF_TX_A : EZ_SR_OFF_TX_B) * 8 + 3;
	boot_flipped(&bit, 1);
	EZ_CHECK_EQ(fx.m.s[0].state, EZ_SS_VALID);
	EZ_CHECK_EQ(fx.m.s[0].tx_off, base_m.s[0].tx_off);
}

static const ez_test_case_t cases[] = {
	{ "single_bit_exhaustive", "SEC-TEST-PTR-002, SEC-META-003, SEC-PTR-001", t_single_bit_exhaustive },
	{ "two_bit_sampled",       "SEC-TEST-PTR-002, SEC-PTR-001", t_two_bit_sampled },
	{ "three_bit_sampled",     "SEC-TEST-PTR-002, SEC-PTR-001", t_three_bit_sampled },
	{ "torn_state_flips",      "SEC-TEST-PTR-002, SEC-META-002", t_torn_state_flips },
	{ "reasons",               "SEC-TEST-PTR-002, SEC-UI-004 (metadata)", t_reasons },
};
EZ_TEST_MAIN(cases)
