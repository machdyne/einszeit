/*
 * test_meta_powercut.c -- simulated power loss at every byte of every
 * metadata write sequence.
 *
 * EZ-SEC-001:
 *   SEC-TEST-PTR-001  offset advancement is monotonic under simulated power
 *                     loss at each stage of the metadata write sequence, for
 *                     both the TX and RX offsets
 *   SEC-META-002      every cut leaves the pre- or post-update state
 *
 * Method: put the device in a base state, boot it, then run the operation
 * with power cut after k byte writes, for every k from 0 to the total
 * number of bytes the operation writes. After each cut: power on, run the
 * full boot verification, and check the resulting state.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "meta_fixture.h"

static fx_t fx;
static uint8_t base_mem[EZ_META_SIZE];

static void save_base(void) { memcpy(base_mem, fx.fram.mem, EZ_META_SIZE); }

/* Restore base, power on, boot, and arm a cut after k bytes (k < 0: none). */
static void prepare(long k)
{
	memcpy(fx.fram.mem, base_mem, EZ_META_SIZE);
	fx_reboot(&fx);
	fx.fram.bytes_written = 0;
	sim_fram_arm_cut(&fx.fram, k);
}

typedef void (*op_fn)(void);
typedef void (*check_fn)(long k, long total);

/* Measure the operation's write count, then sweep every cut point. */
static long sweep(op_fn op, check_fn check)
{
	prepare(-1);
	op();
	long total = (long)fx.fram.bytes_written;
	EZ_CHECK(total > 0);
	for (long k = 0; k <= total; k++) {
		prepare(k);
		op();
		fx_reboot(&fx);
		check(k, total);
	}
	return total;
}

/* ---------------------------------------------------------------- TX -- */
static int g_slot, g_other;
static uint32_t g_old, g_new, g_rx;
static ez_session_t g_other_before;

static void op_commit_tx(void) { ez_meta_commit_tx(&fx.m, g_slot, g_new); }

static void check_commit_tx(long k, long total)
{
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	EZ_CHECK_MSG(s->state == EZ_SS_VALID, "a cut never quarantines a healthy session");
	EZ_CHECK_MSG(s->tx_off == g_old || s->tx_off == g_new, "pre or post state only");
	if (k == total) EZ_CHECK_EQ(s->tx_off, g_new);
	EZ_CHECK_EQ(s->rx_off, g_rx);
	EZ_CHECK(fx_session_same(&fx.m.s[g_other], &g_other_before));
	/* Monotonic continuation: the next commit succeeds and persists. */
	uint32_t next = g_new + 3;
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, next), EZ_OK);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[g_slot].tx_off, next);
}

static void t_commit_tx(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 4096, EZ_ROLE_ALICE, "a");
	g_other = fx_create(&fx, 0xB, 4096, EZ_ROLE_BOB, "b");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 100), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_other, 3000), EZ_OK);
	save_base();
	g_old = 100; g_new = 164; g_rx = 2048;
	g_other_before = fx.m.s[g_other];
	long n = sweep(op_commit_tx, check_commit_tx);
	ez_test_note("TX commit writes %ld bytes; all %ld cut points verified", n, n + 1);
}

/* ---------------------------------------------------------------- RX -- */
static uint32_t g_tx;

static void op_commit_rx(void) { ez_meta_commit_rx(&fx.m, g_slot, g_new); }

static void check_commit_rx(long k, long total)
{
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK_EQ(s->state, EZ_SS_VALID);
	EZ_CHECK(s->rx_off == g_old || s->rx_off == g_new);
	if (k == total) EZ_CHECK_EQ(s->rx_off, g_new);
	EZ_CHECK_MSG(s->tx_off == g_tx, "an RX commit never touches the TX offset");
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, g_slot, g_new + 1), EZ_OK);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[g_slot].rx_off, g_new + 1);
}

static void t_commit_rx(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 4096, EZ_ROLE_BOB, "a");   /* RX [0,2048) */
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 2100), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, g_slot, 10), EZ_OK);
	save_base();
	g_old = 10; g_new = 900; g_tx = 2100;
	sweep(op_commit_rx, check_commit_rx);
}

/* --------------------------------------- commit from a torn-commit state --
 * A cut between writing the new slot and flipping the selector leaves the
 * larger value in the non-selected slot. The next commit must normalise
 * the selector before overwriting anything; otherwise a cut during that
 * commit could lose the only copy of the current offset. */
static void t_commit_after_torn_commit(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 4096, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 50), EZ_OK);
	/* Commit 80, cut exactly after the 6 slot bytes (before the selector). */
	fx.fram.bytes_written = 0;
	sim_fram_arm_cut(&fx.fram, EZ_SLOT_SIZE);
	ez_meta_commit_tx(&fx.m, g_slot, 80);
	fx_reboot(&fx);
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK_EQ(s->state, EZ_SS_VALID);
	EZ_CHECK_MSG(s->tx_off == 80, "larger-of-two rule rolls forward");
	EZ_CHECK_MSG(s->slot_val[0][s->sel[0]] == 80, "boot persisted the roll-forward");
	save_base();
	g_old = 80; g_new = 120; g_rx = 2048;
	g_other = g_slot;                 /* no second session here */
	g_other_before = fx.m.s[g_slot];
	/* Reuse the TX checker without the second-session comparison. */
	prepare(-1);
	op_commit_tx();
	long total = (long)fx.fram.bytes_written;
	EZ_CHECK_MSG(total == EZ_SLOT_SIZE + 1, "already normalised at boot: slot + selector");
	for (long k = 0; k <= total; k++) {
		prepare(k);
		op_commit_tx();
		fx_reboot(&fx);
		s = &fx.m.s[g_slot];
		EZ_CHECK_EQ(s->state, EZ_SS_VALID);
		EZ_CHECK_MSG(s->tx_off == 80 || s->tx_off == 120, "never back to 50");
	}
}

/* A FAULT device is never written at boot, so a torn commit is not
 * normalised there; after `device repair` in the same power cycle, the
 * commit path must normalise before overwriting (IMPL-META-003 step 2). */
static void t_commit_after_repair_normalises(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 4096, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 50), EZ_OK);
	sim_fram_arm_cut(&fx.fram, EZ_SLOT_SIZE);
	ez_meta_commit_tx(&fx.m, g_slot, 80);          /* torn: 80 in non-selected slot */
	sim_fram_power_on(&fx.fram);
	fx.fram.mem[9] ^= 0x01;                        /* and a faulty device record */
	save_base();
	long total = -1;
	for (long k = -1; k <= total || total < 0; k++) {
		memcpy(fx.fram.mem, base_mem, EZ_META_SIZE);
		fx_reboot(&fx);
		EZ_CHECK_EQ(fx.m.dev, EZ_DEV_FAULT);
		const ez_session_t *s = &fx.m.s[g_slot];
		EZ_CHECK(s->slot_val[0][1 - s->sel[0]] == 80 && s->slot_val[0][s->sel[0]] == 50);
		EZ_CHECK_EQ(ez_meta_repair(&fx.m), EZ_OK);
		fx.fram.bytes_written = 0;
		sim_fram_arm_cut(&fx.fram, k < 0 ? -1 : k);
		ez_status_t st = ez_meta_commit_tx(&fx.m, g_slot, 120);
		if (k < 0) {                               /* measuring run */
			EZ_CHECK_EQ(st, EZ_OK);
			total = (long)fx.fram.bytes_written;
			EZ_CHECK_MSG(total == 1 + EZ_SLOT_SIZE + 1, "normalise + slot + selector");
			continue;
		}
		fx_reboot(&fx);
		s = &fx.m.s[g_slot];
		EZ_CHECK_EQ(s->state, EZ_SS_VALID);
		EZ_CHECK_MSG(s->tx_off == 80 || s->tx_off == 120, "never back to 50");
		if (k == total) EZ_CHECK_EQ(s->tx_off, 120);
	}
}

/* --------------------------------------------- random long sequences -- */
static void t_random_sequences(void)
{
	srand(12345);
	fx_init(&fx);
	int a = fx_create(&fx, 0xA, 1u << 20, EZ_ROLE_ALICE, "a");
	int b = fx_create(&fx, 0xB, 1u << 20, EZ_ROLE_BOB, "b");
	uint32_t tx[2] = { 0, 1u << 19 }, rx[2] = { 1u << 19, 0 };
	int slots[2] = { a, b };
	for (int it = 0; it < 20000; it++) {
		int w = rand() & 1, which = rand() & 1;
		uint32_t *cur = which ? &rx[w] : &tx[w];
		uint32_t n = *cur + 1 + (uint32_t)(rand() % 64);
		long cut = (rand() % 3 == 0) ? rand() % 10 : -1;
		fx.fram.bytes_written = 0;
		sim_fram_arm_cut(&fx.fram, cut);
		ez_status_t st = which ? ez_meta_commit_rx(&fx.m, slots[w], n)
		                       : ez_meta_commit_tx(&fx.m, slots[w], n);
		if (cut >= 0) fx_reboot(&fx);
		else EZ_CHECK_EQ(st, EZ_OK);
		const ez_session_t *s = &fx.m.s[slots[w]];
		uint32_t now = which ? s->rx_off : s->tx_off;
		EZ_CHECK_EQ(s->state, EZ_SS_VALID);
		EZ_CHECK_MSG(now == *cur || now == n, "pre or post");
		EZ_CHECK_MSG(now >= *cur, "monotonic");
		*cur = now;
		/* The other offsets never move. */
		for (int j = 0; j < 2; j++) {
			EZ_CHECK_EQ(fx.m.s[slots[j]].tx_off, tx[j]);
			EZ_CHECK_EQ(fx.m.s[slots[j]].rx_off, rx[j]);
		}
	}
}

/* ------------------------------------------------- create and delete -- */
static void op_create(void)
{
	ez_session_params_t p = { 0xC0FFEE, 2048, EZ_ROLE_BOB, 1, "new" };
	ez_meta_session_create(&fx.m, &p, NULL);
}

static void check_create(long k, long total)
{
	const ez_session_t *s = &fx.m.s[1];
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	EZ_CHECK_MSG(s->state == EZ_SS_EMPTY || s->state == EZ_SS_VALID, "empty or complete");
	if (k == total) EZ_CHECK_EQ(s->state, EZ_SS_VALID);
	if (s->state == EZ_SS_VALID) {
		EZ_CHECK_EQ(s->key_id, 0xC0FFEE);
		EZ_CHECK_EQ(s->tx_off, 1024);
		EZ_CHECK_EQ(s->rx_off, 0);
	} else {
		/* An interrupted create can simply be retried. */
		op_create();
		EZ_CHECK_EQ(fx.m.s[1].state, EZ_SS_VALID);
	}
	EZ_CHECK_EQ(fx.m.s[0].tx_off, 7);
}

static void t_create(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xA, 64, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 7), EZ_OK);
	save_base();
	sweep(op_create, check_create);
}

static void op_delete(void) { ez_meta_session_delete(&fx.m, g_slot); }

static void check_delete(long k, long total)
{
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK_MSG(s->state == EZ_SS_EMPTY ||
	             (s->state == EZ_SS_VALID && s->tx_off == 9 && s->rx_off == 40),
	             "deleted, or intact with its offsets");
	if (k == total) EZ_CHECK_EQ(s->state, EZ_SS_EMPTY);
}

static void t_delete(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 64, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 9), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, g_slot, 40), EZ_OK);
	save_base();
	sweep(op_delete, check_delete);
}

/* --------------------------------------------- quarantine / resolve -- */
static void op_quarantine(void) { ez_meta_quarantine(&fx.m, g_slot, EZ_Q_KEY_SIZE); }
static void check_quarantine(long k, long total)
{
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK(s->state == EZ_SS_VALID ||
	         (s->state == EZ_SS_QUARANTINED && s->qreason == EZ_Q_KEY_SIZE));
	if (k == total) EZ_CHECK_EQ(s->state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(s->tx_off, 9);
}
static void op_resolve(void) { ez_meta_resolve(&fx.m, g_slot); }
static void check_resolve(long k, long total)
{
	const ez_session_t *s = &fx.m.s[g_slot];
	EZ_CHECK(s->state == EZ_SS_VALID || s->state == EZ_SS_QUARANTINED);
	if (k == total) EZ_CHECK_EQ(s->state, EZ_SS_VALID);
	EZ_CHECK_EQ(s->tx_off, 9);
}

static void t_quarantine_resolve(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 64, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 9), EZ_OK);
	save_base();
	sweep(op_quarantine, check_quarantine);
	prepare(-1);                      /* back to the base state */
	EZ_CHECK_EQ(ez_meta_quarantine(&fx.m, g_slot, EZ_Q_KEY_SIZE), EZ_OK);
	save_base();
	sweep(op_resolve, check_resolve);
}

/* --------------------------------------- boot counter, drive 0, log -- */
static uint32_t g_boot;

static void op_boot(void) { ez_meta_boot(&fx.m, &fx.fram.hal); }
static void check_boot(long k, long total)
{
	(void)total;
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	/* prepare() booted once (g_boot + 1); the boot under test writes
	 * g_boot + 2 unless cut; the verifying reboot adds one more. */
	EZ_CHECK_MSG(fx.m.boot_count == g_boot + 2 || fx.m.boot_count == g_boot + 3,
	             "boot counter never goes backwards");
	(void)k;
}

static void t_boot_counter(void)
{
	fx_init(&fx);
	fx_reboot(&fx);
	fx_reboot(&fx);
	g_boot = fx.m.boot_count;
	save_base();
	/* prepare() boots once (g_boot + 1); op_boot is the boot under test. */
	sweep(op_boot, check_boot);
}

static void op_drive0(void) { ez_meta_set_drive0(&fx.m, true); }
static void check_drive0(long k, long total)
{
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	if (k == total) EZ_CHECK(fx.m.drive0_enabled);
}

static void t_drive0(void)
{
	fx_init(&fx);
	save_base();
	sweep(op_drive0, check_drive0);
}

static void op_log(void) { ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 0xFEED, 4096); }
static void check_log(long k, long total)
{
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(&fx.m, ev, EZ_META_LOG_ENTRIES);
	EZ_CHECK(n >= 5);   /* the five base entries (+ init) are never damaged */
	if (k == total) EZ_CHECK_EQ(ev[0].key_id, 0xFEED);
	/* Appending after the cut works and gets a fresh sequence number. */
	EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 0xBEEF, 1), EZ_OK);
	n = ez_meta_log_read(&fx.m, ev, EZ_META_LOG_ENTRIES);
	EZ_CHECK_EQ(ev[0].key_id, 0xBEEF);
	EZ_CHECK(ev[0].seq > ev[1].seq);
}

static void t_log_append(void)
{
	fx_init(&fx);
	for (uint32_t i = 0; i < 5; i++)
		EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, i + 1, 64), EZ_OK);
	save_base();
	sweep(op_log, check_log);
}

/* ---------------------------------------------------------- format --
 * An interrupted format must never leave a device that looks valid while
 * still holding old sessions. */
static ez_session_t g_fmt_before[2];

static void op_format(void) { ez_meta_format(&fx.m); }
static void check_format(long k, long total)
{
	if (k == total) EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	if (fx.m.dev != EZ_DEV_VALID) {
		EZ_CHECK(fx.m.dev == EZ_DEV_FAULT);
		return;
	}
	/* Valid means either untouched (cut before the first byte) or fully
	 * formatted -- never valid with a mixture. */
	int untouched = fx_session_same(&fx.m.s[0], &g_fmt_before[0]) &&
	                fx_session_same(&fx.m.s[1], &g_fmt_before[1]);
	int formatted = 1;
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		if (fx.m.s[i].state != EZ_SS_EMPTY) formatted = 0;
	EZ_CHECK_MSG(untouched ? k == 0 : formatted, "valid implies untouched or fully formatted");
}

static void t_format(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xA, 64, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 5), EZ_OK);
	fx_create(&fx, 0xB, 64, EZ_ROLE_BOB, "b");
	g_fmt_before[0] = fx.m.s[0];
	g_fmt_before[1] = fx.m.s[1];
	save_base();
	sweep(op_format, check_format);
}

static void op_repair(void) { ez_meta_repair(&fx.m); }
static void check_repair(long k, long total)
{
	EZ_CHECK(fx.m.dev == EZ_DEV_VALID || fx.m.dev == EZ_DEV_FAULT);
	if (k == total) EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	EZ_CHECK_EQ(fx.m.s[g_slot].tx_off, 5);
	EZ_CHECK(!fx.m.drive0_enabled);
}

static void t_repair(void)
{
	fx_init(&fx);
	g_slot = fx_create(&fx, 0xA, 64, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, g_slot, 5), EZ_OK);
	fx.fram.mem[10] ^= 0x40;
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_FAULT);
	save_base();
	sweep(op_repair, check_repair);
}

static const ez_test_case_t cases[] = {
	{ "commit_tx",                 "SEC-TEST-PTR-001, SEC-META-002, SEC-PTR-003", t_commit_tx },
	{ "commit_rx",                 "SEC-TEST-PTR-001, SEC-META-002, SEC-DEC-004", t_commit_rx },
	{ "commit_after_torn_commit",  "SEC-TEST-PTR-001, IMPL-META-003", t_commit_after_torn_commit },
	{ "commit_after_repair_normalises", "SEC-TEST-PTR-001, IMPL-META-003", t_commit_after_repair_normalises },
	{ "random_sequences",          "SEC-TEST-PTR-001, SEC-ISO-001", t_random_sequences },
	{ "create",                    "IMPL-META-004", t_create },
	{ "delete",                    "IMPL-META-004", t_delete },
	{ "quarantine_resolve",        "IMPL-META-004, SEC-META-003", t_quarantine_resolve },
	{ "boot_counter",              "IMPL-META-001", t_boot_counter },
	{ "drive0",                    "IMPL-DRV-001", t_drive0 },
	{ "log_append",                "SEC-GEN-003, IMPL-LOG-001", t_log_append },
	{ "format",                    "IMPL-META-001", t_format },
	{ "repair",                    "IMPL-META-001", t_repair },
};
EZ_TEST_MAIN(cases)
