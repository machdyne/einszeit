/*
 * test_meta.c -- functional behaviour of the metadata layer.
 *
 * Fault behaviour is in test_meta_powercut.c, test_meta_bitflip.c and
 * test_meta_rollback.c.
 */
#include <stdio.h>
#include <string.h>

#include "meta_fixture.h"

static fx_t fx;

static void t_uninitialised(void)
{
	sim_fram_init(&fx.fram, 0xFF);
	EZ_CHECK_EQ(ez_meta_boot(&fx.m, &fx.fram.hal), EZ_OK);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_UNINIT);
	ez_session_params_t p = { 0x1234, 1024, EZ_ROLE_ALICE, 1, "a" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_DEVICE);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, 0, 1), EZ_ERR_DEVICE);
	/* Booting an uninitialised device never writes to it. */
	EZ_CHECK_EQ(fx.fram.bytes_written, 0);
	sim_fram_init(&fx.fram, 0x00);
	EZ_CHECK_EQ(ez_meta_boot(&fx.m, &fx.fram.hal), EZ_OK);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_UNINIT);
}

/* The fw/test bench firmware writes "EZ-TESTBOARD-001" at offset 0. Such
 * a board is not blank and must not be mistaken for an initialised one. */
static void t_bench_marker_is_fault(void)
{
	sim_fram_init(&fx.fram, 0x00);
	memcpy(fx.fram.mem, "EZ-TESTBOARD-001", 16);
	ez_meta_boot(&fx.m, &fx.fram.hal);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_FAULT);
}

static void t_format_defaults(void)
{
	fx_init(&fx);
	EZ_CHECK(!fx.m.drive0_enabled);                    /* IMPL-DRV-001 */
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		EZ_CHECK_EQ(fx.m.s[i].state, EZ_SS_EMPTY);
	uint32_t b = fx.m.boot_count;
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.boot_count, b + 1);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.boot_count, b + 2);
	ez_event_t ev[16];
	int n = ez_meta_log_read(&fx.m, ev, 16);
	EZ_CHECK(n >= 1);
	EZ_CHECK_EQ(ev[n - 1].type, EZ_EV_DEVICE_INIT);
}

/* Definitions (TX/RX range), SEC-ENC-001 initial TX offset. */
static void t_ranges(void)
{
	uint32_t s, e;
	ez_range_tx(1024, EZ_ROLE_ALICE, &s, &e); EZ_CHECK(s == 0 && e == 512);
	ez_range_rx(1024, EZ_ROLE_ALICE, &s, &e); EZ_CHECK(s == 512 && e == 1024);
	ez_range_tx(1024, EZ_ROLE_BOB, &s, &e);   EZ_CHECK(s == 512 && e == 1024);
	ez_range_rx(1024, EZ_ROLE_BOB, &s, &e);   EZ_CHECK(s == 0 && e == 512);

	fx_init(&fx);
	int a = fx_create(&fx, 0xA1, 1024, EZ_ROLE_ALICE, "alice");
	int b = fx_create(&fx, 0xB1, 1024, EZ_ROLE_BOB, "bob");
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 0);   EZ_CHECK_EQ(fx.m.s[a].rx_off, 512);
	EZ_CHECK_EQ(fx.m.s[b].tx_off, 512); EZ_CHECK_EQ(fx.m.s[b].rx_off, 0);
	EZ_CHECK_EQ(ez_meta_tx_remaining(&fx.m.s[a]), 512);
	EZ_CHECK_EQ(ez_meta_rx_remaining(&fx.m.s[b]), 512);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);
	EZ_CHECK_EQ(fx.m.s[b].tx_off, 512);
}

/* SEC-TEST-STORE-001 */
static void t_key_params(void)
{
	fx_init(&fx);
	ez_session_params_t p = { 0, 1024, EZ_ROLE_ALICE, 1, "x" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_KEY_PARAM);
	p.key_id = 7; p.key_len = 0;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_KEY_PARAM);
	p.key_len = 1023;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_KEY_PARAM);
	p.key_len = 2;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_OK);
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		if (fx.m.s[i].state != EZ_SS_EMPTY) EZ_CHECK(fx.m.s[i].key_id != 0);
}

static void t_label_params(void)
{
	fx_init(&fx);
	ez_session_params_t p = { 7, 1024, EZ_ROLE_ALICE, 1, "" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_BAD_REQUEST);
	p.label = "0123456789abcdef";   /* 16 bytes: one too many */
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_BAD_REQUEST);
	p.label = "0123456789abcde";    /* 15 bytes */
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_OK);
	p.label = NULL;
	p.key_id = 8;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_BAD_REQUEST);
	p.label = "ok"; p.role = 2;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_BAD_REQUEST);
	p.role = EZ_ROLE_BOB; p.drive = 3;
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_BAD_REQUEST);
}

/* SEC-TEST-ISO-001 (SEC-ISO-002) */
static void t_duplicate_key_id(void)
{
	fx_init(&fx);
	fx_create(&fx, 0xCAFE, 4096, EZ_ROLE_ALICE, "one");
	ez_session_params_t p = { 0xCAFE, 4096, EZ_ROLE_BOB, 1, "two" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_EXISTS);
	fx_reboot(&fx);
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_EXISTS);
	p.drive = 0;   /* a different drive does not make it a different key */
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_EXISTS);
	/* Duplicate labels are rejected as well (UI identification). */
	p.key_id = 0xBEEF; p.label = "one";
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_EXISTS);
}

static void t_full(void)
{
	fx_init(&fx);
	char l[16];
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		snprintf(l, sizeof l, "s%d", i);
		fx_create(&fx, 100u + (uint32_t)i, 64, EZ_ROLE_ALICE, l);
	}
	ez_session_params_t p = { 999, 64, EZ_ROLE_ALICE, 1, "extra" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_FULL);
	fx_reboot(&fx);
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		EZ_CHECK_EQ(fx.m.s[i].key_id, 100u + (uint32_t)i);
}

/* SEC-META-004 */
static void t_alloc_check(void)
{
	fx_init(&fx);
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		EZ_CHECK_EQ(ez_meta_check_alloc(&fx.m, i), EZ_OK);
	int s = fx_create(&fx, 5, 64, EZ_ROLE_ALICE, "x");
	EZ_CHECK_EQ(ez_meta_check_alloc(&fx.m, s), EZ_ERR_EXISTS);
	EZ_CHECK_EQ(ez_meta_check_alloc(&fx.m, -1), EZ_ERR_BAD_REQUEST);
	EZ_CHECK_EQ(ez_meta_check_alloc(&fx.m, EZ_META_SESSIONS), EZ_ERR_BAD_REQUEST);
	/* Every slot lies inside the session region and no two overlap. */
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		uint32_t a = EZ_META_SESSION_ADDR + (uint32_t)i * EZ_META_SESSION_SIZE;
		EZ_CHECK(a >= EZ_META_SESSION_ADDR && a + EZ_META_SESSION_SIZE <= EZ_META_LOG_ADDR);
		for (int j = i + 1; j < EZ_META_SESSIONS; j++) {
			uint32_t b = EZ_META_SESSION_ADDR + (uint32_t)j * EZ_META_SESSION_SIZE;
			EZ_CHECK(a + EZ_META_SESSION_SIZE <= b);
		}
	}
}

/* SEC-DEC-004 (TX untouched by RX commits), SEC-ISO-001 (range bounds):
 * the metadata part of SEC-TEST-ISO-003. */
static void t_tx_rx_independent(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xA, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 500);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 700), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 100);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 501), EZ_ERR_RANGE);   /* beyond TX end */
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 1001), EZ_ERR_RANGE);  /* beyond RX end */
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 100);
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 700);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 100);
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 700);
	/* A second session is unaffected by commits to the first (SEC-ISO-001). */
	int b = fx_create(&fx, 0xB, 1000, EZ_ROLE_BOB, "b");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 200), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[b].tx_off, 500);
	EZ_CHECK_EQ(fx.m.s[b].rx_off, 0);
}

/* IMPL-META-005, SEC-UI-001 */
static void t_exhaustion(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xE, 100, EZ_ROLE_BOB, "e");   /* TX [50,100) */
	EZ_CHECK(!ez_meta_tx_low(&fx.m.s[a], 20));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 90), EZ_OK);  /* 10/50 = 20% left */
	EZ_CHECK(!ez_meta_tx_low(&fx.m.s[a], 20));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 91), EZ_OK);  /* 18% */
	EZ_CHECK(ez_meta_tx_low(&fx.m.s[a], 20));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_EXHAUSTED);
	EZ_CHECK(!ez_meta_can_encrypt(&fx.m, a));
	EZ_CHECK(ez_meta_can_decrypt(&fx.m, a));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_ERR_CAPACITY);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 10), EZ_OK);  /* RX still usable */
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_EXHAUSTED);
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 10);
}

/* SEC-UI-004 at the metadata level; IMPL-META-006 */
static void t_quarantine_persisted(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0x9, 100, EZ_ROLE_ALICE, "q");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 10), EZ_OK);
	EZ_CHECK_EQ(ez_meta_quarantine(&fx.m, a, EZ_Q_FORMAT), EZ_ERR_BAD_REQUEST);
	EZ_CHECK_EQ(ez_meta_quarantine(&fx.m, a, EZ_Q_KEY_MISSING), EZ_OK);
	EZ_CHECK(!ez_meta_can_encrypt(&fx.m, a));
	EZ_CHECK(!ez_meta_can_decrypt(&fx.m, a));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 20), EZ_ERR_QUARANTINED);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 60), EZ_ERR_QUARANTINED);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_KEY_MISSING);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 10);
	EZ_CHECK_EQ(ez_meta_resolve(&fx.m, a), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 10);
	EZ_CHECK_EQ(ez_meta_resolve(&fx.m, a), EZ_ERR_STATE);
}

/* IMPL-META-006: RAM quarantine cannot be resolved, only deleted.
 * IMPL-META-007: unreadable identity blocks creation until deleted. */
static void t_quarantine_volatile(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0x9, 100, EZ_ROLE_ALICE, "q");
	fx.fram.mem[EZ_META_SESSION_ADDR + (uint32_t)a * EZ_META_SESSION_SIZE + EZ_SR_OFF_KEY_ID] ^= 0x01;
	unsigned long before = fx.fram.bytes_written;
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_STATIC_CRC);
	EZ_CHECK(!fx.m.s[a].identity);
	/* Only the boot counter was written: the record was not touched. */
	EZ_CHECK_EQ(fx.fram.bytes_written - before, EZ_SLOT_SIZE);
	EZ_CHECK_EQ(ez_meta_resolve(&fx.m, a), EZ_ERR_QUARANTINED);
	ez_session_params_t p = { 0x77, 100, EZ_ROLE_BOB, 1, "new" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_UNRESOLVED);
	EZ_CHECK_EQ(ez_meta_session_delete(&fx.m, a), EZ_OK);
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_OK);
}

static void t_delete(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0x1, 100, EZ_ROLE_ALICE, "d");
	EZ_CHECK_EQ(ez_meta_session_delete(&fx.m, a), EZ_OK);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_EMPTY);
	EZ_CHECK_EQ(ez_meta_session_delete(&fx.m, a), EZ_ERR_NO_SESSION);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_EMPTY);
	const uint8_t *r = fx.fram.mem + EZ_META_SESSION_ADDR + (uint32_t)a * EZ_META_SESSION_SIZE;
	for (unsigned i = 0; i < EZ_META_SESSION_SIZE; i++) EZ_CHECK_EQ(r[i], 0);
}

/* IMPL-LOG-002 */
static void t_role_default(void)
{
	fx_init(&fx);
	EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 0x5150, 1024), EZ_OK);
	EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_REJECTED, 1, 0x6160, 1024), EZ_OK);
	int a = fx_create(&fx, 0x5150, 1024, EZ_ROLE_DEFAULT, "gen");
	int b = fx_create(&fx, 0x7170, 1024, EZ_ROLE_DEFAULT, "recv");
	int c = fx_create(&fx, 0x6160, 1024, EZ_ROLE_DEFAULT, "rej");
	EZ_CHECK_EQ(fx.m.s[a].role, EZ_ROLE_ALICE);
	EZ_CHECK_EQ(fx.m.s[b].role, EZ_ROLE_BOB);
	EZ_CHECK_EQ(fx.m.s[c].role, EZ_ROLE_BOB);
}

/* SEC-GEN-003, IMPL-LOG-001 */
static void t_log_ring(void)
{
	fx_init(&fx);
	for (uint32_t i = 0; i < 40; i++)
		EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 1000 + i, 512), EZ_OK);
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(&fx.m, ev, EZ_META_LOG_ENTRIES);
	EZ_CHECK_EQ(n, EZ_META_LOG_ENTRIES);
	EZ_CHECK_EQ(ev[0].key_id, 1039);
	for (int i = 1; i < n; i++) EZ_CHECK(ev[i].seq + 1 == ev[i - 1].seq);
	EZ_CHECK_EQ(ev[0].boot, fx.m.boot_count);
	fx_reboot(&fx);
	EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_REJECTED, 0x3, 2000, 512), EZ_OK);
	n = ez_meta_log_read(&fx.m, ev, EZ_META_LOG_ENTRIES);
	EZ_CHECK_EQ(ev[0].key_id, 2000);
	EZ_CHECK_EQ(ev[0].seq, ev[1].seq + 1);
	EZ_CHECK_EQ(ev[0].detail, 0x3);
	/* A damaged entry is ignored; the rest remain readable. */
	uint32_t idx = ev[3].seq % EZ_META_LOG_ENTRIES;
	fx.fram.mem[EZ_META_LOG_ADDR + idx * EZ_META_LOG_ENTRY_SIZE + 5] ^= 0x10;
	EZ_CHECK_EQ(ez_meta_log_read(&fx.m, ev, EZ_META_LOG_ENTRIES), EZ_META_LOG_ENTRIES - 1);
}

static uint32_t fake_time(void *ctx, bool *host)
{
	(void)ctx;
	*host = true;
	return 1790000000u;
}

static void t_log_time(void)
{
	fx_init(&fx);
	fx.m.time_fn = fake_time;
	EZ_CHECK_EQ(ez_meta_log_append(&fx.m, EZ_EV_KEY_OK, 0, 1, 2), EZ_OK);
	ez_event_t ev[1];
	EZ_CHECK_EQ(ez_meta_log_read(&fx.m, ev, 1), 1);
	EZ_CHECK(ev[0].host_time);
	EZ_CHECK_EQ(ev[0].time, 1790000000u);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_OK);
}

/* IMPL-META-001: faulty device record */
static void t_device_fault_and_repair(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0x42, 100, EZ_ROLE_ALICE, "keep");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 7), EZ_OK);
	EZ_CHECK_EQ(ez_meta_set_drive0(&fx.m, true), EZ_OK);
	uint32_t boots = fx.m.boot_count;
	fx.fram.mem[8] ^= 0x01;                      /* reserved byte under static CRC */
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_FAULT);
	EZ_CHECK(!fx.m.drive0_enabled);              /* fail closed */
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);   /* sessions still verified and listed */
	EZ_CHECK(!ez_meta_can_encrypt(&fx.m, a));
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 8), EZ_ERR_DEVICE);
	ez_session_params_t p = { 0x43, 100, EZ_ROLE_ALICE, 1, "n" };
	EZ_CHECK_EQ(ez_meta_session_create(&fx.m, &p, NULL), EZ_ERR_DEVICE);
	EZ_CHECK_EQ(ez_meta_repair(&fx.m), EZ_OK);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	EZ_CHECK(!fx.m.drive0_enabled);              /* repair disables drive 0 */
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.dev, EZ_DEV_VALID);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 7);
	EZ_CHECK(fx.m.boot_count > boots);
	EZ_CHECK_EQ(ez_meta_repair(&fx.m), EZ_ERR_STATE);
}

/* IMPL-DRV-001/002 (metadata part) */
static void t_drive0_flag(void)
{
	fx_init(&fx);
	EZ_CHECK(!fx.m.drive0_enabled);
	EZ_CHECK_EQ(ez_meta_set_drive0(&fx.m, true), EZ_OK);
	fx_reboot(&fx);
	EZ_CHECK(fx.m.drive0_enabled);
	EZ_CHECK_EQ(ez_meta_set_drive0(&fx.m, false), EZ_OK);
	fx_reboot(&fx);
	EZ_CHECK(!fx.m.drive0_enabled);
	ez_event_t ev[4];
	int n = ez_meta_log_read(&fx.m, ev, 4);
	EZ_CHECK(n >= 2);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_DRIVE0_OFF);
	EZ_CHECK_EQ(ev[1].type, EZ_EV_DRIVE0_ON);
}

static const ez_test_case_t cases[] = {
	{ "uninitialised",            "IMPL-META-001", t_uninitialised },
	{ "bench_marker_is_fault",    "IMPL-META-001", t_bench_marker_is_fault },
	{ "format_defaults",          "IMPL-DRV-001, IMPL-META-001", t_format_defaults },
	{ "ranges",                   "SEC-ENC-001, SEC-ISO-001", t_ranges },
	{ "key_params",               "SEC-TEST-STORE-001, SEC-STORE-002, SEC-STORE-003", t_key_params },
	{ "label_params",             "IMPL-ARCH-003", t_label_params },
	{ "duplicate_key_id",         "SEC-TEST-ISO-001, SEC-ISO-002", t_duplicate_key_id },
	{ "full",                     "SEC-META-001", t_full },
	{ "alloc_check",              "SEC-META-004", t_alloc_check },
	{ "tx_rx_independent",        "SEC-TEST-ISO-003 (metadata), SEC-DEC-004, SEC-ISO-001", t_tx_rx_independent },
	{ "exhaustion",               "SEC-UI-001 (metadata), IMPL-META-005", t_exhaustion },
	{ "quarantine_persisted",     "SEC-UI-004 (metadata), IMPL-META-006", t_quarantine_persisted },
	{ "quarantine_volatile",      "SEC-META-003, IMPL-META-006, IMPL-META-007", t_quarantine_volatile },
	{ "delete",                   "IMPL-META-004", t_delete },
	{ "role_default",             "IMPL-LOG-002", t_role_default },
	{ "log_ring",                 "SEC-GEN-003 (log), IMPL-LOG-001", t_log_ring },
	{ "log_time",                 "SEC-GEN-003 (timestamp)", t_log_time },
	{ "device_fault_and_repair",  "IMPL-META-001", t_device_fault_and_repair },
	{ "drive0_flag",              "IMPL-DRV-001, IMPL-DRV-002 (metadata)", t_drive0_flag },
};
EZ_TEST_MAIN(cases)
