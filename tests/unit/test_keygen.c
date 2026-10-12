/*
 * test_keygen.c -- key generation pipeline (EZ-IMPL-001 §2.3, §7).
 *
 * EZ-SEC-001:
 *   SEC-ENTROPY-001  key bytes are exactly the TRNG HAL's output
 *   SEC-ENTROPY-002  a key is marked valid only after acceptance tests
 *   SEC-ENTROPY-003  no algorithmic conditioning in software
 *   SEC-ENTROPY-004  hardware faults and monitor failures halt and log
 *   SEC-GEN-001      one block buffered, cleared after each write
 *   SEC-GEN-002      read-back verification per block
 *   SEC-GEN-003      every generation event logged, valid or rejected
 *   SEC-STORE-002    Key ID drawn from the TRNG, separately from the key
 *   SEC-TEST-ENT-002 (integrated) biased source halts within one window
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_import.h"
#include "ez_secure.h"

static ez_status_t run(ezdev_t *d, ez_keygen_t *kg, uint8_t drive, uint32_t len,
                       uint32_t *steps)
{
	ez_status_t st = ez_keygen_start(&d->c, kg, drive, len);
	uint32_t n = 0, last = 0;
	while (st == EZ_PENDING) {
		st = ez_keygen_step(&d->c, kg, 3);
		n++;
		/* SEC-GEN-001: nothing of the key is left in RAM between steps. */
		DEV_KBUF_CLEAR(d);
		EZ_CHECK(ez_is_zero(kg->vbuf, sizeof kg->vbuf));
		uint32_t p = ez_keygen_progress(kg);
		EZ_CHECK(p >= last);
		last = p;
	}
	if (steps) *steps = n;
	return st;
}

static int count_ext(ezdev_t *d, uint8_t drive, const char *ext)
{
	int n = 0;
	for (int i = 0; i < SIM_KS_FILES; i++)
		if (d->ks.d[drive].f[i].used && strstr(d->ks.d[drive].f[i].name, ext)) n++;
	return n;
}

static int last_events(ezdev_t *d, ez_event_t *ev, int n)
{
	return ez_meta_log_read(&d->c.meta, ev, n);
}

static void t_generate(void)
{
	ezdev_t *d = dev_new(0xC0DE);
	ez_keygen_t kg;
	const uint32_t len = 65536;
	EZ_CHECK_EQ(run(d, &kg, 1, len, NULL), EZ_OK);
	char name[EZ_FNAME_MAX];
	ez_key_name(kg.key_id, "KEY", name);
	sim_file_t *f = sim_ks_get(&d->ks, 1, name);
	EZ_CHECK(f != NULL);
	EZ_CHECK_EQ(f->len, len);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP"), 0);
	/* SEC-ENTROPY-001/003, SEC-STORE-002: replay the simulated source.
	 * The first 4 bytes became the Key ID; the key is the next 65,536
	 * bytes, unchanged. Nothing of the ID is in the key. */
	sim_trng_t ref;
	sim_trng_init(&ref, 0xC0DE);
	uint8_t idb[4], inst[2], *k = malloc(len);
	ref.hal.read(ref.hal.ctx, idb, 4);
	ref.hal.read(ref.hal.ctx, inst, 2);        /* instance tag (IMPL-KEY-005) */
	ref.hal.read(ref.hal.ctx, k, len);
	EZ_CHECK_EQ(kg.key_id, (uint32_t)idb[0] | (uint32_t)idb[1] << 8 |
	                       (uint32_t)idb[2] << 16 | (uint32_t)idb[3] << 24);
	EZ_CHECK_MSG(memcmp(f->data, k, len) == 0, "key differs from TRNG output");
	free(k);
	/* SEC-STORE-004: the integrity file was written, carries the instance
	 * tag, and every unit verifies against it. */
	uint16_t instance;
	EZ_CHECK_EQ(ez_sum_check(&d->c, 1, kg.key_id, len, &instance), EZ_OK);
	EZ_CHECK_EQ(instance, (uint16_t)(inst[0] | inst[1] << 8));
	for (uint32_t i = 0; i < ez_unit_count(len); i++) {
		EZ_CHECK_EQ(ez_unit_load(&d->c, 1, kg.key_id, len, i), EZ_OK);
		ez_unit_drop(&d->c);
	}
	EZ_CHECK_EQ(count_ext(d, 1, ".SUT"), 0);
	/* SEC-GEN-003 */
	ez_event_t ev[4];
	EZ_CHECK(last_events(d, ev, 4) >= 1);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_OK);
	EZ_CHECK_EQ(ev[0].key_id, kg.key_id);
	EZ_CHECK_EQ(ev[0].arg, len);
	/* IMPL-LOG-002: the generator defaults to alice. */
	int s = -1;
	EZ_CHECK_EQ(ez_session_create(&d->c, kg.key_id, 1, EZ_ROLE_DEFAULT, "peer", &s), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[s].role, EZ_ROLE_ALICE);
	EZ_CHECK_EQ(d->c.meta.s[s].key_len, len);
	dev_free(d);
}

static void t_params(void)
{
	ezdev_t *d = dev_new(1);
	ez_keygen_t kg;
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, EZ_KEYGEN_MIN_LEN - 512), EZ_ERR_KEY_PARAM);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, EZ_KEYGEN_MIN_LEN + 1), EZ_ERR_KEY_PARAM);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, EZ_KEYGEN_MAX_LEN + 512), EZ_ERR_KEY_PARAM);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 0, 8192), EZ_ERR_DRIVE_DISABLED);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 3, 8192), EZ_ERR_BAD_REQUEST);
	sim_ks_remove(&d->ks, 1);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 8192), EZ_ERR_MEDIA_REMOVED);
	dev_free(d);
}

/* SEC-GEN-002 */
static void t_readback_corruption(void)
{
	ezdev_t *d = dev_new(2);
	ez_keygen_t kg;
	sim_ks_corrupt_append(&d->ks, 5);
	EZ_CHECK_EQ(run(d, &kg, 1, 16384, NULL), EZ_ERR_MEDIA);
	EZ_CHECK_EQ(count_ext(d, 1, ".KEY") + count_ext(d, 1, ".TMP") +
	            count_ext(d, 1, ".SUM") + count_ext(d, 1, ".SUT"), 0);
	ez_event_t ev[2];
	EZ_CHECK(last_events(d, ev, 2) >= 1);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_REJECTED);
	EZ_CHECK(ev[0].detail & EZ_EF_OTHER);
	dev_free(d);
}

/* SEC-ENTROPY-004: hardware health fault */
static void t_trng_fault(void)
{
	ezdev_t *d = dev_new(3);
	ez_keygen_t kg;
	sim_trng_fault_after(&d->trng, 4 + 512 * 7 + 100);
	EZ_CHECK_EQ(run(d, &kg, 1, 16384, NULL), EZ_ERR_ENTROPY);
	EZ_CHECK_EQ(count_ext(d, 1, ".KEY") + count_ext(d, 1, ".TMP"), 0);
	ez_event_t ev[3];
	EZ_CHECK(last_events(d, ev, 3) >= 2);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_REJECTED);
	EZ_CHECK_EQ(ev[1].type, EZ_EV_ENTROPY_FAULT);
	/* No fallback: the next attempt also fails while the source is down. */
	sim_trng_fault_after(&d->trng, 0);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 8192), EZ_ERR_ENTROPY);
	dev_free(d);
}

/* SEC-TEST-ENT-002 in the pipeline: a degraded source halts within the
 * first monitor window (one block), before anything is accepted. */
static void t_monitor_halts(void)
{
	static const struct { sim_trng_mode_t m; uint32_t p; } bad[] = {
		{ SIM_TRNG_BIASED, 160 }, { SIM_TRNG_STUCK, 0xFF }, { SIM_TRNG_ALTERNATING, 0 },
		{ SIM_TRNG_CORRELATED, 128 },
	};
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		ezdev_t *d = dev_new(4);
		ez_keygen_t kg;
		/* Key ID from good bytes, then the bad source. */
		uint8_t id[4] = { 1, 2, 3, 4 };
		d->trng.buf = id; d->trng.buflen = 4;
		sim_trng_mode(&d->trng, SIM_TRNG_BUFFER, 0);
		EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 65536), EZ_PENDING);
		sim_trng_mode(&d->trng, bad[i].m, bad[i].p);
		unsigned long before = d->trng.bytes;
		ez_status_t st;
		while ((st = ez_keygen_step(&d->c, &kg, 1)) == EZ_PENDING) {}
		EZ_CHECK_EQ(st, EZ_ERR_ENTROPY);
		EZ_CHECK_MSG(d->trng.bytes - before <= EZ_MON_WINDOW_BITS / 8,
		             "halt later than one window");
		EZ_CHECK(kg.fail & (EZ_EF_MON_MONOBIT | EZ_EF_MON_RUNS | EZ_EF_MON_AUTOCORR));
		EZ_CHECK_EQ(count_ext(d, 1, ".KEY") + count_ext(d, 1, ".TMP"), 0);
		ez_event_t ev[2];
		EZ_CHECK(last_events(d, ev, 2) == 2 || last_events(d, ev, 2) >= 2);
		EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_REJECTED);
		EZ_CHECK_EQ(ev[1].type, EZ_EV_ENTROPY_FAULT);
		dev_free(d);
	}
}

/* SEC-ENTROPY-002: a subtle bias passes the monitor window by window but
 * fails the whole-key acceptance tests; the key is never marked valid. */
static void t_acceptance_rejects(void)
{
	ezdev_t *d = dev_new(5);
	ez_keygen_t kg;
	uint8_t id[4] = { 9, 9, 9, 9 };
	d->trng.buf = id; d->trng.buflen = 4;
	sim_trng_mode(&d->trng, SIM_TRNG_BUFFER, 0);
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 262144), EZ_PENDING);
	sim_trng_mode(&d->trng, SIM_TRNG_BIASED, 133);        /* P(1) = 0.52 */
	ez_status_t st;
	bool reached_verify = false;
	while ((st = ez_keygen_step(&d->c, &kg, 4)) == EZ_PENDING)
		if (kg.state == EZ_KG_VERIFY) reached_verify = true;
	EZ_CHECK_EQ(st, EZ_ERR_ENTROPY);
	EZ_CHECK_MSG(reached_verify, "expected the monitor to pass this subtle bias");
	EZ_CHECK(kg.fail & (EZ_EF_ACC_WHOLE | EZ_EF_ACC_MONOBIT));
	EZ_CHECK_EQ(count_ext(d, 1, ".KEY") + count_ext(d, 1, ".TMP"), 0);
	ez_event_t ev[1];
	EZ_CHECK_EQ(last_events(d, ev, 1), 1);
	EZ_CHECK_EQ(ev[0].type, EZ_EV_KEY_REJECTED);
	EZ_CHECK_EQ(ev[0].detail, kg.fail);
	EZ_CHECK_EQ(ev[0].arg, 262144);
	dev_free(d);
}

/* IMPL-KEY-003: Key ID 0 and IDs already in use are redrawn; a source
 * that cannot produce a fresh ID is an entropy fault. */
static void t_key_id_draw(void)
{
	ezdev_t *d = dev_new(6);
	dev_put_key(d, 1, 0x04030201, 1024, 1);
	dev_session(d, 0x04030201, 1, EZ_ROLE_BOB, "old");
	static const uint8_t ids[] = { 0, 0, 0, 0,  1, 2, 3, 4,  5, 6, 7, 8 };
	d->trng.buf = ids; d->trng.buflen = sizeof ids;
	sim_trng_mode(&d->trng, SIM_TRNG_BUFFER, 0);
	ez_keygen_t kg;
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 8192), EZ_PENDING);
	EZ_CHECK_EQ(kg.key_id, 0x08070605u);
	ez_keygen_cancel(&d->c, &kg);
	EZ_CHECK_EQ(kg.result, EZ_ERR_ABORTED);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP"), 0);
	sim_trng_mode(&d->trng, SIM_TRNG_STUCK, 0);           /* ID 0 forever */
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 8192), EZ_ERR_ENTROPY);
	dev_free(d);
}

/* Removal mid-generation; the stale .TMP is destroyed on re-insertion
 * (IMPL-GEN-001) and can never be imported. */
static void t_removal(void)
{
	ezdev_t *d = dev_new(7);
	ez_keygen_t kg;
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 32768), EZ_PENDING);
	for (int i = 0; i < 10; i++) EZ_CHECK_EQ(ez_keygen_step(&d->c, &kg, 1), EZ_PENDING);
	sim_ks_remove(&d->ks, 1);
	ez_status_t st;
	while ((st = ez_keygen_step(&d->c, &kg, 1)) == EZ_PENDING) {}
	EZ_CHECK_EQ(st, EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP"), 1);              /* could not be zapped */
	char tmp[EZ_FNAME_MAX];
	ez_key_name(kg.key_id, "TMP", tmp);
	sim_ks_insert(&d->ks, 1);
	int s;
	ez_import_t im;
	(void)s;
	EZ_CHECK_EQ(ez_import_start(&d->c, &im, 1, tmp, 0x1234, EZ_ROLE_ALICE, "x"), EZ_ERR_BAD_REQUEST);
	EZ_CHECK_EQ(ez_core_media_event(&d->c, 1), EZ_OK);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP"), 0);
	dev_free(d);
}

/* Interrupted by power loss: the .TMP left behind is destroyed at boot. */
static void t_power_loss(void)
{
	ezdev_t *d = dev_new(8);
	ez_keygen_t kg;
	EZ_CHECK_EQ(ez_keygen_start(&d->c, &kg, 1, 32768), EZ_PENDING);
	for (int i = 0; i < 70; i++) ez_keygen_step(&d->c, &kg, 1);   /* into VERIFY */
	EZ_CHECK_EQ(kg.state, EZ_KG_VERIFY);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP"), 1);
	EZ_CHECK_EQ(count_ext(d, 1, ".SUT"), 1);
	dev_reboot(d);
	EZ_CHECK_EQ(count_ext(d, 1, ".TMP") + count_ext(d, 1, ".KEY") +
	            count_ext(d, 1, ".SUT") + count_ext(d, 1, ".SUM"), 0);
	dev_free(d);
}

static const ez_test_case_t cases[] = {
	{ "generate",            "SEC-ENTROPY-001, SEC-ENTROPY-003, SEC-GEN-001, SEC-GEN-003, SEC-STORE-002, IMPL-LOG-002", t_generate },
	{ "params",              "IMPL-KEY-002, IMPL-DRV-001", t_params },
	{ "readback_corruption", "SEC-GEN-002, SEC-GEN-003", t_readback_corruption },
	{ "trng_fault",          "SEC-ENTROPY-004, IMPL-ENT-002, SEC-GEN-003", t_trng_fault },
	{ "monitor_halts",       "SEC-TEST-ENT-002, SEC-ENTROPY-004, §2.3", t_monitor_halts },
	{ "acceptance_rejects",  "SEC-ENTROPY-002, SEC-GEN-003", t_acceptance_rejects },
	{ "key_id_draw",         "SEC-STORE-002, IMPL-KEY-003", t_key_id_draw },
	{ "removal",             "SEC-HW-002, IMPL-GEN-001", t_removal },
	{ "power_loss",          "IMPL-GEN-001", t_power_loss },
};
EZ_TEST_MAIN(cases)
