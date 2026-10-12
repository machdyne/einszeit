/*
 * test_core.c -- session, key, drive and device management.
 *
 * EZ-SEC-001: SEC-TEST-PTR-004 / SEC-PTR-004 (deletion erases the key),
 * SEC-META-003 (key files checked at boot), SEC-STORE-001,
 * SEC-STORE-002, SEC-HW-002, SEC-ISO-002; EZ-IMPL-001 IMPL-DRV-001/002,
 * IMPL-KEY-001/004, IMPL-GEN-001, §2.3 (key delete quarantines sessions).
 */
#include <string.h>

#include "core_fixture.h"
#include "ez_import.h"

static void t_key_name(void)
{
	char n[EZ_FNAME_MAX];
	ez_key_name(0xA73F2C01, "KEY", n);
	EZ_CHECK(strcmp(n, "A73F2C01.KEY") == 0);
	ez_key_name(0x0000000F, "TMP", n);
	EZ_CHECK(strcmp(n, "0000000F.TMP") == 0);
}

static void t_session_create(void)
{
	ezdev_t *d = dev_new(1);
	int s;
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x10, 1, EZ_ROLE_ALICE, "x", &s), EZ_ERR_NOT_FOUND);
	dev_put_key(d, 1, 0x10, 999, 1);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x10, 1, EZ_ROLE_ALICE, "x", &s), EZ_ERR_KEY_PARAM);
	dev_put_key(d, 1, 0x10, 1000, 1);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0, 1, EZ_ROLE_ALICE, "x", &s), EZ_ERR_KEY_PARAM);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x10, 1, EZ_ROLE_ALICE, "x", &s), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[s].key_len, 1000);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x10, 1, EZ_ROLE_BOB, "y", &s), EZ_ERR_EXISTS);
	dev_put_key(d, 0, 0x20, 1000, 1);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x20, 0, EZ_ROLE_ALICE, "z", &s), EZ_ERR_DRIVE_DISABLED);
	sim_ks_remove(&d->ks, 2);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x20, 2, EZ_ROLE_ALICE, "z", &s), EZ_ERR_MEDIA_REMOVED);
	dev_free(d);
}

static ez_status_t import(ezdev_t *d, uint8_t drive, const char *file, uint32_t id,
                          uint8_t role, const char *label, ez_import_t *im)
{
	ez_status_t st = ez_import_start(&d->c, im, drive, file, id, role, label);
	while (st == EZ_PENDING) st = ez_import_step(&d->c, im, 3);
	return st;
}

/* IMPL-KEY-004, SEC-STORE-005: a key without an integrity file passes the
 * acceptance and duplicate checks, gets a .SUM, is renamed, and a session
 * is created. */
static void t_import(void)
{
	ezdev_t *d = dev_new(2);
	static uint8_t k[20480];
	sim_fill(k, sizeof k, 3);
	sim_ks_put(&d->ks, 1, "FROMBOB.BIN", k, sizeof k);
	ez_import_t im;
	EZ_CHECK_EQ(ez_import_start(&d->c, &im, 1, "FROMBOB.BIN", 0, EZ_ROLE_BOB, "bob"), EZ_ERR_KEY_PARAM);
	EZ_CHECK_EQ(import(d, 1, "FROMBOB.BIN", 0xFEED, EZ_ROLE_BOB, "bob", &im), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "FROMBOB.BIN") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "0000FEED.KEY") != NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "0000FEED.SUM") != NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "0000FEED.SUT") == NULL);
	int s = im.slot;
	EZ_CHECK_EQ(d->c.meta.s[s].key_len, sizeof k);
	EZ_CHECK_EQ(d->c.meta.s[s].role, EZ_ROLE_BOB);
	EZ_CHECK(ez_is_zero(d->stage, sizeof d->stage));
	DEV_KBUF_CLEAR(d);
	uint8_t pt[64] = {1}, out[128];
	uint32_t n;
	EZ_CHECK_EQ(dev_encrypt(d, s, pt, 64, out, &n), EZ_OK);
	/* Duplicate ID or label refused before anything is touched. */
	sim_ks_put(&d->ks, 1, "AGAIN.BIN", k, sizeof k);
	EZ_CHECK_EQ(ez_import_start(&d->c, &im, 1, "AGAIN.BIN", 0xFEED, EZ_ROLE_BOB, "b2"), EZ_ERR_EXISTS);
	EZ_CHECK_EQ(ez_import_start(&d->c, &im, 1, "AGAIN.BIN", 0xBEEF, EZ_ROLE_BOB, "bob"), EZ_ERR_EXISTS);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "AGAIN.BIN") != NULL);
	sim_ks_put(&d->ks, 1, "12345678.TMP", k, sizeof k);
	EZ_CHECK_EQ(ez_import_start(&d->c, &im, 1, "12345678.TMP", 0x99, EZ_ROLE_BOB, "t"), EZ_ERR_BAD_REQUEST);
	dev_free(d);
}

/* SEC-STORE-005: keys without an integrity file that are not random are
 * refused: blank areas, statistical defects, duplicated blocks. Nothing is
 * renamed, no .SUM or session remains. */
static void t_import_rejects(void)
{
	ezdev_t *d = dev_new(21);
	static uint8_t k[65536];
	ez_import_t im;
	/* duplicated 4 KiB block (a cross-linked cluster) */
	sim_fill(k, sizeof k, 1);
	memcpy(k + 3 * 4096, k + 10 * 4096, 4096);
	sim_ks_put(&d->ks, 1, "DUP.BIN", k, sizeof k);
	EZ_CHECK_EQ(import(d, 1, "DUP.BIN", 0x101, EZ_ROLE_BOB, "d", &im), EZ_ERR_KEY_DAMAGED);
	EZ_CHECK_EQ(im.dups, 1);
	/* a zeroed region */
	sim_fill(k, sizeof k, 2);
	memset(k + 20000, 0, 3000);
	sim_ks_put(&d->ks, 1, "ZERO.BIN", k, sizeof k);
	EZ_CHECK_EQ(import(d, 1, "ZERO.BIN", 0x102, EZ_ROLE_BOB, "z", &im), EZ_ERR_ENTROPY);
	/* biased data */
	sim_trng_t t;
	sim_trng_init(&t, 3);
	sim_trng_mode(&t, SIM_TRNG_BIASED, 140);
	t.hal.read(&t, k, sizeof k);
	sim_ks_put(&d->ks, 1, "BIAS.BIN", k, sizeof k);
	EZ_CHECK_EQ(import(d, 1, "BIAS.BIN", 0x103, EZ_ROLE_BOB, "b", &im), EZ_ERR_ENTROPY);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "DUP.BIN") && sim_ks_get(&d->ks, 1, "ZERO.BIN") &&
	         sim_ks_get(&d->ks, 1, "BIAS.BIN"));
	for (int i = 0; i < SIM_KS_FILES; i++)
		if (d->ks.d[1].f[i].used) {
			EZ_CHECK(!strstr(d->ks.d[1].f[i].name, ".SUM"));
			EZ_CHECK(!strstr(d->ks.d[1].f[i].name, ".SUT"));
		}
	for (int i = 0; i < EZ_META_SESSIONS; i++) EZ_CHECK_EQ(d->c.meta.s[i].state, EZ_SS_EMPTY);
	EZ_CHECK(ez_is_zero(d->stage, sizeof d->stage));
	dev_free(d);
}

/* SEC-STORE-004: a key arriving with its .SUM is verified unit by unit;
 * damage in transfer is caught before either side encrypts. A .SUM for a
 * different Key ID is refused (SEC-DIST-003). */
static void t_import_with_sum(void)
{
	ezdev_t *g = dev_new(30), *r = dev_new(31);
	dev_put_key(g, 1, 0xA1, 65536, 7);                   /* generated, with .SUM */
	dev_copy_key(g, r, 1, 0xA1);
	sim_file_t *f = sim_ks_get(&r->ks, 1, "000000A1.KEY");
	f->data[40000] ^= 0x10;                              /* damaged in transfer */
	ez_import_t im;
	EZ_CHECK_EQ(import(r, 1, "000000A1.KEY", 0xA1, EZ_ROLE_BOB, "g", &im), EZ_ERR_KEY_DAMAGED);
	EZ_CHECK_EQ(im.bad, 1);
	EZ_CHECK_EQ(im.first_bad, 8 + (40000 - 32768) / 4096);   /* bob's half starts at unit 8 */
	f->data[40000] ^= 0x10;
	EZ_CHECK_EQ(import(r, 1, "000000A1.KEY", 0xA1, EZ_ROLE_BOB, "g", &im), EZ_OK);
	uint16_t inst;
	EZ_CHECK_EQ(ez_sum_check(&r->c, 1, 0xA1, 65536, &inst), EZ_OK);
	EZ_CHECK_EQ(r->c.meta.s[im.slot].instance, inst);
	/* A key renamed by the user, arriving with a .SUM for another ID. */
	dev_put_key(g, 1, 0xA2, 65536, 8);
	sim_file_t *k2 = sim_ks_get(&g->ks, 1, "000000A2.KEY");
	sim_file_t *s2 = sim_ks_get(&g->ks, 1, "000000A2.SUM");
	sim_ks_put(&r->ks, 1, "000000A3.KEY", k2->data, k2->len);
	sim_ks_put(&r->ks, 1, "000000A3.SUM", s2->data, s2->len);
	EZ_CHECK_EQ(ez_import_start(&r->c, &im, 1, "000000A3.KEY", 0xA3, EZ_ROLE_BOB, "h"), EZ_ERR_KEY_ID);
	dev_free(g); dev_free(r);
}

/* SEC-META-003 (key file part): missing or resized key files quarantine
 * the session at boot; resolution after the file is restored. */
static void t_boot_key_checks(void)
{
	ezdev_t *d = dev_new(3);
	dev_put_key(d, 1, 0x31, 4096, 1);
	dev_put_key(d, 1, 0x32, 4096, 2);
	int a = dev_session(d, 0x31, 1, EZ_ROLE_ALICE, "a");
	int b = dev_session(d, 0x32, 1, EZ_ROLE_ALICE, "b");
	sim_file_t *fa = sim_ks_get(&d->ks, 1, "00000031.KEY");
	uint8_t saved[4096];
	memcpy(saved, fa->data, 4096);
	EZ_CHECK_EQ(d->ks.hal.zap(d->ks.hal.ctx, 1, "00000031.KEY"), EZ_OK);   /* deleted */
	dev_put_key(d, 1, 0x32, 4098, 2);                      /* resized */
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[a].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(d->c.meta.s[a].qreason, EZ_Q_KEY_MISSING);
	EZ_CHECK_EQ(d->c.meta.s[b].qreason, EZ_Q_KEY_SIZE);
	EZ_CHECK_EQ(ez_session_resolve(&d->c, a), EZ_ERR_NOT_FOUND);
	dev_put_key(d, 1, 0x31, 4096, 1);       /* restored from a copy: key and .SUM */
	EZ_CHECK(memcmp(sim_ks_get(&d->ks, 1, "00000031.KEY")->data, saved, 4096) == 0);
	EZ_CHECK_EQ(ez_session_resolve(&d->c, a), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[a].state, EZ_SS_VALID);
	EZ_CHECK_EQ(ez_session_resolve(&d->c, b), EZ_ERR_KEY_PARAM);
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[a].state, EZ_SS_VALID);
	EZ_CHECK_EQ(d->c.meta.s[b].state, EZ_SS_QUARANTINED);
	dev_free(d);
}

/* SEC-STORE-001; EZ-IMPL-001 §2.3: deleting a linked key quarantines. */
static void t_key_delete(void)
{
	ezdev_t *d = dev_new(4);
	dev_put_key(d, 1, 0x41, 4096, 1);
	int s = dev_session(d, 0x41, 1, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_key_delete(&d->c, 1, 0x41), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000041.KEY") == NULL);
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(d->c.meta.s[s].qreason, EZ_Q_KEY_ERASING);    /* quarantined before the erase */
	EZ_CHECK_EQ(ez_key_delete(&d->c, 1, 0x41), EZ_ERR_NOT_FOUND);
	dev_free(d);
}

static void t_key_copy(void)
{
	ezdev_t *d = dev_new(5);
	dev_put_key(d, 1, 0x51, 10000, 1);
	EZ_CHECK_EQ(ez_key_copy(&d->c, 0x51, 1, 0), EZ_ERR_DRIVE_DISABLED);
	EZ_CHECK_EQ(ez_drive_enable0(&d->c), EZ_OK);
	EZ_CHECK_EQ(ez_key_copy(&d->c, 0x51, 1, 0), EZ_OK);
	sim_file_t *a = sim_ks_get(&d->ks, 1, "00000051.KEY"), *b = sim_ks_get(&d->ks, 0, "00000051.KEY");
	EZ_CHECK(a && b && a->len == b->len && memcmp(a->data, b->data, a->len) == 0);
	EZ_CHECK(sim_ks_get(&d->ks, 0, "00000051.TMP") == NULL);
	EZ_CHECK_EQ(ez_key_copy(&d->c, 0x51, 1, 0), EZ_ERR_EXISTS);
	DEV_KBUF_CLEAR(d);
	/* Interrupted copy leaves no .TMP and no partial key. */
	dev_put_key(d, 1, 0x52, 10000, 2);
	sim_ks_corrupt_append(&d->ks, 1);        /* the second unit written */
	EZ_CHECK_EQ(ez_key_copy(&d->c, 0x52, 1, 2), EZ_ERR_MEDIA);
	EZ_CHECK(sim_ks_get(&d->ks, 2, "00000052.TMP") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 2, "00000052.KEY") == NULL);
	DEV_KBUF_CLEAR(d);
	dev_free(d);
}

/* IMPL-DRV-001/002 */
static void t_drive0(void)
{
	ezdev_t *d = dev_new(6);
	dev_put_key(d, 0, 0x61, 4096, 1);
	int s;
	char n[EZ_NAME_MAX]; uint32_t sz;
	EZ_CHECK_EQ(ez_drive_list(&d->c, 0, 0, n, &sz), EZ_ERR_DRIVE_DISABLED);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x61, 0, EZ_ROLE_ALICE, "a", &s), EZ_ERR_DRIVE_DISABLED);
	EZ_CHECK_EQ(ez_drive_enable0(&d->c), EZ_OK);
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x61, 0, EZ_ROLE_ALICE, "a", &s), EZ_OK);
	EZ_CHECK_EQ(ez_drive_disable0(&d->c), EZ_ERR_STATE);         /* session on drive 0 */
	EZ_CHECK(sim_ks_get(&d->ks, 0, "00000061.KEY") != NULL);
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 0, "00000061.KEY") == NULL);    /* SEC-PTR-004 */
	dev_put_key(d, 0, 0x62, 4096, 1);                           /* an unlinked key */
	unsigned long w = d->ks.d[0].wipes;
	EZ_CHECK_EQ(ez_drive_disable0(&d->c), EZ_OK);
	EZ_CHECK_EQ(d->ks.d[0].wipes, w + 1);
	EZ_CHECK(sim_ks_get(&d->ks, 0, "00000062.KEY") == NULL);    /* erased by the wipe */
	dev_reboot(d);
	EZ_CHECK(!d->c.meta.drive0_enabled);
	dev_free(d);
}

/* Device erase: key files first, then metadata. Other files on the card
 * are left alone; drive 0 is always wiped. A power cut in the metadata
 * phase leaves no usable session pointing at a surviving key. */
static void t_device_erase(void)
{
	ezdev_t *d = dev_new(7);
	dev_put_key(d, 1, 0x71, 4096, 1);
	dev_put_key(d, 2, 0x72, 4096, 2);
	sim_ks_put(&d->ks, 1, "README.TXT", (const uint8_t *)"hi", 2);
	sim_ks_put(&d->ks, 1, "0000ABCD.TMP", (const uint8_t *)"t", 1);
	dev_put_key(d, 0, 0x73, 4096, 3);
	int s = dev_session(d, 0x71, 1, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&d->c.meta, s, 100), EZ_OK);
	uint8_t fram_before[EZ_META_SIZE];
	memcpy(fram_before, d->fram.mem, sizeof fram_before);
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000071.KEY") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 2, "00000072.KEY") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 0, "00000073.KEY") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "0000ABCD.TMP") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "README.TXT") != NULL);
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_EMPTY);

	/* Power cut at every byte of the metadata phase. */
	for (long cut = 0; cut < 2100; cut += 7) {
		memcpy(d->fram.mem, fram_before, sizeof fram_before);
		dev_put_key(d, 1, 0x71, 4096, 1);
		dev_reboot(d);
		EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_VALID);
		sim_fram_arm_cut(&d->fram, cut);
		ez_device_erase(&d->c);
		dev_reboot(d);
		/* Either the erase never started (its intent record was torn), or
		 * it was completed at boot (IMPL-INT-001). */
		sim_file_t *k = sim_ks_get(&d->ks, 1, "00000071.KEY");
		bool untouched = d->c.meta.s[s].state == EZ_SS_VALID && k != NULL;
		bool erased = k == NULL;
		for (int i = 0; i < EZ_META_SESSIONS && erased; i++)
			erased = d->c.meta.s[i].state == EZ_SS_EMPTY;
		EZ_CHECK_MSG(untouched || erased, "device erase neither undone nor completed");
	}
	dev_free(d);
}

/* ---- SEC-TEST-PTR-004: session deletion ------------------------------ */

static int has_event(ezdev_t *d, uint8_t type, uint32_t key_id)
{
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(&d->c.meta, ev, EZ_META_LOG_ENTRIES);
	for (int i = 0; i < n; i++)
		if (ev[i].type == type && ev[i].key_id == key_id) return 1;
	return 0;
}

static void t_delete_erases_key(void)
{
	ezdev_t *d = dev_new(8);
	dev_put_key(d, 1, 0x81, 4096, 1);
	int s = dev_session(d, 0x81, 1, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&d->c.meta, s, 300), EZ_OK);
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000081.KEY") == NULL);
	EZ_CHECK_MSG(sim_ks_get(&d->ks, 1, "00000081.SUM") == NULL, "tags not erased with the key");
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_EMPTY);
	EZ_CHECK(has_event(d, EZ_EV_SESSION_DELETE, 0x81));
	/* The old exploit: re-create the session from the same file. The file
	 * no longer exists, so it cannot restart at offset 0. */
	int s2;
	EZ_CHECK_EQ(ez_session_create(&d->c, 0x81, 1, EZ_ROLE_ALICE, "a", &s2), EZ_ERR_NOT_FOUND);
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_EMPTY);
	dev_free(d);
}

/* Power cut at every byte of the metadata writes that follow the erase:
 * the key is always gone, and the session is never usable afterwards. */
static void t_delete_powercut(void)
{
	ezdev_t *d = dev_new(9);
	dev_put_key(d, 1, 0x82, 4096, 1);
	int s = dev_session(d, 0x82, 1, EZ_ROLE_BOB, "b");
	EZ_CHECK_EQ(ez_meta_commit_tx(&d->c.meta, s, 3000), EZ_OK);
	uint8_t fram[EZ_META_SIZE];
	memcpy(fram, d->fram.mem, sizeof fram);
	sim_file_t *f = sim_ks_get(&d->ks, 1, "00000082.KEY");
	uint8_t key[4096], sum[64];
	memcpy(key, f->data, sizeof key);
	sim_file_t *fs = sim_ks_get(&d->ks, 1, "00000082.SUM");
	uint32_t sumlen = fs->len;
	EZ_CHECK(sumlen <= sizeof sum);
	memcpy(sum, fs->data, sumlen);
	unsigned long before = d->fram.bytes_written;
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	long total = (long)(d->fram.bytes_written - before);
	for (long cut = 0; cut <= total; cut++) {
		memcpy(d->fram.mem, fram, sizeof fram);
		sim_ks_put(&d->ks, 1, "00000082.KEY", key, sizeof key);
		sim_ks_put(&d->ks, 1, "00000082.SUM", sum, sumlen);
		dev_reboot(d);
		EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_VALID);
		sim_fram_arm_cut(&d->fram, cut);
		ez_session_delete(&d->c, s, false);
		dev_reboot(d);
		sim_file_t *k = sim_ks_get(&d->ks, 1, "00000082.KEY");
		const ez_session_t *ss = &d->c.meta.s[s];
		if (ss->state == EZ_SS_VALID)
			EZ_CHECK_MSG(k && memcmp(k->data, key, sizeof key) == 0,
			             "usable session over a missing or altered key");
		else if (ss->state == EZ_SS_EMPTY)
			EZ_CHECK_MSG(k == NULL, "record removed but key survived");
		else
			EZ_CHECK(ss->qreason == EZ_Q_KEY_ERASING || ss->qreason == EZ_Q_KEY_MISSING);
		/* An interrupted deletion can be completed. */
		if (ss->state != EZ_SS_EMPTY)
			EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
		EZ_CHECK(sim_ks_get(&d->ks, 1, "00000082.KEY") == NULL);
	}
	dev_free(d);
}

/* Refused when the key cannot be erased; override removes the record and
 * is logged. */
static void t_delete_refused_and_override(void)
{
	ezdev_t *d = dev_new(10);
	dev_put_key(d, 1, 0x83, 4096, 1);
	dev_put_key(d, 2, 0x84, 4096, 2);
	int a = dev_session(d, 0x83, 1, EZ_ROLE_ALICE, "a");
	int b = dev_session(d, 0x84, 2, EZ_ROLE_ALICE, "b");
	/* Card absent. */
	sim_ks_remove(&d->ks, 1);
	EZ_CHECK_EQ(ez_session_delete(&d->c, a, false), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(d->c.meta.s[a].state, EZ_SS_VALID);
	/* Card removed during the erase: the key is intact but the session has
	 * already been made unusable (SEC-PTR-004 step 1). */
	sim_ks_remove_after(&d->ks, 2, 0);
	EZ_CHECK_EQ(ez_session_delete(&d->c, b, false), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(d->c.meta.s[b].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(d->c.meta.s[b].qreason, EZ_Q_KEY_ERASING);
	EZ_CHECK(sim_ks_get(&d->ks, 2, "00000084.KEY") != NULL);
	/* While b's erase is pending, other destructive operations wait. */
	EZ_CHECK(ez_core_intent_pending(&d->c));
	sim_ks_insert(&d->ks, 1);
	EZ_CHECK_EQ(ez_session_delete(&d->c, a, false), EZ_ERR_BUSY);
	/* Override for a (key not erased): allowed, and logged. */
	sim_ks_remove(&d->ks, 1);
	EZ_CHECK_EQ(ez_session_delete(&d->c, a, true), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[a].state, EZ_SS_EMPTY);
	EZ_CHECK(has_event(d, EZ_EV_SESSION_FORCE, 0x83));
	sim_ks_insert(&d->ks, 1);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000083.KEY") != NULL);   /* not erased */
	/* b's card comes back: its deletion completes on insertion. */
	sim_ks_insert(&d->ks, 2);
	EZ_CHECK_EQ(ez_core_media_event(&d->c, 2), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[b].state, EZ_SS_EMPTY);
	EZ_CHECK(sim_ks_get(&d->ks, 2, "00000084.KEY") == NULL);
	EZ_CHECK(!ez_core_intent_pending(&d->c));
	/* Unverifiable identity: refused, then override. */
	dev_put_key(d, 1, 0x87, 4096, 3);
	int c2 = dev_session(d, 0x87, 1, EZ_ROLE_ALICE, "c");
	d->fram.mem[EZ_META_SESSION_ADDR + (uint32_t)c2 * EZ_META_SESSION_SIZE + EZ_SR_OFF_LABEL] ^= 0x01;
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[c2].qreason, EZ_Q_STATIC_CRC);
	EZ_CHECK_EQ(ez_session_delete(&d->c, c2, false), EZ_ERR_UNRESOLVED);
	EZ_CHECK_EQ(ez_session_delete(&d->c, c2, true), EZ_OK);
	EZ_CHECK(has_event(d, EZ_EV_SESSION_FORCE, 0));
	dev_free(d);
}

/* A session already quarantined because its key file is missing can be
 * deleted normally. */
static void t_delete_missing_key(void)
{
	ezdev_t *d = dev_new(11);
	dev_put_key(d, 1, 0x85, 4096, 1);
	int s = dev_session(d, 0x85, 1, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_key_delete(&d->c, 1, 0x85), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[s].qreason, EZ_Q_KEY_ERASING);
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_EMPTY);
	dev_free(d);
}

/* SEC-PTR-004: an erase interrupted part-way (half the key zeroed, card
 * lost) must leave no usable session -- for session delete, key delete
 * and device erase alike. */
static void interrupted(int which)
{
	ezdev_t *d = dev_new(12);
	dev_put_key(d, 1, 0x86, 8192, 1);
	int s = dev_session(d, 0x86, 1, EZ_ROLE_BOB, "b");
	sim_ks_interrupt_zap(&d->ks);
	ez_status_t st = which == 0 ? ez_session_delete(&d->c, s, false)
	               : which == 1 ? ez_key_delete(&d->c, 1, 0x86)
	                            : ez_device_erase(&d->c);
	EZ_CHECK(st != EZ_OK);
	/* Before the card is back: the session is unusable, never usable over
	 * the partly zeroed key. */
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_QUARANTINED);
	uint8_t pt[64] = {0}, out[128];
	uint32_t n;
	EZ_CHECK_EQ(dev_encrypt(d, s, pt, 64, out, &n), EZ_ERR_QUARANTINED);
	/* IMPL-INT-001: with the card back, the next boot completes the erase. */
	sim_ks_insert(&d->ks, 1);
	dev_reboot(d);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000086.KEY") == NULL);
	EZ_CHECK(sim_ks_get(&d->ks, 1, "00000086.SUM") == NULL);
	EZ_CHECK_EQ(d->c.meta.s[s].state, which == 1 ? EZ_SS_QUARANTINED : EZ_SS_EMPTY);
	EZ_CHECK(!ez_core_intent_pending(&d->c));
	if (which == 1)                       /* key delete leaves its session to the user */
		EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	dev_free(d);
}
static void t_interrupted_session_delete(void) { interrupted(0); }
static void t_interrupted_key_delete(void)     { interrupted(1); }
static void t_interrupted_device_erase(void)   { interrupted(2); }

/* IMPL-INT-001: a device erase interrupted when no drive is usable at the
 * next boot (drive 0 disabled, card absent) is still completed at boot. */
static void t_resume_without_drives(void)
{
	ezdev_t *d = dev_new(13);
	dev_put_key(d, 1, 0x91, 8192, 1);
	int s = dev_session(d, 0x91, 1, EZ_ROLE_ALICE, "a");
	sim_ks_interrupt_zap(&d->ks);                        /* card lost during the erase */
	EZ_CHECK(ez_device_erase(&d->c) != EZ_OK);
	EZ_CHECK(ez_core_intent_pending(&d->c));
	sim_ks_remove(&d->ks, 2);
	ez_core_init(&d->c, &d->fram.hal, &d->ks.hal, &d->trng.hal, d->stage, sizeof d->stage);
	EZ_CHECK_EQ(d->c.meta.dev, EZ_DEV_VALID);
	EZ_CHECK_EQ(d->c.meta.s[s].state, EZ_SS_EMPTY);       /* erase completed */
	EZ_CHECK(!ez_core_intent_pending(&d->c));
	dev_free(d);
}

/* IMPL-DRV-003: with a guard reporting missing protection, drive 0 can
 * neither be enabled nor used; it can still be erased. The guard survives
 * core re-initialisation. */
static bool guard_ok;
static bool guard(void *ctx) { (void)ctx; return guard_ok; }
static void t_drive0_guard(void)
{
	ezdev_t *d = dev_new(14);
	d->c.drive0_guard = guard;
	dev_reboot(d);
	EZ_CHECK(d->c.drive0_guard == guard);                /* kept across init */
	guard_ok = false;
	EZ_CHECK_EQ(ez_core_drive0_protected(&d->c), 0);
	EZ_CHECK_EQ(ez_drive_enable0(&d->c), EZ_ERR_PROTECTION);
	EZ_CHECK(!d->c.meta.drive0_enabled);
	guard_ok = true;
	EZ_CHECK_EQ(ez_drive_enable0(&d->c), EZ_OK);
	dev_put_key(d, 0, 0x2A, 8192, 1);
	int s = dev_session(d, 0x2A, 0, EZ_ROLE_ALICE, "d0");
	uint8_t pt[16] = { 0 }, out[64];
	uint32_t n;
	EZ_CHECK_EQ(dev_encrypt(d, s, pt, 16, out, &n), EZ_OK);
	guard_ok = false;                                    /* protection removed */
	EZ_CHECK_EQ(ez_core_drive_usable(&d->c, 0), EZ_ERR_PROTECTION);
	EZ_CHECK(dev_encrypt(d, s, pt, 16, out, &n) != EZ_OK);
	EZ_CHECK_EQ(d->c.meta.s[s].tx_off, 16);              /* nothing spent */
	/* Erasing never depends on the protection: the session and its key can
	 * be deleted normally, then drive 0 disabled. */
	EZ_CHECK_EQ(ez_drive_disable0(&d->c), EZ_ERR_STATE);   /* a session still uses drive 0 */
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	EZ_CHECK(sim_ks_get(&d->ks, 0, "0000002A.KEY") == NULL);
	EZ_CHECK(!has_event(d, EZ_EV_SESSION_FORCE, 0x2A));
	EZ_CHECK_EQ(ez_drive_disable0(&d->c), EZ_OK);
	dev_free(d);
}

/* IMPL-AV-007: formatting is refused while a session uses the drive, and
 * the hook survives core re-initialisation. */
static int fmt_calls;
static uint8_t fmt_copies;
static ez_status_t fmt(void *ctx, uint8_t drive, uint8_t copies) { (void)ctx; (void)drive; fmt_calls++; fmt_copies = copies; return EZ_OK; }
static void t_drive_format(void)
{
	ezdev_t *d = dev_new(15);
	EZ_CHECK_EQ(ez_drive_format(&d->c, 1, 2), EZ_ERR_UNSUPPORTED);
	d->c.format = fmt;
	dev_reboot(d);
	EZ_CHECK(d->c.format == fmt);
	dev_put_key(d, 1, 0x3A, 8192, 1);
	int s = dev_session(d, 0x3A, 1, EZ_ROLE_ALICE, "x");
	EZ_CHECK_EQ(ez_drive_format(&d->c, 1, 2), EZ_ERR_STATE);
	EZ_CHECK_EQ(fmt_calls, 0);
	EZ_CHECK_EQ(ez_drive_format(&d->c, 0, 1), EZ_ERR_BAD_REQUEST);    /* never drive 0 */
	EZ_CHECK_EQ(ez_drive_format(&d->c, 1, 3), EZ_ERR_BAD_REQUEST);
	EZ_CHECK_EQ(ez_session_delete(&d->c, s, false), EZ_OK);
	EZ_CHECK_EQ(ez_drive_format(&d->c, 1, 2), EZ_OK);
	EZ_CHECK(fmt_calls == 1 && fmt_copies == 2);
	uint8_t n;
	EZ_CHECK_EQ(ez_drive_repair(&d->c, 1, &n), EZ_ERR_UNSUPPORTED);   /* no volume-repair hook here */
	EZ_CHECK_EQ(ez_drive_repair(&d->c, 0, &n), EZ_ERR_BAD_REQUEST);
	dev_free(d);
}

/* EZ-UI-001 §13: device erase leaves drive 0 on when its protection is
 * verified, and off otherwise. */
static bool guard_yes(void *ctx) { (void)ctx; return true; }
static bool guard_no(void *ctx) { (void)ctx; return false; }
static void t_drive0_default(void)
{
	ezdev_t *d = dev_new(16);
	d->c.drive0_guard = guard_yes;
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	EZ_CHECK(d->c.meta.drive0_enabled);
	d->c.drive0_guard = guard_no;
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	EZ_CHECK(!d->c.meta.drive0_enabled);
	d->c.drive0_guard = NULL;                             /* no guard: as before, off */
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	EZ_CHECK(!d->c.meta.drive0_enabled);
	dev_free(d);
}

static const ez_test_case_t cases[] = {
	{ "key_name",         "IMPL-KEY-001", t_key_name },
	{ "session_create",   "SEC-STORE-002, SEC-STORE-003, SEC-ISO-002, IMPL-DRV-001, SEC-HW-002", t_session_create },
	{ "import",           "IMPL-KEY-004, SEC-STORE-005, IMPL-GEN-001, SEC-ISO-002", t_import },
	{ "import_rejects",   "SEC-STORE-005, SEC-ENTROPY-002", t_import_rejects },
	{ "import_with_sum",  "SEC-STORE-004, SEC-DIST-003, IMPL-KEY-005", t_import_with_sum },
	{ "boot_key_checks",  "SEC-META-003, IMPL-META-006", t_boot_key_checks },
	{ "key_delete",       "SEC-STORE-001", t_key_delete },
	{ "key_copy",         "SEC-GEN-002 (copy), SEC-FW-003", t_key_copy },
	{ "drive0",           "IMPL-DRV-001, IMPL-DRV-002, SEC-STORE-001", t_drive0 },
	{ "device_erase",     "SEC-STORE-001, IMPL-META-001", t_device_erase },
	{ "delete_erases_key",            "SEC-TEST-PTR-004, SEC-PTR-004", t_delete_erases_key },
	{ "delete_powercut",              "SEC-TEST-PTR-004, SEC-PTR-004", t_delete_powercut },
	{ "delete_refused_and_override",  "SEC-TEST-PTR-004, SEC-PTR-004, SEC-HW-002, IMPL-INT-001", t_delete_refused_and_override },
	{ "drive_format",                 "IMPL-AV-007", t_drive_format },
	{ "drive0_default",               "EZ-UI-001 §13", t_drive0_default },
	{ "drive0_guard",                 "IMPL-DRV-003, SEC-HW-003", t_drive0_guard },
	{ "resume_without_drives",        "IMPL-INT-001", t_resume_without_drives },
	{ "delete_missing_key",           "SEC-PTR-004", t_delete_missing_key },
	{ "interrupted_session_delete",   "SEC-TEST-PTR-004, SEC-PTR-004, IMPL-INT-001", t_interrupted_session_delete },
	{ "interrupted_key_delete",       "SEC-PTR-004, SEC-STORE-001, IMPL-INT-001", t_interrupted_key_delete },
	{ "interrupted_device_erase",     "SEC-PTR-004, SEC-STORE-001, IMPL-INT-001", t_interrupted_device_erase },
};
EZ_TEST_MAIN(cases)
