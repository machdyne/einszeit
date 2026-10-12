/*
 * test_store0.c -- the drive 0 key store (ports/ezstore) and the intent
 * record (IMPL-INT-001).
 *
 * EZ-SEC-001: SEC-STORE-001 (NOR erase), SEC-META-002 pattern (atomic
 * table commit), SEC-PTR-004 (deletion completes after interruption),
 * SEC-STORE-004 (verify-then-use applies unchanged to drive 0);
 * EZ-IMPL-001 IMPL-DRV-002, IMPL-FS-001, IMPL-S0-001..003, IMPL-INT-001.
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_import.h"
#include "ez_ks_route.h"
#include "ez_store0.h"
#include "sim_flash.h"

#define BLOCKS 512u                     /* 2 MiB partition */

typedef struct {
	sim_fram_t  fram;
	sim_flash_t flash;
	ez_store0_t st;
} rig_t;

static rig_t *rig_new(void)
{
	rig_t *r = calloc(1, sizeof *r);
	sim_fram_init(&r->fram, 0x00);
	sim_flash_init(&r->flash, BLOCKS);
	r->flash.fram = &r->fram;
	EZ_CHECK_EQ(ez_store0_init(&r->st, &r->flash.fl, &r->fram.hal, EZ_META_STORE0_SEL), EZ_OK);
	return r;
}
static void rig_free(rig_t *r) { sim_flash_free(&r->flash); free(r); }
static ez_status_t remount(rig_t *r)
{
	sim_flash_power_on(&r->flash);
	return ez_store0_init(&r->st, &r->flash.fl, &r->fram.hal, EZ_META_STORE0_SEL);
}

#define H(r) (&(r)->st.hal)
#define CALL(r, fn, ...) H(r)->fn(H(r)->ctx, __VA_ARGS__)

static uint8_t data[1 << 21], back[1 << 21];

static void put(rig_t *r, const char *name, const uint8_t *p, uint32_t n)
{
	EZ_CHECK_EQ(CALL(r, create, 0, name), EZ_OK);
	for (uint32_t o = 0; o < n; o += 1000)
		EZ_CHECK_EQ(CALL(r, append, 0, name, p + o, n - o < 1000 ? n - o : 1000), EZ_OK);
}

static void t_basics(void)
{
	rig_t *r = rig_new();
	sim_fill(data, 30000, 1);
	uint32_t sz;
	char name[EZ_NAME_MAX];
	EZ_CHECK(H(r)->present(H(r)->ctx, 0));
	EZ_CHECK(!H(r)->present(H(r)->ctx, 1));
	EZ_CHECK_EQ(CALL(r, size, 0, "A.KEY", &sz), EZ_ERR_NOT_FOUND);
	put(r, "A.TMP", data, 30000);
	EZ_CHECK_EQ(CALL(r, create, 0, "a.tmp"), EZ_ERR_EXISTS);                 /* case-insensitive */
	EZ_CHECK_EQ(CALL(r, create, 0, "TOOLONGNAME.KEY"), EZ_ERR_BAD_REQUEST);  /* 15 > 12 */
	EZ_CHECK_EQ(CALL(r, append, 0, "NONE.TMP", data, 1), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(CALL(r, size, 0, "A.TMP", &sz), EZ_OK);
	EZ_CHECK_EQ(sz, 30000);
	for (uint32_t o = 0; o + 5000 <= 30000; o += 4093) {
		EZ_CHECK_EQ(CALL(r, read, 0, "A.TMP", o, back, 5000), EZ_OK);
		EZ_CHECK(memcmp(back, data + o, 5000) == 0);
	}
	EZ_CHECK_EQ(CALL(r, read, 0, "A.TMP", 29999, back, 2), EZ_ERR_RANGE);
	EZ_CHECK_EQ(CALL(r, rename, 0, "A.TMP", "A.KEY"), EZ_OK);
	put(r, "B.KEY", data + 1, 100);
	EZ_CHECK_EQ(CALL(r, rename, 0, "B.KEY", "A.KEY"), EZ_ERR_EXISTS);
	EZ_CHECK_EQ(CALL(r, list, 0, 0, name, &sz), EZ_OK);
	EZ_CHECK(strcmp(name, "A.KEY") == 0 && sz == 30000);
	EZ_CHECK_EQ(CALL(r, list, 0, 2, name, &sz), EZ_ERR_NOT_FOUND);
	/* Survives a remount (rename committed the appended data). */
	EZ_CHECK_EQ(remount(r), EZ_OK);
	EZ_CHECK_EQ(CALL(r, read, 0, "A.KEY", 0, back, 30000), EZ_OK);
	EZ_CHECK(memcmp(back, data, 30000) == 0);
	/* Zap erases with NOR erase; the bytes are gone from flash. */
	EZ_CHECK_EQ(CALL(r, zap, 0, "A.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(r, size, 0, "A.KEY", &sz), EZ_ERR_NOT_FOUND);
	for (uint32_t o = 0; o + 32 <= 30000; o += 1024) EZ_CHECK(!sim_flash_contains(&r->flash, data + o, 32));
	/* Wipe */
	EZ_CHECK_EQ(H(r)->wipe(H(r)->ctx, 0), EZ_OK);
	EZ_CHECK_EQ(CALL(r, list, 0, 0, name, &sz), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(remount(r), EZ_OK);
	EZ_CHECK_EQ(CALL(r, list, 0, 0, name, &sz), EZ_ERR_NOT_FOUND);
	rig_free(r);
}

/* Appends are not committed: only temporaries are appended to, and a
 * rename finalises them. Generating a 2 MiB key costs a few table writes,
 * not thousands. */
static void t_table_wear(void)
{
	rig_t *r = rig_new();
	sim_fill(data, sizeof data, 2);
	unsigned long before = r->st.table_writes;
	uint32_t n = (BLOCKS - 2 - 2) * EZ_FLASH_BLOCK;       /* nearly full */
	EZ_CHECK_EQ(CALL(r, create, 0, "BIG.TMP"), EZ_OK);
	for (uint32_t o = 0; o < n; o += 512)
		EZ_CHECK_EQ(CALL(r, append, 0, "BIG.TMP", data + (o % (sizeof data - 512)), 512), EZ_OK);
	EZ_CHECK_EQ(CALL(r, rename, 0, "BIG.TMP", "BIG.KEY"), EZ_OK);
	EZ_CHECK_EQ(r->st.table_writes - before, 2);           /* create + rename */
	EZ_CHECK(r->flash.erase_count[0] + r->flash.erase_count[1] <= 6);
	/* Full: no block left for 3 more. */
	EZ_CHECK_EQ(CALL(r, create, 0, "X.TMP"), EZ_OK);
	EZ_CHECK_EQ(CALL(r, append, 0, "X.TMP", data, 3 * EZ_FLASH_BLOCK), EZ_ERR_FULL);
	rig_free(r);
}

/* ---- power cut at every flash operation of each commit ---------------- */

static uint8_t snap_flash[BLOCKS * EZ_FLASH_BLOCK], snap_fram[EZ_META_SIZE];

static void snapshot(rig_t *r)
{
	memcpy(snap_flash, r->flash.mem, sizeof snap_flash);
	memcpy(snap_fram, r->fram.mem, sizeof snap_fram);
}
static void restore(rig_t *r)
{
	memcpy(r->flash.mem, snap_flash, sizeof snap_flash);
	memcpy(r->fram.mem, snap_fram, sizeof snap_fram);
	EZ_CHECK_EQ(remount(r), EZ_OK);
}

/* Every byte of `name` is either its original value or erased. */
static void original_or_erased(rig_t *r, const char *name, const uint8_t *orig, uint32_t n)
{
	EZ_CHECK_EQ(CALL(r, read, 0, name, 0, back, n), EZ_OK);
	/* per byte: a torn erase leaves part of a block erased */
	for (uint32_t i = 0; i < n; i++)
		EZ_CHECK_MSG(back[i] == orig[i] || back[i] == 0xFF,
		             "a byte that is neither original nor erased");
}

typedef void (*scen_fn)(rig_t *);
typedef void (*verify_fn)(rig_t *, bool completed);
static ez_status_t g_res;

static void sweep(rig_t *r, scen_fn op, verify_fn verify)
{
	snapshot(r);
	unsigned long e0 = r->flash.erases, p0 = r->flash.programs;
	op(r);
	EZ_CHECK_EQ(g_res, EZ_OK);
	long total = (long)(r->flash.erases - e0 + r->flash.programs - p0);
	verify(r, true);
	for (long k = 0; k <= total; k++) {
		restore(r);
		sim_flash_arm_cut(&r->flash, k);
		op(r);
		EZ_CHECK_MSG(remount(r) == EZ_OK, "store not mountable after a power cut");
		verify(r, false);
	}
	/* and power lost exactly at the F-RAM selector byte */
	restore(r);
	sim_fram_arm_cut(&r->fram, 0);
	op(r);
	EZ_CHECK_EQ(remount(r), EZ_OK);
	verify(r, false);
}

static void s_new_key(rig_t *r)
{
	g_res = CALL(r, create, 0, "N.TMP");
	for (uint32_t o = 0; g_res == EZ_OK && o < 20000; o += 512)
		g_res = CALL(r, append, 0, "N.TMP", data + o, 512);
	if (g_res == EZ_OK) g_res = CALL(r, rename, 0, "N.TMP", "N.KEY");
}
static void v_new_key(rig_t *r, bool done)
{
	uint32_t sz;
	ez_status_t st = CALL(r, size, 0, "N.KEY", &sz);
	if (done) EZ_CHECK_EQ(st, EZ_OK);
	if (st == EZ_OK) {                                    /* complete or absent */
		EZ_CHECK_EQ(sz, 20480);
		EZ_CHECK_EQ(CALL(r, read, 0, "N.KEY", 0, back, sz), EZ_OK);
		EZ_CHECK(memcmp(back, data, sz) == 0);
	}
	/* the existing key is never touched */
	EZ_CHECK_EQ(CALL(r, read, 0, "OLD.KEY", 0, back, 9000), EZ_OK);
	EZ_CHECK(memcmp(back, data + 100000, 9000) == 0);
}

static void s_zap(rig_t *r) { g_res = CALL(r, zap, 0, "OLD.KEY"); }
static void v_zap(rig_t *r, bool done)
{
	uint32_t sz;
	ez_status_t st = CALL(r, size, 0, "OLD.KEY", &sz);
	if (done) EZ_CHECK_EQ(st, EZ_ERR_NOT_FOUND);
	if (st == EZ_OK) original_or_erased(r, "OLD.KEY", data + 100000, 9000);
	else    /* gone from the table means gone from flash (erase before commit) */
		for (uint32_t o = 0; o + 32 <= 9000; o += 512)
			EZ_CHECK_MSG(!sim_flash_contains(&r->flash, data + 100000 + o, 32),
			             "erased file's bytes remain in flash");
	EZ_CHECK_EQ(CALL(r, read, 0, "KEEP.KEY", 0, back, 5000), EZ_OK);
	EZ_CHECK(memcmp(back, data + 200000, 5000) == 0);
}

static void s_wipe(rig_t *r) { g_res = H(r)->wipe(H(r)->ctx, 0); }
static void v_wipe(rig_t *r, bool done)
{
	uint32_t sz;
	ez_status_t st = CALL(r, size, 0, "OLD.KEY", &sz);
	if (done) EZ_CHECK_EQ(st, EZ_ERR_NOT_FOUND);
	if (st == EZ_OK) original_or_erased(r, "OLD.KEY", data + 100000, 9000);
}

static void t_powercut(void)
{
	sim_fill(data, sizeof data, 3);
	rig_t *r = rig_new();
	put(r, "OLD.TMP", data + 100000, 9000);
	EZ_CHECK_EQ(CALL(r, rename, 0, "OLD.TMP", "OLD.KEY"), EZ_OK);
	put(r, "KEEP.TMP", data + 200000, 5000);
	EZ_CHECK_EQ(CALL(r, rename, 0, "KEEP.TMP", "KEEP.KEY"), EZ_OK);
	sweep(r, s_new_key, v_new_key);
	sweep(r, s_zap, v_zap);
	sweep(r, s_wipe, v_wipe);
	rig_free(r);
}

/* The current table is never second-guessed: damage to it, or to the F-RAM
 * selector, makes drive 0 faulty until wiped. A table with a cross-linked
 * chain but a valid CRC is caught by the mount-time chain check. */
static void t_mount_faults(void)
{
	rig_t *r = rig_new();
	sim_fill(data, 20000, 4);
	put(r, "A.TMP", data, 9000);
	EZ_CHECK_EQ(CALL(r, rename, 0, "A.TMP", "A.KEY"), EZ_OK);
	snapshot(r);
	uint32_t sel = r->st.sel;
	r->flash.mem[sel * EZ_FLASH_BLOCK + 100] ^= 0x01;
	EZ_CHECK_EQ(remount(r), EZ_ERR_MEDIA);
	EZ_CHECK(!H(r)->present(H(r)->ctx, 0));
	restore(r);
	r->fram.mem[EZ_META_STORE0_SEL] = 0x5B;
	EZ_CHECK_EQ(remount(r), EZ_ERR_MEDIA);
	EZ_CHECK_EQ(H(r)->wipe(H(r)->ctx, 0), EZ_OK);                 /* the way out */
	EZ_CHECK(H(r)->present(H(r)->ctx, 0));
	/* Two files sharing a block, with lengths and the map otherwise
	 * consistent and a valid CRC: only the sharing check can catch it. */
	put(r, "B.TMP", data, 8192);                         /* 2 blocks */
	put(r, "C.TMP", data, 4096);                         /* 1 block */
	int bi = -1, ci = -1;
	for (int i = 0; i < EZS_ENTRIES; i++) {
		if (r->st.e[i].used && strcmp(r->st.e[i].name, "B.TMP") == 0) bi = i;
		if (r->st.e[i].used && strcmp(r->st.e[i].name, "C.TMP") == 0) ci = i;
	}
	uint16_t b2 = r->st.map[r->st.e[bi].first];          /* B's second block */
	r->st.map[r->st.e[ci].first] = 0xFFFF;               /* free C's own block */
	r->st.e[ci].first = b2;                              /* C now shares B's */
	EZ_CHECK_EQ(CALL(r, rename, 0, "B.TMP", "B.KEY"), EZ_OK);
	EZ_CHECK_EQ(remount(r), EZ_ERR_MEDIA);
	rig_free(r);
}

/* ---- a device whose drive 0 is the store ------------------------------ */

typedef struct {
	sim_fram_t fram; sim_flash_t flash; ez_store0_t st;
	sim_ks_t cards; ez_ks_route_t route; sim_trng_t trng;
	ez_core_t c; uint8_t stage[EZ_STAGE_SIZE];
} s0dev_t;

static void s0_boot(s0dev_t *d)
{
	sim_flash_power_on(&d->flash);
	ez_store0_init(&d->st, &d->flash.fl, &d->fram.hal, EZ_META_STORE0_SEL);
	ez_ks_route_init(&d->route, &d->st.hal, &d->cards.hal);
	ez_core_init(&d->c, &d->fram.hal, &d->route.hal, &d->trng.hal, d->stage, sizeof d->stage);
}

static s0dev_t *s0_new(uint64_t seed)
{
	s0dev_t *d = calloc(1, sizeof *d);
	sim_fram_init(&d->fram, 0xFF);
	sim_flash_init(&d->flash, BLOCKS);
	d->flash.fram = &d->fram;
	sim_ks_init(&d->cards);
	sim_trng_init(&d->trng, seed);
	s0_boot(d);
	/* The store formatted itself (writing its F-RAM selector) before the
	 * core booted: the device must still read as new, not faulty. */
	EZ_CHECK(d->st.table_writes == 1);
	EZ_CHECK_EQ(d->c.meta.dev, EZ_DEV_UNINIT);
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	s0_boot(d);
	EZ_CHECK_EQ(d->c.meta.dev, EZ_DEV_VALID);
	EZ_CHECK(d->st.mounted && !d->st.fault);
	return d;
}
static void s0_free(s0dev_t *d) { sim_flash_free(&d->flash); sim_ks_free(&d->cards); free(d); }

static uint8_t pt[20000], msg[20100], dec[20000];

/* Import a key from a card to drive 0 (copy, verified unit by unit),
 * generate one on drive 0, use both with a simulator-backed peer, delete,
 * disable drive 0: no key bytes remain in flash. */
static void t_device_drive0(void)
{
	s0dev_t *a = s0_new(0x50);
	EZ_CHECK_EQ(ez_drive_enable0(&a->c), EZ_OK);
	/* a key arrives on a card, with its .SUM */
	ezdev_t *peer = dev_new(0x51);
	dev_put_key(peer, 1, 0x7001, 262144, 77);
	sim_file_t *k = sim_ks_get(&peer->ks, 1, "00007001.KEY");
	sim_file_t *s = sim_ks_get(&peer->ks, 1, "00007001.SUM");
	sim_ks_put(&a->cards, 1, "00007001.KEY", k->data, k->len);
	sim_ks_put(&a->cards, 1, "00007001.SUM", s->data, s->len);
	static uint8_t key1[262144];
	memcpy(key1, k->data, sizeof key1);
	EZ_CHECK_EQ(ez_key_copy(&a->c, 0x7001, 1, 0), EZ_OK);           /* import to drive 0 */
	EZ_CHECK_EQ(a->cards.hal.zap(&a->cards, 1, "00007001.KEY"), EZ_OK);   /* card goes home */
	int sa = -1, sp = dev_session(peer, 0x7001, 1, EZ_ROLE_BOB, "a");
	EZ_CHECK_EQ(ez_session_create(&a->c, 0x7001, 0, EZ_ROLE_ALICE, "peer", &sa), EZ_OK);
	/* a key generated on drive 0 */
	ez_keygen_t kg;
	ez_status_t r = ez_keygen_start(&a->c, &kg, 0, 65536);
	while (r == EZ_PENDING) r = ez_keygen_step(&a->c, &kg, 16);
	EZ_CHECK_EQ(r, EZ_OK);
	uint32_t n, m;
	for (int i = 0; i < 5; i++) {
		sim_fill(pt, 20000, (uint64_t)i);
		uint8_t *p = ez_stage_plaintext(&a->c, 20000);
		memcpy(p, pt, 20000);
		const uint8_t *o;
		EZ_CHECK_EQ(ez_encrypt_buffered(&a->c, sa, 20000, &o, &n), EZ_OK);
		memcpy(msg, o, n);
		ez_release(&a->c);
		EZ_CHECK_EQ(dev_decrypt(peer, sp, msg, n, dec, &m), EZ_OK);
		EZ_CHECK(memcmp(dec, pt, 20000) == 0);
		EZ_CHECK_EQ(dev_encrypt(peer, sp, pt, 20000, msg, &n), EZ_OK);
		p = ez_stage_message(&a->c, n);
		memcpy(p, msg, n);
		EZ_CHECK_EQ(ez_decrypt_buffered(&a->c, sa, n, &o, &m), EZ_OK);
		EZ_CHECK(memcmp(o, pt, 20000) == 0);
		ez_release(&a->c);
	}
	/* reboot: everything on drive 0 persists */
	uint32_t tx = a->c.meta.s[sa].tx_off;
	s0_boot(a);
	EZ_CHECK_EQ(a->c.meta.s[sa].state, EZ_SS_VALID);
	EZ_CHECK_EQ(a->c.meta.s[sa].tx_off, tx);
	/* delete the session: key and .SUM erased from flash */
	EZ_CHECK_EQ(ez_session_delete(&a->c, sa, false), EZ_OK);
	for (uint32_t o = 0; o + 32 <= sizeof key1; o += 4096)
		EZ_CHECK_MSG(!sim_flash_contains(&a->flash, key1 + o, 32), "deleted key bytes remain in flash");
	EZ_CHECK_EQ(ez_drive_disable0(&a->c), EZ_OK);
	EZ_CHECK(!a->c.meta.drive0_enabled);
	char nm[EZ_NAME_MAX]; uint32_t sz;
	EZ_CHECK_EQ(a->st.hal.list(&a->st, 0, 0, nm, &sz), EZ_ERR_NOT_FOUND);
	DEV_KBUF_CLEAR(peer);
	dev_free(peer);
	s0_free(a);
}

/* IMPL-INT-001 with the store: a session deletion on drive 0 interrupted
 * at every flash operation completes at the next boot. */
static void t_intent_drive0(void)
{
	s0dev_t *a = s0_new(0x60);
	EZ_CHECK_EQ(ez_drive_enable0(&a->c), EZ_OK);
	ez_keygen_t kg;
	ez_status_t r = ez_keygen_start(&a->c, &kg, 0, 16384);
	while (r == EZ_PENDING) r = ez_keygen_step(&a->c, &kg, 16);
	EZ_CHECK_EQ(r, EZ_OK);
	int s = -1;
	EZ_CHECK_EQ(ez_session_create(&a->c, kg.key_id, 0, EZ_ROLE_ALICE, "x", &s), EZ_OK);
	static uint8_t key[16384], fl[BLOCKS * EZ_FLASH_BLOCK], fr[EZ_META_SIZE];
	char kn[EZ_FNAME_MAX];
	ez_key_name(kg.key_id, "KEY", kn);
	EZ_CHECK_EQ(a->st.hal.read(&a->st, 0, kn, 0, key, sizeof key), EZ_OK);
	memcpy(fl, a->flash.mem, sizeof fl);
	memcpy(fr, a->fram.mem, sizeof fr);
	unsigned long ops0 = a->flash.erases + a->flash.programs;
	EZ_CHECK_EQ(ez_session_delete(&a->c, s, false), EZ_OK);
	long total = (long)(a->flash.erases + a->flash.programs - ops0);
	for (long k = 0; k <= total; k++) {
		memcpy(a->flash.mem, fl, sizeof fl);
		memcpy(a->fram.mem, fr, sizeof fr);
		s0_boot(a);
		EZ_CHECK_EQ(a->c.meta.s[s].state, EZ_SS_VALID);
		sim_flash_arm_cut(&a->flash, k);
		ez_session_delete(&a->c, s, false);
		s0_boot(a);                                         /* resumes */
		EZ_CHECK_MSG(a->c.meta.s[s].state == EZ_SS_EMPTY, "interrupted deletion not completed");
		EZ_CHECK(!ez_core_intent_pending(&a->c));
		for (uint32_t o = 0; o + 32 <= sizeof key; o += 2048)
			EZ_CHECK(!sim_flash_contains(&a->flash, key + o, 32));
	}
	s0_free(a);
}

static const ez_test_case_t cases[] = {
	{ "basics",          "IMPL-S0-001, SEC-STORE-001", t_basics },
	{ "table_wear",      "IMPL-S0-002", t_table_wear },
	{ "powercut",        "IMPL-S0-002, SEC-META-002 (pattern)", t_powercut },
	{ "mount_faults",    "IMPL-S0-003", t_mount_faults },
	{ "device_drive0",   "SEC-STORE-004 (drive 0), SEC-PTR-004, IMPL-DRV-002, SEC-STORE-001", t_device_drive0 },
	{ "intent_drive0",   "IMPL-INT-001, SEC-TEST-PTR-004 (drive 0)", t_intent_drive0 },
};
EZ_TEST_MAIN(cases)
