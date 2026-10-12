/*
 * test_mirror.c -- keys kept as several copies (SEC-AVAIL-001..004,
 * EZ-IMPL-001 §2.8, ports/mirror).
 *
 * Logical drive 1 is mirrored onto simulated drives 1 (copy 0) and 2
 * (copy 1) of one sim_ks: one "card" with two volumes. Removing the card
 * removes both.
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_ks_mirror.h"

typedef struct { ezdev_t *d; ez_ks_mirror_t m; } mdev_t;

static void mboot(mdev_t *x)
{
	sim_fram_power_on(&x->d->fram);
	sim_ks_clear_faults(&x->d->ks);
	ez_core_init(&x->d->c, &x->d->fram.hal, &x->m.hal, &x->d->trng.hal, x->d->stage, sizeof x->d->stage);
}

static mdev_t *mnew(uint64_t seed)
{
	mdev_t *x = calloc(1, sizeof *x);
	x->d = dev_new(seed);
	ez_mirror_vol_t v[2] = { { &x->d->ks.hal, 1 }, { &x->d->ks.hal, 2 } };
	ez_ks_mirror_init(&x->m, &x->d->ks.hal, 1, v, 2);
	mboot(x);
	return x;
}
static void mfree(mdev_t *x) { dev_free(x->d); free(x); }


static int msession(mdev_t *x, uint32_t id, uint8_t role)
{
	int s = -1;
	EZ_CHECK_EQ(ez_session_create(&x->d->c, id, 1, role, role ? "a" : "b", &s), EZ_OK);
	return s;
}

static sim_file_t *f(mdev_t *x, uint8_t vol, uint32_t id, const char *ext)
{
	char n[EZ_FNAME_MAX];
	ez_key_name(id, ext, n);
	return sim_ks_get(&x->d->ks, vol, n);
}

static uint8_t pt[20000], ct[20100], out[20000];

/* Session creation replicates copy 0 into copy 1 -- identical key and
 * .SUM -- and writes nothing to copy 0 while doing so (SEC-AVAIL-004). */
static void t_replicate(void)
{
	mdev_t *x = mnew(1);
	dev_put_key(x->d, 1, 0x101, 65536, 1);           /* on copy 0 (sim drive 1) */
	static uint8_t k0[65536], s0[1024];
	memcpy(k0, f(x, 1, 0x101, "KEY")->data, 65536);
	uint32_t sl = f(x, 1, 0x101, "SUM")->len;
	memcpy(s0, f(x, 1, 0x101, "SUM")->data, sl);
	int s = msession(x, 0x101, EZ_ROLE_ALICE);
	EZ_CHECK_EQ(x->d->c.last_replicate, EZ_OK);
	EZ_CHECK(f(x, 2, 0x101, "KEY") && !memcmp(f(x, 2, 0x101, "KEY")->data, k0, 65536));
	EZ_CHECK(f(x, 2, 0x101, "SUM") && f(x, 2, 0x101, "SUM")->len == sl &&
	         !memcmp(f(x, 2, 0x101, "SUM")->data, s0, sl));       /* rebuilt from data: identical */
	EZ_CHECK(!memcmp(f(x, 1, 0x101, "KEY")->data, k0, 65536));      /* copy 0 untouched */
	EZ_CHECK(f(x, 2, 0x101, "TMP") == NULL && f(x, 2, 0x101, "SUT") == NULL);
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(ck.copies == 2 && ck.lost == 0 && ck.copy[0].bad == 0 && ck.copy[1].bad == 0);
	EZ_CHECK(ck.copy[0].has_key && ck.copy[1].has_key);
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

/* IMPL-AV-003: a damaged unit in one copy is served from the other; the
 * peer decrypts correctly. Damage to the same unit in both copies is
 * refused. SEC-AVAIL-001: none of this writes to key storage. */
static void t_failover(void)
{
	mdev_t *a = mnew(2);
	ezdev_t *b = dev_new(3);
	dev_put_key(a->d, 1, 0x202, 65536, 4);
	dev_copy_key(a->d, b, 1, 0x202);
	int sa = msession(a, 0x202, EZ_ROLE_ALICE);
	int sb = dev_session(b, 0x202, 1, EZ_ROLE_BOB, "a");
	f(a, 1, 0x202, "KEY")->data[5000] ^= 0x40;           /* unit 1, copy 0 */
	f(a, 2, 0x202, "KEY")->data[13000] ^= 0x40;          /* unit 3, copy 1 */
	unsigned long m0 = a->d->ks.mutations;
	sim_fill(pt, 20000, 5);
	uint32_t n, m;
	EZ_CHECK_EQ(dev_encrypt(a->d, sa, pt, 20000, ct, &n), EZ_OK);
	/* Units 0..4 are used: unit 1 comes from copy 1. Copy 1's damage in
	 * unit 3 is never reached, because copy 0's unit 3 verifies first. */
	EZ_CHECK_EQ(a->d->c.failovers, 1);
	EZ_CHECK_EQ(dev_decrypt(b, sb, ct, n, out, &m), EZ_OK);
	EZ_CHECK(m == 20000 && !memcmp(out, pt, 20000));
	EZ_CHECK_EQ(dev_encrypt(b, sb, pt, 300, ct, &n), EZ_OK);
	EZ_CHECK_EQ(dev_decrypt(a->d, sa, ct, n, out, &m), EZ_OK);
	EZ_CHECK_EQ(a->d->ks.mutations, m0);                 /* SEC-AVAIL-001 */
	/* the same unit in both copies: no copy verifies */
	f(a, 1, 0x202, "KEY")->data[25000] ^= 0x01;
	f(a, 2, 0x202, "KEY")->data[25000] ^= 0x01;
	EZ_CHECK_EQ(dev_encrypt(a->d, sa, pt, 10000, ct, &n), EZ_ERR_KEY_DAMAGED);
	DEV_KBUF_CLEAR(a->d);
	dev_free(b);
	mfree(a);
}

/* IMPL-AV-004: check reports damage per copy; repair rebuilds each damaged
 * copy from units that verify; afterwards both copies are clean and equal
 * to the original. Unrecoverable units are reported, not invented. */
static void t_check_repair(void)
{
	mdev_t *x = mnew(4);
	dev_put_key(x->d, 1, 0x303, 65536, 6);
	static uint8_t k0[65536];
	memcpy(k0, f(x, 1, 0x303, "KEY")->data, 65536);
	int s = msession(x, 0x303, EZ_ROLE_ALICE);
	memset(f(x, 1, 0x303, "KEY")->data + 8192, 0, 4096);         /* unit 2 in copy 0 */
	f(x, 2, 0x303, "SUM")->data[EZ_SUM_HDR + 8 * 5] ^= 1;        /* a tag in copy 1 */
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK_EQ(ck.lost, 0);
	EZ_CHECK_EQ(ck.copy[0].bad, 1);
	EZ_CHECK_EQ(ck.copy[1].bad, 0);          /* its unit 5 verifies against copy 0's tag */
	uint8_t rep;
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
	EZ_CHECK_EQ(rep, 1);
	EZ_CHECK(!memcmp(f(x, 1, 0x303, "KEY")->data, k0, 65536));
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(ck.copy[0].bad == 0 && ck.copy[1].bad == 0 && ck.lost == 0);
	/* a copy missing entirely */
	char n[EZ_FNAME_MAX];
	ez_key_name(0x303, "KEY", n);
	EZ_CHECK_EQ(x->d->ks.hal.zap(&x->d->ks, 2, n), EZ_OK);
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(!ck.copy[1].has_key && ck.copy[1].bad == ck.units);
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
	EZ_CHECK(!memcmp(f(x, 2, 0x303, "KEY")->data, k0, 65536));
	/* lost in both: reported, nothing rewritten */
	f(x, 1, 0x303, "KEY")->data[100] ^= 1;
	f(x, 2, 0x303, "KEY")->data[100] ^= 1;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK_EQ(ck.lost, 1);
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_ERR_KEY_DAMAGED);
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

/* SEC-PTR-004 with copies: deletion erases every copy. With one copy
 * unreachable, deletion does not skip it: it waits (intent) and completes
 * when the copy is back. */
static void t_delete_all_copies(void)
{
	mdev_t *x = mnew(5);
	dev_put_key(x->d, 1, 0x404, 16384, 7);
	int s = msession(x, 0x404, EZ_ROLE_ALICE);
	EZ_CHECK(f(x, 2, 0x404, "KEY") != NULL);
	sim_ks_remove(&x->d->ks, 2);                          /* copy 1's volume unreadable */
	EZ_CHECK(ez_session_delete(&x->d->c, s, false) != EZ_OK);
	EZ_CHECK(ez_core_intent_pending(&x->d->c));
	sim_ks_insert(&x->d->ks, 2);
	mboot(x);                                             /* resumes */
	EZ_CHECK_EQ(x->d->c.meta.s[s].state, EZ_SS_EMPTY);
	for (uint8_t v = 1; v <= 2; v++) {
		EZ_CHECK(f(x, v, 0x404, "KEY") == NULL);
		EZ_CHECK(f(x, v, 0x404, "SUM") == NULL);
	}
	mfree(x);
}

/* Power lost (the card pulled) at every storage call of a replication:
 * copy 0 is never damaged by it, the next mount removes the partial copy,
 * the key is usable, and repair completes the mirror. */
static void t_replication_interrupted(void)
{
	mdev_t *x = mnew(6);
	dev_put_key(x->d, 1, 0x505, 16384, 8);
	static uint8_t k0[16384];
	memcpy(k0, f(x, 1, 0x505, "KEY")->data, sizeof k0);
	uint8_t fr[EZ_META_SIZE];
	memcpy(fr, x->d->fram.mem, sizeof fr);
	int cut, total = 0;
	for (cut = 0; ; cut++) {
		memcpy(x->d->fram.mem, fr, sizeof fr);
		char n[EZ_FNAME_MAX];
		const char *ext[] = { "KEY", "SUM", "TMP", "SUT" };
		for (int e = 0; e < 4; e++) { ez_key_name(0x505, ext[e], n); x->d->ks.hal.zap(&x->d->ks, 2, n); }
		mboot(x);
		sim_ks_remove_after(&x->d->ks, 2, cut);
		int s = -1;
		ez_session_create(&x->d->c, 0x505, 1, EZ_ROLE_ALICE, "x", &s);
		bool complete = x->d->c.last_replicate == EZ_OK;
		sim_ks_insert(&x->d->ks, 2);
		mboot(x);                                         /* mount: cleanup in every copy */
		EZ_CHECK(!memcmp(f(x, 1, 0x505, "KEY")->data, k0, sizeof k0));
		EZ_CHECK(f(x, 2, 0x505, "TMP") == NULL && f(x, 2, 0x505, "SUT") == NULL);
		if (s >= 0) {
			uint32_t on;
			EZ_CHECK_EQ(dev_encrypt(x->d, s, pt, 100, ct, &on), EZ_OK);
			uint8_t rep;
			EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
			ez_check_t ck;
			EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
			EZ_CHECK(ck.copy[1].has_key && ck.copy[1].bad == 0);
		}
		total++;
		if (complete) break;
		EZ_CHECK(cut < 2000);
	}
	ez_test_note("replication interrupted at %d points", total);
	mfree(x);
}

/* IMPL-KEY-005 across copies (found by the mirrored chaos run): a
 * different key under the same Key ID, with a valid .SUM of its own, in
 * copy 1 must never be used when copy 0's unit is damaged -- its tags match
 * its own data, but its instance does not match the session's. */
static void t_other_instance_in_copy(void)
{
	mdev_t *x = mnew(7);
	dev_put_key(x->d, 1, 0x606, 16384, 9);
	int s = msession(x, 0x606, EZ_ROLE_ALICE);
	static uint8_t other[16384];
	sim_fill(other, sizeof other, 1234);
	char n[EZ_FNAME_MAX];
	ez_key_name(0x606, "KEY", n);
	sim_ks_put(&x->d->ks, 2, n, other, sizeof other);
	put_sum(&x->d->ks, 2, 0x606, other, sizeof other, 0x0BAD);   /* valid, other instance */
	f(x, 1, 0x606, "KEY")->data[10] ^= 0x01;                     /* unit 0 of copy 0 */
	uint32_t on;
	EZ_CHECK_EQ(dev_encrypt(x->d, s, pt, 100, ct, &on), EZ_ERR_KEY_DAMAGED);
	EZ_CHECK_EQ(x->d->c.failovers, 0);
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(!ck.copy[1].has_key);                   /* reported as not this key */
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

/* IMPL-AV-005: a critical key is also kept on drive 0. It serves units
 * that fail in every card copy, rebuilds a lost card, and is erased with
 * the session. Without a usable drive 0 the session still exists, and
 * the missing copy is reported. */
static void t_critical(void)
{
	mdev_t *x = mnew(8);
	dev_put_key(x->d, 1, 0x707, 16384, 10);
	static uint8_t k0[16384];
	memcpy(k0, f(x, 1, 0x707, "KEY")->data, sizeof k0);
	int s = -1;
	/* drive 0 disabled: created, but no drive 0 copy */
	EZ_CHECK_EQ(ez_session_create_flags(&x->d->c, 0x707, 1, EZ_ROLE_ALICE, "c", EZ_SESS_CRITICAL, &s), EZ_OK);
	EZ_CHECK_EQ(x->d->c.last_critical, EZ_ERR_DRIVE_DISABLED);
	EZ_CHECK(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL);
	EZ_CHECK_EQ(ez_session_delete(&x->d->c, s, false), EZ_OK);
	dev_put_key(x->d, 1, 0x707, 16384, 10);
	EZ_CHECK_EQ(ez_drive_enable0(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(ez_session_create_flags(&x->d->c, 0x707, 1, EZ_ROLE_ALICE, "c", EZ_SESS_CRITICAL, &s), EZ_OK);
	EZ_CHECK_EQ(x->d->c.last_critical, EZ_OK);
	EZ_CHECK(f(x, 0, 0x707, "KEY") && !memcmp(f(x, 0, 0x707, "KEY")->data, k0, sizeof k0));
	EZ_CHECK(f(x, 0, 0x707, "SUM") != NULL);
	/* the same unit damaged in both card copies: served from drive 0 */
	f(x, 1, 0x707, "KEY")->data[100] ^= 1;
	f(x, 2, 0x707, "KEY")->data[100] ^= 1;
	uint32_t n;
	EZ_CHECK_EQ(dev_encrypt(x->d, s, pt, 200, ct, &n), EZ_OK);
	EZ_CHECK_EQ(x->d->c.failovers, 1);
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(ck.lost == 0 && ck.critical && ck.d0_state == 2);
	uint8_t rep;
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
	EZ_CHECK_EQ(rep, 2);                                 /* both card copies rewritten */
	/* the whole card lost: a new, empty card; repair rebuilds it from drive 0 */
	for (uint8_t v = 1; v <= 2; v++) {
		const char *ext[2] = { "KEY", "SUM" };
		for (int e = 0; e < 2; e++) {
			char nm[EZ_FNAME_MAX];
			ez_key_name(0x707, ext[e], nm);
			x->d->ks.hal.zap(&x->d->ks, v, nm);
		}
	}
	mboot(x);                                            /* the new card: key missing */
	EZ_CHECK_EQ(x->d->c.meta.s[s].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
	EZ_CHECK(!memcmp(f(x, 1, 0x707, "KEY")->data, k0, sizeof k0));
	EZ_CHECK(!memcmp(f(x, 2, 0x707, "KEY")->data, k0, sizeof k0));
	EZ_CHECK_EQ(ez_session_resolve(&x->d->c, s), EZ_OK);
	EZ_CHECK_EQ(x->d->c.meta.s[s].tx_off, 200);          /* the offsets were never lost */
	EZ_CHECK_EQ(dev_encrypt(x->d, s, pt, 100, ct, &n), EZ_OK);
	/* deletion erases every copy, drive 0 included */
	EZ_CHECK_EQ(ez_session_delete(&x->d->c, s, false), EZ_OK);
	for (uint8_t v = 0; v <= 2; v++) EZ_CHECK(f(x, v, 0x707, "KEY") == NULL);
	EZ_CHECK(f(x, 0, 0x707, "SUM") == NULL);
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

/* A copy whose volume is unavailable is skipped by repair, not an error:
 * the other copies are repaired, and check reports the missing volume. */
static void t_repair_unavailable_copy(void)
{
	mdev_t *x = mnew(9);
	dev_put_key(x->d, 1, 0x808, 16384, 11);
	int s = msession(x, 0x808, EZ_ROLE_ALICE);
	f(x, 1, 0x808, "KEY")->data[50] ^= 1;               /* copy 0 damaged */
	sim_ks_remove(&x->d->ks, 2);                         /* copy 1's volume gone */
	uint8_t rep;
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_ERR_KEY_DAMAGED);   /* unit 0 now in no copy */
	f(x, 1, 0x808, "KEY")->data[50] ^= 1;
	EZ_CHECK_EQ(ez_session_repair(&x->d->c, s, &rep), EZ_OK);
	EZ_CHECK_EQ(rep, 0);
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(ck.copy[0].bad == 0 && !ck.copy[1].present);
	sim_ks_insert(&x->d->ks, 2);
	mfree(x);
}

/* Round 16: ez_sync brings a mirrored drive to a nominal state by itself,
 * and reports what it cannot fix as degraded. */
static void t_sync(void)
{
	mdev_t *x = mnew(12);
	dev_put_key(x->d, 1, 0x909, 16384, 13);
	int s = msession(x, 0x909, EZ_ROLE_ALICE);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	/* a damaged unit in copy 0, then copy 1's key gone: each repaired.
	 * (Both at once would lose that unit: no copy would have it.) */
	f(x, 1, 0x909, "KEY")->data[300] ^= 1;
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	char n[EZ_FNAME_MAX];
	ez_key_name(0x909, "KEY", n);
	x->d->ks.hal.zap(&x->d->ks, 2, n);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	/* both at once: that unit is lost, and the sync says so */
	f(x, 1, 0x909, "KEY")->data[300] ^= 1;
	x->d->ks.hal.zap(&x->d->ks, 2, n);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_DEGRADED);
	EZ_CHECK(x->d->c.health_detail & EZ_HD_LOST);
	f(x, 1, 0x909, "KEY")->data[300] ^= 1;               /* undo, for the rest of the test */
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	ez_check_t ck;
	EZ_CHECK_EQ(ez_session_check(&x->d->c, s, &ck), EZ_OK);
	EZ_CHECK(ck.copy[0].has_key && !ck.copy[0].bad && ck.copy[1].has_key && !ck.copy[1].bad);
	/* "key missing" quarantine lifted once the key is back */
	EZ_CHECK_EQ(ez_meta_quarantine(&x->d->c.meta, s, EZ_Q_KEY_MISSING), EZ_OK);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.meta.s[s].state, EZ_SS_VALID);
	/* other quarantine reasons are left for the user */
	EZ_CHECK_EQ(ez_meta_quarantine(&x->d->c.meta, s, 0x02), EZ_OK);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.meta.s[s].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(ez_session_resolve(&x->d->c, s), EZ_OK);
	/* copy 1's volume unavailable: degraded */
	sim_ks_remove(&x->d->ks, 2);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_DEGRADED);
	EZ_CHECK(x->d->c.health_detail & EZ_HD_VOLUME);
	sim_ks_insert(&x->d->ks, 2);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	/* a critical key with drive 0 disabled: degraded (no critical copy) */
	EZ_CHECK_EQ(ez_session_delete(&x->d->c, s, false), EZ_OK);
	dev_put_key(x->d, 1, 0x90A, 16384, 14);
	EZ_CHECK_EQ(ez_session_create_flags(&x->d->c, 0x90A, 1, EZ_ROLE_ALICE, "c", EZ_SESS_CRITICAL, &s), EZ_OK);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_DEGRADED);
	EZ_CHECK(x->d->c.health_detail & EZ_HD_NO_CRITICAL);
	/* drive 0 enabled: the sync writes the critical copy and is nominal */
	EZ_CHECK_EQ(ez_drive_enable0(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_OK);
	EZ_CHECK_EQ(x->d->c.health, EZ_HEALTH_OK);
	EZ_CHECK(f(x, 0, 0x90A, "KEY") != NULL);
	/* yield: stops at a checkpoint */
	volatile bool y = true;
	x->d->c.yield = &y;
	EZ_CHECK_EQ(ez_sync(&x->d->c), EZ_ERR_BUSY);
	x->d->c.yield = NULL;
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

/* Device erase reaches every copy: a file only in copy 1 (an interrupted
 * replication) is erased too. */
static void t_erase_every_copy(void)
{
	mdev_t *x = mnew(13);
	dev_put_key(x->d, 1, 0xA0A, 8192, 15);
	static uint8_t k[8192];
	sim_fill(k, sizeof k, 3);
	char n[EZ_FNAME_MAX];
	ez_key_name(0xB0B, "KEY", n);
	sim_ks_put(&x->d->ks, 2, n, k, sizeof k);            /* copy 1 only */
	EZ_CHECK_EQ(ez_device_erase(&x->d->c), EZ_OK);
	EZ_CHECK(f(x, 1, 0xA0A, "KEY") == NULL);
	EZ_CHECK(f(x, 2, 0xB0B, "KEY") == NULL);
	mfree(x);
}

/* Round 20: critical can be turned on and off. On: drive 0's copy, then
 * the flag; off: the flag, then the copy is erased. The flag survives a
 * reboot (toggle bitmap), and a new session in the slot starts clear. */
static void t_critical_toggle(void)
{
	mdev_t *x = mnew(14);
	EZ_CHECK_EQ(ez_drive_enable0(&x->d->c), EZ_OK);
	dev_put_key(x->d, 1, 0xC0C, 16384, 16);
	int s = msession(x, 0xC0C, EZ_ROLE_ALICE);
	EZ_CHECK(!(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL));
	EZ_CHECK_EQ(ez_session_set_critical(&x->d->c, s, true), EZ_OK);
	EZ_CHECK(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL);
	EZ_CHECK(f(x, 0, 0xC0C, "KEY") && f(x, 0, 0xC0C, "SUM"));
	mboot(x);
	EZ_CHECK(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL);          /* persisted */
	EZ_CHECK_EQ(ez_session_set_critical(&x->d->c, s, false), EZ_OK);
	EZ_CHECK(!(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL));
	EZ_CHECK(f(x, 0, 0xC0C, "KEY") == NULL && f(x, 0, 0xC0C, "SUM") == NULL);
	mboot(x);
	EZ_CHECK(!(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL));
	/* created critical, turned off: the toggle undoes the record's flag */
	EZ_CHECK_EQ(ez_session_delete(&x->d->c, s, false), EZ_OK);
	dev_put_key(x->d, 1, 0xC0D, 16384, 17);
	EZ_CHECK_EQ(ez_session_create_flags(&x->d->c, 0xC0D, 1, EZ_ROLE_ALICE, "c", EZ_SESS_CRITICAL, &s), EZ_OK);
	EZ_CHECK_EQ(ez_session_set_critical(&x->d->c, s, false), EZ_OK);
	mboot(x);
	EZ_CHECK(!(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL));
	/* deleted and recreated in the same slot: starts from the new record */
	EZ_CHECK_EQ(ez_session_delete(&x->d->c, s, false), EZ_OK);
	dev_put_key(x->d, 1, 0xC0E, 16384, 18);
	EZ_CHECK_EQ(ez_session_create_flags(&x->d->c, 0xC0E, 1, EZ_ROLE_ALICE, "c", EZ_SESS_CRITICAL, &s), EZ_OK);
	mboot(x);
	EZ_CHECK(x->d->c.meta.s[s].flags & EZ_SESS_CRITICAL);
	/* a key on drive 0 cannot be its own copy; drive 0 off: refused */
	EZ_CHECK_EQ(ez_session_set_critical(&x->d->c, 99, true), EZ_ERR_BAD_REQUEST);
	DEV_KBUF_CLEAR(x->d);
	mfree(x);
}

static const ez_test_case_t cases[] = {
	{ "replicate",                "SEC-AVAIL-003, SEC-AVAIL-004", t_replicate },
	{ "failover",                 "IMPL-AV-003, SEC-AVAIL-001, SEC-STORE-004", t_failover },
	{ "check_repair",             "IMPL-AV-004", t_check_repair },
	{ "delete_all_copies",        "SEC-PTR-004, IMPL-INT-001", t_delete_all_copies },
	{ "other_instance_in_copy",   "IMPL-KEY-005, SEC-STORE-004 (copies)", t_other_instance_in_copy },
	{ "critical",                 "IMPL-AV-005, SEC-AVAIL-003, SEC-PTR-004", t_critical },
	{ "repair_unavailable_copy",  "IMPL-AV-004", t_repair_unavailable_copy },
	{ "erase_every_copy",         "SEC-PTR-004 across copies", t_erase_every_copy },
	{ "critical_toggle",          "round 20: critical on/off", t_critical_toggle },
	{ "sync",                     "round 16: automatic mirror maintenance", t_sync },
	{ "replication_interrupted",  "SEC-AVAIL-004, IMPL-GEN-001", t_replication_interrupted },
};
EZ_TEST_MAIN(cases)
