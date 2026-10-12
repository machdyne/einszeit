/*
 * test_chaos.c -- the perfect-secrecy invariant under arbitrary storage
 * misbehaviour.
 *
 * EZ-SEC-001 SEC-TEST-STORE-002: two devices (alice, bob) exchange
 * messages over a long randomised run while their cards misbehave:
 *   - persistent corruption of key files: zeroed or 0xFF runs, bit flips,
 *     a 4 KiB block copied from elsewhere in the same key, a block copied
 *     from an unrelated key file;
 *   - corruption of the integrity file (tags or header);
 *   - the whole card replaced by a different key under the same Key ID,
 *     with its own valid integrity file; later the right card is back;
 *   - transient read errors (one read returns a flipped bit);
 *   - the card removed before any storage call of an operation;
 *   - power lost at any byte of an F-RAM write;
 *   - reboots, replayed and reordered messages.
 *
 * The test knows the true key. After every operation it checks the
 * ORACLE, which is the invariant itself:
 *   1. every ciphertext byte that left a device equals the plaintext byte
 *      XOR the TRUE key byte at its position, within that device's TX half;
 *   2. no key position is ever output in two messages (no reuse, across
 *      both devices, reboots, failures and skips);
 *   3. every decryption that reports success returns the original
 *      plaintext.
 * A single violation fails the test with the seed and step.
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_bytes.h"
#include "ez_ks_mirror.h"

#define KID    0x0C4A0500u
#define OTHER  0x0BADBEEFu
#define KLEN   (4u << 20)
#define HALF   (KLEN / 2)
#define QMAX   24
#define MSGMAX 2400

static uint8_t truekey[KLEN];
static uint8_t used[KLEN];
static char    keyname[EZ_FNAME_MAX], sumname[EZ_FNAME_MAX];
static uint8_t truesum[EZ_SUM_HDR + 8 * 2048];
static uint32_t sumlen;

typedef struct {
	int     to;                  /* 0: for alice, 1: for bob */
	uint32_t len;
	uint8_t pt[MSGMAX], msg[MSGMAX + EZ_MSG_OVERHEAD];
} qmsg_t;
static qmsg_t q[QMAX];
static int nq;

static struct stats {
	unsigned long enc_ok, enc_stream_partial, enc_refused_damage, enc_other_fail,
	              skips, dec_ok, dec_refused, bytes_checked, corruptions, steps;
} st;

static uint64_t rs;
static uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
	return (uint32_t)(rs >> 11);
}
static uint32_t rnd_n(uint32_t n) { return n ? rnd() % n : 0; }

/* ORACLE 1 and 2, applied to bytes the moment a device hands them out. */
static void oracle_output(int who, uint32_t off, const uint8_t *pt, const uint8_t *ct, uint32_t n)
{
	uint32_t lo = who == 0 ? 0 : HALF, hi = who == 0 ? HALF : KLEN;
	EZ_CHECK_MSG(off >= lo && (uint64_t)off + n <= hi, "output outside the sender's TX half");
	for (uint32_t i = 0; i < n; i++) {
		EZ_CHECK_MSG((uint8_t)(ct[i] ^ pt[i]) == truekey[off + i],
		             "ciphertext not made with the true key byte");
		EZ_CHECK_MSG(used[off + i] == 0, "key position used twice (reuse)");
		used[off + i] = 1;
	}
	st.bytes_checked += n;
}

static ezdev_t *dev[2];
static int slot[2];
static bool last_damaged[2];

/* Mirrored runs (SEC-AVAIL-003): the "card" is two volumes, sim drives 1
 * (copy 0) and 2 (copy 1) of logical drive 1. */
static bool mirrored;
static ez_ks_mirror_t mir[2];

static void boot(int who)
{
	sim_fram_power_on(&dev[who]->fram);
	sim_ks_clear_faults(&dev[who]->ks);
	ez_core_init(&dev[who]->c, &dev[who]->fram.hal, mirrored ? &mir[who].hal : &dev[who]->ks.hal,
	             &dev[who]->trng.hal, dev[who]->stage, sizeof dev[who]->stage);
}

static void restore_card(int who)
{
	for (uint8_t v = 1; v <= (mirrored ? 2 : 1); v++) {
		sim_ks_put(&dev[who]->ks, v, keyname, truekey, KLEN);
		sim_ks_put(&dev[who]->ks, v, sumname, truesum, sumlen);
	}
}

static void enqueue(int to, const uint8_t *pt, uint32_t len, const uint8_t *msg)
{
	qmsg_t *m = &q[nq < QMAX ? nq++ : (int)rnd_n(QMAX)];
	m->to = to;
	m->len = len;
	memcpy(m->pt, pt, len);
	memcpy(m->msg, msg, len + EZ_MSG_OVERHEAD);
}

static void op_encrypt_(int who);
static void op_encrypt(int who)
{
	unsigned long m0 = dev[who]->ks.mutations;
	op_encrypt_(who);
	EZ_CHECK_MSG(dev[who]->ks.mutations == m0, "encryption wrote to key storage (SEC-AVAIL-001)");
}
static void op_encrypt_(int who)
{
	ezdev_t *d = dev[who];
	uint32_t len = 1 + rnd_n(MSGMAX);
	uint8_t pt[MSGMAX], msg[MSGMAX + EZ_MSG_OVERHEAD];
	for (uint32_t i = 0; i < len; i++) pt[i] = (uint8_t)rnd();
	ez_status_t r;
	if (rnd() & 1) {                                          /* buffered */
		uint8_t *p = ez_stage_plaintext(&d->c, len);
		memcpy(p, pt, len);
		const uint8_t *o; uint32_t n;
		r = ez_encrypt_buffered(&d->c, slot[who], len, &o, &n);
		if (r == EZ_OK) {
			EZ_CHECK_EQ(n, len + EZ_MSG_OVERHEAD);
			oracle_output(who, ez_get_le32(o + 8), pt, o + EZ_MSG_HDR, len);
			memcpy(msg, o, n);
			enqueue(1 - who, pt, len, msg);
		}
		ez_release(&d->c);
	} else {                                                  /* streaming */
		ez_stream_t s;
		uint32_t chunk = 1 + rnd_n(300), done = 0;
		r = ez_enc_stream_begin(&d->c, &s, slot[who], len, msg);
		uint32_t base = ez_get_le32(msg + 8);
		while (r == EZ_OK && done < len) {
			uint32_t c = len - done < chunk ? len - done : chunk;
			uint8_t *b = msg + EZ_MSG_HDR + done;
			memcpy(b, pt + done, c);
			r = ez_enc_stream_update(&d->c, &s, b, c);
			if (r == EZ_OK) {
				oracle_output(who, base + done, pt + done, b, c);   /* handed out */
				done += c;
			} else {
				EZ_CHECK_MSG(ez_is_zero(b, c), "failed chunk not cleared");
			}
		}
		if (r == EZ_OK) {
			r = ez_enc_stream_end(&d->c, &s, msg + EZ_MSG_HDR + len);
			if (r == EZ_OK) enqueue(1 - who, pt, len, msg);
		} else if (done) {
			st.enc_stream_partial++;
		}
	}
	if (r == EZ_OK) st.enc_ok++;
	else if (r == EZ_ERR_KEY_DAMAGED) {
		st.enc_refused_damage++;
		last_damaged[who] = true;
		if (rnd() & 1) {                       /* the user confirms the skip at once */
			uint32_t units;
			if (ez_session_skip(&d->c, slot[who], &units) == EZ_OK) st.skips++;
		}
	}
	else st.enc_other_fail++;
	DEV_KBUF_CLEAR(d);
}

static void op_deliver_(void);
static void op_deliver(void)
{
	unsigned long m0 = dev[0]->ks.mutations + dev[1]->ks.mutations;
	op_deliver_();
	EZ_CHECK_MSG(dev[0]->ks.mutations + dev[1]->ks.mutations == m0, "decryption wrote to key storage (SEC-AVAIL-001)");
}
static void op_deliver_(void)
{
	if (!nq) return;
	int i = (int)rnd_n((uint32_t)nq);
	qmsg_t *m = &q[i];
	ezdev_t *d = dev[m->to];
	static uint8_t out[MSGMAX];
	uint32_t n = 0;
	uint32_t total = m->len + EZ_MSG_OVERHEAD;
	ez_status_t r = (rnd() & 1) ? dev_decrypt(d, (rnd() & 1) ? slot[m->to] : -1, m->msg, total, out, &n)
	                            : dev_decrypt_stream(d, -1, m->msg, total, 1 + rnd_n(200), out, &n);
	if (r == EZ_OK) {
		EZ_CHECK_EQ(n, m->len);
		EZ_CHECK_MSG(memcmp(out, m->pt, m->len) == 0, "decryption reported success with wrong plaintext");
		st.dec_ok++;
	} else {
		st.dec_refused++;
	}
	if (rnd_n(4)) q[i] = q[--nq];                 /* sometimes keep it for a replay */
	DEV_KBUF_CLEAR(d);
}

static void corrupt(int who)
{
	uint8_t vol = mirrored ? (uint8_t)(1 + (rnd() & 1)) : 1;     /* either copy */
	sim_file_t *f = sim_ks_get(&dev[who]->ks, vol, keyname);
	sim_file_t *s = sim_ks_get(&dev[who]->ks, vol, sumname);
	sim_file_t *o = sim_ks_get(&dev[who]->ks, 1, "0BADBEEF.KEY");
	if (!f || !s || !o) return;
	uint32_t pos = rnd_n(KLEN - 8192);
	/* Half the time, damage what this device is about to use next. */
	uint32_t ahead = dev[who]->c.meta.s[slot[who]].tx_off + rnd_n(8192);
	if ((rnd() & 1) && ahead < KLEN - 8192) pos = ahead;
	uint32_t kind = rnd_n(20);
	if (kind >= 8) kind = rnd_n(5);           /* whole-card faults are rarer */
	switch (kind) {
	case 0: memset(f->data + pos, 0, 1 + rnd_n(300)); break;
	case 1: memset(f->data + pos, 0xFF, 4096); break;
	case 2: for (int k = 0; k < 1 + (int)rnd_n(5); k++) f->data[rnd_n(KLEN)] ^= (uint8_t)(1u << rnd_n(8)); break;
	case 3: memcpy(f->data + (pos & ~4095u), f->data + (rnd_n(KLEN - 4096) & ~4095u), 4096); break;
	case 4: memcpy(f->data + pos, o->data + rnd_n(o->len - 4096), 4096); break;
	case 5: s->data[EZ_SUM_HDR + rnd_n(s->len - EZ_SUM_HDR)] ^= (uint8_t)(1u << rnd_n(8)); break;
	case 6: s->data[rnd_n(EZ_SUM_HDR)] ^= 0x10; break;
	case 7: {                     /* a different key under the same ID, with a valid .SUM */
		static uint8_t other[KLEN];
		sim_fill(other, KLEN, rnd());
		sim_ks_put(&dev[who]->ks, 1, keyname, other, KLEN);
		put_sum(&dev[who]->ks, 1, KID, other, KLEN, (uint16_t)rnd());
		break;
	}
	}
	st.corruptions++;
}

static void reboot(int who)
{
	sim_ks_insert(&dev[who]->ks, 1);
	sim_ks_insert(&dev[who]->ks, 2);
	boot(who);
	/* A quarantined session (e.g. its .SUM header was damaged when the
	 * card was mounted) is resolved once the right card is back. */
	if (dev[who]->c.meta.s[slot[who]].state == EZ_SS_QUARANTINED &&
	    dev[who]->c.meta.s[slot[who]].qreason < 0x80) {
		restore_card(who);
		ez_session_resolve(&dev[who]->c, slot[who]);
	}
}

static void run(uint64_t seed, unsigned steps)
{
	rs = seed * 0x9E3779B97F4A7C15ull + 1;
	memset(used, 0, sizeof used);
	memset(&st, 0, sizeof st);
	nq = 0;
	sim_fill(truekey, KLEN, seed);
	ez_key_name(KID, "KEY", keyname);
	ez_key_name(KID, "SUM", sumname);
	dev[0] = dev_new(seed + 1);
	dev[1] = dev_new(seed + 2);
	for (int w = 0; w < 2; w++) {
		ez_mirror_vol_t v[2] = { { &dev[w]->ks.hal, 1 }, { &dev[w]->ks.hal, 2 } };
		ez_ks_mirror_init(&mir[w], &dev[w]->ks.hal, 1, v, 2);
		boot(w);
	}
	sim_ks_put(&dev[0]->ks, 1, keyname, truekey, KLEN);
	put_sum(&dev[0]->ks, 1, KID, truekey, KLEN, 0x7E57);
	sim_file_t *sf = sim_ks_get(&dev[0]->ks, 1, sumname);
	sumlen = sf->len;
	memcpy(truesum, sf->data, sumlen);
	restore_card(1);
	for (int w = 0; w < 2; w++) dev_put_key(dev[w], 1, OTHER, 65536, seed + 9);
	slot[0] = dev_session(dev[0], KID, 1, EZ_ROLE_ALICE, "bob");
	slot[1] = dev_session(dev[1], KID, 1, EZ_ROLE_BOB, "alice");

	for (unsigned step = 0; step < steps; step++) {
		st.steps++;
		int who = (int)(rnd() & 1);
		uint32_t a = rnd_n(100);
		if (a < 30) op_encrypt(who);
		else if (a < 55) op_deliver();
		else if (a < 61) corrupt(who);
		else if (a < 66) restore_card(who);                    /* the right card is back */
		else if (a < 71) { sim_ks_corrupt_reads(&dev[who]->ks, 1 + rnd_n(3)); op_encrypt(who); }
		else if (a < 76) { long n = (long)rnd_n(40); sim_ks_remove_after(&dev[who]->ks, 1, n); sim_ks_remove_after(&dev[who]->ks, 2, n); op_encrypt(who); reboot(who); }
		else if (a < 80) { long n = (long)rnd_n(40); sim_ks_remove_after(&dev[who]->ks, 1, n); sim_ks_remove_after(&dev[who]->ks, 2, n); op_deliver(); reboot(who); }
		else if (a < 85) { sim_fram_arm_cut(&dev[who]->fram, (long)rnd_n(24)); op_encrypt(who); reboot(who); }
		else if (a < 88) reboot(who);
		else if (last_damaged[who]) {                           /* user confirms the skip */
			uint32_t units;
			if (ez_session_skip(&dev[who]->c, slot[who], &units) == EZ_OK) st.skips++;
			last_damaged[who] = false;
		}
		sim_ks_corrupt_reads(&dev[who]->ks, 0);
		EZ_CHECK(dev[who]->ks.dirty_reads == 0);
	}
	ez_test_note("seed %llu: %lu steps, %lu encryptions (%lu refused as damaged, %lu other "
	             "failures, %lu streams cut part-way), %lu skips, %lu decryptions ok, %lu refused, "
	             "%lu corruptions; %lu ciphertext bytes checked against the true key",
	             (unsigned long long)seed, st.steps, st.enc_ok, st.enc_refused_damage,
	             st.enc_other_fail, st.enc_stream_partial, st.skips, st.dec_ok, st.dec_refused,
	             st.corruptions, st.bytes_checked);
	dev_free(dev[0]);
	dev_free(dev[1]);
}

static unsigned long refused_single, ok_single;

static void t_chaos(void)
{
	struct stats total = { 0 };
	mirrored = false;
	for (uint64_t seed = 1; seed <= 4; seed++) {
		run(seed, 3000);
		total.enc_ok += st.enc_ok;
		total.enc_refused_damage += st.enc_refused_damage;
		total.enc_stream_partial += st.enc_stream_partial;
		total.skips += st.skips;
		total.dec_ok += st.dec_ok;
		total.bytes_checked += st.bytes_checked;
	}
	/* The runs must have exercised what they claim to. */
	EZ_CHECK(total.enc_ok > 1000 && total.enc_refused_damage > 100 &&
	         total.enc_stream_partial > 50 && total.skips > 20 &&
	         total.dec_ok > 300 && total.bytes_checked > 2000000);
	refused_single = total.enc_refused_damage;
	ok_single = total.enc_ok;
}

/* The same runs with every key kept as two copies: the oracle must hold
 * (secrecy), and far fewer encryptions may be refused (availability). */
static void t_chaos_mirror(void)
{
	struct stats total = { 0 };
	mirrored = true;
	for (uint64_t seed = 1; seed <= 4; seed++) {
		run(seed, 3000);
		total.enc_ok += st.enc_ok;
		total.enc_refused_damage += st.enc_refused_damage;
		total.dec_ok += st.dec_ok;
		total.bytes_checked += st.bytes_checked;
	}
	mirrored = false;
	ez_test_note("refused as damaged: %lu with one copy, %lu with two; encryptions ok: %lu vs %lu",
	             refused_single, total.enc_refused_damage, ok_single, total.enc_ok);
	EZ_CHECK(total.bytes_checked > 2000000);
	if (refused_single) EZ_CHECK(total.enc_refused_damage * 2 < refused_single);
}

static const ez_test_case_t cases[] = {
	{ "chaos", "SEC-TEST-STORE-002, SEC-STORE-004, SEC-PTR-002, SEC-PTR-003, SEC-HW-002, SEC-AVAIL-001", t_chaos },
	{ "chaos_mirror", "SEC-TEST-STORE-002 with copies, SEC-AVAIL-003, SEC-AVAIL-001", t_chaos_mirror },
};
EZ_TEST_MAIN(cases)
