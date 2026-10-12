/*
 * test_media.c -- removable media during operations, and power loss during
 * streaming encryption.
 *
 * EZ-SEC-001:
 *   SEC-TEST-MEDIA-001 (a) buffered encryption: removal before the commit
 *                      -> no ciphertext, no offset change
 *                      (b) streaming encryption: every byte output is
 *                      covered by a committed TX offset; no rollback; no
 *                      output after the failure
 *                      (c) decryption: RX offset not advanced
 *   SEC-HW-002         removal (and card swap) detected and not continued
 *   SEC-PTR-003        no output before a verified commit (power-cut sweep)
 *
 * Method: count the HAL calls an operation makes on the key drive, then
 * repeat it with the card removed (or swapped) before every one of them.
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_secure.h"

#define KID 0x5EC0u
static uint8_t pt[8192], out[16384], dec[16384];

static ezdev_t *setup(int *slot, uint8_t role, uint64_t seed)
{
	ezdev_t *d = dev_new(seed);
	dev_put_key(d, 1, KID, 1u << 22, 42);      /* 4 MiB: room for every sweep */
	*slot = dev_session(d, KID, 1, role, "m");
	sim_fill(pt, sizeof pt, seed);
	return d;
}

/* The number of HAL calls an operation makes depends on how its key range
 * aligns to blocks, so the sweeps do not measure it in advance: the fault
 * position k increases until the operation completes, and the completing
 * run must have used at most k calls (the fault was never reached). */
#define SWEEP_MAX 2000

/* ------------------------------------------------------------ (a) -- */
static void fault_sweep_buffered(int swap)
{
	int slot;
	ezdev_t *d = setup(&slot, EZ_ROLE_ALICE, 1);
	unsigned long k;
	for (k = 0; k < SWEEP_MAX; k++) {
		uint32_t tx = d->c.meta.s[slot].tx_off;
		if (swap) sim_ks_swap_after(&d->ks, 1, (long)k);
		else      sim_ks_remove_after(&d->ks, 1, (long)k);
		unsigned long before = d->ks.d[1].calls;
		uint8_t *p = ez_stage_plaintext(&d->c, 3000);
		memcpy(p, pt, 3000);
		const uint8_t *o; uint32_t n;
		ez_status_t st = ez_encrypt_buffered(&d->c, slot, 3000, &o, &n);
		unsigned long used = d->ks.d[1].calls - before;
		DEV_KBUF_CLEAR(d);
		if (st == EZ_OK) {
			EZ_CHECK_MSG(used <= k, "completed although the fault was reached");
			EZ_CHECK_EQ(d->c.meta.s[slot].tx_off, tx + 3000);
			break;
		}
		EZ_CHECK_MSG(st == EZ_ERR_MEDIA_REMOVED, "fault before the commit not detected");
		EZ_CHECK_MSG(o == NULL && n == 0, "output despite failure");
		EZ_CHECK_MSG(ez_is_zero(d->stage, sizeof d->stage), "staging not wiped");
		EZ_CHECK_MSG(d->c.meta.s[slot].tx_off == tx, "offset advanced without output");
		/* Re-insert (a new mount) and reboot: persisted state agrees. */
		sim_ks_insert(&d->ks, 1);
		dev_reboot(d);
		EZ_CHECK_EQ(d->c.meta.s[slot].tx_off, tx);
		EZ_CHECK_EQ(d->c.meta.s[slot].state, EZ_SS_VALID);
	}
	EZ_CHECK(k > 3 && k < SWEEP_MAX);
	ez_test_note("%s: fault injected before each of %lu HAL calls", swap ? "swap" : "removal", k);
	dev_free(d);
}

static void t_buffered_removal(void) { fault_sweep_buffered(0); }
static void t_buffered_swap(void)    { fault_sweep_buffered(1); }

/* ------------------------------------------------------------ (b) -- */
static void t_streaming_removal(void)
{
	int slot;
	ezdev_t *d = setup(&slot, EZ_ROLE_BOB, 2);
	const uint32_t len = 2000, chunk = 58;
	unsigned long k;
	for (k = 0; k < SWEEP_MAX; k++) {
		uint32_t base = d->c.meta.s[slot].tx_off;
		sim_ks_remove_after(&d->ks, 1, (long)k);
		unsigned long before = d->ks.d[1].calls;
		ez_stream_t s;
		uint8_t hdr[16];
		uint32_t output = 0;
		ez_status_t st = ez_enc_stream_begin(&d->c, &s, slot, len, hdr);
		while (st == EZ_OK && output < len) {
			uint32_t c = len - output < chunk ? len - output : chunk;
			uint8_t buf[64];
			memcpy(buf, pt + output, c);
			st = ez_enc_stream_update(&d->c, &s, buf, c);
			if (st == EZ_OK) {
				output += c;          /* the caller outputs this chunk */
				/* Invariant at the moment of output (SEC-PTR-003). */
				EZ_CHECK(d->c.meta.s[slot].tx_off >= base + output);
			} else {
				EZ_CHECK_MSG(ez_is_zero(buf, c), "failed chunk not cleared");
			}
		}
		unsigned long used = d->ks.d[1].calls - before;
		if (st == EZ_OK) {
			EZ_CHECK_MSG(used <= k, "completed although the fault was reached");
			uint8_t trl[4];
			EZ_CHECK_EQ(ez_enc_stream_end(&d->c, &s, trl), EZ_OK);
			break;
		}
		EZ_CHECK_EQ(st, EZ_ERR_MEDIA_REMOVED);
		/* No output after the failure: the stream is dead. */
		uint8_t again[8] = {0};
		EZ_CHECK(ez_enc_stream_update(&d->c, &s, again, 1) != EZ_OK);
		/* Spent exactly what was output (IMPL-ENG-005). */
		EZ_CHECK_EQ(d->c.meta.s[slot].tx_off, base + output);
		EZ_CHECK_EQ(ez_stream_spent(&s), output);
		sim_ks_insert(&d->ks, 1);
		dev_reboot(d);
		EZ_CHECK_MSG(d->c.meta.s[slot].tx_off == base + output, "rollback after reboot");
	}
	EZ_CHECK(k > 30 && k < SWEEP_MAX);
	ez_test_note("removal injected before each of %lu HAL calls", k);
	dev_free(d);
}

/* SEC-PTR-003 under power loss: cut the F-RAM at every byte of a streamed
 * encryption. Whatever had been handed out must be covered after reboot. */
static void t_streaming_powercut(void)
{
	int slot;
	ezdev_t *d = setup(&slot, EZ_ROLE_ALICE, 3);
	const uint32_t len = 290, chunk = 29;    /* 10 commits */
	for (long cut = 0; cut <= 10 * 7 + 2; cut++) {   /* 7 bytes per commit */
		uint32_t base = d->c.meta.s[slot].tx_off;
		sim_fram_arm_cut(&d->fram, cut);
		ez_stream_t s;
		uint8_t hdr[16];
		uint32_t output = 0;
		ez_status_t st = ez_enc_stream_begin(&d->c, &s, slot, len, hdr);
		while (st == EZ_OK && output < len) {
			uint8_t buf[64];
			memcpy(buf, pt + output, chunk);
			st = ez_enc_stream_update(&d->c, &s, buf, chunk);
			if (st == EZ_OK) output += chunk;
		}
		if (st == EZ_OK) ez_stream_abort(&d->c, &s);
		dev_reboot(d);
		uint32_t now = d->c.meta.s[slot].tx_off;
		EZ_CHECK_EQ(d->c.meta.s[slot].state, EZ_SS_VALID);
		EZ_CHECK_MSG(now >= base + output, "output not covered after power loss");
		EZ_CHECK_MSG(now <= base + output + chunk, "more than one commit unit lost");
	}
	dev_free(d);
}

/* ------------------------------------------------------------ (c) -- */
static void t_decrypt_removal(void)
{
	int sa;
	ezdev_t *a = setup(&sa, EZ_ROLE_ALICE, 4);
	uint32_t n, m;
	EZ_CHECK_EQ(dev_encrypt(a, sa, pt, 4000, out, &n), EZ_OK);
	for (int mode = 0; mode < 2; mode++) {
		unsigned long k;
		for (k = 0; k < SWEEP_MAX; k++) {
			ezdev_t *c = dev_new(6);
			dev_copy_key(a, c, 1, KID);
			int sc = dev_session(c, KID, 1, EZ_ROLE_BOB, "a");
			sim_ks_remove_after(&c->ks, 1, (long)k);
			unsigned long before = c->ks.d[1].calls;
			ez_status_t st = mode ? dev_decrypt_stream(c, sc, out, n, 100, dec, &m)
			                      : dev_decrypt(c, sc, out, n, dec, &m);
			unsigned long used = c->ks.d[1].calls - before;
			if (st == EZ_OK) {
				EZ_CHECK(used <= k);
				EZ_CHECK(memcmp(dec, pt, 4000) == 0);
				EZ_CHECK_EQ(c->c.meta.s[sc].rx_off, 4000);
				dev_free(c);
				break;
			}
			EZ_CHECK_MSG(st == EZ_ERR_MEDIA_REMOVED, "removal not detected");
			EZ_CHECK_MSG(c->c.meta.s[sc].rx_off == 0, "RX advanced on failed decryption");
			if (!mode) EZ_CHECK(ez_is_zero(c->stage, sizeof c->stage));
			sim_ks_insert(&c->ks, 1);
			dev_reboot(c);
			EZ_CHECK_EQ(c->c.meta.s[sc].rx_off, 0);
			/* The interrupted message can still be decrypted. */
			EZ_CHECK_EQ(dev_decrypt(c, sc, out, n, dec, &m), EZ_OK);
			EZ_CHECK(memcmp(dec, pt, 4000) == 0);
			dev_free(c);
		}
		EZ_CHECK(k > 3 && k < SWEEP_MAX);
	}
	dev_free(a);
}

/* A card absent from the start: refused before anything happens. */
static void t_absent(void)
{
	int slot;
	ezdev_t *d = setup(&slot, EZ_ROLE_ALICE, 7);
	sim_ks_remove(&d->ks, 1);
	uint32_t n;
	EZ_CHECK_EQ(dev_encrypt(d, slot, pt, 10, out, &n), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(dev_encrypt_stream(d, slot, pt, 10, 5, out, &n), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(d->c.meta.s[slot].tx_off, 0);
	/* Boot without the card: the session is not quarantined (its file is
	 * not missing, the card is). */
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.s[slot].state, EZ_SS_VALID);
	sim_ks_insert(&d->ks, 1);
	EZ_CHECK_EQ(ez_core_media_event(&d->c, 1), EZ_OK);
	EZ_CHECK_EQ(dev_encrypt(d, slot, pt, 10, out, &n), EZ_OK);
	dev_free(d);
}

static const ez_test_case_t cases[] = {
	{ "buffered_removal",   "SEC-TEST-MEDIA-001 (a), SEC-HW-002, IMPL-ENG-003, IMPL-ENG-010", t_buffered_removal },
	{ "buffered_swap",      "SEC-TEST-MEDIA-001 (a), SEC-HW-002, IMPL-ENG-010", t_buffered_swap },
	{ "streaming_removal",  "SEC-TEST-MEDIA-001 (b), SEC-HW-002, IMPL-ENG-004, IMPL-ENG-005", t_streaming_removal },
	{ "streaming_powercut", "SEC-PTR-003, SEC-ENC-002, SEC-TEST-PTR-001", t_streaming_powercut },
	{ "decrypt_removal",    "SEC-TEST-MEDIA-001 (c), SEC-DEC-004, IMPL-ENG-006", t_decrypt_removal },
	{ "absent",             "SEC-HW-002", t_absent },
};
EZ_TEST_MAIN(cases)
