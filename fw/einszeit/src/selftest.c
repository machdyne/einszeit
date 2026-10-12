/*
 * selftest.c -- on-target known-answer test (SEC-TEST-ENC-001 on the real
 * CPU and compiler). Runs the unchanged core over RAM-only HALs: a 2 KB RAM
 * metadata store and a two-file RAM key store holding the KAT key and its
 * .SUM. No TRNG is involved. The vectors are those of tests/unit/test_engine.c,
 * computed independently in Python.
 */
#include <stdio.h>
#include <string.h>

#include "ez_core.h"
#include "ez_engine.h"
#include "ez_secure.h"
#include "ez_sum.h"
#include "selftest.h"

#include "kat_vectors.inc"

#define KAT_ID 0x0000BEEFu
static const char KAT_PT[] = "Einszeit KAT 01";

/* ---- RAM metadata ---- */
static uint8_t ram_meta[2048];
static ez_status_t m_rd(void *c, uint32_t a, void *b, uint32_t n)
{ (void)c; if (a > 2048 || n > 2048 - a) return EZ_ERR_META; memcpy(b, ram_meta + a, n); return EZ_OK; }
static ez_status_t m_wr(void *c, uint32_t a, const void *b, uint32_t n)
{ (void)c; if (a > 2048 || n > 2048 - a) return EZ_ERR_META; memcpy(ram_meta + a, b, n); return EZ_OK; }
static const ez_hal_meta_t meta = { NULL, 2048, m_rd, m_wr };

/* ---- RAM key store: two fixed files on drive 1 ---- */
static uint8_t f_key[1024], f_sum[EZ_SUM_HDR + 8 * 2];
static uint32_t key_len, sum_len;
static int is(const char *n, const char *ext) { return strlen(n) == 12 && strcmp(n + 8, ext) == 0; }
static uint8_t *file(const char *n, uint32_t **len)
{
	if (is(n, ".KEY")) { *len = &key_len; return f_key; }
	if (is(n, ".SUM")) { *len = &sum_len; return f_sum; }
	return NULL;
}
static bool k_present(void *c, uint8_t d) { (void)c; return d == 1; }
static ez_status_t k_check(void *c, uint8_t d) { (void)c; return d == 1 ? EZ_OK : EZ_ERR_MEDIA_REMOVED; }
static ez_status_t k_size(void *c, uint8_t d, const char *n, uint32_t *s)
{
	(void)c;
	uint32_t *l;
	if (d != 1 || !file(n, &l) || !*l) return EZ_ERR_NOT_FOUND;
	*s = *l;
	return EZ_OK;
}
static ez_status_t k_read(void *c, uint8_t d, const char *n, uint32_t o, void *b, uint32_t len)
{
	(void)c;
	uint32_t *l;
	uint8_t *f = d == 1 ? file(n, &l) : NULL;
	if (!f || !*l) return EZ_ERR_NOT_FOUND;
	if ((uint64_t)o + len > *l) return EZ_ERR_RANGE;
	memcpy(b, f + o, len);
	return EZ_OK;
}
static ez_status_t k_none(void *c, uint8_t d, const char *n) { (void)c; (void)d; (void)n; return EZ_ERR_UNSUPPORTED; }
static ez_status_t k_app(void *c, uint8_t d, const char *n, const void *b, uint32_t l)
{ (void)c; (void)d; (void)n; (void)b; (void)l; return EZ_ERR_UNSUPPORTED; }
static ez_status_t k_ren(void *c, uint8_t d, const char *a, const char *b)
{ (void)c; (void)d; (void)a; (void)b; return EZ_ERR_UNSUPPORTED; }
static ez_status_t k_list(void *c, uint8_t d, uint32_t i, char n[EZ_NAME_MAX], uint32_t *s)
{ (void)c; (void)d; (void)i; (void)n; (void)s; return EZ_ERR_NOT_FOUND; }
static ez_status_t k_wipe(void *c, uint8_t d) { (void)c; (void)d; return EZ_OK; }
static const ez_hal_keystore_t ks = { NULL, k_present, k_check, k_size, k_read, k_none, k_app,
                                      k_ren, k_none, k_list, k_wipe, NULL };
static ez_status_t t_none(void *c, void *b, uint32_t l) { (void)c; (void)b; (void)l; return EZ_ERR_ENTROPY; }
static const ez_hal_trng_t trng = { NULL, 0, t_none };

static void load_key(void)
{
	for (int i = 0; i < 1024; i++) f_key[i] = (uint8_t)(i * 7 + 3 + (i >> 8) * 13);
	key_len = 1024;
	ez_sum_hdr_t h = { KAT_ID, 1024, ez_unit_count(1024), 0x4B41 };
	ez_sum_hdr_encode(&h, f_sum);
	for (uint32_t i = 0; i < ez_unit_count(1024); i++) {
		uint32_t s, l;
		ez_unit_geom(1024, i, &s, &l);
		ez_unit_tag(KAT_ID, 1024, i, f_key + s, l, f_sum + EZ_SUM_HDR + 8 * i);
	}
	sum_len = ez_sum_size(1024);
}

static int fresh(ez_core_t *c, uint8_t *stage, uint8_t role)
{
	memset(ram_meta, 0xFF, sizeof ram_meta);
	load_key();
	if (ez_core_init(c, &meta, &ks, &trng, stage, EZ_STAGE_SIZE) != EZ_OK) return -1;
	if (ez_device_erase(c) != EZ_OK) return -1;
	if (ez_core_init(c, &meta, &ks, &trng, stage, EZ_STAGE_SIZE) != EZ_OK) return -1;
	int slot = -1;
	if (ez_session_create(c, KAT_ID, 1, role, role == EZ_ROLE_ALICE ? "bob" : "alice", &slot) != EZ_OK)
		return -1;
	return slot;
}

#define FAIL(...) do { printf("KAT FAIL: " __VA_ARGS__); printf("\n"); ok = false; goto out; } while (0)

bool selftest_kat(ez_core_t *c, uint8_t *stage)
{
	bool ok = true;
	const uint8_t *o; uint32_t n;
	int s = fresh(c, stage, EZ_ROLE_ALICE);
	if (s < 0) FAIL("alice setup");
	for (int k = 0; k < 2; k++) {
		uint8_t *p = ez_stage_plaintext(c, 15);
		memcpy(p, KAT_PT, 15);
		if (ez_encrypt_buffered(c, s, 15, &o, &n) != EZ_OK) FAIL("alice encrypt %d", k);
		if (n != 35 || memcmp(o, k ? KAT_ALICE_2 : KAT_ALICE_1, 35) != 0) FAIL("alice vector %d", k + 1);
		ez_release(c);
	}
	s = fresh(c, stage, EZ_ROLE_BOB);
	if (s < 0) FAIL("bob setup");
	uint8_t *p = ez_stage_message(c, 35);
	memcpy(p, KAT_ALICE_1, 35);
	if (ez_decrypt_buffered(c, s, 35, &o, &n) != EZ_OK || n != 15 || memcmp(o, KAT_PT, 15) != 0)
		FAIL("bob decrypt");
	ez_release(c);
	p = ez_stage_plaintext(c, 15);
	memcpy(p, KAT_PT, 15);
	if (ez_encrypt_buffered(c, s, 15, &o, &n) != EZ_OK || memcmp(o, KAT_BOB_1, 35) != 0)
		FAIL("bob vector");
	ez_release(c);
out:
	ez_secure_zero(f_key, sizeof f_key);
	ez_secure_zero(f_sum, sizeof f_sum);
	ez_secure_zero(ram_meta, sizeof ram_meta);
	return ok;
}
