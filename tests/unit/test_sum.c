/*
 * test_sum.c -- SHA-256 and the integrity-tag format (EZ-IMPL-001 §2.4).
 *
 * EZ-SEC-001: SEC-STORE-004 (tags bound to Key ID and position).
 */
#include <stdlib.h>
#include <string.h>

#include "ez_sha256.h"
#include "ez_sum.h"
#include "ez_test.h"
#include "sim_trng.h"

static void hex(const uint8_t *d, char *out)
{
	for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

/* FIPS 180-4 / NIST CAVS vectors (digests from Python hashlib). */
static void t_sha256_vectors(void)
{
	static const struct { const char *m; const char *d; } v[] = {
		{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	};
	uint8_t d[32];
	char h[65];
	for (unsigned i = 0; i < 3; i++) {
		ez_sha256_t s;
		ez_sha256_init(&s);
		ez_sha256_update(&s, v[i].m, strlen(v[i].m));
		ez_sha256_final(&s, d);
		hex(d, h);
		EZ_CHECK_MSG(strcmp(h, v[i].d) == 0, v[i].m);
	}
	/* one million 'a', fed in odd pieces */
	ez_sha256_t s;
	ez_sha256_init(&s);
	static char a[1000];
	memset(a, 'a', sizeof a);
	for (int i = 0, k = 1; i < 1000000; i += k, k = k % 997 + 1)
		ez_sha256_update(&s, a, (size_t)(1000000 - i < k ? 1000000 - i : k));
	ez_sha256_final(&s, d);
	hex(d, h);
	EZ_CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
}

static void t_geometry(void)
{
	/* 8704-byte key: halves of 4352 = one full unit + 256 each. */
	EZ_CHECK_EQ(ez_units_per_half(8704), 2);
	EZ_CHECK_EQ(ez_unit_count(8704), 4);
	EZ_CHECK_EQ(ez_sum_size(8704), 32 + 32);
	uint32_t st, len;
	ez_unit_geom(8704, 0, &st, &len); EZ_CHECK(st == 0 && len == 4096);
	ez_unit_geom(8704, 1, &st, &len); EZ_CHECK(st == 4096 && len == 256);
	ez_unit_geom(8704, 2, &st, &len); EZ_CHECK(st == 4352 && len == 4096);
	ez_unit_geom(8704, 3, &st, &len); EZ_CHECK(st == 8448 && len == 256);
	EZ_CHECK_EQ(ez_unit_index(8704, 4351), 1);
	EZ_CHECK_EQ(ez_unit_index(8704, 4352), 2);           /* never straddles halves */
	EZ_CHECK_EQ(ez_unit_index(8704, 8703), 3);
	/* Every byte of many key sizes maps to exactly one unit, in order. */
	static const uint32_t sizes[] = { 2, 4096, 8192, 8194, 12290, 65536, 100002 };
	for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
		uint32_t L = sizes[k], covered = 0;
		for (uint32_t i = 0; i < ez_unit_count(L); i++) {
			ez_unit_geom(L, i, &st, &len);
			EZ_CHECK_EQ(st, covered);
			EZ_CHECK(len > 0 && len <= EZ_UNIT_SIZE);
			EZ_CHECK(st >= L / 2 || st + len <= L / 2);
			EZ_CHECK_EQ(ez_unit_index(L, st), i);
			EZ_CHECK_EQ(ez_unit_index(L, st + len - 1), i);
			covered += len;
		}
		EZ_CHECK_EQ(covered, L);
	}
}

/* The tag binds Key ID, key length and position. */
static void t_tag_binding(void)
{
	uint8_t u[4096], t0[8], t1[8];
	sim_fill(u, sizeof u, 1);
	ez_unit_tag(7, 65536, 3, u, sizeof u, t0);
	ez_unit_tag(7, 65536, 3, u, sizeof u, t1);
	EZ_CHECK(memcmp(t0, t1, 8) == 0);
	ez_unit_tag(8, 65536, 3, u, sizeof u, t1);  EZ_CHECK(memcmp(t0, t1, 8) != 0);
	ez_unit_tag(7, 65538, 3, u, sizeof u, t1);  EZ_CHECK(memcmp(t0, t1, 8) != 0);
	ez_unit_tag(7, 65536, 4, u, sizeof u, t1);  EZ_CHECK(memcmp(t0, t1, 8) != 0);
	u[100] ^= 1;
	ez_unit_tag(7, 65536, 3, u, sizeof u, t1);  EZ_CHECK(memcmp(t0, t1, 8) != 0);
}

/* The incremental tagger equals the one-shot tag, for any piece size. */
static void t_tagger(void)
{
	static uint8_t k[20000];
	sim_fill(k, sizeof k, 2);
	for (uint32_t piece = 1; piece < 600; piece += 37) {
		ez_tagger_t t;
		ez_tagger_init(&t, 99, sizeof k);
		uint32_t got = 0;
		for (uint32_t o = 0; o < sizeof k;) {
			bool done; uint32_t idx; uint8_t tag[8];
			uint32_t n = sizeof k - o < piece ? sizeof k - o : piece;
			o += ez_tagger_feed(&t, k + o, n, &done, &idx, tag);
			if (done) {
				uint32_t st, len; uint8_t want[8];
				EZ_CHECK_EQ(idx, got);
				ez_unit_geom(sizeof k, idx, &st, &len);
				ez_unit_tag(99, sizeof k, idx, k + st, len, want);
				EZ_CHECK(memcmp(tag, want, 8) == 0);
				got++;
			}
		}
		EZ_CHECK_EQ(got, ez_unit_count(sizeof k));
		ez_tagger_clear(&t);
	}
}

static void t_header(void)
{
	ez_sum_hdr_t h = { 0xA73F2C01, 65536, ez_unit_count(65536), 0xBEEF }, g;
	uint8_t b[EZ_SUM_HDR], x[EZ_SUM_HDR];
	ez_sum_hdr_encode(&h, b);
	EZ_CHECK_EQ(ez_sum_hdr_decode(b, &g), EZ_OK);
	EZ_CHECK(g.key_id == h.key_id && g.key_len == h.key_len && g.tags == h.tags && g.instance == 0xBEEF);
	for (unsigned i = 0; i < EZ_SUM_HDR; i++) {
		memcpy(x, b, sizeof x);
		x[i] ^= 0x04;
		EZ_CHECK_EQ(ez_sum_hdr_decode(x, &g), EZ_ERR_KEY_DAMAGED);
	}
	h.tags++;
	ez_sum_hdr_encode(&h, b);
	EZ_CHECK_EQ(ez_sum_hdr_decode(b, &g), EZ_ERR_KEY_DAMAGED);  /* count must match length */
}

static const ez_test_case_t cases[] = {
	{ "sha256_vectors", "SEC-STORE-004 (primitive)", t_sha256_vectors },
	{ "geometry",       "SEC-STORE-004, SEC-ISO-001 (units never straddle halves)", t_geometry },
	{ "tag_binding",    "SEC-STORE-004", t_tag_binding },
	{ "tagger",         "SEC-STORE-004", t_tagger },
	{ "header",         "SEC-STORE-004, IMPL-KEY-005", t_header },
};
EZ_TEST_MAIN(cases)
