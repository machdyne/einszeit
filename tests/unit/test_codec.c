/*
 * test_codec.c -- message header and base64.
 *
 * EZ-SEC-001: SEC-ENC-004 (offset in header), SEC-TX-002 (header layout),
 * SEC-DEC-002 (Key ID carried); EZ-IMPL-001 §5.
 */
#include <stdlib.h>
#include <string.h>

#include "ez_base64.h"
#include "ez_msg.h"
#include "ez_test.h"
#include "sim_trng.h"

static void t_header_roundtrip(void)
{
	ez_msg_hdr_t h = { 0xA73F2C01, 0x00100000, 4242 }, g;
	uint8_t b[EZ_MSG_HDR];
	ez_msg_hdr_encode(&h, b);
	static const uint8_t want[16] = { 0x5A, 0x45, 0x01, 0x00, 0x01, 0x2C, 0x3F, 0xA7,
	                                  0x00, 0x00, 0x10, 0x00, 0x92, 0x10, 0x00, 0x00 };
	EZ_CHECK(memcmp(b, want, 16) == 0);
	EZ_CHECK_EQ(ez_msg_hdr_decode(b, &g), EZ_OK);
	EZ_CHECK(g.key_id == h.key_id && g.offset == h.offset && g.length == h.length);
}

static void t_header_rejects(void)
{
	ez_msg_hdr_t h = { 7, 100, 10 }, g;
	uint8_t b[EZ_MSG_HDR], x[EZ_MSG_HDR];
	ez_msg_hdr_encode(&h, b);
	for (int i = 0; i < 4; i++) {           /* magic, version, flags */
		memcpy(x, b, sizeof x);
		x[i] ^= 0x01;
		EZ_CHECK_EQ(ez_msg_hdr_decode(x, &g), EZ_ERR_BAD_REQUEST);
	}
	h.key_id = 0;
	ez_msg_hdr_encode(&h, x);
	EZ_CHECK_EQ(ez_msg_hdr_decode(x, &g), EZ_ERR_BAD_REQUEST);
	h.key_id = 7; h.offset = 0xFFFFFFF0u; h.length = 0x20;
	ez_msg_hdr_encode(&h, x);
	EZ_CHECK_EQ(ez_msg_hdr_decode(x, &g), EZ_ERR_BAD_REQUEST);   /* overflow */
}

/* RFC 4648 §10 test vectors */
static void t_b64_rfc4648(void)
{
	static const char *in[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
	static const char *out[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
	for (int i = 0; i < 7; i++) {
		char e[16];
		size_t n = ez_b64_encode((const uint8_t *)in[i], strlen(in[i]), e);
		EZ_CHECK_EQ(n, strlen(out[i]));
		EZ_CHECK(memcmp(e, out[i], n) == 0);
		ez_b64_dec_t d; uint8_t dec[16]; size_t dn;
		ez_b64_dec_init(&d);
		EZ_CHECK_EQ(ez_b64_dec_update(&d, out[i], strlen(out[i]), dec, &dn), EZ_OK);
		EZ_CHECK_EQ(ez_b64_dec_final(&d), EZ_OK);
		EZ_CHECK_EQ(dn, strlen(in[i]));
		EZ_CHECK(memcmp(dec, in[i], dn) == 0);
	}
}

static void t_b64_incremental(void)
{
	enum { N = 5000 };
	static uint8_t data[N], dec[N + 8];
	static char enc[N * 2], enc2[N * 2];
	sim_fill(data, N, 77);
	for (size_t len = 0; len < 64; len++) {
		size_t n1 = ez_b64_encode(data, len, enc);
		/* incremental encoder, odd piece sizes */
		ez_b64_enc_t e; size_t o = 0;
		ez_b64_enc_init(&e);
		for (size_t i = 0; i < len; i += 1 + (i % 4)) {
			size_t p = len - i < 1 + (i % 4) ? len - i : 1 + (i % 4);
			o += ez_b64_enc_update(&e, data + i, p, enc2 + o);
		}
		o += ez_b64_enc_final(&e, enc2 + o);
		EZ_CHECK_EQ(o, n1);
		EZ_CHECK(memcmp(enc, enc2, o) == 0);
	}
	size_t n = ez_b64_encode(data, N, enc);
	/* decode in pieces of every size 1..13, with line breaks inserted */
	for (size_t piece = 1; piece <= 13; piece++) {
		ez_b64_dec_t d; size_t out = 0, dn;
		ez_b64_dec_init(&d);
		for (size_t i = 0; i < n; i += piece) {
			size_t p = n - i < piece ? n - i : piece;
			EZ_CHECK_EQ(ez_b64_dec_update(&d, enc + i, p, dec + out, &dn), EZ_OK);
			out += dn;
			EZ_CHECK_EQ(ez_b64_dec_update(&d, "\r\n", 2, dec + out, &dn), EZ_OK);
		}
		EZ_CHECK_EQ(ez_b64_dec_final(&d), EZ_OK);
		EZ_CHECK_EQ(out, N);
		EZ_CHECK(memcmp(dec, data, N) == 0);
	}
}

static void t_b64_rejects(void)
{
	static const char *bad[] = { "Zg=", "Z===", "Zm9v!", "Zg==Zg==", "Zh==", "Zm9=",
	                             "=Zm9", "Zm8=x", "Zg=a" };
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		ez_b64_dec_t d; uint8_t o[16]; size_t n;
		ez_b64_dec_init(&d);
		ez_status_t a = ez_b64_dec_update(&d, bad[i], strlen(bad[i]), o, &n);
		ez_status_t b = ez_b64_dec_final(&d);
		EZ_CHECK_MSG(a != EZ_OK || b != EZ_OK, bad[i]);
	}
}

static const ez_test_case_t cases[] = {
	{ "header_roundtrip", "SEC-ENC-004, SEC-TX-002, IMPL §5", t_header_roundtrip },
	{ "header_rejects",   "SEC-DEC-002, IMPL §5", t_header_rejects },
	{ "b64_rfc4648",      "IMPL §5", t_b64_rfc4648 },
	{ "b64_incremental",  "IMPL §5", t_b64_incremental },
	{ "b64_rejects",      "IMPL §5", t_b64_rejects },
};
EZ_TEST_MAIN(cases)
