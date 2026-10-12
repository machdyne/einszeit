/*
 * fuzz_message.c -- libFuzzer: arbitrary input as a received message:
 * base64 (in random-sized pieces) or raw, then buffered and streaming
 * decryption against a live session. Must never crash, and must never
 * release plaintext for a message whose CRC fails (checked by the engine
 * tests; here: memory safety of every path).
 */
#include <string.h>

#include "core_fixture.h"
#include "ez_base64.h"
#include "ez_engine.h"

static ezdev_t *dev;
static uint8_t buf[EZ_STAGE_SIZE + 64], out[EZ_STAGE_SIZE + 64];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
	if (!dev) {
		dev = dev_new(3);
		dev_put_key(dev, 1, 0xBEEF, 65536, 4);
		int s;
		ez_session_create(&dev->c, 0xBEEF, 1, EZ_ROLE_BOB, "a", &s);
	}
	if (n == 0 || n > EZ_STAGE_SIZE) return 0;
	size_t m = n;
	const uint8_t *msg = data;
	if (data[0] != 0x5A) {                    /* treat as base64, fed in pieces */
		ez_b64_dec_t d;
		ez_b64_dec_init(&d);
		m = 0;
		for (size_t o = 0; o < n;) {
			size_t k = (data[o] % 7) + 1, got = 0;
			if (k > n - o) k = n - o;
			if (ez_b64_dec_update(&d, (const char *)data + o, k, buf + m, &got) != EZ_OK) return 0;
			m += got;
			o += k;
		}
		if (ez_b64_dec_final(&d) != EZ_OK || m == 0) return 0;
		msg = buf;
	}
	uint8_t *p = ez_stage_message(&dev->c, (uint32_t)m);
	if (p) {
		memcpy(p, msg, m);
		const uint8_t *pt;
		uint32_t pn;
		ez_decrypt_buffered(&dev->c, -1, (uint32_t)m, &pt, &pn);
	}
	ez_release(&dev->c);
	/* streaming, in 13-byte chunks */
	uint32_t got = 0;
	dev_decrypt_stream(dev, -1, msg, (uint32_t)m, 13, out, &got);
	return 0;
}
