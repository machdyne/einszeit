/*
 * fuzz_store0.c -- libFuzzer: arbitrary drive 0 flash contents and F-RAM
 * selector through the store's mount-time validation, then listing and
 * reading whatever it accepted.
 */
#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_meta.h"
#include "ez_store0.h"
#include "sim_flash.h"
#include "sim_fram.h"

#define BLOCKS 64u

static sim_flash_t fl;
static sim_fram_t fr;
static ez_store0_t st;
static uint8_t rb[4096];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
	if (!fl.mem) { sim_flash_init(&fl, BLOCKS); sim_fram_init(&fr, 0x00); }
	if (n < 1) return 0;
	size_t total = (size_t)BLOCKS * EZ_FLASH_BLOCK;
	memset(fl.mem, 0xFF, total);
	memcpy(fl.mem, data + 1, n - 1 < total ? n - 1 : total);
	/* Most of the time, give both table copies a valid CRC so the fuzzer
	 * reaches the entry and chain validation behind it. */
	if (data[0] & 1)
		for (int t = 0; t < 2; t++) {
			uint8_t *b = fl.mem + (size_t)t * EZ_FLASH_BLOCK;
			memcpy(b, "EZD0", 4);
			b[4] = 1;
			ez_put_le32(b + 12, BLOCKS - 2);
			ez_put_le32(b + EZ_FLASH_BLOCK - 4, ez_crc32(b, EZ_FLASH_BLOCK - 4));
		}
	/* selector: one of the valid codes most of the time */
	fr.mem[EZ_META_STORE0_SEL] = data[0] < 128 ? 0x5A : data[0] < 250 ? 0xA5 : data[0];
	if (ez_store0_init(&st, &fl.fl, &fr.hal, EZ_META_STORE0_SEL) != EZ_OK) return 0;
	const ez_hal_keystore_t *h = &st.hal;
	char name[EZ_NAME_MAX];
	uint32_t size;
	for (uint32_t i = 0; h->list(h->ctx, 0, i, name, &size) == EZ_OK; i++)
		for (uint32_t o = 0; o < size; o += sizeof rb)
			if (h->read(h->ctx, 0, name, o, rb, size - o < sizeof rb ? size - o : (uint32_t)sizeof rb) != EZ_OK) break;
	return 0;
}
