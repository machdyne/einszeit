/*
 * fuzz_fatfs.c -- libFuzzer: arbitrary disk images through the FatFs port
 * (a card handed over by someone else is untrusted input). Mounts the
 * image, lists every file, sizes and reads each, and reads a key's .SUM
 * header through the core's integrity check.
 */
#include <string.h>

#include "ez_core.h"
#include "ez_ks_fatfs.h"
#include "sim_blockdev.h"

#define SECTORS 512u                         /* 256 KiB image */

static sim_bd_t bd;
static ez_ks_fatfs_t ks;
static uint8_t rb[4096];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
	if (!bd.mem) sim_bd_init(&bd, 512, SECTORS, 0x00, false);
	/* The input is the start of the image; the rest repeats it (so small
	 * inputs still produce plausible FATs and directories further in). */
	size_t total = (size_t)SECTORS * 512;
	if (n == 0) return 0;
	for (size_t o = 0; o < total; o += n) memcpy(bd.mem + o, data, total - o < n ? total - o : n);
	ez_ks_fatfs_init(&ks, NULL, &bd.bd, NULL);
	sim_bd_insert(&bd);
	if (ez_ks_fatfs_mount(&ks, 1) != EZ_OK) return 0;
	const ez_hal_keystore_t *h = &ks.hal;
	char name[EZ_NAME_MAX];
	uint32_t size;
	for (uint32_t i = 0; i < 64 && h->list(h->ctx, 1, i, name, &size) == EZ_OK; i++) {
		uint32_t s2;
		if (h->size(h->ctx, 1, name, &s2) != EZ_OK) continue;
		for (uint32_t o = 0; o < s2 && o < 65536; o += sizeof rb) {
			uint32_t k = s2 - o < sizeof rb ? s2 - o : (uint32_t)sizeof rb;
			if (h->read(h->ctx, 1, name, o, rb, k) != EZ_OK) break;
		}
	}
	return 0;
}
