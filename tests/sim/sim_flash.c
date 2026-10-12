/* sim_flash.c -- see sim_flash.h */
#include "sim_flash.h"

#include <stdlib.h>
#include <string.h>

static bool op_allowed(sim_flash_t *f, bool *torn)
{
	*torn = false;
	if (f->off) return false;
	if (f->budget == 0) {
		*torn = true;
		f->off = true;
		if (f->fram) f->fram->off = true;
		return true;
	}
	if (f->budget > 0) f->budget--;
	return true;
}

static ez_status_t rd(void *ctx, uint32_t addr, void *buf, uint32_t len)
{
	sim_flash_t *f = ctx;
	if (f->off || (uint64_t)addr + len > (uint64_t)f->blocks * EZ_FLASH_BLOCK) return EZ_ERR_MEDIA;
	memcpy(buf, f->mem + addr, len);
	return EZ_OK;
}

static ez_status_t er(void *ctx, uint32_t block)
{
	sim_flash_t *f = ctx;
	bool torn;
	if (block >= f->blocks || !op_allowed(f, &torn)) return EZ_ERR_MEDIA;
	memset(f->mem + (size_t)block * EZ_FLASH_BLOCK, 0xFF, torn ? EZ_FLASH_BLOCK / 2 : EZ_FLASH_BLOCK);
	f->erases++;
	f->erase_count[block]++;
	return torn ? EZ_ERR_MEDIA : EZ_OK;
}

static ez_status_t pg(void *ctx, uint32_t addr, const void *buf, uint32_t len)
{
	sim_flash_t *f = ctx;
	bool torn;
	if ((uint64_t)addr + len > (uint64_t)f->blocks * EZ_FLASH_BLOCK || !op_allowed(f, &torn))
		return EZ_ERR_MEDIA;
	const uint8_t *p = buf;
	uint32_t n = torn ? len / 2 : len;
	for (uint32_t i = 0; i < n; i++) f->mem[addr + i] &= p[i];      /* NOR: clear bits only */
	f->programs++;
	return torn ? EZ_ERR_MEDIA : EZ_OK;
}

void sim_flash_init(sim_flash_t *f, uint32_t blocks)
{
	memset(f, 0, sizeof *f);
	f->blocks = blocks;
	f->mem = malloc((size_t)blocks * EZ_FLASH_BLOCK);
	memset(f->mem, 0xFF, (size_t)blocks * EZ_FLASH_BLOCK);
	f->erase_count = calloc(blocks, sizeof *f->erase_count);
	f->budget = -1;
	f->fl = (ez_flash_t){ f, blocks, rd, er, pg };
}

void sim_flash_free(sim_flash_t *f) { free(f->mem); free(f->erase_count); f->mem = NULL; }
void sim_flash_arm_cut(sim_flash_t *f, long ops) { f->budget = ops; }

void sim_flash_power_on(sim_flash_t *f)
{
	f->off = false;
	f->budget = -1;
	if (f->fram) sim_fram_power_on(f->fram);
}

bool sim_flash_contains(const sim_flash_t *f, const uint8_t *p, size_t n)
{
	size_t total = (size_t)f->blocks * EZ_FLASH_BLOCK;
	for (size_t i = 0; i + n <= total; i++)
		if (f->mem[i] == p[0] && memcmp(f->mem + i, p, n) == 0) return true;
	return false;
}
