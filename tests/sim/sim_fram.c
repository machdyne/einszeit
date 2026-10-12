/* sim_fram.c -- see sim_fram.h */
#include "sim_fram.h"

#include <string.h>

static ez_status_t f_read(void *ctx, uint32_t addr, void *buf, uint32_t len)
{
	sim_fram_t *f = (sim_fram_t *)ctx;
	if (f->off || addr > EZ_META_SIZE || len > EZ_META_SIZE - addr)
		return EZ_ERR_META;
	memcpy(buf, f->mem + addr, len);
	return EZ_OK;
}

static ez_status_t f_write(void *ctx, uint32_t addr, const void *buf, uint32_t len)
{
	sim_fram_t *f = (sim_fram_t *)ctx;
	if (f->off || addr > EZ_META_SIZE || len > EZ_META_SIZE - addr)
		return EZ_ERR_META;
	const uint8_t *p = (const uint8_t *)buf;
	for (uint32_t i = 0; i < len; i++) {        /* ascending, byte-atomic */
		if (f->budget == 0) { f->off = true; return EZ_ERR_META; }
		if (f->budget > 0) f->budget--;
		f->mem[addr + i] = p[i];
		f->bytes_written++;
	}
	return EZ_OK;
}

void sim_fram_init(sim_fram_t *f, uint8_t fill)
{
	memset(f, 0, sizeof *f);
	memset(f->mem, fill, sizeof f->mem);
	f->budget = -1;
	f->hal.ctx = f;
	f->hal.size = EZ_META_SIZE;
	f->hal.read = f_read;
	f->hal.write = f_write;
}

void sim_fram_arm_cut(sim_fram_t *f, long after_bytes) { f->budget = after_bytes; }

void sim_fram_power_on(sim_fram_t *f) { f->off = false; f->budget = -1; }

void sim_fram_flip(sim_fram_t *f, uint32_t bit)
{
	f->mem[(bit / 8) % EZ_META_SIZE] ^= (uint8_t)(1u << (bit % 8));
}
