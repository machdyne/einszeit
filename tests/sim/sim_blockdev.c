/* sim_blockdev.c -- see sim_blockdev.h */
#include "sim_blockdev.h"

#include <stdlib.h>
#include <string.h>

static bool tick(sim_bd_t *s)
{
	s->calls++;
	if (s->remove_after == 0) { s->present = false; s->remove_after = -1; }
	else if (s->remove_after > 0) s->remove_after--;
	if (s->swap_after == 0) { s->card_id++; s->swap_after = -1; }
	else if (s->swap_after > 0) s->swap_after--;
	return s->present;
}

static bool present(void *ctx) { return ((sim_bd_t *)ctx)->present; }

static ez_status_t init(void *ctx)
{
	sim_bd_t *s = ctx;
	if (!tick(s)) return EZ_ERR_MEDIA_REMOVED;
	s->mounted_id = s->card_id;
	return EZ_OK;
}

static ez_status_t check(void *ctx)
{
	sim_bd_t *s = ctx;
	if (!tick(s) || s->card_id != s->mounted_id) return EZ_ERR_MEDIA_REMOVED;
	return EZ_OK;
}

static uint32_t count(void *ctx) { return ((sim_bd_t *)ctx)->sectors; }

static ez_status_t rd(void *ctx, uint32_t lba, uint8_t *buf, uint32_t n)
{
	sim_bd_t *s = ctx;
	if (!tick(s)) return EZ_ERR_MEDIA_REMOVED;
	if ((uint64_t)lba + n > s->sectors) return EZ_ERR_RANGE;
	memcpy(buf, s->mem + (size_t)lba * s->bd.sector_size, (size_t)n * s->bd.sector_size);
	return EZ_OK;
}

static ez_status_t wr(void *ctx, uint32_t lba, const uint8_t *buf, uint32_t n)
{
	sim_bd_t *s = ctx;
	if (!tick(s)) return EZ_ERR_MEDIA_REMOVED;
	if ((uint64_t)lba + n > s->sectors) return EZ_ERR_RANGE;
	memcpy(s->mem + (size_t)lba * s->bd.sector_size, buf, (size_t)n * s->bd.sector_size);
	return EZ_OK;
}

static ez_status_t sync_(void *ctx)
{
	return tick(ctx) ? EZ_OK : EZ_ERR_MEDIA_REMOVED;
}

static ez_status_t erase_all(void *ctx)
{
	sim_bd_t *s = ctx;
	if (!tick(s)) return EZ_ERR_MEDIA_REMOVED;
	memset(s->mem, s->erased, (size_t)s->sectors * s->bd.sector_size);
	return EZ_OK;
}

void sim_bd_init(sim_bd_t *s, uint32_t sector_size, uint32_t sectors, uint8_t erased, bool flash)
{
	memset(s, 0, sizeof *s);
	s->sectors = sectors;
	s->erased = erased;
	s->mem = malloc((size_t)sectors * sector_size);
	memset(s->mem, erased, (size_t)sectors * sector_size);
	s->present = true;
	s->card_id = s->mounted_id = 1;
	s->remove_after = s->swap_after = -1;
	s->bd = (ez_blockdev_t){ s, sector_size, present, init, check, count, rd, wr, sync_,
	                         flash ? erase_all : NULL };
}

void sim_bd_free(sim_bd_t *s) { free(s->mem); s->mem = NULL; }
void sim_bd_remove(sim_bd_t *s) { s->present = false; }
void sim_bd_insert(sim_bd_t *s) { s->present = true; }
void sim_bd_remove_after(sim_bd_t *s, long n) { s->remove_after = n; }
void sim_bd_swap_after(sim_bd_t *s, long n) { s->swap_after = n; }

bool sim_bd_contains(const sim_bd_t *s, const uint8_t *p, size_t n)
{
	size_t total = (size_t)s->sectors * s->bd.sector_size;
	for (size_t i = 0; i + n <= total; i++)
		if (s->mem[i] == p[0] && memcmp(s->mem + i, p, n) == 0) return true;
	return false;
}
