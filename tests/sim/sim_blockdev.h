/*
 * sim_blockdev.h -- RAM disk implementing ez_blockdev_t, for testing the
 * FatFs key storage port on the host.
 *
 * Fault injection: removal or card swap before the (n+1)th call from now
 * (any call, including FatFs's own sector reads). sim_bd_contains() scans
 * the raw medium for a byte sequence, to prove erased key data is gone.
 */
#ifndef SIM_BLOCKDEV_H
#define SIM_BLOCKDEV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ez_blockdev.h"

typedef struct {
	uint8_t *mem;
	uint32_t sectors;
	uint8_t  erased;          /* value of erased media: 0xFF for NOR flash */
	bool     present;
	uint32_t card_id, mounted_id;
	long     remove_after, swap_after;
	unsigned long calls;
	ez_blockdev_t bd;
} sim_bd_t;

void sim_bd_init(sim_bd_t *s, uint32_t sector_size, uint32_t sectors, uint8_t erased, bool flash);
void sim_bd_free(sim_bd_t *s);
void sim_bd_remove(sim_bd_t *s);
void sim_bd_insert(sim_bd_t *s);       /* new mount: identity recorded by init() */
void sim_bd_remove_after(sim_bd_t *s, long n);
void sim_bd_swap_after(sim_bd_t *s, long n);
/* True if the raw medium contains the n-byte sequence p anywhere. */
bool sim_bd_contains(const sim_bd_t *s, const uint8_t *p, size_t n);

#endif
