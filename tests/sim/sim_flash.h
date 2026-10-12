/*
 * sim_flash.h -- NOR flash simulator implementing ez_flash_t
 *
 * Erase sets a 4 KiB block to 0xFF; program can only clear bits
 * (new = old AND data). Power cut: sim_flash_arm_cut(f, n) lets n erase or
 * program operations complete; the next one is torn (an erase leaves the
 * first half of the block erased and the rest as it was; a program writes
 * only the first half of its bytes), and power is then off for the flash
 * and, if linked, for the F-RAM simulator too.
 */
#ifndef SIM_FLASH_H
#define SIM_FLASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ez_flash.h"
#include "sim_fram.h"

typedef struct {
	uint8_t *mem;
	uint32_t blocks;
	long     budget;          /* <0: no cut armed */
	bool     off;
	sim_fram_t *fram;         /* powered down together, if set */
	unsigned long erases, programs;
	unsigned long *erase_count;   /* per block */
	ez_flash_t fl;
} sim_flash_t;

void sim_flash_init(sim_flash_t *f, uint32_t blocks);
void sim_flash_free(sim_flash_t *f);
void sim_flash_arm_cut(sim_flash_t *f, long ops);
void sim_flash_power_on(sim_flash_t *f);
bool sim_flash_contains(const sim_flash_t *f, const uint8_t *p, size_t n);

#endif
