/*
 * sim_fram.h -- simulated SPI F-RAM implementing ez_hal_meta_t
 *
 * Models the MB85RS16 for the metadata tests (EZ-IMPL-001 §12.1):
 * byte-atomic writes in ascending address order, no write cache.
 *
 * Fault injection:
 *   power cut   sim_fram_arm_cut(f, n): the next n byte writes succeed,
 *               then power is lost: every later write is dropped and
 *               every access fails until sim_fram_power_on().
 *   bit flips   sim_fram_flip(f, bit): flips one bit at rest.
 *   tampering   direct access to f->mem.
 *
 * EZ-SEC-001 traceability: instrument for SEC-TEST-PTR-001/002/003.
 */
#ifndef SIM_FRAM_H
#define SIM_FRAM_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_hal_meta.h"
#include "ez_meta.h"

typedef struct {
	uint8_t  mem[EZ_META_SIZE];
	long     budget;          /* byte writes left before the cut; <0: none armed */
	bool     off;             /* power has been cut */
	unsigned long bytes_written;
	ez_hal_meta_t hal;
} sim_fram_t;

void sim_fram_init(sim_fram_t *f, uint8_t fill);
void sim_fram_arm_cut(sim_fram_t *f, long after_bytes);
void sim_fram_power_on(sim_fram_t *f);
void sim_fram_flip(sim_fram_t *f, uint32_t bit);

#endif
