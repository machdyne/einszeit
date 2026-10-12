/*
 * sim_trng.h -- simulated entropy source implementing ez_hal_trng_t
 *
 * TEST ONLY. Every mode is deterministic; GOOD is a SplitMix64 stream.
 * This violates SEC-ENTROPY-001 by design and must never be linked into
 * firmware (see ez_hal_trng.h).
 *
 * Modes model the failures SEC-TEST-ENT-002 and SEC-ENTROPY-002/004
 * require the device to catch: bias, a stuck output, serial correlation,
 * periodic patterns, a counter (perfectly uniform, not random), replay of
 * a supplied buffer, and a hardware health fault after n bytes.
 */
#ifndef SIM_TRNG_H
#define SIM_TRNG_H

#include <stddef.h>
#include <stdint.h>

#include "ez_hal_trng.h"

typedef enum {
	SIM_TRNG_GOOD = 0,
	SIM_TRNG_BIASED,       /* P(1) = param/256 */
	SIM_TRNG_STUCK,        /* every byte = param */
	SIM_TRNG_CORRELATED,   /* each bit repeats the previous with P = param/256 */
	SIM_TRNG_ALTERNATING,  /* 0x55 0x55 ... */
	SIM_TRNG_COUNTER,      /* 0,1,2,...,255,0,... */
	SIM_TRNG_BUFFER,       /* bytes from buf, then GOOD */
} sim_trng_mode_t;

typedef struct {
	sim_trng_mode_t mode;
	uint32_t param;
	uint64_t s;
	uint8_t  ctr, last;
	long     fault_after;    /* <0: never */
	const uint8_t *buf;
	size_t   buflen, pos;
	unsigned long bytes;
	ez_hal_trng_t hal;
} sim_trng_t;

void sim_trng_init(sim_trng_t *t, uint64_t seed);
void sim_trng_mode(sim_trng_t *t, sim_trng_mode_t mode, uint32_t param);
void sim_trng_fault_after(sim_trng_t *t, long n);
/* Deterministic bytes from a seed (used to make known key files). */
void sim_fill(uint8_t *out, size_t n, uint64_t seed);

#endif
