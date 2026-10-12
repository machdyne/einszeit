/*
 * ez_hal_trng.h -- hardware entropy HAL (EZ-IMPL-001 §1.3, §7)
 *
 * Contract:
 *   1. read() returns only output of the hardware TRNG with its health
 *      tests enabled and its hardware debiasing applied. It MUST NOT be
 *      backed, in whole or in part, by a DRNG, PRNG or CSPRNG, and never
 *      falls back to one (SEC-ENTROPY-001, SEC-ENTROPY-004).
 *   2. On any hardware health fault it resets the entropy block and
 *      returns EZ_ERR_ENTROPY; the data in buf is then undefined and the
 *      caller discards it.
 *   3. profile identifies the TRNG configuration (IMPL-ENT-001).
 *
 * The host test suite's simulator (tests/sim/sim_trng) deliberately
 * violates (1) -- it is a deterministic generator -- and exists only to
 * drive tests. It must never be linked into firmware.
 *
 * EZ-SEC-001 traceability: SEC-ENTROPY-001, SEC-ENTROPY-004, IMPL-ENT-001.
 */
#ifndef EZ_HAL_TRNG_H
#define EZ_HAL_TRNG_H

#include <stdint.h>

#include "ez_status.h"

typedef struct ez_hal_trng {
	void   *ctx;
	uint8_t profile;
	ez_status_t (*read)(void *ctx, void *buf, uint32_t len);
} ez_hal_trng_t;

#endif /* EZ_HAL_TRNG_H */
