/*
 * ez_hal_meta.h -- metadata storage HAL (EZ-IMPL-001 §1.3)
 *
 * The backend contract, which the offset commit protocol (IMPL-META-003)
 * depends on:
 *
 *   1. Each single-byte write is atomic: after a power loss a byte holds
 *      either its old or its new value, never a mixture.
 *   2. A multi-byte write stores bytes in ascending address order, so a
 *      power loss part-way through leaves a prefix written.
 *   3. Writes are not cached: when write() returns EZ_OK the data is in
 *      non-volatile storage (verified separately by read-back).
 *
 * SPI F-RAM (MB85RS16 on V1) meets all three natively. A backend that
 * does not (for example NOR flash on Zeitlos) needs an adapter that does,
 * and must pass the metadata conformance tests in tests/unit
 * (EZ-IMPL-001 §12.2).
 *
 * EZ-SEC-001 traceability: SEC-META-002 (atomicity rests on this
 * contract), IMPL-ARCH-001.
 */
#ifndef EZ_HAL_META_H
#define EZ_HAL_META_H

#include <stdint.h>
#include "ez_status.h"

typedef struct ez_hal_meta {
	void    *ctx;
	uint32_t size;  /* bytes; the core requires at least EZ_META_SIZE */
	ez_status_t (*read)(void *ctx, uint32_t addr, void *buf, uint32_t len);
	ez_status_t (*write)(void *ctx, uint32_t addr, const void *buf, uint32_t len);
} ez_hal_meta_t;

#endif /* EZ_HAL_META_H */
