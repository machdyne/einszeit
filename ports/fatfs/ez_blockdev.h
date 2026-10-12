/*
 * ez_blockdev.h -- block device under the FatFs key storage port
 *
 * Implemented by the RP2350 flash and microSD drivers (Phase 3) and by the
 * host RAM disk simulator (tests/sim/sim_blockdev). Sector size is 512
 * (microSD) or 4096 (NOR flash: one erase block per sector, IMPL-FS-001).
 *
 * Contract:
 *   - read/write move whole sectors; write reaches the medium before sync
 *     returns.
 *   - init() is called on insertion (and at boot) and records the medium's
 *     identity (microSD: CID). check() verifies the same medium is still
 *     present (microSD: SEND_STATUS + CID compare) -- IMPL-ENG-010.
 *   - erase_all() physically erases the whole device (NOR: sector erase),
 *     used to wipe drive 0 (IMPL-DRV-002). May be NULL: the port then
 *     writes zero sectors over the device.
 *   - Driver-internal buffers that held sector data are cleared before the
 *     call returns (SEC-FW-003).
 *
 * EZ-SEC-001 traceability: SEC-HW-002, SEC-STORE-001, SEC-FW-003.
 */
#ifndef EZ_BLOCKDEV_H
#define EZ_BLOCKDEV_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_status.h"

typedef struct ez_blockdev {
	void    *ctx;
	uint32_t sector_size;
	bool        (*present)(void *ctx);
	ez_status_t (*init)(void *ctx);
	ez_status_t (*check)(void *ctx);
	uint32_t    (*sector_count)(void *ctx);
	ez_status_t (*read)(void *ctx, uint32_t lba, uint8_t *buf, uint32_t count);
	ez_status_t (*write)(void *ctx, uint32_t lba, const uint8_t *buf, uint32_t count);
	ez_status_t (*sync)(void *ctx);
	ez_status_t (*erase_all)(void *ctx);
} ez_blockdev_t;

#endif /* EZ_BLOCKDEV_H */
