/*
 * ez_flash.h -- NOR flash interface under the drive 0 key store
 *
 * The RP2350 port implements it over the QSPI flash key partition (Phase 3,
 * with flash_safe_execute); the host suite over a simulator with NOR
 * semantics and power-cut injection (tests/sim/sim_flash).
 *
 * Contract: erase() sets a whole 4 KiB block to 0xFF; program() can only
 * clear bits (new = old AND data) and reaches the flash before returning;
 * addresses are relative to the start of the key partition, which never
 * overlaps the firmware (SEC-HW-003). Internal buffers holding data are
 * cleared before returning (SEC-FW-003).
 */
#ifndef EZ_FLASH_H
#define EZ_FLASH_H

#include <stdint.h>

#include "ez_status.h"

#define EZ_FLASH_BLOCK 4096u

typedef struct ez_flash {
	void    *ctx;
	uint32_t blocks;
	ez_status_t (*read)(void *ctx, uint32_t addr, void *buf, uint32_t len);
	ez_status_t (*erase)(void *ctx, uint32_t block);
	ez_status_t (*program)(void *ctx, uint32_t addr, const void *buf, uint32_t len);
} ez_flash_t;

#endif /* EZ_FLASH_H */
