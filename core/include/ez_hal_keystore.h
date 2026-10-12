/*
 * ez_hal_keystore.h -- key data storage HAL (EZ-IMPL-001 §1.3, §2)
 *
 * File-level access to key files on a drive (0 = NOR flash partition,
 * 1 = microSD, 2 = second microSD on P1). The RP2350 port implements it
 * over FatFS; the host suite over an in-memory simulator.
 *
 * Contract:
 *   1. No caching of file data across calls. Any internal buffer that held
 *      file data is cleared before the call returns (SEC-FW-003).
 *   2. create/append/rename/zap reach non-volatile storage before
 *      returning EZ_OK.
 *   3. check() re-verifies that the medium mounted at boot or insertion is
 *      still present and is the same medium (microSD: SEND_STATUS and a CID
 *      comparison). It returns EZ_ERR_MEDIA_REMOVED otherwise (IMPL-ENG-010,
 *      SEC-HW-002). Any other operation on a removed medium also fails.
 *   4. zap() overwrites the file's contents with zeros, verifies, then
 *      deletes it. On microSD this is best effort (wear levelling).
 *   5. wipe() erases the whole drive and leaves an empty filesystem. Only
 *      used for drive 0 (IMPL-DRV-002).
 *   6. The HAL performs no access-control decisions; the core does
 *      (IMPL-ARCH-003). It never exposes key data other than to the core.
 *
 * Names are UTF-8, NUL-terminated, at most EZ_NAME_MAX - 1 bytes. Key files
 * created by the device are 8.3 upper case (IMPL-KEY-001); names of other
 * files (for example keys received from another source) may be long. A
 * name that is too long is rejected (EZ_ERR_BAD_REQUEST), never truncated:
 * a truncated name could address a different file. Name matching is
 * case-insensitive, as on FAT.
 *
 * EZ-SEC-001 traceability: SEC-STORE-001, SEC-HW-002, SEC-FW-003,
 * SEC-FW-004, IMPL-ARCH-001.
 */
#ifndef EZ_HAL_KEYSTORE_H
#define EZ_HAL_KEYSTORE_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_status.h"

#define EZ_DRIVES      3
#define EZ_FNAME_MAX   13    /* key file names: 8.3 (IMPL-KEY-001) */
#define EZ_NAME_MAX    256   /* any file name: up to 255 UTF-8 bytes + NUL */

typedef struct ez_hal_keystore {
	void *ctx;
	bool        (*present)(void *ctx, uint8_t drive);
	ez_status_t (*check)(void *ctx, uint8_t drive);
	ez_status_t (*size)(void *ctx, uint8_t drive, const char *name, uint32_t *size);
	ez_status_t (*read)(void *ctx, uint8_t drive, const char *name, uint32_t off,
	                    void *buf, uint32_t len);
	ez_status_t (*create)(void *ctx, uint8_t drive, const char *name);
	ez_status_t (*append)(void *ctx, uint8_t drive, const char *name,
	                      const void *buf, uint32_t len);
	ez_status_t (*rename)(void *ctx, uint8_t drive, const char *from, const char *to);
	ez_status_t (*zap)(void *ctx, uint8_t drive, const char *name);
	ez_status_t (*list)(void *ctx, uint8_t drive, uint32_t index,
	                    char name[EZ_NAME_MAX], uint32_t *size);
	ez_status_t (*wipe)(void *ctx, uint8_t drive);
	/* Optional (NULL = 1): independent copies kept of this drive's files
	 * (SEC-AVAIL-003). Copy k of drive d is addressed as EZ_COPY(d, k) in
	 * every other function; a plain drive number means the logical drive. */
	uint8_t     (*copies)(void *ctx, uint8_t drive);
} ez_hal_keystore_t;

#define EZ_COPY(d, k)      ((uint8_t)(0x80u | ((unsigned)(k) << 4) | (d)))
#define EZ_COPY_DRIVE(x)   ((uint8_t)((x) & 0x0Fu))
#define EZ_COPY_INDEX(x)   ((uint8_t)(((x) & 0x80u) ? (((x) >> 4) & 0x07u) : 0u))
#define EZ_IS_COPY(x)      (((x) & 0x80u) != 0)
#define EZ_COPIES_MAX      4

#endif /* EZ_HAL_KEYSTORE_H */
