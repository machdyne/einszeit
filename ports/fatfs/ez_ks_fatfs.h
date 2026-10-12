/*
 * ez_ks_fatfs.h -- key storage HAL (ez_hal_keystore_t) over FatFs
 *
 *   static ez_ks_fatfs_t ks;
 *   ez_ks_fatfs_init(&ks, &flash_bd, &sd_bd, NULL);
 *   ez_ks_fatfs_mount(&ks, 0);     // drive 0: formats if blank
 *   ez_ks_fatfs_mount(&ks, 1);     // on boot and on every card insertion
 *   ez_core_init(&core, ..., &ks.hal, ...);
 *
 * One instance per firmware image (FatFs's disk interface is global).
 * All FatFs objects that can hold file data are owned here and cleared
 * after every call (contract 1 of ez_hal_keystore.h).
 *
 * EZ-SEC-001 traceability: SEC-STORE-001 (zap, wipe), SEC-HW-002 (check),
 * SEC-FW-003 (buffers cleared), SEC-FW-004 (no access except via the core).
 */
#ifndef EZ_KS_FATFS_H
#define EZ_KS_FATFS_H

#include <stdbool.h>

#include "ez_blockdev.h"
#include "ez_hal_keystore.h"
#include "ff.h"

typedef struct {
	const ez_blockdev_t *bd[EZ_DRIVES];
	bool     mounted[EZ_DRIVES];
	FATFS    fs[EZ_DRIVES];
	FIL      fil;       /* shared; cleared after every call */
	DIR      dir;
	FILINFO  fno;
	ez_hal_keystore_t hal;
} ez_ks_fatfs_t;

void        ez_ks_fatfs_init(ez_ks_fatfs_t *k, const ez_blockdev_t *bd0,
                             const ez_blockdev_t *bd1, const ez_blockdev_t *bd2);
/* Bring up the medium and mount it. Drive 0 is formatted when it holds no
 * filesystem; other drives must already be FAT formatted. */
ez_status_t ez_ks_fatfs_mount(ez_ks_fatfs_t *k, uint8_t drive);
void        ez_ks_fatfs_unmount(ez_ks_fatfs_t *k, uint8_t drive);

#endif /* EZ_KS_FATFS_H */
