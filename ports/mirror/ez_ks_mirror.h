/*
 * ez_ks_mirror.h -- one logical drive kept as N independent copies
 * (SEC-AVAIL-003/004, EZ-IMPL-001 §2.8).
 *
 * Each copy is a separate volume behind its own keystore HAL: two FAT
 * volumes on one card (firmware), two directories (virtual device), two
 * simulated stores (tests). Every other drive passes through to `base`.
 *
 * On the logical drive:
 *   read, size, list    copy 0, or the first copy that has the file
 *   create, append,     copy 0 only. The core writes a complete, verified
 *   rename              copy 0 first and only then replicates it to the
 *                       other copies, one at a time (ez_replicate()), so no
 *                       two copies are ever being written at once.
 *   zap, wipe           every copy in turn. An error from any copy is
 *                       returned (SEC-PTR-004: no copy may be skipped).
 *   present             any copy present; check: the first present copy.
 * Copy k is addressed directly as EZ_COPY(drive, k).
 */
#ifndef EZ_KS_MIRROR_H
#define EZ_KS_MIRROR_H

#include "ez_hal_keystore.h"

typedef struct {
	const ez_hal_keystore_t *hal;
	uint8_t drive;
} ez_mirror_vol_t;

typedef struct {
	const ez_hal_keystore_t *base;     /* every other drive */
	uint8_t drive;                     /* the mirrored logical drive */
	uint8_t n;                         /* copies, 1..EZ_COPIES_MAX */
	ez_mirror_vol_t vol[EZ_COPIES_MAX];
	ez_hal_keystore_t hal;
} ez_ks_mirror_t;

void ez_ks_mirror_init(ez_ks_mirror_t *m, const ez_hal_keystore_t *base, uint8_t drive,
                       const ez_mirror_vol_t *vols, uint8_t n);

#endif
