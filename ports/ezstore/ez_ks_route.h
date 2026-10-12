/*
 * ez_ks_route.h -- one key storage HAL from two: drive 0 to the Einszeit
 * store (ez_store0), drives 1 and 2 to FatFs (ez_ks_fatfs). The core sees
 * a single ez_hal_keystore_t.
 */
#ifndef EZ_KS_ROUTE_H
#define EZ_KS_ROUTE_H

#include "ez_hal_keystore.h"

typedef struct {
	const ez_hal_keystore_t *d0, *cards;
	ez_hal_keystore_t hal;
} ez_ks_route_t;

void ez_ks_route_init(ez_ks_route_t *r, const ez_hal_keystore_t *drive0,
                      const ez_hal_keystore_t *cards);

#endif
