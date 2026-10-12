/*
 * hal_rp2350.h -- RP2350 implementations of the core's HAL interfaces
 * (EZ-IMPL-001 §1.3) for Einszeit V1.
 *
 *   hal_fram   ez_hal_meta_t over SPI0 (MB85RS16, 2-byte addressing)
 *   hal_flash  ez_flash_t over the QSPI key partition (drive 0 store)
 *   hal_sdblk  ez_blockdev_t over the microSD on SPI1 (FatFs, drive 1)
 *   hal_trng   ez_hal_trng_t over the RP2350 TRNG, production profile
 */
#ifndef HAL_RP2350_H
#define HAL_RP2350_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_blockdev.h"
#include "ez_flash.h"
#include "ez_hal_meta.h"
#include "ez_hal_trng.h"

extern const ez_hal_meta_t  hal_fram;
extern const ez_flash_t     hal_flash;
extern const ez_blockdev_t  hal_sdblk;
extern const ez_hal_trng_t  hal_trng;

void hal_fram_init(void);
void hal_flash_init(void);                  /* maps the key partition (XIP window 1) */
bool hal_flash_protected(void *ctx);        /* IMPL-DRV-003 guard */
const char *hal_flash_protection_reason(void);
bool hal_fram_probe(uint8_t *sr_idle, uint8_t *sr_wren);   /* WEL toggles */

/* TRNG production profile (IMPL-ENT-001). */
#define TRNG_PROFILE_ID      1u
#define TRNG_SAMPLE_CNT1     16384u
typedef struct {
	unsigned long collections, vn_err, crngt_err, autocorr_err, timeouts, faults;
} hal_trng_stats_t;
void hal_trng_get_stats(hal_trng_stats_t *s);

/* SD: card identity captured at mount; SD_DET level for diagnostics. */
bool hal_sd_present(void);
void hal_sd_forget(void);
int  hal_sd_det_raw(void);
void hal_sd_info(uint32_t *sectors, uint8_t cid[16]);

uint32_t hal_uptime_s(void);

#endif
