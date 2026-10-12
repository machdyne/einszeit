/*
 * app.h -- the device application shared by every firmware image: the
 * core, its storage, the protocol dispatcher over HID, and card polling.
 *
 * Images (IMPL-MODE-001):
 *   development  (EZ_DEV)        composite CDC + HID, debug shell, `fw update`,
 *                                marks the device (IMPL-MODE-002)
 *   production   (EZ_PRODUCTION) HID only; no shell, no software path into
 *                                the bootloader (IMPL-DRV-004)
 */
#ifndef APP_H
#define APP_H

#include <stdbool.h>

#include "ez_core.h"
#include "ez_dispatch.h"
#include "ez_ks_fatfs.h"
#include "ez_store0.h"

#if defined(EZ_PRODUCTION) == defined(EZ_DEV)
#error "build exactly one of EZ_PRODUCTION or EZ_DEV"
#endif
#if defined(EZ_PRODUCTION) && defined(EZ_BRINGUP)
#error "a production image must not contain development features (IMPL-DRV-004)"
#endif

#ifdef EZ_DEV
#define FW_VERSION "0.4.1-dev"
#else
#define FW_VERSION "0.3.11"
#endif

extern ez_store0_t   store0;
extern ez_ks_fatfs_t cards;
extern ez_core_t     core;
extern uint8_t       stage[EZ_STAGE_SIZE];
extern ez_dispatch_t disp;
extern bool          app_console_busy;   /* the console holds the core */

void app_boot(void);        /* (re)initialise storage, core and dispatcher */
void app_idle(void);
void app_start_worker(void);    /* core 1: all long work (round 16) */
__attribute__((noreturn)) void app_main_on_stack(void (*fn)(void));   /* core 0, first thing in main(): run fn on a 16 KB stack */
uint32_t app_core0_stack_used(void);   /* bytes of each core's stack ever used */
uint32_t app_core1_stack_used(void);
uint32_t app_stack_size(void);
void app_log_drain(void);        /* serve HID (or answer BUSY), poll the card */
void app_service_hid(void);

#endif
