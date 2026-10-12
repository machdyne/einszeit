/*
 * card.h -- the microSD as key storage (EZ-IMPL-001 §2.8, IMPL-AV-007).
 *
 * A card formatted by Einszeit has an MBR with disk signature "EZM2" and
 * two FAT32 partitions, A (4 MiB .. half the card) and B (half .. end),
 * each its own volume with its own FATs and directory. Such a card is
 * kept as two copies of drive 1 (ports/mirror). Any other card is a plain
 * FAT card: one copy, as before.
 */
#ifndef CARD_H
#define CARD_H
#include <stdint.h>
#include "ez_hal_keystore.h"
#include "ez_status.h"

void  card_init(void);                        /* configure and mount, if a card is in */
ez_status_t card_mount(void);                 /* detect the format, mount the volume(s) */
const ez_hal_keystore_t *card_hal(void);      /* drive 1 (mirror), drive 2 absent */
uint8_t card_copies(void);
ez_status_t card_fs_status(void);             /* the last mount: OK, or why not */
bool card_volume_mounted(uint8_t k);
void card_info_text(char *o, uint32_t cap);   /* for the status displays */
void card_service(void);                      /* retry unmounted copy volumes */
extern int card_force_volume;                 /* development shell: sd repair a|b */
extern int (*card_printf)(const char *fmt, ...);   /* step and progress output */
extern volatile uint16_t *card_progress;   /* a recreated volume's progress goes here (per mille) */
ez_status_t card_repair(void *ctx, uint8_t drive, uint8_t *recreated);   /* core hook */
ez_status_t card_format(void *ctx, uint8_t drive, uint8_t copies);   /* core hook */
extern int card_verbose;                      /* development shell */
#endif
