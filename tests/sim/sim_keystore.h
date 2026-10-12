/*
 * sim_keystore.h -- simulated key storage implementing ez_hal_keystore_t
 *
 * Three drives of in-memory files. Fault injection:
 *   removal      sim_ks_remove_after(k, drive, n): the drive disappears
 *                before its (n+1)th HAL call from now
 *   swap         sim_ks_swap_after(k, drive, n): a different card is in the
 *                slot (present, but check() fails)
 *   corruption   sim_ks_corrupt_append(k, n): the nth append from now
 *                stores one flipped bit (read-back verification test)
 *   interrupted erase  sim_ks_interrupt_zap(k): the next zap() zeroes only
 *                the first half of the file, then the medium disappears --
 *                as a power cut part-way through a real erase would
 *   dirty reads  a read into a buffer that is not all zero is counted:
 *                the core must clear key scratch before reusing it
 *   read log     every read() is recorded when logging is on, so tests can
 *                prove which key bytes an operation touched (SEC-ISO-*)
 *
 * EZ-SEC-001 traceability: instrument for SEC-TEST-ISO-002/003,
 * SEC-TEST-REPLAY-001, SEC-TEST-MEDIA-001, SEC-GEN-002.
 */
#ifndef SIM_KEYSTORE_H
#define SIM_KEYSTORE_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_hal_keystore.h"

#define SIM_KS_FILES   32
#define SIM_KS_LOGMAX  65536

typedef struct {
	bool     used;
	char     name[EZ_NAME_MAX];
	uint8_t *data;
	uint32_t len, cap;
} sim_file_t;

typedef struct {
	bool       present;
	uint32_t   card_id, mounted_id;
	sim_file_t f[SIM_KS_FILES];
	long       remove_after, swap_after;
	unsigned long wipes;
	unsigned long calls;      /* HAL calls addressed to this drive */
} sim_drive_t;

typedef struct {
	uint8_t  drive;
	char     name[EZ_NAME_MAX];
	uint32_t off, len;
} sim_read_t;

typedef struct {
	sim_drive_t d[EZ_DRIVES];
	long        corrupt_append;          /* <0: off */
	bool        zap_interrupt;           /* next zap stops half way: medium lost */
	long        corrupt_reads;           /* next n reads return one flipped bit */
	unsigned long mutations;             /* create/append/rename/zap/wipe calls (SEC-AVAIL-001) */
	bool        logging;
	uint32_t    nlog;
	sim_read_t  log[SIM_KS_LOGMAX];
	unsigned long reads, appends;
	/* Reads whose destination buffer was not all-zero beforehand: the core
	 * reuses a scratch buffer that still held key bytes (SEC-FW-003). */
	unsigned long dirty_reads;
	ez_hal_keystore_t hal;
} sim_ks_t;

void sim_ks_init(sim_ks_t *k);          /* drives 0..2 present, empty */
void sim_ks_free(sim_ks_t *k);
void sim_ks_insert(sim_ks_t *k, uint8_t drive);   /* present; mounts the card */
void sim_ks_remove(sim_ks_t *k, uint8_t drive);
void sim_ks_remove_after(sim_ks_t *k, uint8_t drive, long n);
void sim_ks_swap_after(sim_ks_t *k, uint8_t drive, long n);
void sim_ks_corrupt_append(sim_ks_t *k, long n);
void sim_ks_interrupt_zap(sim_ks_t *k);
void sim_ks_corrupt_reads(sim_ks_t *k, long n);
void sim_ks_clear_faults(sim_ks_t *k);

/* Test helpers: create/replace a file directly; look one up. */
void sim_ks_put(sim_ks_t *k, uint8_t drive, const char *name, const uint8_t *data, uint32_t len);
sim_file_t *sim_ks_get(sim_ks_t *k, uint8_t drive, const char *name);
void sim_ks_log_reset(sim_ks_t *k, bool on);

#endif
