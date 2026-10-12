/*
 * ez_store0.h -- drive 0 key store (EZ-IMPL-001 §2.6)
 *
 * An Einszeit-specific store for the internal NOR flash key partition,
 * replacing FatFs on drive 0. It implements ez_hal_keystore_t for drive 0,
 * so the core's verify-then-use, .SUM handling and quarantine rules apply
 * unchanged.
 *
 * Layout: flash blocks 0 and 1 hold two copies of a 4 KiB allocation table
 * (64 file entries and a block map, with a CRC-32); blocks 2.. hold data.
 * One coded byte in F-RAM selects the current copy.
 *
 * Commit (create, rename, erase, wipe): write the RAM state to the other
 * copy, verify it, then flip the F-RAM byte (one atomic byte write). A
 * power cut at any point leaves the previous committed state or the new
 * one. Appends write data into newly erased blocks but are not committed:
 * the core only appends to temporary files, which a rename finalises, and
 * committing per append would wear out the table blocks.
 *
 * Mount verifies the selected table completely (CRC, entries, every block
 * chain: no shared blocks, no cycles, lengths consistent). It never falls
 * back to the other copy: a damaged current table makes drive 0 faulty
 * until it is wiped. Erasing a file uses NOR block erase.
 *
 * Names are at most 12 characters (8.3); drive 0 only ever holds key
 * files and their temporaries.
 *
 * EZ-SEC-001 traceability: SEC-STORE-001 (erase), SEC-HW-003 (partition
 * separate from firmware), SEC-FW-003, SEC-META-002 pattern for commits;
 * IMPL-DRV-002, IMPL-FS-001 (one file per erase block).
 */
#ifndef EZ_STORE0_H
#define EZ_STORE0_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_flash.h"
#include "ez_hal_keystore.h"
#include "ez_hal_meta.h"

#define EZS_ENTRIES   64
#define EZS_NAME_MAX  12
#define EZS_MAX_DATA  1014u                  /* data blocks one table can map */

typedef struct {
	bool     used;
	char     name[EZS_NAME_MAX + 1];
	uint16_t first;
	uint32_t len;
} ezs_entry_t;

typedef struct {
	const ez_flash_t    *fl;
	const ez_hal_meta_t *fram;
	uint32_t sel_addr;
	bool     mounted, fault;
	uint8_t  sel;
	uint32_t seq;
	uint32_t ndata;
	ezs_entry_t e[EZS_ENTRIES];
	uint16_t map[EZS_MAX_DATA];
	uint8_t  buf[EZ_FLASH_BLOCK];
	unsigned long table_writes;
	ez_hal_keystore_t hal;
} ez_store0_t;

/* Bind to flash and the F-RAM selector byte, and mount. A blank selector
 * (new device, or after device erase) formats the store. */
ez_status_t ez_store0_init(ez_store0_t *s, const ez_flash_t *fl,
                           const ez_hal_meta_t *fram, uint32_t sel_addr);
ez_status_t ez_store0_mount(ez_store0_t *s);

#endif /* EZ_STORE0_H */
