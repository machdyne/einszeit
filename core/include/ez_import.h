/*
 * ez_import.h -- importing a key file into a session (EZ-IMPL-001 §2.5)
 *
 * The only way a key becomes usable on this device, whether or not an
 * integrity file came with it:
 *
 *   with <ID>.SUM   every unit is verified against it, catching damage in
 *                   transfer before either party encrypts (SEC-STORE-004);
 *   without         the key must pass the per-key acceptance tests
 *                   (SEC-ENTROPY-002 thresholds) and contain no two identical
 *                   4 KiB blocks; then tags are computed from it as it is now
 *                   and written as <ID>.SUM, with a new instance tag
 *                   (SEC-STORE-005).
 *
 * Then the file is renamed to <ID>.KEY if needed (IMPL-KEY-004) and the
 * session is created. Like key generation, a stepwise job:
 *
 *   ez_import_start(c, &im, drive, "from bob.bin", 0xA73F2C01, EZ_ROLE_BOB, "Bob");
 *   while ((st = ez_import_step(c, &im, 4)) == EZ_PENDING) { ...poll USB... }
 *
 * Without an integrity file the job uses the core's staging buffer for its
 * duplicate check, so no buffered operation can run meanwhile; keys of up
 * to 64 MiB (16,384 blocks) can be imported that way. With one, any size.
 *
 * EZ-SEC-001 traceability: SEC-STORE-004, SEC-STORE-005, SEC-ENTROPY-002
 * (acceptance at import), SEC-ISO-002, SEC-DIST-003 (the Key ID must match
 * the integrity file's); IMPL-KEY-004, IMPL-KEY-005.
 */
#ifndef EZ_IMPORT_H
#define EZ_IMPORT_H

#include "ez_core.h"
#include "ez_entropy.h"

typedef enum { EZ_IM_IDLE = 0, EZ_IM_SCAN, EZ_IM_DONE } ez_im_state_t;

typedef struct {
	ez_im_state_t state;
	uint8_t  drive, role;
	bool     have_sum;
	uint16_t instance;
	uint32_t key_id, key_len;
	uint32_t unit, units;          /* next unit; total */
	uint32_t bad, first_bad;       /* units failing their tag (with .SUM) */
	uint32_t dups;                 /* duplicate blocks found (without) */
	uint8_t  fail;                 /* acceptance failure bits (without) */
	char     src[EZ_NAME_MAX];
	char     label[EZ_LABEL_MAX + 1];
	ez_accept_t acc;
	uint8_t  tags[8 * EZ_TAG_LEN];
	uint32_t ntags;
	ez_status_t result;
	int      slot;                 /* the session created, on success */
} ez_import_t;

ez_status_t ez_import_start(ez_core_t *c, ez_import_t *im, uint8_t drive, const char *file,
                            uint32_t key_id, uint8_t role, const char *label);
/* EZ_PENDING while running; then EZ_OK (session in im->slot) or the
 * reason for refusal: EZ_ERR_KEY_DAMAGED (tag mismatch: im->bad units,
 * first im->first_bad; or duplicate blocks: im->dups), EZ_ERR_ENTROPY
 * (acceptance failed: im->fail), media errors. */
ez_status_t ez_import_step(ez_core_t *c, ez_import_t *im, uint32_t max_units);
void        ez_import_cancel(ez_core_t *c, ez_import_t *im);

#endif /* EZ_IMPORT_H */
