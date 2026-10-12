/*
 * ez_keygen.h -- key generation job (EZ-IMPL-001 §2.3, §7)
 *
 * Generation takes minutes to hours, so it runs as a job advanced by
 * ez_keygen_step() from the main loop, keeping USB responsive:
 *
 *   ez_keygen_start(c, &kg, drive, len);
 *   while ((st = ez_keygen_step(c, &kg, 8)) == EZ_PENDING) { ...poll USB... }
 *   st == EZ_OK: kg.key_id names the new <KEYID>.KEY
 *
 * Pipeline: draw a Key ID from the TRNG (separately from the key bytes);
 * write <ID>.TMP one 512-byte block at a time with online monitoring;
 * read each block back and compare; then read the whole file back through
 * the acceptance tests while computing the integrity tags (from the key as
 * stored) into <ID>.SUT; log the result; rename .SUT to .SUM and .TMP to
 * .KEY only if accepted.
 * Any failure halts, logs, and destroys the .TMP file.
 *
 * EZ-SEC-001 traceability: SEC-ENTROPY-001 (TRNG HAL only),
 * SEC-ENTROPY-002 (acceptance before valid), SEC-ENTROPY-004 (halt and
 * log on fault), SEC-GEN-001 (one block buffered, cleared after write),
 * SEC-GEN-002 (read-back per block), SEC-GEN-003 (event log entry),
 * SEC-STORE-002 (TRNG Key ID), SEC-STORE-004 (integrity tags);
 * IMPL-KEY-002/003/005, IMPL-GEN-001, IMPL-ENT-002.
 */
#ifndef EZ_KEYGEN_H
#define EZ_KEYGEN_H

#include <stdint.h>

#include "ez_core.h"
#include "ez_entropy.h"
#include "ez_sum.h"

typedef enum { EZ_KG_IDLE = 0, EZ_KG_GENERATE, EZ_KG_VERIFY, EZ_KG_DONE } ez_kg_state_t;

typedef struct {
	ez_kg_state_t state;
	uint8_t  drive;
	uint8_t  fail;           /* EZ_EF_* bits of the last run */
	uint32_t key_id;
	uint16_t instance;       /* IMPL-KEY-005 */
	uint32_t len;
	uint32_t done;           /* bytes written (GENERATE) or verified (VERIFY) */
	uint32_t since_check;
	ez_status_t result;
	ez_monitor_t mon;
	ez_accept_t  acc;
	ez_tagger_t  tagger;
	uint8_t  tags[8 * EZ_TAG_LEN]; /* tag batch for the .SUT; cleared after writing */
	uint32_t ntags;
	uint8_t  vbuf[EZ_KEY_BLOCK];   /* read-back buffer; zero between steps */
} ez_keygen_t;

ez_status_t ez_keygen_start(ez_core_t *c, ez_keygen_t *kg, uint8_t drive, uint32_t len);
/* Processes up to max_blocks blocks. Returns EZ_PENDING while running,
 * then the final status: EZ_OK (accepted), EZ_ERR_ENTROPY (rejected or
 * TRNG fault), EZ_ERR_MEDIA / EZ_ERR_MEDIA_REMOVED, EZ_ERR_ABORTED. */
ez_status_t ez_keygen_step(ez_core_t *c, ez_keygen_t *kg, uint32_t max_blocks);
void        ez_keygen_cancel(ez_core_t *c, ez_keygen_t *kg);
/* Progress in parts per thousand over both passes. */
uint32_t    ez_keygen_progress(const ez_keygen_t *kg);

#endif /* EZ_KEYGEN_H */
