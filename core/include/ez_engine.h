/*
 * ez_engine.h -- encryption and decryption (EZ-IMPL-001 §6)
 *
 * Buffered mode (up to EZ_BUFFERED_MAX bytes of plaintext):
 *   p = ez_stage_plaintext(c, n);  ...write n bytes to p...
 *   ez_encrypt_buffered(c, slot, n, &out, &out_len);  -> whole message
 *   (resend with ez_retained(); finish with ez_release())
 *
 *   p = ez_stage_message(c, n);  ...write the n-byte message to p...
 *   ez_decrypt_buffered(c, slot_or_-1, n, &pt, &pt_len);
 *   ez_release(c) when the plaintext has been delivered.
 *
 * Streaming mode (any size): begin / update* / end. Each update transforms
 * the caller's buffer in place. For encryption, update returns EZ_OK only
 * after the TX offset has been committed past the end of that chunk; the
 * caller may output the chunk only then (SEC-PTR-003). For decryption, the
 * RX offset is committed by end, after the CRC has been verified
 * (SEC-DEC-004); the caller must not release plaintext before end returns
 * EZ_OK (IMPL-ENG-007).
 *
 * On any error the stream is aborted, the caller's buffer is cleared, and
 * further updates fail. ez_stream_spent() reports key bytes committed.
 *
 * EZ-SEC-001 traceability:
 *   SEC-ENC-001/002/003, SEC-DEC-001/002/003/004, SEC-PTR-003, SEC-KDF-001,
 *   SEC-ISO-001, SEC-HW-002, SEC-FW-002/003, SEC-TX-002;
 *   SEC-STORE-004 (verify before use);
 *   IMPL-ENG-001..010, IMPL-ENG-012..014, IMPL-MSG-001.
 */
#ifndef EZ_ENGINE_H
#define EZ_ENGINE_H

#include <stdint.h>

#include "ez_core.h"

/* ---- buffered ------------------------------------------------------- */
uint8_t *ez_stage_plaintext(ez_core_t *c, uint32_t len);
uint8_t *ez_stage_message(ez_core_t *c, uint32_t len);

ez_status_t ez_encrypt_buffered(ez_core_t *c, int slot, uint32_t len,
                                const uint8_t **out, uint32_t *out_len);
/* slot < 0: select the session by the header's Key ID (IMPL-MSG-001). */
ez_status_t ez_decrypt_buffered(ez_core_t *c, int slot, uint32_t msg_len,
                                const uint8_t **pt, uint32_t *pt_len);

/* Read-only view of retained output (IMPL-ENG-008/009); NULL if none. */
const uint8_t *ez_retained(const ez_core_t *c, uint32_t *len);
/* Clear the staging buffer and any retained output. */
void ez_release(ez_core_t *c);

/* ---- streaming ------------------------------------------------------ */
typedef struct {
	int      slot;
	uint8_t  dir;            /* 0 encrypt, 1 decrypt */
	uint8_t  active;
	uint8_t  drive;
	uint32_t key_id;
	uint32_t base;           /* absolute key offset of the message */
	uint32_t len;
	uint32_t done;           /* bytes transformed */
	uint32_t committed;      /* encryption: bytes covered by a committed TX offset */
	uint32_t crc;            /* running CRC-32 (not finalised) */
	uint32_t run0, runff;    /* current runs of 0x00 / 0xFF key bytes (IMPL-ENG-012) */
} ez_stream_t;

ez_status_t ez_enc_stream_begin(ez_core_t *c, ez_stream_t *st, int slot,
                                uint32_t len, uint8_t hdr[EZ_MSG_HDR]);
ez_status_t ez_enc_stream_update(ez_core_t *c, ez_stream_t *st, uint8_t *buf, uint32_t n);
ez_status_t ez_enc_stream_end(ez_core_t *c, ez_stream_t *st, uint8_t trl[EZ_MSG_TRL]);

ez_status_t ez_dec_stream_begin(ez_core_t *c, ez_stream_t *st, int slot,
                                const uint8_t hdr[EZ_MSG_HDR]);
ez_status_t ez_dec_stream_update(ez_core_t *c, ez_stream_t *st, uint8_t *buf, uint32_t n);
ez_status_t ez_dec_stream_end(ez_core_t *c, ez_stream_t *st, const uint8_t trl[EZ_MSG_TRL]);

void     ez_stream_abort(ez_core_t *c, ez_stream_t *st);

/* IMPL-ENG-014: after an encryption was refused because a unit ahead in
 * the TX range failed verification (reported in c->damage), move the TX
 * offset forward past that run of damaged units to the next unit that
 * verifies (or the end of the range). The bytes between are never used:
 * skipping wastes key, never reuses it. The caller must have shown the
 * user the damaged range and obtained confirmation. EZ_ERR_STATE if no
 * such damage is recorded, or it is no longer there. */
ez_status_t ez_session_skip(ez_core_t *c, int slot, uint32_t *units);
uint32_t ez_stream_spent(const ez_stream_t *st);

#endif /* EZ_ENGINE_H */
