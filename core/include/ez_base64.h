/*
 * ez_base64.h -- RFC 4648 base64 (standard alphabet, '=' padding)
 *
 * Used by the device console and the host CLI to carry messages over text
 * channels (EZ-IMPL-001 §5). Not an OTP operation (SEC-HW-001).
 *
 * The decoder is incremental, so input may arrive in arbitrary pieces.
 * Whitespace (space, tab, CR, LF) is skipped so that pasted, wrapped text
 * decodes; every other non-alphabet character, misplaced padding, data
 * after padding, or non-zero pad bits is an error.
 */
#ifndef EZ_BASE64_H
#define EZ_BASE64_H

#include <stddef.h>
#include <stdint.h>

#include "ez_status.h"

/* Output length for n input bytes (no terminator). */
static inline size_t ez_b64_enc_len(size_t n) { return (n + 2) / 3 * 4; }

/* One-shot encode; out must hold ez_b64_enc_len(n) bytes. Returns length. */
size_t ez_b64_encode(const uint8_t *in, size_t n, char *out);

/* Incremental encoder: feed any amount; output is emitted 4 chars per 3
 * bytes. Call ez_b64_enc_final once. Buffers must hold 4*(n/3+2) chars. */
typedef struct { uint8_t pend[2]; uint8_t npend; } ez_b64_enc_t;
void   ez_b64_enc_init(ez_b64_enc_t *e);
size_t ez_b64_enc_update(ez_b64_enc_t *e, const uint8_t *in, size_t n, char *out);
size_t ez_b64_enc_final(ez_b64_enc_t *e, char *out);

typedef struct {
	uint32_t acc;
	uint8_t  nacc;     /* sextets accumulated in the current quantum */
	uint8_t  npad;     /* '=' seen */
	uint8_t  done;     /* padding complete: only whitespace may follow */
	uint8_t  err;
} ez_b64_dec_t;

void ez_b64_dec_init(ez_b64_dec_t *d);
/* Decodes what it can; writes at most 3*(n/4+1) bytes to out and returns
 * the count via *out_n. EZ_ERR_BAD_REQUEST on malformed input. */
ez_status_t ez_b64_dec_update(ez_b64_dec_t *d, const char *in, size_t n,
                              uint8_t *out, size_t *out_n);
/* Checks that the input ended on a quantum boundary. */
ez_status_t ez_b64_dec_final(ez_b64_dec_t *d);

#endif /* EZ_BASE64_H */
