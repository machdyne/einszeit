/*
 * ez_sha256.h -- SHA-256 (FIPS 180-4)
 *
 * Used only to compute integrity tags over key data (EZ-IMPL-001 §2.4).
 * Never used to derive, stretch or condition key material: the key
 * stream is always the key bytes themselves (EZ-SEC-001 SEC-KDF-001 as
 * clarified in Rev 1.3). Portable implementation; a port may substitute
 * the RP2350 SHA-256 accelerator behind the same interface.
 *
 * The context holds data derived from key bytes and is cleared by
 * ez_sha256_final() (SEC-FW-003).
 */
#ifndef EZ_SHA256_H
#define EZ_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t h[8];
	uint64_t len;          /* bytes processed */
	uint8_t  buf[64];
	uint32_t nbuf;
} ez_sha256_t;

void ez_sha256_init(ez_sha256_t *s);
void ez_sha256_update(ez_sha256_t *s, const void *data, size_t n);
void ez_sha256_final(ez_sha256_t *s, uint8_t out[32]);

#endif /* EZ_SHA256_H */
