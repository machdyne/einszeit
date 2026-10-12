/*
 * ez_sum.h -- key integrity tags and the <KEYID>.SUM file (EZ-IMPL-001 §2.4)
 *
 * The key file stays raw random bytes. Its integrity file holds one tag
 * per 4 KiB unit. Units are counted separately within each half of the
 * key, so a unit never straddles the alice/bob boundary; the last unit of
 * each half may be shorter. Global unit index i < n covers the first
 * half, n <= i < 2n the second, n = ceil((L/2) / 4096).
 *
 *   tag(i) = first 8 bytes of SHA-256("EZ-UNIT1" || KeyID || L || i || unit)
 *
 * Binding the Key ID, length and position means a unit from another key,
 * or from elsewhere in this key, cannot verify.
 *
 * File layout (little-endian):
 *    0  4  magic "EZSU"           12  4  key length L
 *    4  1  version 1              16  4  tag count (2n)
 *    5  1  log2(unit size) = 12   20  2  instance tag (random, IMPL-KEY-005)
 *    6  1  tag length = 8         22  6  reserved (0)
 *    7  1  reserved (0)           28  4  CRC-32 of bytes 0..27
 *    8  4  Key ID                 32  .. tags, 8 bytes each, in unit order
 *
 * Tags are derived from key bytes: they are handled exactly like key
 * material -- stored only beside the key, never transmitted, never
 * logged, erased with the key (EZ-SEC-001 SEC-STORE-004, Rev 1.3).
 *
 * EZ-SEC-001 traceability: SEC-STORE-004, SEC-KDF-001 (tags never enter
 * the key stream).
 */
#ifndef EZ_SUM_H
#define EZ_SUM_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_sha256.h"
#include "ez_status.h"

#define EZ_UNIT_SIZE   4096u
#define EZ_TAG_LEN     8u
#define EZ_SUM_HDR     32u

typedef struct {
	uint32_t key_id;
	uint32_t key_len;
	uint32_t tags;
	uint16_t instance;
} ez_sum_hdr_t;

void        ez_sum_hdr_encode(const ez_sum_hdr_t *h, uint8_t out[EZ_SUM_HDR]);
/* EZ_ERR_KEY_DAMAGED on any format error (magic, version, sizes, CRC). */
ez_status_t ez_sum_hdr_decode(const uint8_t in[EZ_SUM_HDR], ez_sum_hdr_t *h);

uint32_t ez_units_per_half(uint32_t key_len);
uint32_t ez_unit_count(uint32_t key_len);
uint32_t ez_sum_size(uint32_t key_len);
/* Geometry of unit i: absolute start and length. */
void     ez_unit_geom(uint32_t key_len, uint32_t i, uint32_t *start, uint32_t *len);
/* Index of the unit holding absolute byte offset abs (abs < key_len). */
uint32_t ez_unit_index(uint32_t key_len, uint32_t abs);

void ez_unit_tag(uint32_t key_id, uint32_t key_len, uint32_t i,
                 const uint8_t *data, uint32_t len, uint8_t tag[EZ_TAG_LEN]);

/* Incremental tagger: feed the key from byte 0 in order, in pieces of any
 * size; a tag is emitted each time a unit completes. */
typedef struct {
	uint32_t key_id, key_len;
	uint32_t index;        /* unit being hashed */
	uint32_t start, len;   /* its geometry */
	uint32_t pos;          /* absolute bytes fed */
	ez_sha256_t sha;
} ez_tagger_t;

void ez_tagger_init(ez_tagger_t *t, uint32_t key_id, uint32_t key_len);
/* Consumes up to n bytes, stopping after a unit completes. Returns the
 * number consumed; if *done, tag holds the completed unit's tag and
 * *index its index. */
uint32_t ez_tagger_feed(ez_tagger_t *t, const uint8_t *p, uint32_t n,
                        bool *done, uint32_t *index, uint8_t tag[EZ_TAG_LEN]);
void ez_tagger_clear(ez_tagger_t *t);

#endif /* EZ_SUM_H */
