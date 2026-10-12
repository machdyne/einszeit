/*
 * ez_msg.h -- message format version 1 (EZ-IMPL-001 §5)
 *
 *   0  2  magic 0x455A        8  4  OTP offset (absolute, into the key)
 *   2  1  version 0x01       12  4  plaintext length N
 *   3  1  flags (0)          16  N  ciphertext
 *   4  4  Key ID (non-zero)  16+N 4 CRC-32 over bytes 0 .. 15+N
 *
 * EZ-SEC-001 traceability: SEC-ENC-004 (offset in header), SEC-TX-002
 * (nothing beyond header, ciphertext and CRC), SEC-DEC-002 (Key ID).
 */
#ifndef EZ_MSG_H
#define EZ_MSG_H

#include <stdint.h>

#include "ez_status.h"

#define EZ_MSG_HDR        16u
#define EZ_MSG_TRL        4u
#define EZ_MSG_OVERHEAD   (EZ_MSG_HDR + EZ_MSG_TRL)
#define EZ_MSG_VERSION    0x01

typedef struct {
	uint32_t key_id;
	uint32_t offset;
	uint32_t length;
} ez_msg_hdr_t;

void ez_msg_hdr_encode(const ez_msg_hdr_t *h, uint8_t out[EZ_MSG_HDR]);
/* Rejects wrong magic/version, non-zero flags, Key ID 0, and
 * offset + length overflowing 32 bits (EZ_ERR_BAD_REQUEST). */
ez_status_t ez_msg_hdr_decode(const uint8_t in[EZ_MSG_HDR], ez_msg_hdr_t *h);

#endif /* EZ_MSG_H */
