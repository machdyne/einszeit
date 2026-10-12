/*
 * ez_crc.h -- CRC-32 (IEEE 802.3) and CRC-16/CCITT-FALSE
 *
 * CRC-32: message trailer (EZ-IMPL-001 §5), static CRC of metadata records
 *         (§3.3, §3.4). Check value for "123456789": 0xCBF43926.
 * CRC-16: checked slots and event log entries (§3.2, §3.7).
 *         Check value for "123456789": 0x29B1.
 *
 * Both detect accidental corruption only; neither is a MAC.
 *
 * EZ-SEC-001 traceability: SEC-META-001, SEC-PTR-001 (integrity protection).
 */
#ifndef EZ_CRC_H
#define EZ_CRC_H

#include <stddef.h>
#include <stdint.h>

/* Incremental CRC-32: crc = ez_crc32_update(EZ_CRC32_INIT, ...); ...;
 * result = ez_crc32_final(crc). */
#define EZ_CRC32_INIT 0xFFFFFFFFu
uint32_t ez_crc32_update(uint32_t crc, const void *data, size_t len);
static inline uint32_t ez_crc32_final(uint32_t crc) { return crc ^ 0xFFFFFFFFu; }
uint32_t ez_crc32(const void *data, size_t len);

#define EZ_CRC16_INIT 0xFFFFu
uint16_t ez_crc16_update(uint16_t crc, const void *data, size_t len);
uint16_t ez_crc16(const void *data, size_t len);

#endif /* EZ_CRC_H */
