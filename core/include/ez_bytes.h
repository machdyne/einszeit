/*
 * ez_bytes.h -- explicit little-endian serialisation
 *
 * All persistent and wire formats are little-endian (EZ-IMPL-001 §3, §5).
 * Fields are always (de)serialised byte by byte so that layout never
 * depends on struct packing, alignment or host byte order (IMPL-ARCH-002).
 */
#ifndef EZ_BYTES_H
#define EZ_BYTES_H

#include <stdint.h>

static inline void ez_put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void ez_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline uint16_t ez_get_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}
static inline uint32_t ez_get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#endif /* EZ_BYTES_H */
