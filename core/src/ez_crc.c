/*
 * ez_crc.c -- bitwise CRC implementations (see ez_crc.h)
 *
 * Bitwise rather than table-driven: the data volumes are small (metadata
 * records, message trailers at USB speed) and the code is trivially
 * reviewable. EZ-SEC-001 traceability: SEC-META-001, SEC-PTR-001.
 */
#include "ez_crc.h"

uint32_t ez_crc32_update(uint32_t crc, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	while (len--) {
		crc ^= *p++;
		for (int i = 0; i < 8; i++)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	}
	return crc;
}

uint32_t ez_crc32(const void *data, size_t len)
{
	return ez_crc32_final(ez_crc32_update(EZ_CRC32_INIT, data, len));
}

uint16_t ez_crc16_update(uint16_t crc, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint32_t c = crc;
	while (len--) {
		c ^= (uint32_t)*p++ << 8;
		for (int i = 0; i < 8; i++)
			c = (c & 0x8000u) ? ((c << 1) ^ 0x1021u) : (c << 1);
		c &= 0xFFFFu;
	}
	return (uint16_t)c;
}

uint16_t ez_crc16(const void *data, size_t len)
{
	return ez_crc16_update(EZ_CRC16_INIT, data, len);
}
