/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-ENTROPY-001, SEC-DIST-001 -- captures are tagged as non-key material.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <string.h>

#include "ez_container.h"
#include "ez_xmodem.h"

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void ez_container_write_header(uint8_t *hdr, const uint8_t *payload,
                               uint32_t payload_len, const char *meta)
{
    memset(hdr, 0, EZ_HDR_BYTES);
    memcpy(hdr, EZ_MAGIC, 8);

    size_t meta_len = meta ? strlen(meta) : 0;
    if (meta_len > EZ_META_MAX) meta_len = EZ_META_MAX;

    put_le32(hdr + 8,  EZ_HDR_BYTES);
    put_le32(hdr + 12, payload_len);
    put_le32(hdr + 16, ez_crc32(payload, payload_len));
    put_le32(hdr + 20, (uint32_t)meta_len);
    if (meta_len) memcpy(hdr + 24, meta, meta_len);
}
