/*
 * ez_container.h -- framing for entropy captures sent over XMODEM
 *
 * XMODEM pads the last block to a 128/1024-byte boundary with 0x1A. Padding
 * bytes fed into an entropy estimator would drag the min-entropy figure down,
 * so every transfer carries a fixed 512-byte header giving the exact payload
 * length and a CRC-32 over it. The host trims the padding and verifies the CRC
 * before anything reaches the statistics code.
 *
 *   offset  size       field
 *   0       8          magic "EZTB0001"
 *   8       4          header_len (always EZ_HDR_BYTES), LE
 *   12      4          payload_len, LE
 *   16      4          payload CRC-32 (IEEE, reflected), LE
 *   20      4          meta_len, LE
 *   24      meta_len   metadata, JSON, ASCII
 *   ...                zero fill to EZ_HDR_BYTES
 *   1024    payload_len  raw capture bytes
 *
 * The header was 512 bytes in 1.0.0 and is 1024 from 1.1.0; the host reads
 * header_len rather than assuming, so both parse. Metadata that would overrun
 * the header is a hard error rather than a silent truncation, because a
 * truncated JSON object fails to parse on the host after the capture has
 * already cost minutes or hours to collect.
 */

/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-ENTROPY-001, SEC-DIST-001  every capture carries key_material:false
 *                  and a usage string; captures are characterisation data and
 *                  must never be used as key material (deviation D-05).
 *
 * Bench validation firmware. Not a production artifact.
 */
#ifndef EZ_CONTAINER_H
#define EZ_CONTAINER_H

#include <stddef.h>
#include <stdint.h>

#define EZ_MAGIC      "EZTB0001"
#define EZ_HDR_BYTES  1024u
#define EZ_META_MAX   (EZ_HDR_BYTES - 24u)

/*
 * Writes the header into hdr[0..EZ_HDR_BYTES) describing a payload of
 * payload_len bytes that immediately follows it. `meta` is a JSON string.
 */
void ez_container_write_header(uint8_t *hdr, const uint8_t *payload,
                               uint32_t payload_len, const char *meta);

#endif /* EZ_CONTAINER_H */
