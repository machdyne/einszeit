/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Deviates SEC-DIST-001  entropy leaves the device over USB for analysis;
 *            the payload is characterisation data, not key material (D-05).
 *
 * Bench validation firmware. Not a production artifact.
 */

#ifndef EZ_XMODEM_H
#define EZ_XMODEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    EZ_XM_OK = 0,
    EZ_XM_NO_RECEIVER,   /* receiver never sent 'C' or NAK */
    EZ_XM_CANCELLED,     /* receiver sent CAN CAN          */
    EZ_XM_TOO_MANY_NAKS,
    EZ_XM_NO_EOT_ACK,
} ez_xm_result_t;

typedef struct {
    uint32_t blocks_sent;
    uint32_t retransmits;
    bool     crc_mode;       /* false = 8-bit checksum fallback */
    uint64_t elapsed_us;
} ez_xm_stats_t;

/*
 * Send `len` bytes as XMODEM-1K (STX/1024 blocks, falling back to SOH/128 for
 * a short tail). Blocks the CLI until the transfer finishes or aborts.
 *
 * The caller must have disabled CRLF translation on the USB stdio driver
 * first, otherwise every 0x0A in the payload becomes 0x0D 0x0A.
 */
ez_xm_result_t ez_xmodem_send(const uint8_t *data, size_t len, ez_xm_stats_t *st);

const char *ez_xmodem_strerror(ez_xm_result_t r);

/* CRC-32 (IEEE 802.3, reflected) used for the payload integrity field. */
uint32_t ez_crc32(const uint8_t *data, size_t len);

#endif /* EZ_XMODEM_H */
