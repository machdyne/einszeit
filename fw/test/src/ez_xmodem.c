/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Deviation D-05 (SEC-DIST-001): transfers characterisation data only.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <string.h>

#include "pico/stdlib.h"
#include "pico/stdio.h"
#include "pico/stdio_usb.h"

#include "ez_xmodem.h"

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18
#define SUB 0x1A   /* pad byte */

#define HANDSHAKE_TIMEOUT_MS 60000
#define ACK_TIMEOUT_MS       10000
#define MAX_RETRIES          10

static uint16_t crc16_xmodem(const uint8_t *p, size_t n)
{
    uint16_t crc = 0;
    while (n--) {
        crc ^= (uint16_t)(*p++) << 8;
        for (int i = 0; i < 8; i++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

uint32_t ez_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

/* Raw byte output; cr_translation is off so binary passes through intact. */
static void xm_write(const uint8_t *p, size_t n)
{
    stdio_put_string((const char *)p, (int)n, false, false);
}

static void xm_flush(void)
{
    stdio_flush();
}

static int xm_getc_ms(uint32_t ms)
{
    return getchar_timeout_us((uint32_t)ms * 1000u);
}

static void xm_cancel(void)
{
    static const uint8_t cans[] = { CAN, CAN, CAN, CAN, CAN };
    xm_write(cans, sizeof(cans));
    xm_flush();
}

ez_xm_result_t ez_xmodem_send(const uint8_t *data, size_t len, ez_xm_stats_t *st)
{
    uint8_t block[3 + 1024 + 2];
    memset(st, 0, sizeof(*st));

    /* --- handshake: receiver drives the mode ---------------------------- */
    bool crc_mode = true;
    bool started = false;
    absolute_time_t hs_deadline = make_timeout_time_ms(HANDSHAKE_TIMEOUT_MS);

    while (!started) {
        int c = xm_getc_ms(1000);
        if (c == 'C')      { crc_mode = true;  started = true; }
        else if (c == NAK) { crc_mode = false; started = true; }
        else if (c == CAN) { return EZ_XM_CANCELLED; }
        if (absolute_time_diff_us(get_absolute_time(), hs_deadline) < 0)
            return EZ_XM_NO_RECEIVER;
    }
    st->crc_mode = crc_mode;

    uint64_t t0 = time_us_64();
    size_t offset = 0;
    uint8_t blkno = 1;

    while (offset < len) {
        size_t remaining = len - offset;
        size_t payload = (remaining > 128) ? 1024 : 128;

        block[0] = (payload == 1024) ? STX : SOH;
        block[1] = blkno;
        block[2] = (uint8_t)~blkno;

        size_t copy = (remaining < payload) ? remaining : payload;
        memcpy(&block[3], &data[offset], copy);
        if (copy < payload) memset(&block[3 + copy], SUB, payload - copy);

        size_t total;
        if (crc_mode) {
            uint16_t crc = crc16_xmodem(&block[3], payload);
            block[3 + payload]     = (uint8_t)(crc >> 8);
            block[3 + payload + 1] = (uint8_t)(crc & 0xff);
            total = 3 + payload + 2;
        } else {
            uint8_t sum = 0;
            for (size_t i = 0; i < payload; i++) sum = (uint8_t)(sum + block[3 + i]);
            block[3 + payload] = sum;
            total = 3 + payload + 1;
        }

        int retries = 0;
        for (;;) {
            xm_write(block, total);
            xm_flush();

            int c = xm_getc_ms(ACK_TIMEOUT_MS);
            if (c == ACK) break;
            if (c == CAN) { xm_cancel(); return EZ_XM_CANCELLED; }

            /* NAK, garbage or timeout -- resend the same block. */
            st->retransmits++;
            if (++retries >= MAX_RETRIES) { xm_cancel(); return EZ_XM_TOO_MANY_NAKS; }
        }

        offset += copy;
        blkno++;
        st->blocks_sent++;
    }

    /* --- end of transmission -------------------------------------------- */
    for (int i = 0; i < MAX_RETRIES; i++) {
        uint8_t eot = EOT;
        xm_write(&eot, 1);
        xm_flush();
        int c = xm_getc_ms(ACK_TIMEOUT_MS);
        if (c == ACK) {
            st->elapsed_us = time_us_64() - t0;
            return EZ_XM_OK;
        }
        if (c == CAN) return EZ_XM_CANCELLED;
    }
    st->elapsed_us = time_us_64() - t0;
    return EZ_XM_NO_EOT_ACK;
}

const char *ez_xmodem_strerror(ez_xm_result_t r)
{
    switch (r) {
    case EZ_XM_OK:            return "ok";
    case EZ_XM_NO_RECEIVER:   return "receiver did not start (no C/NAK)";
    case EZ_XM_CANCELLED:     return "cancelled by receiver";
    case EZ_XM_TOO_MANY_NAKS: return "too many retransmits";
    case EZ_XM_NO_EOT_ACK:    return "EOT not acknowledged";
    default:                  return "unknown";
    }
}
