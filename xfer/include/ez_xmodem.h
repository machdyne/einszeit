/*
 * ez_xmodem.h -- XMODEM, XMODEM-CRC and XMODEM-1K, both directions.
 *
 * Written for Einszeit from the protocol's description (Christensen 1977;
 * Forsberg's XMODEM/YMODEM reference); no code is taken from elsewhere.
 * Portable C11, no heap, never blocks: bytes go in through ez_xm_input(),
 * out through the out() callback, and ez_xm_tick() handles the timeouts.
 * The other transfer protocols live in their own modules beside it.
 *
 * Receiving: asks for CRC mode ('C') three times, then checksum mode (NAK);
 * accepts 128- and 1024-byte blocks; data goes to sink() block by block.
 * XMODEM has no file length: the sender pads the last block with SUB (0x1A).
 * Sending: 1024-byte blocks when the receiver asked for CRC (and 1K is
 * allowed), 128-byte blocks otherwise and for a short tail; EOT at the end.
 */
#ifndef EZ_XMODEM_H
#define EZ_XMODEM_H

#include <stdbool.h>
#include <stdint.h>

#define EZ_XM_SOH 0x01
#define EZ_XM_STX 0x02
#define EZ_XM_EOT 0x04
#define EZ_XM_ACK 0x06
#define EZ_XM_NAK 0x15
#define EZ_XM_CAN 0x18
#define EZ_XM_SUB 0x1A

typedef enum { EZ_XM_RUNNING, EZ_XM_DONE, EZ_XM_FAILED } ez_xm_result_t;
typedef enum {
	EZ_XM_OK, EZ_XM_ERR_TIMEOUT, EZ_XM_ERR_CANCELLED, EZ_XM_ERR_REMOTE,
	EZ_XM_ERR_RETRIES, EZ_XM_ERR_SYNC, EZ_XM_ERR_SINK
} ez_xm_err_t;

typedef void (*ez_xm_out_fn)(void *ctx, const uint8_t *b, uint32_t n);
/* Receiving: a block's data. false stops the transfer (e.g. too large). */
typedef bool (*ez_xm_sink_fn)(void *ctx, const uint8_t *b, uint32_t n);

typedef struct {
	ez_xm_out_fn  out;
	ez_xm_sink_fn sink;
	void *ctx;
	int   sending, phase;
	ez_xm_result_t result;
	ez_xm_err_t err;
	bool  crc, k1;
	uint32_t t_phase, t_rx;      /* ms: when the phase began, when a byte last came */
	int   tries, cans;
	/* receiving */
	uint8_t  pkt[3 + 1024 + 2];
	uint32_t pkt_n, pkt_need;
	uint8_t  expect;
	uint32_t total;              /* data bytes received (sink) or acknowledged (send) */
	/* sending */
	const uint8_t *data;
	uint32_t len, off, blk_len;
	uint8_t  blk;
	bool     allow_1k;
} ez_xm_t;

void ez_xm_recv(ez_xm_t *x, ez_xm_sink_fn sink, ez_xm_out_fn out, void *ctx, uint32_t now_ms);
void ez_xm_send(ez_xm_t *x, const uint8_t *data, uint32_t len, bool allow_1k,
                ez_xm_out_fn out, void *ctx, uint32_t now_ms);
ez_xm_result_t ez_xm_input(ez_xm_t *x, const uint8_t *b, uint32_t n, uint32_t now_ms);
ez_xm_result_t ez_xm_tick(ez_xm_t *x, uint32_t now_ms);
void ez_xm_cancel(ez_xm_t *x);              /* sends CAN x3; result FAILED, CANCELLED */
const char *ez_xm_error(ez_xm_err_t e);
uint16_t ez_xm_crc16(const uint8_t *p, uint32_t n);   /* CRC-16/XMODEM (CCITT, 0x1021, init 0) */

#endif
