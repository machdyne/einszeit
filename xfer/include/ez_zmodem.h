/*
 * ez_zmodem.h -- ZMODEM, one file each way.
 *
 * Written for Einszeit from Chuck Forsberg's description ("The ZMODEM Inter
 * Application File Transfer Protocol", 1988); no code is taken from
 * elsewhere. Portable C11, no heap, never blocks (the common shape of the
 * xfer/ modules: bytes in through ez_zm_input(), out through out(), time
 * through ez_zm_tick(), received data through sink()).
 *
 * Supported:
 *   - hex headers; binary headers with CRC-16 (ZBIN) or CRC-32 (ZBIN32)
 *   - data subpackets with every frame end (ZCRCE, ZCRCG, ZCRCQ, ZCRCW)
 *   - ZDLE escaping both ways, ZRUB0/ZRUB1, and all control characters
 *     when the receiver asks (ESCCTL); XON/XOFF on the line are ignored
 *   - recovery from damaged or lost data with ZRPOS; the five-CAN abort
 * Receiving: one file, with its exact length (ZFILE); a file over max_len,
 * and any further file in a batch, is refused with ZSKIP. ZCOMMAND is never
 * executed: it aborts the transfer.
 * Sending: "rz\r" and ZRQINIT, so terminals start their receiver by
 * themselves; CRC-32 when the receiver can; 1 KiB subpackets in 4 KiB
 * windows, each ending ZCRCW and acknowledged.
 */
#ifndef EZ_ZMODEM_H
#define EZ_ZMODEM_H

#include <stdbool.h>
#include <stdint.h>

typedef enum { EZ_ZM_RUNNING, EZ_ZM_DONE, EZ_ZM_FAILED } ez_zm_result_t;
typedef enum {
	EZ_ZM_OK, EZ_ZM_ERR_TIMEOUT, EZ_ZM_ERR_CANCELLED, EZ_ZM_ERR_REMOTE,
	EZ_ZM_ERR_RETRIES, EZ_ZM_ERR_SINK, EZ_ZM_ERR_SKIPPED, EZ_ZM_ERR_PROTOCOL
} ez_zm_err_t;

typedef void (*ez_zm_out_fn)(void *ctx, const uint8_t *b, uint32_t n);
/* Receiving: file data, in order. false stops the transfer. */
typedef bool (*ez_zm_sink_fn)(void *ctx, const uint8_t *b, uint32_t n);

#define EZ_ZM_SUBPKT_MAX 8192u       /* the largest data subpacket accepted */

typedef struct {
	ez_zm_out_fn  out;
	ez_zm_sink_fn sink;
	void *ctx;
	bool  sending;
	int   state;
	ez_zm_result_t result;
	ez_zm_err_t err;
	uint32_t t_wait, t_rx;           /* ms: when we last sent, when a byte last came */
	int   tries, cans;
	/* the line parser (both directions) */
	int   hp;                        /* header parser state */
	uint8_t hfmt, hbuf[10];
	int   hn, hneed;
	bool  zdle;                      /* the previous byte was ZDLE */
	int   skip_crlf;                 /* a hex header's CR LF still to come */
	bool  in_data;                   /* reading a data subpacket */
	bool  data32;                    /* its CRC is 32 bits */
	uint8_t  sub[EZ_ZM_SUBPKT_MAX + 1];
	uint32_t sub_n;
	int   sub_end, crc_n;            /* frame end seen (0 none); CRC bytes read */
	uint8_t crc_b[4];
	int   want_sub;                  /* which header's subpacket is being read */
	/* the transfer */
	uint32_t pos, len, max_len, wend;
	uint32_t blk, win;                /* sending: subpacket and window size (they shrink on errors) */
	uint32_t good_pos;                /* sending: the furthest position acknowledged */
	uint32_t last_sync;               /* sending: the last ZRPOS position, and how often in a row */
	int      sync_repeats;
	bool  len_known, got_file, crc32, escctl, last_at;
	char  name[64];
	const uint8_t *data;
	uint8_t last_type;               /* receiving: the last header sent, for timeouts and ZNAK */
	uint32_t last_arg;
	uint32_t total;                  /* bytes received (sink) or acknowledged (send) */
} ez_zm_t;

void ez_zm_recv(ez_zm_t *z, ez_zm_sink_fn sink, uint32_t max_len, ez_zm_out_fn out, void *ctx, uint32_t now_ms);
void ez_zm_send(ez_zm_t *z, const uint8_t *data, uint32_t len, const char *name,
                ez_zm_out_fn out, void *ctx, uint32_t now_ms);
ez_zm_result_t ez_zm_input(ez_zm_t *z, const uint8_t *b, uint32_t n, uint32_t now_ms);
ez_zm_result_t ez_zm_tick(ez_zm_t *z, uint32_t now_ms);
void ez_zm_cancel(ez_zm_t *z);             /* sends the CAN abort; FAILED, CANCELLED */
const char *ez_zm_error(ez_zm_err_t e);
/* CRC-32 (IEEE 802.3, reflected 0xEDB88320) update; start with ~0, finish with ~. */
uint32_t ez_zm_crc32(uint32_t crc, const uint8_t *p, uint32_t n);
uint16_t ez_zm_crc16(uint16_t crc, const uint8_t *p, uint32_t n);   /* CRC-16/XMODEM update */

#endif
