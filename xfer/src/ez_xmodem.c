/* ez_xmodem.c -- see ez_xmodem.h */
#include "ez_xmodem.h"

#include <string.h>

enum { R_START, R_BLOCKS, R_DONE };              /* receiving */
enum { S_START, S_ACK, S_EOT, S_DONE };          /* sending */

#define START_MS   3000u   /* receiver: 'C' / NAK every 3 s */
#define CRC_TRIES  3       /* then fall back to checksum */
#define START_MAX  10      /* ... 30 s in all */
#define BYTE_MS    1000u   /* a gap inside a packet */
#define BLOCK_MS   10000u  /* no packet / no answer */
#define SEND_START_MS 60000u
#define RETRIES    10

uint16_t ez_xm_crc16(const uint8_t *p, uint32_t n)
{
	uint16_t c = 0;
	for (uint32_t i = 0; i < n; i++) {
		c = (uint16_t)(c ^ (uint16_t)(p[i] << 8));
		for (int b = 0; b < 8; b++) c = (uint16_t)((c & 0x8000u) ? ((unsigned)c << 1) ^ 0x1021u : (unsigned)c << 1);
	}
	return c;
}

static void put1(ez_xm_t *x, uint8_t b) { x->out(x->ctx, &b, 1); }

static ez_xm_result_t fail(ez_xm_t *x, ez_xm_err_t e, bool send_can)
{
	if (send_can) { static const uint8_t can[3] = { EZ_XM_CAN, EZ_XM_CAN, EZ_XM_CAN }; x->out(x->ctx, can, 3); }
	x->result = EZ_XM_FAILED;
	x->err = e;
	return x->result;
}

void ez_xm_cancel(ez_xm_t *x) { if (x->result == EZ_XM_RUNNING) fail(x, EZ_XM_ERR_CANCELLED, true); }

const char *ez_xm_error(ez_xm_err_t e)
{
	switch (e) {
	case EZ_XM_OK:            return "ok";
	case EZ_XM_ERR_TIMEOUT:   return "no answer from the other side";
	case EZ_XM_ERR_CANCELLED: return "cancelled";
	case EZ_XM_ERR_REMOTE:    return "cancelled by the other side";
	case EZ_XM_ERR_RETRIES:   return "too many errors on the line";
	case EZ_XM_ERR_SYNC:      return "the transfer lost its place";
	case EZ_XM_ERR_SINK:      return "the file is too large";
	}
	return "?";
}

/* ---- receiving ------------------------------------------------------------ */

void ez_xm_recv(ez_xm_t *x, ez_xm_sink_fn sink, ez_xm_out_fn out, void *ctx, uint32_t now)
{
	memset(x, 0, sizeof *x);
	x->sink = sink;
	x->out = out;
	x->ctx = ctx;
	x->crc = true;
	x->expect = 1;
	x->phase = R_START;
	x->t_phase = x->t_rx = now;
	put1(x, 'C');
}

static void rx_packet(ez_xm_t *x)
{
	uint32_t dlen = x->pkt[0] == EZ_XM_STX ? 1024u : 128u;
	const uint8_t *d = x->pkt + 3;
	bool ok = (uint8_t)(x->pkt[1] ^ x->pkt[2]) == 0xFF;
	if (ok && x->crc) {
		uint16_t c = ez_xm_crc16(d, dlen);
		ok = d[dlen] == (uint8_t)(c >> 8) && d[dlen + 1] == (uint8_t)c;
	} else if (ok) {
		uint8_t s = 0;
		for (uint32_t i = 0; i < dlen; i++) s = (uint8_t)(s + d[i]);
		ok = d[dlen] == s;
	}
	x->pkt_n = 0;
	if (!ok) {
		if (++x->tries > RETRIES) { fail(x, EZ_XM_ERR_RETRIES, true); return; }
		put1(x, EZ_XM_NAK);
		return;
	}
	uint8_t blk = x->pkt[1];
	if (blk == x->expect) {
		if (!x->sink(x->ctx, d, dlen)) { fail(x, EZ_XM_ERR_SINK, true); return; }
		x->total += dlen;
		x->expect++;
		x->tries = 0;
		put1(x, EZ_XM_ACK);
	} else if (blk == (uint8_t)(x->expect - 1)) {
		put1(x, EZ_XM_ACK);                      /* our ACK was lost: a repeat */
	} else {
		fail(x, EZ_XM_ERR_SYNC, true);
	}
}

static void rx_byte(ez_xm_t *x, uint8_t b)
{
	if (x->pkt_n == 0) {
		if (b == EZ_XM_CAN) { if (++x->cans >= 2) fail(x, EZ_XM_ERR_REMOTE, false); return; }
		x->cans = 0;
		if (b == EZ_XM_SOH || b == EZ_XM_STX) {
			x->pkt_need = 3u + (b == EZ_XM_STX ? 1024u : 128u) + (x->crc ? 2u : 1u);
			x->pkt[x->pkt_n++] = b;
			x->phase = R_BLOCKS;
		} else if (b == EZ_XM_EOT) {                    /* the end (straight away: an empty file) */
			put1(x, EZ_XM_ACK);
			x->phase = R_DONE;
			x->result = EZ_XM_DONE;
		}
		return;                                  /* anything else between packets: noise */
	}
	x->pkt[x->pkt_n++] = b;
	if (x->pkt_n == x->pkt_need) rx_packet(x);
}

/* ---- sending -------------------------------------------------------------- */

static void tx_block(ez_xm_t *x)
{
	uint32_t left = x->len - x->off;
	x->blk_len = x->k1 && left > 128u ? 1024u : 128u;
	uint8_t h[3] = { x->blk_len == 1024u ? EZ_XM_STX : EZ_XM_SOH, x->blk, (uint8_t)~x->blk };
	static uint8_t d[1024 + 2];
	uint32_t n = left < x->blk_len ? left : x->blk_len;
	memcpy(d, x->data + x->off, n);
	memset(d + n, EZ_XM_SUB, x->blk_len - n);
	uint32_t t;
	if (x->crc) {
		uint16_t c = ez_xm_crc16(d, x->blk_len);
		d[x->blk_len] = (uint8_t)(c >> 8);
		d[x->blk_len + 1] = (uint8_t)c;
		t = x->blk_len + 2;
	} else {
		uint8_t s = 0;
		for (uint32_t i = 0; i < x->blk_len; i++) s = (uint8_t)(s + d[i]);
		d[x->blk_len] = s;
		t = x->blk_len + 1;
	}
	x->out(x->ctx, h, 3);
	x->out(x->ctx, d, t);
	x->phase = S_ACK;
}

static void tx_next(ez_xm_t *x, uint32_t now)
{
	x->t_phase = now;
	x->tries = 0;
	if (x->off >= x->len) { put1(x, EZ_XM_EOT); x->phase = S_EOT; }
	else tx_block(x);
}

void ez_xm_send(ez_xm_t *x, const uint8_t *data, uint32_t len, bool allow_1k,
                ez_xm_out_fn out, void *ctx, uint32_t now)
{
	memset(x, 0, sizeof *x);
	x->sending = 1;
	x->out = out;
	x->ctx = ctx;
	x->data = data;
	x->len = len;
	x->allow_1k = allow_1k;
	x->blk = 1;
	x->phase = S_START;
	x->t_phase = now;
}

static void tx_byte(ez_xm_t *x, uint8_t b, uint32_t now)
{
	if (b == EZ_XM_CAN) { if (++x->cans >= 2) fail(x, EZ_XM_ERR_REMOTE, false); return; }
	x->cans = 0;
	switch (x->phase) {
	case S_START:
		if (b == 'C') { x->crc = true; x->k1 = x->allow_1k; }
		else if (b == EZ_XM_NAK) { x->crc = false; x->k1 = false; }
		else return;
		tx_next(x, now);
		return;
	case S_ACK:
		if (b == EZ_XM_ACK) {
			x->off += x->blk_len < x->len - x->off ? x->blk_len : x->len - x->off;
			x->total = x->off;
			x->blk++;
			tx_next(x, now);
		} else if (b == EZ_XM_NAK || (b == 'C' && x->blk == 1)) {
			if (++x->tries > RETRIES) { fail(x, EZ_XM_ERR_RETRIES, true); return; }
			x->t_phase = now;
			tx_block(x);
		}
		return;
	case S_EOT:
		if (b == EZ_XM_ACK) { x->phase = S_DONE; x->result = EZ_XM_DONE; }
		else if (b == EZ_XM_NAK) {
			if (++x->tries > RETRIES) { fail(x, EZ_XM_ERR_RETRIES, true); return; }
			x->t_phase = now;
			put1(x, EZ_XM_EOT);
		}
		return;
	}
}

/* ---- common --------------------------------------------------------------- */

ez_xm_result_t ez_xm_input(ez_xm_t *x, const uint8_t *b, uint32_t n, uint32_t now)
{
	for (uint32_t i = 0; i < n && x->result == EZ_XM_RUNNING; i++) {
		x->t_rx = now;
		if (x->sending) tx_byte(x, b[i], now);
		else rx_byte(x, b[i]);
	}
	return x->result;
}

ez_xm_result_t ez_xm_tick(ez_xm_t *x, uint32_t now)
{
	if (x->result != EZ_XM_RUNNING) return x->result;
	if (!x->sending) {
		if (x->phase == R_START) {
			if (now - x->t_phase < START_MS) return x->result;
			x->t_phase = now;
			if (++x->tries >= START_MAX) return fail(x, EZ_XM_ERR_TIMEOUT, true);
			if (x->tries >= CRC_TRIES) x->crc = false;           /* an old sender: checksum */
			put1(x, x->crc ? 'C' : EZ_XM_NAK);
			return x->result;
		}
		if (x->pkt_n && now - x->t_rx > BYTE_MS) {              /* a broken packet */
			x->pkt_n = 0;
			x->t_rx = now;
			if (++x->tries > RETRIES) return fail(x, EZ_XM_ERR_RETRIES, true);
			put1(x, EZ_XM_NAK);
		} else if (!x->pkt_n && now - x->t_rx > BLOCK_MS) {
			x->t_rx = now;
			if (++x->tries > RETRIES) return fail(x, EZ_XM_ERR_TIMEOUT, true);
			put1(x, EZ_XM_NAK);
		}
		return x->result;
	}
	if (x->phase == S_START) {
		if (now - x->t_phase > SEND_START_MS) return fail(x, EZ_XM_ERR_TIMEOUT, true);
		return x->result;
	}
	if (now - x->t_phase > BLOCK_MS) {
		x->t_phase = now;
		if (++x->tries > RETRIES) return fail(x, EZ_XM_ERR_TIMEOUT, true);
		if (x->phase == S_ACK) tx_block(x);
		else put1(x, EZ_XM_EOT);
	}
	return x->result;
}
