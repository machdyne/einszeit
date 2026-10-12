/* ez_xfer.c -- see ez_xfer.h */
#include "ez_xfer.h"

#include <stdio.h>
#include <string.h>

void ez_xf_recv(ez_xf_t *x, ez_xf_sink_fn sink, uint32_t max_len, ez_xf_out_fn out, void *ctx, uint32_t now)
{
	memset(x, 0, sizeof *x);
	x->sink = sink;
	x->out = out;
	x->ctx = ctx;
	x->max_len = max_len;
	x->proto = EZ_XF_ZMODEM;                         /* ZMODEM first: see ez_xfer.h */
	x->t0 = now;
	ez_zm_recv(&x->u.zm, sink, max_len, out, ctx, now);
}

#define ZMODEM_FIRST_MS 6000u

void ez_xf_recv_zmodem(ez_xf_t *x, ez_xf_sink_fn sink, uint32_t max_len, ez_xf_out_fn out, void *ctx,
                       const uint8_t *seen, uint32_t n, uint32_t now)
{
	memset(x, 0, sizeof *x);
	x->sink = sink;
	x->out = out;
	x->ctx = ctx;
	x->max_len = max_len;
	x->proto = EZ_XF_ZMODEM;
	x->locked = true;
	ez_zm_recv(&x->u.zm, sink, max_len, out, ctx, now);
	if (n) ez_zm_input(&x->u.zm, seen, n, now);
}

void ez_xf_send(ez_xf_t *x, const uint8_t *data, uint32_t len, const char *name,
                ez_xf_out_fn out, void *ctx, uint32_t now)
{
	memset(x, 0, sizeof *x);
	x->sending = true;
	x->out = out;
	x->ctx = ctx;
	x->data = data;
	x->len = len;
	snprintf(x->name, sizeof x->name, "%s", name ? name : "file");
	x->proto = EZ_XF_ZMODEM;
	ez_zm_send(&x->u.zm, data, len, x->name, out, ctx, now);
}

static ez_xf_result_t map_xm(ez_xm_result_t r) { return r == EZ_XM_RUNNING ? EZ_XF_RUNNING : r == EZ_XM_DONE ? EZ_XF_DONE : EZ_XF_FAILED; }
static ez_xf_result_t map_zm(ez_zm_result_t r) { return r == EZ_ZM_RUNNING ? EZ_XF_RUNNING : r == EZ_ZM_DONE ? EZ_XF_DONE : EZ_XF_FAILED; }

static ez_xf_result_t result(const ez_xf_t *x)
{
	return x->proto == EZ_XF_XMODEM ? map_xm(x->u.xm.result) : map_zm(x->u.zm.result);
}

ez_xf_result_t ez_xf_input(ez_xf_t *x, const uint8_t *b, uint32_t n, uint32_t now)
{
	if (x->locked) {
		if (x->proto == EZ_XF_XMODEM) ez_xm_input(&x->u.xm, b, n, now);
		else ez_zm_input(&x->u.zm, b, n, now);
		return result(x);
	}
	/* Undecided: byte by byte, watching for the other protocol. */
	for (uint32_t i = 0; i < n && result(x) == EZ_XF_RUNNING; i++) {
		if (x->locked) {
			if (x->proto == EZ_XF_XMODEM) ez_xm_input(&x->u.xm, b + i, n - i, now);
			else ez_zm_input(&x->u.zm, b + i, n - i, now);
			break;
		}
		uint8_t c = b[i];
		if (!x->sending && x->proto == EZ_XF_ZMODEM) {
			/* The ZMODEM-first phase: ZPAD ZDLE from the other side means a
			 * ZMODEM sender; it stays ZMODEM. */
			if (x->prev == '*' && c == 0x18) x->locked = true;
			x->prev = c;
			ez_zm_input(&x->u.zm, &c, 1, now);
			continue;
		}
		if (!x->sending) {
			/* An XMODEM receiver waiting for its first packet sees ZPAD ZDLE:
			 * a ZMODEM sender. Restart as a ZMODEM receiver. */
			if (x->prev == '*' && c == 0x18 && x->u.xm.pkt_n == 0) {
				static const uint8_t zp[2] = { '*', 0x18 };
				ez_xf_recv_zmodem(x, x->sink, x->max_len, x->out, x->ctx, zp, 2, now);
				if (i + 1 < n) ez_zm_input(&x->u.zm, b + i + 1, n - i - 1, now);
				break;
			}
			x->prev = c;
			ez_xm_input(&x->u.xm, &c, 1, now);
			if (x->u.xm.total > 0) x->locked = true;        /* a packet arrived: XMODEM */
		} else {
			/* A ZMODEM sender still announcing itself hears 'C' or NAK
			 * outside any header: an XMODEM receiver. Restart as XMODEM. */
			if ((c == 'C' || c == EZ_XM_NAK) && x->u.zm.state == 0 && x->u.zm.hp == 0) {
				x->proto = EZ_XF_XMODEM;
				x->locked = true;
				ez_xm_send(&x->u.xm, x->data, x->len, true, x->out, x->ctx, now);
				ez_xm_input(&x->u.xm, b + i, n - i, now);
				break;
			}
			ez_zm_input(&x->u.zm, &c, 1, now);
			if (x->u.zm.state != 0) x->locked = true;       /* a ZMODEM receiver answered */
		}
	}
	return result(x);
}

ez_xf_result_t ez_xf_tick(ez_xf_t *x, uint32_t now)
{
	/* No ZMODEM sender in the first seconds: ask as an XMODEM receiver. */
	if (!x->sending && !x->locked && x->proto == EZ_XF_ZMODEM && now - x->t0 >= ZMODEM_FIRST_MS &&
	    x->u.zm.result == EZ_ZM_RUNNING) {
		x->proto = EZ_XF_XMODEM;
		x->prev = 0;
		ez_xm_recv(&x->u.xm, x->sink, x->out, x->ctx, now);
		return EZ_XF_RUNNING;
	}
	/* Until then, ZMODEM's own repeats stay quiet: every ZMODEM header
	 * carries a CAN, and two CANs cancel an XMODEM sender (lrzsz's sx). A
	 * ZMODEM sender's ZRQINIT is still answered, from ez_xf_input(). */
	if (!x->sending && !x->locked && x->proto == EZ_XF_ZMODEM) return result(x);
	if (x->proto == EZ_XF_XMODEM) ez_xm_tick(&x->u.xm, now);
	else ez_zm_tick(&x->u.zm, now);
	return result(x);
}

void ez_xf_cancel(ez_xf_t *x)
{
	if (x->proto == EZ_XF_XMODEM) ez_xm_cancel(&x->u.xm);
	else ez_zm_cancel(&x->u.zm);
}

const char *ez_xf_error(const ez_xf_t *x)
{
	return x->proto == EZ_XF_XMODEM ? ez_xm_error(x->u.xm.err) : ez_zm_error(x->u.zm.err);
}

const char *ez_xf_proto_name(const ez_xf_t *x) { return x->proto == EZ_XF_XMODEM ? "XMODEM" : "ZMODEM"; }

bool ez_xf_padded(const ez_xf_t *x) { return !x->sending && x->proto == EZ_XF_XMODEM; }
