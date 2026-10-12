/*
 * test_xfer.c -- automatic protocol detection (xfer/ez_xfer): our auto
 * receiver and sender against plain XMODEM and ZMODEM peers, over a
 * simulated line. Against lrzsz: tests/xfer/test_interop.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ez_test.h"
#include "ez_xfer.h"

#define QCAP (1u << 20)
typedef struct { uint8_t *b; uint32_t head, tail; } q_t;
static q_t to_a, to_b;            /* auto side -> peer, peer -> auto side */
static uint32_t now, rng = 77;
static void q_put(q_t *q, const uint8_t *b, uint32_t n) { for (uint32_t i = 0; i < n; i++) q->b[q->head++ % QCAP] = b[i]; }
static void out_auto(void *c, const uint8_t *b, uint32_t n) { (void)c; q_put(&to_a, b, n); }
static void out_peer(void *c, const uint8_t *b, uint32_t n) { (void)c; q_put(&to_b, b, n); }

static uint8_t got[1u << 17];
static uint32_t got_n;
static bool sink(void *c, const uint8_t *b, uint32_t n)
{
	(void)c;
	if (got_n + n > sizeof got) return false;
	memcpy(got + got_n, b, n);
	got_n += n;
	return true;
}

static ez_xf_t xf;
static ez_xm_t pxm;
static ez_zm_t pzm;
static int peer;                   /* 1 XMODEM, 2 ZMODEM */
static uint8_t data[60000];

static bool peer_running(void) { return peer == 1 ? pxm.result == EZ_XM_RUNNING : pzm.result == EZ_ZM_RUNNING; }
static bool peer_done(void) { return peer == 1 ? pxm.result == EZ_XM_DONE : pzm.result == EZ_ZM_DONE; }

static void reset(int p)
{
	if (!to_a.b) { to_a.b = malloc(QCAP); to_b.b = malloc(QCAP); }
	to_a.head = to_a.tail = to_b.head = to_b.tail = 0;
	got_n = 0;
	peer = p;
	now = 1000;
}

static void run(uint32_t limit)
{
	uint32_t end = now + limit;
	while (now < end && (peer_running() || ez_xf_tick(&xf, now) == EZ_XF_RUNNING)) {
		uint8_t b[128];
		uint32_t n = 0;
		while (to_a.tail != to_a.head && n < sizeof b) b[n++] = to_a.b[to_a.tail++ % QCAP];
		if (n) { if (peer == 1) ez_xm_input(&pxm, b, n, now); else ez_zm_input(&pzm, b, n, now); }
		n = 0;
		while (to_b.tail != to_b.head && n < sizeof b) b[n++] = to_b.b[to_b.tail++ % QCAP];
		if (n) ez_xf_input(&xf, b, n, now);
		now++;
		if (peer == 1) ez_xm_tick(&pxm, now); else ez_zm_tick(&pzm, now);
		ez_xf_tick(&xf, now);
	}
}

static void t_recv_detects(void)
{
	for (uint32_t i = 0; i < sizeof data; i++) { rng = rng * 1103515245u + 12345u; data[i] = (uint8_t)(rng >> 8); }
	static const uint32_t sizes[] = { 0, 1, 5000, 60000 };
	for (int p = 1; p <= 2; p++)
		for (int k1 = 0; k1 < 2; k1++)
			for (unsigned s = 0; s < 4; s++) {
				reset(p);
				ez_xf_recv(&xf, sink, sizeof got, out_auto, NULL, now);
				/* the peer starts a little later, as a person would */
				now += 1500;
				if (p == 1) ez_xm_send(&pxm, data, sizes[s], k1, out_peer, NULL, now);
				else ez_zm_send(&pzm, data, sizes[s], "m.ez", out_peer, NULL, now);
				run(600000);
				bool ok = peer_done() && xf.proto == (p == 1 ? EZ_XF_XMODEM : EZ_XF_ZMODEM) &&
				          got_n >= sizes[s] && !memcmp(got, data, sizes[s]);
				if (p == 2) ok = ok && got_n == sizes[s];                /* ZMODEM: exact */
				if (!ok) ez_test_note("recv from %s, size %u: %s, got %u", p == 1 ? "XMODEM" : "ZMODEM",
				                      (unsigned)sizes[s], ez_xf_error(&xf), (unsigned)got_n);
				EZ_CHECK(ok);
				EZ_CHECK(ez_xf_padded(&xf) == (p == 1));
				if (p == 2) break;                                        /* 1K applies to XMODEM only */
			}
}

static void t_send_detects(void)
{
	static const uint32_t sizes[] = { 0, 1, 5000, 60000 };
	for (int p = 1; p <= 2; p++)
		for (unsigned s = 0; s < 4; s++) {
			reset(p);
			ez_xf_send(&xf, data, sizes[s], "message.ez", out_auto, NULL, now);
			now += 1500;
			if (p == 1) ez_xm_recv(&pxm, sink, out_peer, NULL, now);
			else ez_zm_recv(&pzm, sink, sizeof got, out_peer, NULL, now);
			run(600000);
			bool ok = peer_done() && xf.proto == (p == 1 ? EZ_XF_XMODEM : EZ_XF_ZMODEM) &&
			          got_n >= sizes[s] && !memcmp(got, data, sizes[s]);
			if (!ok) ez_test_note("send to %s, size %u: %s, got %u", p == 1 ? "XMODEM" : "ZMODEM",
			                      (unsigned)sizes[s], ez_xf_error(&xf), (unsigned)got_n);
			EZ_CHECK(ok);
			if (p == 2) EZ_CHECK(!strcmp(pzm.name, "message.ez"));
		}
}

/* An XMODEM receiver that started first: it has been asking with 'C'
 * before the device began, and the ZMODEM announcement crosses it. */
static void t_send_crossing(void)
{
	reset(1);
	ez_xm_recv(&pxm, sink, out_peer, NULL, now);
	now += 2500;
	ez_xf_send(&xf, data, 3000, "message.ez", out_auto, NULL, now);
	run(600000);
	EZ_CHECK(pxm.result == EZ_XM_DONE && xf.proto == EZ_XF_XMODEM && !memcmp(got, data, 3000));
}

static const ez_test_case_t cases[] = {
	{ "recv_detects",   "auto receiver vs XMODEM (128 and 1K) and ZMODEM senders", t_recv_detects },
	{ "send_detects",   "auto sender vs XMODEM and ZMODEM receivers", t_send_detects },
	{ "send_crossing",  "an XMODEM receiver already asking", t_send_crossing },
};
EZ_TEST_MAIN(cases)
