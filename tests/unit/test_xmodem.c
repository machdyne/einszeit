/*
 * test_xmodem.c -- the XMODEM module on its own (xfer/): a sender and a
 * receiver connected through a simulated line, with simulated time and
 * injected faults. Interoperability with an independent implementation
 * (lrzsz) is tested separately (tests/xfer/).
 */
#include <stdlib.h>
#include <string.h>

#include "ez_test.h"
#include "ez_xmodem.h"

/* ---- a simulated line, both ways -------------------------------------------- */
#define QCAP (1u << 20)
typedef struct { uint8_t *b; uint32_t head, tail; } q_t;
static q_t to_rx, to_tx;          /* sender -> receiver, receiver -> sender */
static uint32_t now, rng = 12345;
static unsigned drop_per, flip_per;   /* 1 in N bytes, 0 = never */
static bool drop_C;                   /* an old sender: never sees 'C' */

static uint32_t rnd(void) { rng = rng * 1103515245u + 12345u; return rng >> 8; }

static void q_put(q_t *q, const uint8_t *b, uint32_t n, bool from_rx)
{
	for (uint32_t i = 0; i < n; i++) {
		uint8_t v = b[i];
		if (from_rx && drop_C && v == 'C') continue;
		if (drop_per && rnd() % drop_per == 0) continue;
		if (flip_per && rnd() % flip_per == 0) v ^= (uint8_t)(1u << (rnd() % 8));
		q->b[q->head++ % QCAP] = v;
	}
}
static void out_tx(void *c, const uint8_t *b, uint32_t n) { (void)c; q_put(&to_rx, b, n, false); }
static void out_rx(void *c, const uint8_t *b, uint32_t n) { (void)c; q_put(&to_tx, b, n, true); }

static uint8_t got[1u << 18];
static uint32_t got_n, sink_limit;
static bool sink(void *c, const uint8_t *b, uint32_t n)
{
	(void)c;
	if (got_n + n > sink_limit) return false;
	memcpy(got + got_n, b, n);
	got_n += n;
	return true;
}

static ez_xm_t tx, rx;

static void reset(void)
{
	if (!to_rx.b) { to_rx.b = malloc(QCAP); to_tx.b = malloc(QCAP); }
	to_rx.head = to_rx.tail = to_tx.head = to_tx.tail = 0;
	got_n = 0;
	sink_limit = sizeof got;
	drop_per = flip_per = 0;
	drop_C = false;
	now = 1000;
}

/* Run both ends until both finish (or a limit of simulated time). */
static void run(bool with_tx, bool with_rx, uint32_t limit_ms)
{
	uint32_t end = now + limit_ms;
	while (now < end) {
		bool tx_live = with_tx && tx.result == EZ_XM_RUNNING, rx_live = with_rx && rx.result == EZ_XM_RUNNING;
		if (!tx_live && !rx_live) break;
		uint8_t b[64];
		uint32_t n = 0;
		while (to_rx.tail != to_rx.head && n < sizeof b) b[n++] = to_rx.b[to_rx.tail++ % QCAP];
		if (rx_live && n) ez_xm_input(&rx, b, n, now);
		else if (!with_rx) to_rx.tail = to_rx.head;
		n = 0;
		while (to_tx.tail != to_tx.head && n < sizeof b) b[n++] = to_tx.b[to_tx.tail++ % QCAP];
		if (tx_live && n) ez_xm_input(&tx, b, n, now);
		else if (!with_tx) to_tx.tail = to_tx.head;
		now += 1;                                /* about 64 bytes per ms: a fast line */
		if (with_tx) ez_xm_tick(&tx, now);
		if (with_rx) ez_xm_tick(&rx, now);
	}
}

static uint8_t data[1u << 17];

/* The data, then nothing but SUB padding to the end of the last block. */
static bool arrived(uint32_t len)
{
	if (got_n < len || memcmp(got, data, len) != 0) return false;
	for (uint32_t i = len; i < got_n; i++) if (got[i] != EZ_XM_SUB) return false;
	return got_n - len < 1024u;
}

static void t_crc_kat(void)
{
	EZ_CHECK_EQ(ez_xm_crc16((const uint8_t *)"123456789", 9), 0x31C3);   /* CRC-16/XMODEM check value */
}

static void t_sizes(void)
{
	static const uint32_t sizes[] = { 0, 1, 127, 128, 129, 1023, 1024, 1025, 65536 };
	for (uint32_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)rnd();
	for (int k1 = 0; k1 < 2; k1++)
		for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
			reset();
			ez_xm_recv(&rx, sink, out_rx, NULL, now);
			ez_xm_send(&tx, data, sizes[s], k1, out_tx, NULL, now);
			run(true, true, 600000);
			bool ok = tx.result == EZ_XM_DONE && rx.result == EZ_XM_DONE && arrived(sizes[s]);
			if (!ok) ez_test_note("size %u, 1k %d: %s / %s", (unsigned)sizes[s], k1, ez_xm_error(tx.err), ez_xm_error(rx.err));
			EZ_CHECK(ok);
			if (k1 && sizes[s] == 65536) EZ_CHECK_EQ(got_n, 65536);        /* 64 blocks of 1K, no padding */
		}
}

/* A sender that never sees 'C' (an old one): the receiver falls back. */
static void t_checksum_fallback(void)
{
	reset();
	drop_C = true;
	ez_xm_recv(&rx, sink, out_rx, NULL, now);
	ez_xm_send(&tx, data, 5000, true, out_tx, NULL, now);
	run(true, true, 600000);
	EZ_CHECK(tx.result == EZ_XM_DONE && rx.result == EZ_XM_DONE);
	EZ_CHECK(!rx.crc && !tx.crc && !tx.k1);                 /* checksum, 128-byte blocks */
	EZ_CHECK(arrived(5000));
}

/* A bad line: corrupted and lost bytes. The data still arrives intact. */
static void t_noisy_line(void)
{
	for (int round = 0; round < 6; round++) {
		reset();
		rng = 777u + (uint32_t)round;
		flip_per = 1500;
		drop_per = round % 2 ? 3000 : 0;
		ez_xm_recv(&rx, sink, out_rx, NULL, now);
		ez_xm_send(&tx, data, 30000, round % 3 != 0, out_tx, NULL, now);
		run(true, true, 3000000);
		bool ok = tx.result == EZ_XM_DONE && rx.result == EZ_XM_DONE && arrived(30000);
		if (!ok) ez_test_note("round %d: %s / %s", round, ez_xm_error(tx.err), ez_xm_error(rx.err));
		EZ_CHECK(ok);
	}
}

static void t_cancel_and_limits(void)
{
	/* the receiver cancels part-way: the sender learns it */
	reset();
	ez_xm_recv(&rx, sink, out_rx, NULL, now);
	ez_xm_send(&tx, data, 60000, true, out_tx, NULL, now);
	run(true, true, 20);
	ez_xm_cancel(&rx);
	run(true, false, 100000);
	EZ_CHECK(rx.result == EZ_XM_FAILED && rx.err == EZ_XM_ERR_CANCELLED);
	EZ_CHECK(tx.result == EZ_XM_FAILED && tx.err == EZ_XM_ERR_REMOTE);
	/* the sender cancels: the receiver learns it */
	reset();
	ez_xm_recv(&rx, sink, out_rx, NULL, now);
	ez_xm_send(&tx, data, 60000, true, out_tx, NULL, now);
	run(true, true, 20);
	ez_xm_cancel(&tx);
	run(false, true, 100000);
	EZ_CHECK(rx.result == EZ_XM_FAILED && rx.err == EZ_XM_ERR_REMOTE);
	/* too large for the receiver */
	reset();
	sink_limit = 4096;
	ez_xm_recv(&rx, sink, out_rx, NULL, now);
	ez_xm_send(&tx, data, 10000, true, out_tx, NULL, now);
	run(true, true, 100000);
	EZ_CHECK(rx.result == EZ_XM_FAILED && rx.err == EZ_XM_ERR_SINK);
	EZ_CHECK(tx.result == EZ_XM_FAILED && tx.err == EZ_XM_ERR_REMOTE);
	/* nobody sends: the receiver gives up after its 10 tries (30 s) */
	reset();
	uint32_t t0 = now;
	ez_xm_recv(&rx, sink, out_rx, NULL, now);
	run(false, true, 100000);
	EZ_CHECK(rx.result == EZ_XM_FAILED && rx.err == EZ_XM_ERR_TIMEOUT);
	EZ_CHECK(now - t0 >= 27000 && now - t0 <= 31000);
	/* nobody receives: the sender gives up after 60 s */
	reset();
	t0 = now;
	ez_xm_send(&tx, data, 100, true, out_tx, NULL, now);
	run(true, false, 100000);
	EZ_CHECK(tx.result == EZ_XM_FAILED && tx.err == EZ_XM_ERR_TIMEOUT);
	EZ_CHECK(now - t0 > 60000);
}

static const ez_test_case_t cases[] = {
	{ "crc_kat",           "CRC-16/XMODEM", t_crc_kat },
	{ "sizes",             "XMODEM-CRC and -1K, every boundary", t_sizes },
	{ "checksum_fallback", "an old sender: checksum mode", t_checksum_fallback },
	{ "noisy_line",        "corruption and loss: retries", t_noisy_line },
	{ "cancel_and_limits", "cancel both ways, oversize, timeouts", t_cancel_and_limits },
};
EZ_TEST_MAIN(cases)
