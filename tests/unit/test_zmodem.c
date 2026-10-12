/*
 * test_zmodem.c -- the ZMODEM module on its own (xfer/): a sender and a
 * receiver over a simulated line, with simulated time and injected faults.
 * Interoperability with lrzsz (sz, rz) is tested in tests/xfer/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ez_test.h"
#include "ez_zmodem.h"

#define QCAP (1u << 21)
typedef struct { uint8_t *b; uint32_t head, tail; } q_t;
static q_t to_rx, to_tx;
static uint32_t now, rng = 4242;
static unsigned drop_per, flip_per;
static bool force_escctl;
static bool dup_rx;                /* the receiver's ZRINIT arrives twice, as rz sends it */          /* the receiver asks for control characters escaped */

static uint32_t rnd(void) { rng = rng * 1103515245u + 12345u; return rng >> 8; }

static void q_put(q_t *q, const uint8_t *b, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		uint8_t v = b[i];
		if (drop_per && rnd() % drop_per == 0) continue;
		if (flip_per && rnd() % flip_per == 0) v ^= (uint8_t)(1u << (rnd() % 8));
		q->b[q->head++ % QCAP] = v;
	}
}
static void out_tx(void *c, const uint8_t *b, uint32_t n) { (void)c; q_put(&to_rx, b, n); }
static void out_rx(void *c, const uint8_t *b, uint32_t n)
{
	(void)c;
	q_put(&to_tx, b, n);
	if (dup_rx && n >= 6 && !memcmp(b, "**\x18" "B01", 6)) q_put(&to_tx, b, n);
}

static uint8_t got[1u << 18];
static uint32_t got_n;
static bool sink(void *c, const uint8_t *b, uint32_t n)
{
	(void)c;
	if (got_n + n > sizeof got) return false;
	memcpy(got + got_n, b, n);
	got_n += n;
	return true;
}

static ez_zm_t tx, rx;

static void reset(void)
{
	if (!to_rx.b) { to_rx.b = malloc(QCAP); to_tx.b = malloc(QCAP); }
	to_rx.head = to_rx.tail = to_tx.head = to_tx.tail = 0;
	got_n = 0;
	drop_per = flip_per = 0;
	force_escctl = false;
	dup_rx = false;
	now = 1000;
}

static void run(bool with_tx, bool with_rx, uint32_t limit_ms)
{
	uint32_t end = now + limit_ms;
	while (now < end) {
		bool tl = with_tx && tx.result == EZ_ZM_RUNNING, rl = with_rx && rx.result == EZ_ZM_RUNNING;
		if (!tl && !rl) break;
		uint8_t b[256];
		uint32_t n = 0;
		while (to_rx.tail != to_rx.head && n < sizeof b) b[n++] = to_rx.b[to_rx.tail++ % QCAP];
		if (rl && n) ez_zm_input(&rx, b, n, now);
		n = 0;
		while (to_tx.tail != to_tx.head && n < sizeof b) b[n++] = to_tx.b[to_tx.tail++ % QCAP];
		if (tl && n) {
			if (force_escctl) tx.escctl = true;
			ez_zm_input(&tx, b, n, now);
		}
		now += 1;
		if (with_tx) ez_zm_tick(&tx, now);
		if (with_rx) ez_zm_tick(&rx, now);
	}
}

static uint8_t data[1u << 17];

static void t_crc_kat(void)
{
	EZ_CHECK_EQ(~ez_zm_crc32(0xFFFFFFFFu, (const uint8_t *)"123456789", 9), 0xCBF43926u);
	EZ_CHECK_EQ(ez_zm_crc16(0, (const uint8_t *)"123456789", 9), 0x31C3);
}

/* Every size boundary; the data arrives exact (ZMODEM carries the length). */
static void t_sizes(void)
{
	static const uint32_t sizes[] = { 0, 1, 1023, 1024, 1025, 4095, 4096, 4097, 65536, 100000 };
	for (uint32_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)rnd();
	for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
		reset();
		ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
		ez_zm_send(&tx, data, sizes[s], "msg.ez", out_tx, NULL, now);
		run(true, true, 600000);
		bool ok = tx.result == EZ_ZM_DONE && rx.result == EZ_ZM_DONE && got_n == sizes[s] &&
		          !memcmp(got, data, sizes[s]);
		if (!ok) ez_test_note("size %u: %s / %s, got %u", (unsigned)sizes[s], ez_zm_error(tx.err),
		                      ez_zm_error(rx.err), (unsigned)got_n);
		EZ_CHECK(ok);
		EZ_CHECK(!strcmp(rx.name, "msg.ez") && rx.len_known && rx.len == sizes[s]);
		EZ_CHECK(tx.crc32);                                     /* both sides can: CRC-32 */
	}
}

/* Every byte value, with and without escaping of all control characters. */
static void t_escaping(void)
{
	static uint8_t all[512];
	for (int i = 0; i < 512; i++) all[i] = (uint8_t)i;
	for (int e = 0; e < 2; e++) {
		reset();
		force_escctl = e == 1;
		ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
		ez_zm_send(&tx, all, sizeof all, "all", out_tx, NULL, now);
		run(true, true, 100000);
		EZ_CHECK(tx.result == EZ_ZM_DONE && rx.result == EZ_ZM_DONE);
		EZ_CHECK(got_n == sizeof all && !memcmp(got, all, sizeof all));
	}
}

static void t_noisy_line(void)
{
	for (int round = 0; round < 6; round++) {
		reset();
		rng = 991u + (uint32_t)round;
		flip_per = 2000;
		drop_per = round % 2 ? 4000 : 0;
		ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
		ez_zm_send(&tx, data, 40000, "noisy", out_tx, NULL, now);
		run(true, true, 3000000);
		bool ok = tx.result == EZ_ZM_DONE && rx.result == EZ_ZM_DONE && got_n == 40000 && !memcmp(got, data, 40000);
		if (!ok) ez_test_note("round %d: %s / %s, got %u", round, ez_zm_error(tx.err), ez_zm_error(rx.err), (unsigned)got_n);
		EZ_CHECK(ok);
	}
}

static void t_limits(void)
{
	/* too large: refused with ZSKIP, both sides end cleanly */
	reset();
	ez_zm_recv(&rx, sink, 1000, out_rx, NULL, now);
	ez_zm_send(&tx, data, 5000, "big", out_tx, NULL, now);
	run(true, true, 100000);
	EZ_CHECK(rx.result == EZ_ZM_FAILED && rx.err == EZ_ZM_ERR_SINK);
	EZ_CHECK(tx.result == EZ_ZM_FAILED && tx.err == EZ_ZM_ERR_SKIPPED);
	EZ_CHECK_EQ(got_n, 0);
	/* the receiver cancels part-way */
	reset();
	ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
	ez_zm_send(&tx, data, 100000, "x", out_tx, NULL, now);
	run(true, true, 30);
	ez_zm_cancel(&rx);
	run(true, false, 100000);
	EZ_CHECK(rx.err == EZ_ZM_ERR_CANCELLED && tx.result == EZ_ZM_FAILED && tx.err == EZ_ZM_ERR_REMOTE);
	/* the sender cancels part-way */
	reset();
	ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
	ez_zm_send(&tx, data, 100000, "x", out_tx, NULL, now);
	run(true, true, 30);
	ez_zm_cancel(&tx);
	run(false, true, 100000);
	EZ_CHECK(rx.result == EZ_ZM_FAILED && rx.err == EZ_ZM_ERR_REMOTE);
	/* nobody sends: the receiver gives up in about 30 s */
	reset();
	uint32_t t0 = now;
	ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
	run(false, true, 200000);
	EZ_CHECK(rx.result == EZ_ZM_FAILED && rx.err == EZ_ZM_ERR_TIMEOUT);
	EZ_CHECK(now - t0 >= 27000 && now - t0 <= 33000);
	/* nobody receives: the sender gives up in about a minute */
	reset();
	t0 = now;
	ez_zm_send(&tx, data, 100, "x", out_tx, NULL, now);
	run(true, false, 200000);
	EZ_CHECK(tx.result == EZ_ZM_FAILED && tx.err == EZ_ZM_ERR_TIMEOUT);
	EZ_CHECK(now - t0 >= 60000 && now - t0 <= 70000);
	/* the sender's start: "rz\r" and a ZRQINIT hex header (terminal autostart) */
	reset();
	ez_zm_send(&tx, data, 10, "x", out_tx, NULL, now);
	EZ_CHECK(to_rx.head >= 7 && !memcmp(to_rx.b, "rz\r**\x18" "B00", 9));
}

/* A ZCOMMAND is never executed: the transfer is aborted. */
static void t_no_commands(void)
{
	reset();
	ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
	/* a hex ZCOMMAND header: type 0x12, zero flags, CRC-16 of those 5 bytes */
	uint8_t h[5] = { 18, 0, 0, 0, 0 };
	uint16_t c = ez_zm_crc16(0, h, 5);
	char hex[40];
	snprintf(hex, sizeof hex, "**\x18" "B1200000000%02x%02x\r\n", c >> 8, c & 0xFF);
	ez_zm_input(&rx, (const uint8_t *)hex, (uint32_t)strlen(hex), now);
	EZ_CHECK(rx.result == EZ_ZM_FAILED && rx.err == EZ_ZM_ERR_PROTOCOL);
}

/* Random garbage never crashes the receiver or sinks anything. */
static void t_garbage(void)
{
	for (int r = 0; r < 200; r++) {
		reset();
		ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
		uint8_t g[2048];
		for (unsigned i = 0; i < sizeof g; i++) {
			uint32_t v = rnd();
			g[i] = (uint8_t)(v % 7 == 0 ? 0x18 : v % 11 == 0 ? '*' : v);
		}
		ez_zm_input(&rx, g, sizeof g, now);
		EZ_CHECK_EQ(got_n, 0);
	}
}

/* lrzsz's rz sends ZRINIT twice at the start. Our sender answered both
 * with ZFILE, rz answered both with ZRPOS 0, and the second rewound the
 * transfer. That regression is caught by the interop test against rz
 * (tests/xfer/test_interop.py): our own receiver answers a repeated ZFILE
 * with its position, so here it only shows the pair tolerates the repeat. */
static void t_duplicates(void)
{
	static const uint32_t sizes[] = { 0, 5000, 50000 };
	for (unsigned s = 0; s < 3; s++) {
		reset();
		dup_rx = true;
		ez_zm_recv(&rx, sink, sizeof got, out_rx, NULL, now);
		ez_zm_send(&tx, data, sizes[s], "dup", out_tx, NULL, now);
		run(true, true, 600000);
		bool ok = tx.result == EZ_ZM_DONE && rx.result == EZ_ZM_DONE && got_n == sizes[s] && !memcmp(got, data, sizes[s]);
		if (!ok) ez_test_note("size %u: %s / %s, got %u, blk %u", (unsigned)sizes[s], ez_zm_error(tx.err), ez_zm_error(rx.err), (unsigned)got_n, (unsigned)tx.blk);
		EZ_CHECK(ok);
		/* converges without excessive overhead: at most 3x the file on the line */
		if (to_rx.head > 3u * sizes[s] + 8192u) ez_test_note("size %u: %u bytes on the line", (unsigned)sizes[s], (unsigned)to_rx.head);
		EZ_CHECK(to_rx.head <= 3u * sizes[s] + 8192u);
	}
}

static const ez_test_case_t cases[] = {
	{ "duplicates",   "ZRINIT twice, as rz sends it", t_duplicates },
	{ "crc_kat",      "CRC-32 and CRC-16 check values", t_crc_kat },
	{ "sizes",        "every window and subpacket boundary, exact length", t_sizes },
	{ "escaping",     "every byte value, with and without ESCCTL", t_escaping },
	{ "noisy_line",   "corruption and loss: ZRPOS recovery", t_noisy_line },
	{ "limits",       "oversize (ZSKIP), cancels, timeouts, autostart", t_limits },
	{ "no_commands",  "ZCOMMAND aborts, never runs", t_no_commands },
	{ "garbage",      "random input: nothing sunk, no crash", t_garbage },
};
EZ_TEST_MAIN(cases)
