/*
 * fuzz_xfer.c -- the file-transfer receivers and senders (xfer/) on hostile
 * input from the line: XMODEM, ZMODEM and automatic detection. The first
 * byte picks the mode; the rest arrives in chunks, with time passing
 * between them so the timeouts run too. Checked: no crash, no memory
 * error, and a receiver never delivers more than its limit.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ez_xfer.h"

static uint32_t sunk, limit;
static void out(void *c, const uint8_t *b, uint32_t n) { (void)c; (void)b; (void)n; }
static bool sink(void *c, const uint8_t *b, uint32_t n)
{
	(void)c; (void)b;
	if (sunk + n > limit) return false;
	sunk += n;
	return true;
}
static const uint8_t payload[3000] = { 1, 2, 3 };

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
	if (n < 2) return 0;
	static ez_xm_t xm;
	static ez_zm_t zm;
	static ez_xf_t xf;
	int mode = d[0] % 6;
	uint32_t now = 1000;
	sunk = 0;
	limit = 2000u + d[1] * 64u;
	switch (mode) {
	case 0: ez_xm_recv(&xm, sink, out, NULL, now); break;
	case 1: ez_zm_recv(&zm, sink, limit, out, NULL, now); break;
	case 2: ez_xf_recv(&xf, sink, limit, out, NULL, now); break;
	case 3: ez_xm_send(&xm, payload, sizeof payload, true, out, NULL, now); break;
	case 4: ez_zm_send(&zm, payload, sizeof payload, "f", out, NULL, now); break;
	case 5: ez_xf_send(&xf, payload, sizeof payload, "f", out, NULL, now); break;
	}
	size_t i = 2;
	while (i < n) {
		size_t k = 1 + d[i] % 64;                  /* chunk length, then the chunk */
		i++;
		if (i + k > n) k = n - i;
		switch (mode) {
		case 0: case 3: ez_xm_input(&xm, d + i, (uint32_t)k, now); ez_xm_tick(&xm, now); break;
		case 1: case 4: ez_zm_input(&zm, d + i, (uint32_t)k, now); ez_zm_tick(&zm, now); break;
		default:        ez_xf_input(&xf, d + i, (uint32_t)k, now); ez_xf_tick(&xf, now); break;
		}
		now += (k & 3) ? 7u : 4000u;               /* sometimes long enough for a timeout */
		i += k;
	}
	if (sunk > limit) abort();
	return 0;
}
