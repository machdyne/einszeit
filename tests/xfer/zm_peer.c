#define _POSIX_C_SOURCE 200809L
/*
 * zm_peer.c -- the ZMODEM module over standard input and output, to test it
 * against an independent implementation (lrzsz's sz and rz; test_interop.py).
 *   zm_peer recv <out file>         receive, write the data (with padding)
 *   zm_peer send <in file> [name]     send the file
 * Exit status 0 when the transfer completed.
 */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ez_zmodem.h"

static FILE *outf;
static uint8_t data[1 << 20];

static uint32_t ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000);
}
static void out(void *c, const uint8_t *b, uint32_t n) { (void)c; if (write(1, b, n) != (ssize_t)n) exit(3); }
static bool sink(void *c, const uint8_t *b, uint32_t n) { (void)c; return fwrite(b, 1, n, outf) == n; }

int main(int argc, char **argv)
{
	if (argc < 3) return 2;
	ez_zm_t x;
	if (!strcmp(argv[1], "recv")) {
		if (!(outf = fopen(argv[2], "wb"))) return 2;
		ez_zm_recv(&x, sink, sizeof data, out, NULL, ms());
	} else {
		FILE *f = fopen(argv[2], "rb");
		if (!f) return 2;
		size_t n = fread(data, 1, sizeof data, f);
		fclose(f);
		ez_zm_send(&x, data, (uint32_t)n, argc > 3 ? argv[3] : "file", out, NULL, ms());
	}
	while (x.result == EZ_ZM_RUNNING) {
		struct pollfd p = { 0, POLLIN, 0 };
		if (poll(&p, 1, 20) > 0) {
			uint8_t b[4096];
			ssize_t k = read(0, b, sizeof b);
			if (k <= 0) break;
			ez_zm_input(&x, b, (uint32_t)k, ms());
		}
		ez_zm_tick(&x, ms());
	}
	if (outf) fclose(outf);
	if (x.result != EZ_ZM_DONE) fprintf(stderr, "zm_peer: %s\n", ez_zm_error(x.err));
	return x.result == EZ_ZM_DONE ? 0 : 1;
}
