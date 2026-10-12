/*
 * ez_entropy_check -- run the device's online monitor and per-key
 * acceptance tests (core/src/ez_entropy.c, the same code the firmware
 * runs) over a capture file.
 *
 *   ez_entropy_check <file> [key_bytes]
 *
 * The monitor runs over the whole file, window by window, and every
 * failing window is reported. The acceptance tests run over consecutive
 * key-sized slices (default 1 MiB) as if each were a generated key.
 *
 * Purpose: EZ-IMPL-001 §7.2 requires the thresholds to be checked
 * against characterisation data from the real entropy source. Run it on
 * fw/test captures (conditioned output). A healthy source should show no
 * monitor failures and no rejected slices; raw (unconditioned) captures
 * are expected to fail.
 *
 * A fw/test container (1024-byte header with "key_material") is detected
 * and its header skipped.
 *
 * EZ-SEC-001 traceability: evidence for SEC-ENTROPY-002 and §2.3
 * threshold derivation; DEV-01.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ez_entropy.h"

static void bits(uint8_t f, char *out)
{
	static const char *n[8] = { "mon-monobit", "mon-runs", "mon-autocorr", "fips-monobit",
	                            "fips-poker", "fips-runs", "whole-key", "other" };
	out[0] = 0;
	for (int i = 0; i < 8; i++)
		if (f & (1u << i)) { strcat(out, out[0] ? "," : ""); strcat(out, n[i]); }
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <file> [key_bytes]\n", argv[0]);
		return 2;
	}
	unsigned long key = argc > 2 ? strtoul(argv[2], NULL, 0) : 1048576ul;
	if (key < 8192 || key % 512) {
		fprintf(stderr, "key_bytes must be >= 8192 and a multiple of 512\n");
		return 2;
	}
	FILE *f = fopen(argv[1], "rb");
	if (!f) { perror(argv[1]); return 2; }
	static uint8_t buf[1 << 16];
	size_t n = fread(buf, 1, 1024, f);
	long skip = 0;
	if (n == 1024 && memmem(buf, 1024, "key_material", 12)) skip = 1024;
	fseek(f, skip, SEEK_SET);

	ez_monitor_t mon; ez_mon_init(&mon);
	ez_accept_t acc;  ez_acc_init(&acc);
	unsigned long long total = 0;
	unsigned long win_fail = 0, slices = 0, rejected = 0, in_slice = 0, prev_windows = 0;
	char names[128];
	while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
		for (size_t i = 0; i < n; i += 512) {
			uint32_t p = (uint32_t)(n - i < 512 ? n - i : 512);
			/* monitor: re-arm after each failing window so all are counted */
			uint8_t mf = ez_mon_feed(&mon, buf + i, p);
			if (mf && mon.windows != prev_windows) {
				win_fail++;
				bits(mf, names);
				if (win_fail <= 20)
					printf("monitor: window %lu (byte %llu) FAILED: %s\n",
					       (unsigned long)mon.windows - 1, total + i, names);
				uint32_t w = mon.windows;
				ez_mon_init(&mon);
				mon.windows = w;
			}
			prev_windows = mon.windows;
			ez_acc_feed(&acc, buf + i, p);
			in_slice += p;
			if (in_slice == key) {
				uint8_t af = ez_acc_finish(&acc);
				slices++;
				if (af) {
					rejected++;
					bits(af, names);
					printf("acceptance: slice %lu (bytes %llu..%llu) REJECTED: %s\n",
					       slices - 1, total + i + p - key, total + i + p, names);
				}
				ez_acc_init(&acc);
				in_slice = 0;
			}
		}
		total += n;
	}
	fclose(f);
	printf("\nfile: %s (%llu bytes%s)\n", argv[1], total, skip ? ", container header skipped" : "");
	printf("monitor: %lu windows of %u bits, %lu failed (ideal-source expectation %.2g)\n",
	       (unsigned long)mon.windows, (unsigned)EZ_MON_WINDOW_BITS, win_fail, mon.windows * 7.5e-9);
	printf("acceptance: %lu slices of %lu bytes, %lu rejected (ideal-source expectation %.2g)\n",
	       slices, key, rejected, slices * 4.0e-9);
	if (in_slice) printf("acceptance: final %lu bytes not tested (partial slice)\n", in_slice);
	return (win_fail || rejected) ? 1 : 0;
}
