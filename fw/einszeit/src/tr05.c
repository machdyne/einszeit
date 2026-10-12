/*
 * tr05.c -- TR-05: what a power cut during a write does to an SD card
 * (development images only; destroys the card's contents).
 *
 * Layout under test (EZ-IMPL-001 §2.8): two independent FAT32 volumes on
 * one card, each with its own pair of FATs, far apart:
 *   A at 4 MiB, B at half the card, 256 MiB each (no partition table).
 * Both hold eight 256 KiB reference files (K0..K7) of known content.
 *
 * Armed, the device does this at every power-up, instead of normal work:
 *   1. check A and B file by file against the known content;
 *   2. add the result to a tally in F-RAM;
 *   3. repair whatever was damaged (reformat, rewrite the reference files);
 *   4. rewrite a 256 KiB file on A in a loop (create, append, rename,
 *      erase the previous) -- the write pattern of key copies -- until
 *      power is cut.
 * The question it answers: when a write to A is interrupted, is B ever
 * damaged? It also measures how often A itself is.
 *
 * `tr05 wp` checks separately whether the card honours the temporary
 * write-protect bit (CSD TMP_WRITE_PROTECT, set with PROGRAM_CSD).
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/watchdog.h"

#include "board.h"
#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_ks_fatfs.h"
#include "ez_meta.h"
#include "ez_sd.h"
#include "ff.h"
#include "hal_rp2350.h"
#include "tr05.h"
#include "usb.h"

#define VOL_SECTORS   (256u * 2048u)        /* 256 MiB */
#define A_START       8192u                 /* 4 MiB */
#define NREF          8
#define FILE_LEN      (256u * 1024u)

/* ---- tally in F-RAM ------------------------------------------------------- */
typedef struct {
	uint8_t  armed, need_format;
	uint32_t boots, a_mount_fail, a_files_bad, b_mount_fail, b_files_bad, b_events, cycles;
} tally_t;

static bool tally_read(tally_t *t)
{
	uint8_t b[EZ_META_TR05_SIZE];
	memset(t, 0, sizeof *t);
	if (hal_fram.read(NULL, EZ_META_TR05_ADDR, b, sizeof b) != EZ_OK) return false;
	if (b[0] != 'T' || b[1] != '5' || ez_get_le16(b + 34) != ez_crc16(b, 34)) return false;
	t->armed = b[2]; t->need_format = b[3];
	uint32_t *f[] = { &t->boots, &t->a_mount_fail, &t->a_files_bad, &t->b_mount_fail,
	                  &t->b_files_bad, &t->b_events, &t->cycles };
	for (int i = 0; i < 7; i++) *f[i] = ez_get_le32(b + 4 + 4 * i);
	return true;
}

static void tally_write(const tally_t *t)
{
	uint8_t b[EZ_META_TR05_SIZE] = { 'T', '5', t->armed, t->need_format };
	const uint32_t f[] = { t->boots, t->a_mount_fail, t->a_files_bad, t->b_mount_fail,
	                       t->b_files_bad, t->b_events, t->cycles };
	for (int i = 0; i < 7; i++) ez_put_le32(b + 4 + 4 * i, f[i]);
	ez_put_le16(b + 34, ez_crc16(b, 34));
	hal_fram.write(NULL, EZ_META_TR05_ADDR, b, sizeof b);
}

static void tally_print(const tally_t *t)
{
	printf("TR-05: %lu power-ups, %lu write cycles completed\n"
	       "  A (written): %lu failed to mount, %lu reference files damaged\n"
	       "  B (idle):    %lu failed to mount, %lu reference files damaged, damaged on %lu power-ups\n",
	       (unsigned long)t->boots, (unsigned long)t->cycles, (unsigned long)t->a_mount_fail,
	       (unsigned long)t->a_files_bad, (unsigned long)t->b_mount_fail,
	       (unsigned long)t->b_files_bad, (unsigned long)t->b_events);
}

bool tr05_armed(void)
{
	tally_t t;
	return tally_read(&t) && t.armed;
}

/* ---- two volumes on one card: offset block devices ------------------------------- */
typedef struct { uint32_t start, count; ez_blockdev_t bd; } offbd_t;
static offbd_t vol[2];

static bool o_present(void *c) { (void)c; return true; }
static ez_status_t o_init(void *c) { (void)c; return hal_sd_present() ? EZ_OK : hal_sdblk.init(NULL); }
static ez_status_t o_check(void *c) { (void)c; return hal_sdblk.check(NULL); }
static uint32_t o_count(void *c) { return ((offbd_t *)c)->count; }
static ez_status_t o_read(void *c, uint32_t lba, uint8_t *buf, uint32_t n)
{ offbd_t *o = c; return lba + n > o->count ? EZ_ERR_RANGE : hal_sdblk.read(NULL, o->start + lba, buf, n); }
static ez_status_t o_write(void *c, uint32_t lba, const uint8_t *buf, uint32_t n)
{ offbd_t *o = c; return lba + n > o->count ? EZ_ERR_RANGE : hal_sdblk.write(NULL, o->start + lba, buf, n); }
static ez_status_t o_sync(void *c) { (void)c; return hal_sdblk.sync(NULL); }

static ez_ks_fatfs_t t5;
static uint8_t blk[512];

static void pattern(uint32_t seed, uint32_t off, uint8_t *b, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		uint32_t x = (off + i) * 2654435761u ^ seed * 0x9E3779B9u;
		x ^= x >> 15; x *= 0x2C1B3C6Du; x ^= x >> 12;
		b[i] = (uint8_t)x;
	}
}

static bool write_file(uint8_t d, const char *name, uint32_t seed)
{
	const ez_hal_keystore_t *h = &t5.hal;
	if (h->create(h->ctx, d, name) != EZ_OK) return false;
	for (uint32_t o = 0; o < FILE_LEN; o += sizeof blk) {
		pattern(seed, o, blk, sizeof blk);
		if (h->append(h->ctx, d, name, blk, sizeof blk) != EZ_OK) return false;
	}
	return true;
}

static int check_files(uint8_t d)
{
	const ez_hal_keystore_t *h = &t5.hal;
	int bad = 0;
	char name[8];
	uint8_t want[512];
	for (int k = 0; k < NREF; k++) {
		snprintf(name, sizeof name, "K%d.BIN", k);
		uint32_t size = 0;
		bool ok = h->size(h->ctx, d, name, &size) == EZ_OK && size == FILE_LEN;
		for (uint32_t o = 0; ok && o < FILE_LEN; o += sizeof blk) {
			pattern((uint32_t)k, o, want, sizeof want);
			ok = h->read(h->ctx, d, name, o, blk, sizeof blk) == EZ_OK && !memcmp(blk, want, sizeof blk);
		}
		if (!ok) bad++;
	}
	return bad;
}

static bool format_and_fill(uint8_t d)
{
	static uint8_t work[4096];
	char path[4] = { (char)('0' + d), ':', 0 };
	ez_ks_fatfs_unmount(&t5, d);
	MKFS_PARM opt = { FM_FAT32 | FM_SFD, 2, 0, 0, 4096 };
	if (f_mkfs(path, &opt, work, sizeof work) != FR_OK) return false;
	if (ez_ks_fatfs_mount(&t5, d) != EZ_OK) return false;
	char name[8];
	for (int k = 0; k < NREF; k++) {
		snprintf(name, sizeof name, "K%d.BIN", k);
		if (!write_file(d, name, (uint32_t)k)) return false;
	}
	return true;
}

static void setup_volumes(void)
{
	uint32_t sectors;
	uint8_t cid[16];
	if (hal_sdblk.init(NULL) != EZ_OK) return;
	hal_sd_info(&sectors, cid);
	uint32_t b_start = (sectors / 2) & ~8191u;
	if (b_start < A_START + VOL_SECTORS + 8192u) b_start = A_START + VOL_SECTORS + 8192u;
	vol[0] = (offbd_t){ A_START, VOL_SECTORS, { 0 } };
	vol[1] = (offbd_t){ b_start, VOL_SECTORS, { 0 } };
	for (int i = 0; i < 2; i++)
		vol[i].bd = (ez_blockdev_t){ &vol[i], 512, o_present, o_init, o_check, o_count, o_read, o_write, o_sync, NULL };
	ez_ks_fatfs_init(&t5, NULL, &vol[0].bd, &vol[1].bd);
}

static bool key_q(void)
{
	int c = getchar_timeout_us(0);
	return c == 'q' || c == 'Q';
}

void tr05_mode(void)
{
	tally_t t;
	tally_read(&t);
	t.boots++;
	tally_write(&t);
	setup_volumes();
	uint32_t sectors;
	uint8_t cid[16];
	hal_sd_info(&sectors, cid);
	if (sectors < A_START + 2 * VOL_SECTORS + 16384u) {
		printf("TR-05: card missing or smaller than 1 GB; 'q' disarms\n");
		while (!key_q()) { usb_task(); sleep_ms(50); }
		t.armed = 0; tally_write(&t); watchdog_reboot(0, 0, 10); for (;;) {}
	}
	if (t.need_format) {
		printf("TR-05: formatting both volumes and writing the reference files...\n");
		bool ok = format_and_fill(1) && format_and_fill(2);
		printf("TR-05: %s\n", ok ? "ready" : "FORMAT FAILED");
		t.need_format = 0;
		tally_write(&t);
	} else {
		/* 1-2. check both volumes, count */
		for (uint8_t d = 1; d <= 2; d++) {
			bool mounted = ez_ks_fatfs_mount(&t5, d) == EZ_OK;
			int bad = mounted ? check_files(d) : NREF;
			if (d == 1) { if (!mounted) t.a_mount_fail++; t.a_files_bad += (uint32_t)(mounted ? bad : 0); }
			else { if (!mounted) t.b_mount_fail++; t.b_files_bad += (uint32_t)(mounted ? bad : 0); if (!mounted || bad) t.b_events++; }
			tally_write(&t);
			/* 3. repair */
			if (!mounted || bad) format_and_fill(d);
		}
	}
	/* 4. churn on A until the power goes; q stops */
	const ez_hal_keystore_t *h = &t5.hal;
	char name[12], prev[12] = "";
	uint32_t n = t.cycles;
	for (uint32_t i = 0; ; i++) {             /* clear leftovers of the interrupted cycle */
		uint32_t size;
		if (h->list(h->ctx, 1, i, name, &size) != EZ_OK) break;
		if (name[0] == 'T') { h->zap(h->ctx, 1, name); i = (uint32_t)-1; }
	}
	tally_print(&t);
	printf("TR-05: writing volume A in a loop. Cut the power at any time; 'q' disarms.\n");
	for (;;) {
		if (key_q()) {
			t.armed = 0;
			tally_write(&t);
			tally_print(&t);
			printf("TR-05 disarmed; rebooting into the normal firmware\n");
			sleep_ms(200);
			watchdog_reboot(0, 0, 10);
			for (;;) {}
		}
		snprintf(name, sizeof name, "T%lu.BIN", (unsigned long)n);
		if (!write_file(1, "T.TMP", n) || h->rename(h->ctx, 1, "T.TMP", name) != EZ_OK) {
			printf("TR-05: write failed (card error); repairing A\n");
			format_and_fill(1);
			continue;
		}
		if (prev[0]) h->zap(h->ctx, 1, prev);
		memcpy(prev, name, sizeof prev);
		t.cycles = ++n;
		tally_write(&t);
		usb_task();
	}
}

/* ---- shell commands -------------------------------------------------------------- */

static void wp_test(void)
{
	uint32_t sectors;
	uint8_t cid[16], csd[16];
	if (hal_sdblk.init(NULL) != EZ_OK || !ez_sd_read_csd(csd)) { printf("wp: no card\n"); return; }
	hal_sd_info(&sectors, cid);
	uint32_t lba = sectors - 4096u;               /* scratch, near the end of the card */
	printf("wp: CSD TMP_WRITE_PROTECT=%d PERM_WRITE_PROTECT=%d\n", (csd[14] >> 4) & 1, (csd[14] >> 5) & 1);
	if ((csd[14] >> 5) & 1) { printf("wp: card is permanently write-protected; stopping\n"); return; }
	uint8_t a[512], b[512], r[512];
	memset(a, 0xA5, sizeof a);
	memset(b, 0x5A, sizeof b);
	bool c;
	bool w1 = ez_sd_write_block(lba, a) && ez_sd_read_block(lba, r, &c) && !memcmp(r, a, 512);
	bool set = ez_sd_set_tmp_write_protect(true);
	bool rd = ez_sd_read_csd(csd);
	int bit = rd ? (csd[14] >> 4) & 1 : -1;
	bool w2 = ez_sd_write_block(lba, b);
	ez_sd_status();
	bool same = ez_sd_read_block(lba, r, &c) && !memcmp(r, a, 512);
	bool clr = ez_sd_set_tmp_write_protect(false);
	ez_sd_read_csd(csd);
	bool w3 = ez_sd_write_block(lba, b) && ez_sd_read_block(lba, r, &c) && !memcmp(r, b, 512);
	printf("wp: write before %s; PROGRAM_CSD(set) %s, bit reads %d; write while protected %s, data %s;\n"
	       "    PROGRAM_CSD(clear) %s, bit reads %d; write after %s\n",
	       w1 ? "ok" : "FAILED", set ? "ok" : "FAILED", bit, w2 ? "ACCEPTED" : "refused",
	       same ? "unchanged" : "CHANGED", clr ? "ok" : "FAILED", (csd[14] >> 4) & 1, w3 ? "ok" : "FAILED");
	printf("wp: result: %s\n", set && bit == 1 && !w2 && same && clr && w3 ? "the card HONOURS temporary write protection"
	                          : "the card does NOT honour it reliably (see the lines above)");
	hal_sdblk.init(NULL);
}

void tr05_cmd(int argc, char **argv)
{
	tally_t t;
	const char *sub = argc > 1 ? argv[1] : "status";
	if (!strcmp(sub, "status")) {
		if (tally_read(&t)) tally_print(&t); else printf("TR-05: no tally\n");
	} else if (!strcmp(sub, "prep")) {
		memset(&t, 0, sizeof t);
		t.armed = 1;
		t.need_format = 1;
		tally_write(&t);
		printf("TR-05 armed; rebooting into test mode\n");
		sleep_ms(200);
		watchdog_reboot(0, 0, 10);
		for (;;) {}
	} else if (!strcmp(sub, "disarm")) {
		if (tally_read(&t)) { t.armed = 0; tally_write(&t); }
		printf("TR-05 disarmed\n");
	} else if (!strcmp(sub, "wp")) {
		wp_test();
	} else {
		printf("tr05 prep | status | disarm | wp\n");
	}
}
