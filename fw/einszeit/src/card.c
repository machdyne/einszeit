/*
 * card.c -- see card.h.
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"

#include "app.h"
#include "board.h"
#include "card.h"
#include "ez_bytes.h"
#include "ez_ks_mirror.h"
#include "ez_sd.h"
#include "ez_secure.h"
#include "ff.h"
#include "hal_rp2350.h"

#define A_START   8192u                 /* 4 MiB */
#define ALIGN     8192u                 /* 4 MiB, a typical allocation unit */
static const uint8_t SIG[4] = { 'E', 'Z', 'M', '2' };

/* ---- volumes: offset block devices over the card ------------------------------ */
typedef struct { uint32_t start, count; ez_blockdev_t bd; } offbd_t;
static offbd_t vol[2];

static bool o_present(void *c) { (void)c; return true; }
static ez_status_t o_init(void *c) { (void)c; return hal_sd_present() ? EZ_OK : hal_sdblk.init(NULL); }
static ez_status_t o_check(void *c) { (void)c; return hal_sdblk.check(NULL); }
static uint32_t o_count(void *c) { return ((offbd_t *)c)->count; }
static ez_status_t o_read(void *c, uint32_t lba, uint8_t *buf, uint32_t n)
{ offbd_t *o = c; return lba + n > o->count ? EZ_ERR_RANGE : hal_sdblk.read(NULL, o->start + lba, buf, n); }
int (*card_printf)(const char *fmt, ...) = printf;   /* the firmware routes this through core 0 */
int card_verbose;                   /* development shell: print each step and progress */
static uint32_t written;            /* sectors written by the current format or repair */
static uint32_t expected;           /* about how many it will write */
static uint64_t t_start, t_print;
static bool report;                 /* a volume recreated in a job: its progress is the job's */
volatile uint16_t *card_progress;   /* where to report it (the core's progress; NULL: nowhere) */
static ez_status_t o_write(void *c, uint32_t lba, const uint8_t *buf, uint32_t n)
{
	offbd_t *o = c;
	if (lba + n > o->count) return EZ_ERR_RANGE;
	if (!written) t_start = t_print = time_us_64();
	ez_status_t st = hal_sdblk.write(NULL, o->start + lba, buf, n);
	written += n;
	/* Progress for 'ez device info' and the waiting 'ez' (TR-08: a volume
	 * recreated by the background sync showed 0% for minutes). */
	if (report && expected && card_progress) {
		uint64_t pm = (uint64_t)written * 1000u / expected;
		*card_progress = (uint16_t)(pm > 999u ? 999u : pm);
	}
	/* Progress every 64 KiB or 2 s, so a slow card is visibly alive (TR-07). */
	uint64_t now = time_us_64();
	if (card_verbose && (written % 128u < n || now - t_print > 2000000u)) {
		t_print = now;
		unsigned pct = expected ? (unsigned)((uint64_t)written * 100u / expected) : 0;
		card_printf("\r  writing ... %lu.%lu of ~%lu.%lu MiB (%u%%), %lu s   ",
		       (unsigned long)(written / 2048u), (unsigned long)(written % 2048u * 10u / 2048u),
		       (unsigned long)(expected / 2048u), (unsigned long)(expected % 2048u * 10u / 2048u),
		       pct > 99 ? 99 : pct, (unsigned long)((now - t_start) / 1000000u));
	}
	return st;
}

/* About how many sectors FatFs writes creating FAT32 on `count` sectors
 * with 32 KiB clusters: two FATs, the root directory, the reserved area. */
static uint32_t mkfs_estimate(uint32_t count)
{
	uint32_t clusters = count / 64u;
	uint32_t fat = (clusters * 4u + 511u) / 512u;
	return 2u * fat + 64u + 32u;
}
static ez_status_t o_sync(void *c) { (void)c; return hal_sdblk.sync(NULL); }

static void set_vol(int i, uint32_t start, uint32_t count)
{
	vol[i] = (offbd_t){ start, count, { 0 } };
	vol[i].bd = (ez_blockdev_t){ &vol[i], 512, o_present, o_init, o_check, o_count, o_read, o_write, o_sync, NULL };
}

/* ---- a keystore with nothing in it: every drive except the card ---------------- */
static bool n_present(void *c, uint8_t d) { (void)c; (void)d; return false; }
static ez_status_t n_gone(void *c, uint8_t d) { (void)c; (void)d; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_size(void *c, uint8_t d, const char *n, uint32_t *s) { (void)c; (void)d; (void)n; (void)s; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_read(void *c, uint8_t d, const char *n, uint32_t o, void *b, uint32_t l)
{ (void)c; (void)d; (void)n; (void)o; (void)b; (void)l; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_name(void *c, uint8_t d, const char *n) { (void)c; (void)d; (void)n; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_append(void *c, uint8_t d, const char *n, const void *b, uint32_t l)
{ (void)c; (void)d; (void)n; (void)b; (void)l; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_rename(void *c, uint8_t d, const char *a, const char *b) { (void)c; (void)d; (void)a; (void)b; return EZ_ERR_MEDIA_REMOVED; }
static ez_status_t n_list(void *c, uint8_t d, uint32_t i, char n[EZ_NAME_MAX], uint32_t *s)
{ (void)c; (void)d; (void)i; (void)n; (void)s; return EZ_ERR_MEDIA_REMOVED; }
static const ez_hal_keystore_t none = { NULL, n_present, n_gone, n_size, n_read, n_name, n_append,
                                        n_rename, n_name, n_list, n_gone, NULL };

/* ---- mount ----------------------------------------------------------------------- */
static ez_ks_mirror_t mir;
static uint8_t work[4096];

/* FatFs's automatic cluster size (32 KiB for volumes this large already).
 * Creating a 15 GB volume is ~7,600 block writes: about a minute or more on
 * V1's card, so progress is printed (TR-07). */
static MKFS_PARM mkfs_opt(uint32_t sectors)
{
	(void)sectors;
	MKFS_PARM o = { FM_FAT32 | FM_SFD, 2, 0, 0, 0u };
	return o;
}
static uint8_t ncopies = 1;
static ez_status_t fs_status = EZ_ERR_MEDIA_REMOVED;   /* the last mount's result */
ez_status_t card_fs_status(void) { return fs_status; }
static uint8_t sec[512];

/* Our two-volume layout, read from the MBR. */
/* Partition type while a volume's file system is being created. FatFs
 * writes the boot sector first, so an interrupted creation leaves a volume
 * that mounts over incomplete FATs; a volume still marked pending is never
 * mounted (TR-07). */
#define T_FAT32    0x0C
#define T_PENDING  0xDA
static bool complete[2];

static bool layout(uint32_t sectors, uint32_t s[2], uint32_t n[2])
{
	if (hal_sdblk.read(NULL, 0, sec, 1) != EZ_OK) return false;
	if (sec[510] != 0x55 || sec[511] != 0xAA || memcmp(sec + 440, SIG, 4) != 0) return false;
	for (int i = 0; i < 2; i++) {
		const uint8_t *e = sec + 446 + 16 * i;
		if (e[4] != T_FAT32 && e[4] != T_PENDING) return false;
		complete[i] = e[4] == T_FAT32;
		s[i] = ez_get_le32(e + 8);
		n[i] = ez_get_le32(e + 12);
		if (!n[i] || s[i] + n[i] > sectors) return false;
	}
	return s[0] == A_START && s[0] + n[0] <= s[1];
}

static void busy_line(const char *what, uint32_t s)
{
	card_printf("\r  card busy (%s) for %lu s, %lu blocks written so far   ", what, (unsigned long)s, (unsigned long)written);
}

static ez_status_t step(const char *what, ez_status_t st)
{
	if (card_verbose) {
		if (written) {
			uint64_t us = time_us_64() - t_start;
			card_printf("\r  wrote %lu.%lu MiB in %lu s, %lu.%lu ms per block           \n",
			       (unsigned long)(written / 2048u), (unsigned long)(written % 2048u * 10u / 2048u),
			       (unsigned long)(us / 1000000u), (unsigned long)(us / written / 1000u),
			       (unsigned long)(us / written % 1000u / 100u));
			written = 0;
		}
		card_printf("  %-34s %s", what, ez_status_name(st));
		if (st != EZ_OK) card_printf("  (card: %s)", ez_sd_last_error());
		card_printf("\n");
	}
	return st;
}

static bool key_file(const char *n)
{
	size_t l = strlen(n);
	if (l < 4 || n[l - 4] != '.') return false;
	const char *e = n + l - 3;
	return !strcmp(e, "KEY") || !strcmp(e, "SUM") || !strcmp(e, "TMP") || !strcmp(e, "SUT");
}

/* reinit: initialise the card first (insertion, boot). After a format the
 * card is already initialised and working; initialising it again is
 * unnecessary, and was where formatting failed on V1 (TR-07). */
static ez_status_t mount(bool reinit)
{
	ez_status_t st = reinit || !hal_sd_present() ? hal_sdblk.init(NULL) : EZ_OK;
	ez_mirror_vol_t v[2] = { { &cards.hal, 1 }, { &cards.hal, 2 } };
	if (st != EZ_OK) {
		ez_ks_fatfs_init(&cards, NULL, &hal_sdblk, NULL);
		ez_ks_mirror_init(&mir, &none, 1, v, 1);
		ncopies = 1;
		return st;
	}
	uint32_t sectors, s[2], n[2];
	uint8_t cid[16];
	hal_sd_info(&sectors, cid);
	if (layout(sectors, s, n)) {
		set_vol(0, s[0], n[0]);
		set_vol(1, s[1], n[1]);
		ez_ks_fatfs_init(&cards, NULL, &vol[0].bd, &vol[1].bd);
		ez_status_t a = complete[0] ? ez_ks_fatfs_mount(&cards, 1) : EZ_ERR_MEDIA;
		ez_status_t b = complete[1] ? ez_ks_fatfs_mount(&cards, 2) : EZ_ERR_MEDIA;
		ez_ks_mirror_init(&mir, &none, 1, v, 2);
		ncopies = 2;
		return a == EZ_OK || b == EZ_OK ? EZ_OK : a;      /* one healthy volume is enough to read */
	}
	ez_ks_fatfs_init(&cards, NULL, &hal_sdblk, NULL);   /* a plain FAT card: one copy */
	ez_ks_mirror_init(&mir, &none, 1, v, 1);
	ncopies = 1;
	return ez_ks_fatfs_mount(&cards, 1);
}

ez_status_t card_mount(void) { return fs_status = mount(true); }

/* Mark volume k pending or complete in the MBR (one sector write). */
static ez_status_t set_type(int k, uint8_t type)
{
	ez_status_t st = hal_sdblk.read(NULL, 0, sec, 1);
	if (st != EZ_OK) return st;
	sec[446 + 16 * k + 4] = type;
	st = hal_sdblk.write(NULL, 0, sec, 1);
	if (st == EZ_OK) complete[k] = type == T_FAT32;
	return st;
}

bool card_volume_mounted(uint8_t k)
{
	return k < ncopies && cards.hal.present(&cards, (uint8_t)(1 + k));
}

/* Retry mounting copy volumes that are not mounted (a card still busy
 * right after a format, TR-07). Called periodically while idle. */
void card_service(void)
{
	/* Never block the main loop (USB, shell): at most every 30 s, and
	 * not while the card is busy -- each command to a busy card can wait
	 * seconds (TR-07: the shell froze). */
	static uint64_t next;
	if (ncopies < 2 || !hal_sd_present()) return;
	if (card_volume_mounted(0) && card_volume_mounted(1)) return;
	if (time_us_64() < next) return;
	next = time_us_64() + 30u * 1000u * 1000u;
	if (ez_sd_busy_now()) return;
	for (uint8_t k = 0; k < ncopies; k++)
		if (!card_volume_mounted(k) && complete[k]) ez_ks_fatfs_mount(&cards, (uint8_t)(1 + k));
}

/* IMPL-AV-004: recreate the file system of copy volumes that will not
 * mount; healthy volumes are never touched. */
int card_force_volume = -1;          /* development shell: recreate this volume even if it mounts */

ez_status_t card_repair(void *ctx, uint8_t drive, uint8_t *recreated)
{
	(void)ctx;
	*recreated = 0;
	if (drive != 1) return EZ_ERR_BAD_REQUEST;
	if (ncopies < 2) return EZ_ERR_UNSUPPORTED;            /* a plain card: format it instead */
	ez_status_t first = EZ_OK;
	for (uint8_t k = 0; k < ncopies; k++) {
		uint8_t d = (uint8_t)(1 + k);
		bool force = card_force_volume == k;
		if (!force && complete[k] && (card_volume_mounted(k) || ez_ks_fatfs_mount(&cards, d) == EZ_OK)) continue;
		char path[3] = { (char)('0' + d), ':', 0 };
		ez_ks_fatfs_unmount(&cards, d);
		/* The same patience as formatting (TR-07: repair failed after 10 s). */
		step("card ready", ez_sd_settle(120000) ? EZ_OK : EZ_ERR_BUSY);
		ez_sd_set_write_timeout_ms(300000);
		if (card_verbose) card_printf("  recreating volume %c: about 7,600 writes on a 32 GB card, can take a few minutes\n", k ? 'B' : 'A');
		if (card_verbose) ez_sd_wait_hook = busy_line;
		ez_status_t st = step("mark it pending", set_type(k, T_PENDING));
		MKFS_PARM opt = mkfs_opt(vol[k].count);
		expected = mkfs_estimate(vol[k].count);
		written = 0;
		report = true;
		if (st == EZ_OK)
			st = step(k ? "recreate volume B" : "recreate volume A",
			          f_mkfs(path, &opt, work, sizeof work) == FR_OK ? EZ_OK : EZ_ERR_MEDIA);
		report = false;
		if (st == EZ_OK) st = step("mark it complete", set_type(k, T_FAT32));
		ez_sd_wait_hook = NULL;
		ez_sd_set_write_timeout_ms(10000);
		ez_secure_zero(work, sizeof work);
		if (st == EZ_OK) st = step("mount it", ez_ks_fatfs_mount(&cards, d));
		if (st == EZ_OK) (*recreated)++;
		else if (first == EZ_OK) first = st;
	}
	return first;
}

void card_init(void)
{
	ez_mirror_vol_t v[1] = { { &cards.hal, 1 } };
	ez_ks_fatfs_init(&cards, NULL, &hal_sdblk, NULL);
	ez_ks_mirror_init(&mir, &none, 1, v, 1);
	fs_status = card_mount();
}

const ez_hal_keystore_t *card_hal(void) { return &mir.hal; }
uint8_t card_copies(void) { return ncopies; }

/* ---- format (IMPL-AV-007) ---------------------------------------------------------- */

static void put_entry(uint8_t *e, uint32_t start, uint32_t count)
{
	e[0] = 0x00; e[1] = 0xFE; e[2] = 0xFF; e[3] = 0xFF;     /* CHS: use LBA */
	e[4] = 0x0C;                                         /* FAT32, LBA */
	e[5] = 0xFE; e[6] = 0xFF; e[7] = 0xFF;
	ez_put_le32(e + 8, start);
	ez_put_le32(e + 12, count);
}

static ez_status_t format(uint8_t drive, uint8_t copies);

ez_status_t card_format(void *ctx, uint8_t drive, uint8_t copies)
{
	(void)ctx;
	/* Patience for the whole format: the card may still be finishing an
	 * erase in the background (TR-07; reproduced in tests/hwsim). */
	ez_sd_set_write_timeout_ms(300000);
	if (card_verbose) ez_sd_wait_hook = busy_line;
	ez_status_t st = format(drive, copies);
	ez_sd_wait_hook = NULL;
	ez_sd_set_write_timeout_ms(10000);
	return st;
}

static ez_status_t format(uint8_t drive, uint8_t copies)
{
	if (drive != 1) return EZ_ERR_BAD_REQUEST;
	bool full_erase = (copies & 0x80u) != 0;
	copies &= 0x7Fu;
	/* 1. Erase every key file still reachable, in place (SEC-STORE-001). */
	/* Key files only: zero-filling the whole card through SPI would take
	 * hours; what the file system does not reach, SD ERASE covers. */
	{
		ez_status_t first = EZ_OK;
		for (uint8_t k = 0; k < ncopies; k++) {
			uint8_t a = ncopies > 1 ? EZ_COPY(1, k) : 1;
			char n[EZ_NAME_MAX];
			uint32_t sz, i = 0;
			while (mir.hal.list(mir.hal.ctx, a, i, n, &sz) == EZ_OK) {
				if (key_file(n)) {
					ez_status_t z = mir.hal.zap(mir.hal.ctx, a, n);
					if (z == EZ_OK) continue;                 /* listing shifted */
					if (first == EZ_OK) first = z;
				}
				i++;
			}
		}
		step("erase reachable key files", first);
	}
	/* 2. SD ERASE over the whole card, for what the file system no longer
	 *    reaches. How physically thorough this is depends on the card. */
	if (!hal_sd_present() && step("initialise card", hal_sdblk.init(NULL)) != EZ_OK)
		return EZ_ERR_MEDIA_REMOVED;
	uint32_t sectors;
	uint8_t cid[16];
	hal_sd_info(&sectors, cid);
	if (sectors < 4u * ALIGN) return step("card size (under 64 MiB)", EZ_ERR_MEDIA);
	uint32_t erased = 0, chunks = 0;
	/* Whole-card SD ERASE only on request: consumer cards may finish it in
	 * the background and stay busy for minutes (TR-07), and on an SD card
	 * it does not guarantee physical erasure anyway. */
	for (uint32_t b = 0; full_erase && b < sectors; b += ALIGN) {
		uint32_t e = b + ALIGN - 1u < sectors - 1u ? b + ALIGN - 1u : sectors - 1u;
		chunks++;
		if (!ez_sd_erase(b, e)) break;                            /* best effort; the MBR and mkfs follow */
		erased++;
	}
	if (full_erase && card_verbose) card_printf("  %-34s %lu of %lu\n", "SD ERASE (4 MiB steps)", (unsigned long)erased, (unsigned long)chunks);
	fs_status = EZ_ERR_MEDIA;                         /* until the format completes */
	/* A card can still be busy from an earlier erase (TR-07): be patient. */
	step("card ready", ez_sd_settle(full_erase ? 300000 : 120000) ? EZ_OK : EZ_ERR_BUSY);
	/* Still answering? Re-initialise only if not. */
	if (!ez_sd_status() && step("re-initialise after erase", hal_sdblk.init(NULL)) != EZ_OK)
		return EZ_ERR_MEDIA_REMOVED;
	/* 3. MBR and file systems. */
	uint32_t half = (sectors / 2u) & ~(ALIGN - 1u);
	uint32_t s0 = A_START, n0 = half - A_START, s1 = half, n1 = (sectors - half) & ~(ALIGN - 1u);
	if (copies == 1) n0 = (sectors - A_START) & ~(ALIGN - 1u);
	memset(sec, 0, sizeof sec);
	if (copies == 2) memcpy(sec + 440, SIG, 4);
	put_entry(sec + 446, s0, n0);
	if (copies == 2) put_entry(sec + 462, s1, n1);
	if (copies == 2) { sec[446 + 4] = T_PENDING; sec[462 + 4] = T_PENDING; }   /* until each is complete */
	sec[510] = 0x55; sec[511] = 0xAA;
	if (step("write MBR", hal_sdblk.write(NULL, 0, sec, 1)) != EZ_OK) return fs_status = EZ_ERR_MEDIA;
	set_vol(0, s0, n0);
	set_vol(1, s1, n1);
	ez_ks_fatfs_init(&cards, NULL, &vol[0].bd, copies == 2 ? &vol[1].bd : NULL);
	MKFS_PARM oa = mkfs_opt(n0), ob = mkfs_opt(n1);
	written = 0;
	if (card_verbose) card_printf("  creating file systems: can take a few minutes on a large card\n");
	expected = mkfs_estimate(n0);
	ez_status_t st = step("file system on volume A", f_mkfs("1:", &oa, work, sizeof work) == FR_OK ? EZ_OK : EZ_ERR_MEDIA);
	expected = mkfs_estimate(n1);
	if (st == EZ_OK && copies == 2) st = set_type(0, T_FAT32);
	if (st == EZ_OK && copies == 2)
		st = step("file system on volume B", f_mkfs("2:", &ob, work, sizeof work) == FR_OK ? EZ_OK : EZ_ERR_MEDIA);
	if (st == EZ_OK && copies == 2) st = set_type(1, T_FAT32);
	ez_secure_zero(work, sizeof work);
	if (st != EZ_OK) return fs_status = st;
	ez_status_t m = step("mount", fs_status = mount(false));
	if (m == EZ_OK && copies == 2) {
		step("  volume A", card_volume_mounted(0) ? EZ_OK : EZ_ERR_MEDIA);
		step("  volume B", card_volume_mounted(1) ? EZ_OK : EZ_ERR_MEDIA);
	}
	return m;
}

/* For the status displays (EZ-UI-001): "absent", "31.7 GB, 2 copies". */
void card_info_text(char *o, uint32_t cap)
{
	if (!hal_sd_present()) { snprintf(o, cap, "absent"); return; }
	uint32_t sec;
	uint8_t cid[16];
	hal_sd_info(&sec, cid);
	unsigned t = (unsigned)((uint64_t)sec * 512u / 100000000u);      /* tenths of a GB */
	if (fs_status != EZ_OK) snprintf(o, cap, "%u.%u GB, not formatted", t / 10u, t % 10u);
	else snprintf(o, cap, "%u.%u GB, %u cop%s", t / 10u, t % 10u, ncopies, ncopies == 1 ? "y" : "ies");
}
