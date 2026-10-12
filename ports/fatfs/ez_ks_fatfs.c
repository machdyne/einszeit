/*
 * ez_ks_fatfs.c -- see ez_ks_fatfs.h. Also provides FatFs's disk
 * interface (diskio.h) for the block devices registered here.
 */
#include "ez_ks_fatfs.h"

#include <string.h>

#include "diskio.h"
#include "ez_secure.h"

static ez_ks_fatfs_t *g_ks;                 /* FatFs's disk layer is global */
static const uint8_t zero[512];
static uint8_t work[FF_MAX_SS];             /* mkfs and zap verification */

/* ---- FatFs disk interface -------------------------------------------- */

static const ez_blockdev_t *bdev(BYTE pdrv)
{
	return (g_ks && pdrv < EZ_DRIVES) ? g_ks->bd[pdrv] : NULL;
}

DSTATUS disk_status(BYTE pdrv)
{
	const ez_blockdev_t *b = bdev(pdrv);
	return (b && b->present(b->ctx)) ? 0 : (STA_NOINIT | STA_NODISK);
}

DSTATUS disk_initialize(BYTE pdrv) { return disk_status(pdrv); }

DRESULT disk_read(BYTE pdrv, BYTE *buff, LBA_t sector, UINT count)
{
	const ez_blockdev_t *b = bdev(pdrv);
	if (!b || !b->present(b->ctx)) return RES_NOTRDY;
	return b->read(b->ctx, (uint32_t)sector, buff, count) == EZ_OK ? RES_OK : RES_ERROR;
}

DRESULT disk_write(BYTE pdrv, const BYTE *buff, LBA_t sector, UINT count)
{
	const ez_blockdev_t *b = bdev(pdrv);
	if (!b || !b->present(b->ctx)) return RES_NOTRDY;
	return b->write(b->ctx, (uint32_t)sector, buff, count) == EZ_OK ? RES_OK : RES_ERROR;
}

DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void *buff)
{
	const ez_blockdev_t *b = bdev(pdrv);
	if (!b || !b->present(b->ctx)) return RES_NOTRDY;
	switch (cmd) {
	case CTRL_SYNC:        return b->sync(b->ctx) == EZ_OK ? RES_OK : RES_ERROR;
	case GET_SECTOR_COUNT: *(LBA_t *)buff = b->sector_count(b->ctx); return RES_OK;
	case GET_SECTOR_SIZE:  *(WORD *)buff = (WORD)b->sector_size; return RES_OK;
	case GET_BLOCK_SIZE:   *(DWORD *)buff = 1; return RES_OK;
	default:               return RES_PARERR;
	}
}

/* ---- helpers --------------------------------------------------------- */

#define PATH_MAX_ (2 + EZ_NAME_MAX)

/* "N:name". A name that does not fit is refused, never truncated: a
 * truncated name could address a different file. */
static bool path(char out[PATH_MAX_], uint8_t drive, const char *name)
{
	out[0] = (char)('0' + drive);
	out[1] = ':';
	size_t i = 0;
	for (; name && name[i]; i++) {
		if (i >= EZ_NAME_MAX - 1) return false;
		out[2 + i] = name[i];
	}
	out[2 + i] = '\0';
	return true;
}

static void clear(ez_ks_fatfs_t *k)
{
	ez_secure_zero(&k->fil, sizeof k->fil);
	ez_secure_zero(&k->dir, sizeof k->dir);
	ez_secure_zero(&k->fno, sizeof k->fno);
	ez_secure_zero(work, sizeof work);
}

static bool usable(ez_ks_fatfs_t *k, uint8_t drive)
{
	if (drive >= EZ_DRIVES || !k->bd[drive] || !k->mounted[drive])
		return false;
	if (!k->bd[drive]->present(k->bd[drive]->ctx)) {
		k->mounted[drive] = false;          /* removed: must be remounted */
		return false;
	}
	return true;
}

static ez_status_t map(ez_ks_fatfs_t *k, uint8_t drive, FRESULT fr)
{
	switch (fr) {
	case FR_OK:          return EZ_OK;
	case FR_NO_FILE:
	case FR_NO_PATH:     return EZ_ERR_NOT_FOUND;
	case FR_EXIST:       return EZ_ERR_EXISTS;
	case FR_DENIED:      return EZ_ERR_FULL;
	default:
		if (!usable(k, drive) || k->bd[drive]->check(k->bd[drive]->ctx) != EZ_OK)
			return EZ_ERR_MEDIA_REMOVED;
		return EZ_ERR_MEDIA;
	}
}

/* ---- ez_hal_keystore_t ----------------------------------------------- */

static bool ks_present(void *ctx, uint8_t drive) { return usable(ctx, drive); }

static ez_status_t ks_check(void *ctx, uint8_t drive)
{
	ez_ks_fatfs_t *k = ctx;
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	return k->bd[drive]->check(k->bd[drive]->ctx) == EZ_OK ? EZ_OK : EZ_ERR_MEDIA_REMOVED;
}

static ez_status_t ks_size(void *ctx, uint8_t drive, const char *name, uint32_t *size)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(p, drive, name)) return EZ_ERR_BAD_REQUEST;
	FRESULT fr = f_stat(p, &k->fno);
	/* exFAT sizes are 64-bit; key lengths are 32-bit (SEC-STORE-003). */
	bool big = fr == FR_OK && (uint64_t)k->fno.fsize > 0xFFFFFFFFull;
	if (fr == FR_OK) *size = (uint32_t)k->fno.fsize;
	clear(k);
	if (big) return EZ_ERR_KEY_PARAM;
	return map(k, drive, fr);
}

static ez_status_t ks_read(void *ctx, uint8_t drive, const char *name, uint32_t off,
                           void *buf, uint32_t len)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(p, drive, name)) return EZ_ERR_BAD_REQUEST;
	UINT br = 0;
	FRESULT fr = f_open(&k->fil, p, FA_READ);
	if (fr == FR_OK) {
		if ((uint64_t)off + len > f_size(&k->fil)) fr = FR_INVALID_PARAMETER;
		if (fr == FR_OK) fr = f_lseek(&k->fil, off);
		if (fr == FR_OK) fr = f_read(&k->fil, buf, len, &br);
		FRESULT fc = f_close(&k->fil);
		if (fr == FR_OK) fr = fc;
		if (fr == FR_OK && br != len) fr = FR_DISK_ERR;
	}
	clear(k);                               /* FIL.buf held key bytes */
	if (fr == FR_INVALID_PARAMETER) return EZ_ERR_RANGE;
	return map(k, drive, fr);
}

static ez_status_t ks_create(void *ctx, uint8_t drive, const char *name)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(p, drive, name)) return EZ_ERR_BAD_REQUEST;
	FRESULT fr = f_open(&k->fil, p, FA_CREATE_NEW | FA_WRITE);
	if (fr == FR_OK) fr = f_close(&k->fil);
	clear(k);
	return map(k, drive, fr);
}

static ez_status_t ks_append(void *ctx, uint8_t drive, const char *name,
                             const void *buf, uint32_t len)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(p, drive, name)) return EZ_ERR_BAD_REQUEST;
	UINT bw = 0;
	/* FA_OPEN_APPEND would create a missing file; the contract requires
	 * appending to a missing file to fail, so open existing and seek. */
	FRESULT fr = f_open(&k->fil, p, FA_WRITE);
	if (fr == FR_OK) {
		fr = f_lseek(&k->fil, f_size(&k->fil));
		if (fr == FR_OK) fr = f_write(&k->fil, buf, len, &bw);
		FRESULT fc = f_close(&k->fil);       /* close syncs: contract 2 */
		if (fr == FR_OK) fr = fc;
		if (fr == FR_OK && bw != len) fr = FR_DENIED;     /* volume full */
	}
	clear(k);
	return map(k, drive, fr);
}

static ez_status_t ks_rename(void *ctx, uint8_t drive, const char *from, const char *to)
{
	ez_ks_fatfs_t *k = ctx;
	char a[PATH_MAX_], b[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(a, drive, from) || !path(b, drive, to)) return EZ_ERR_BAD_REQUEST;
	/* The destination path of f_rename must not carry a drive prefix. */
	FRESULT fr = f_rename(a, b + 2);
	if (fr == FR_INVALID_NAME) { clear(k); return EZ_ERR_BAD_REQUEST; }
	clear(k);
	return map(k, drive, fr);
}

/* Overwrite with zeros in place, flush, verify, then delete. FatFs writes
 * into the file's existing clusters, so on flash and on the host RAM disk
 * the bytes are gone; on microSD the card's wear levelling may keep old
 * copies (best effort, EZ-IMPL-001 §6.3). */
static ez_status_t ks_zap(void *ctx, uint8_t drive, const char *name)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!path(p, drive, name)) return EZ_ERR_BAD_REQUEST;
	FRESULT fr = f_open(&k->fil, p, FA_READ | FA_WRITE);
	if (fr == FR_OK) {
		FSIZE_t size = f_size(&k->fil), done = 0;
		UINT n;
		while (fr == FR_OK && done < size) {
			UINT chunk = (UINT)(size - done < sizeof zero ? size - done : sizeof zero);
			fr = f_write(&k->fil, zero, chunk, &n);
			if (fr == FR_OK && n != chunk) fr = FR_DISK_ERR;
			done += chunk;
		}
		if (fr == FR_OK) fr = f_sync(&k->fil);
		if (fr == FR_OK) fr = f_lseek(&k->fil, 0);
		done = 0;
		while (fr == FR_OK && done < size) {
			UINT chunk = (UINT)(size - done < sizeof work ? size - done : sizeof work);
			fr = f_read(&k->fil, work, chunk, &n);
			if (fr == FR_OK && (n != chunk || !ez_is_zero(work, chunk))) fr = FR_DISK_ERR;
			done += chunk;
		}
		FRESULT fc = f_close(&k->fil);
		if (fr == FR_OK) fr = fc;
		if (fr == FR_OK) fr = f_unlink(p);
	}
	clear(k);
	return map(k, drive, fr);
}

static ez_status_t ks_list(void *ctx, uint8_t drive, uint32_t index,
                           char name[EZ_NAME_MAX], uint32_t *size)
{
	ez_ks_fatfs_t *k = ctx;
	char p[PATH_MAX_];
	if (!usable(k, drive)) return EZ_ERR_MEDIA_REMOVED;
	(void)path(p, drive, "");
	FRESULT fr = f_opendir(&k->dir, p);
	uint32_t i = 0;
	ez_status_t st = EZ_ERR_NOT_FOUND;
	while (fr == FR_OK) {
		fr = f_readdir(&k->dir, &k->fno);
		if (fr != FR_OK || k->fno.fname[0] == '\0') break;
		if (k->fno.fattrib & (AM_DIR | AM_SYS | AM_HID)) continue;
		if (i++ == index) {
			size_t nl = 0;                                       /* FF_LFN_BUF = 255 */
			while (nl < EZ_NAME_MAX - 1 && k->fno.fname[nl]) nl++;
			memset(name, 0, EZ_NAME_MAX);
			memcpy(name, k->fno.fname, nl);
			*size = (uint64_t)k->fno.fsize > 0xFFFFFFFFull ? 0xFFFFFFFFu
			                                               : (uint32_t)k->fno.fsize;
			st = EZ_OK;
			break;
		}
	}
	f_closedir(&k->dir);
	clear(k);
	return fr == FR_OK ? st : map(k, drive, fr);
}

static ez_status_t format(ez_ks_fatfs_t *k, uint8_t drive)
{
	char p[PATH_MAX_];
	(void)path(p, drive, "");
	/* Drive 0: one cluster = one sector = one 4 KiB NOR erase block, so no
	 * two files share an erase block (IMPL-FS-001). Cards: FatFs chooses. */
	MKFS_PARM opt = { FM_FAT | FM_SFD, 1, 0, 0, drive == 0 ? k->bd[drive]->sector_size : 0 };
	FRESULT fr = f_mkfs(p, &opt, work, sizeof work);
	clear(k);
	return fr == FR_OK ? EZ_OK : EZ_ERR_MEDIA;
}

static ez_status_t ks_wipe(void *ctx, uint8_t drive)
{
	ez_ks_fatfs_t *k = ctx;
	if (drive >= EZ_DRIVES || !k->bd[drive]) return EZ_ERR_BAD_REQUEST;
	const ez_blockdev_t *b = k->bd[drive];
	if (!b->present(b->ctx)) return EZ_ERR_MEDIA_REMOVED;
	ez_ks_fatfs_unmount(k, drive);
	ez_status_t st = EZ_OK;
	if (b->erase_all) {
		st = b->erase_all(b->ctx);
	} else {
		uint32_t n = b->sector_count(b->ctx), per = (uint32_t)(sizeof work / b->sector_size);
		memset(work, 0, sizeof work);
		for (uint32_t s = 0; st == EZ_OK && s < n; s += per)
			st = b->write(b->ctx, s, work, n - s < per ? n - s : per);
		if (st == EZ_OK) st = b->sync(b->ctx);
	}
	if (st == EZ_OK) st = format(k, drive);
	if (st == EZ_OK) st = ez_ks_fatfs_mount(k, drive);
	return st;
}

/* ---- lifecycle ------------------------------------------------------- */

void ez_ks_fatfs_init(ez_ks_fatfs_t *k, const ez_blockdev_t *bd0,
                      const ez_blockdev_t *bd1, const ez_blockdev_t *bd2)
{
	memset(k, 0, sizeof *k);
	k->bd[0] = bd0; k->bd[1] = bd1; k->bd[2] = bd2;
	k->hal = (ez_hal_keystore_t){ k, ks_present, ks_check, ks_size, ks_read, ks_create,
	                              ks_append, ks_rename, ks_zap, ks_list, ks_wipe, NULL };
	g_ks = k;
}

ez_status_t ez_ks_fatfs_mount(ez_ks_fatfs_t *k, uint8_t drive)
{
	if (drive >= EZ_DRIVES || !k->bd[drive]) return EZ_ERR_BAD_REQUEST;
	const ez_blockdev_t *b = k->bd[drive];
	k->mounted[drive] = false;
	if (!b->present(b->ctx) || b->init(b->ctx) != EZ_OK) return EZ_ERR_MEDIA_REMOVED;
	char p[PATH_MAX_];
	(void)path(p, drive, "");
	FRESULT fr = f_mount(&k->fs[drive], p, 1);
	if (fr == FR_NO_FILESYSTEM && drive == 0) {          /* internal flash only */
		if (format(k, drive) != EZ_OK) return EZ_ERR_MEDIA;
		fr = f_mount(&k->fs[drive], p, 1);
	}
	if (fr != FR_OK) return EZ_ERR_MEDIA;
	k->mounted[drive] = true;
	return EZ_OK;
}

void ez_ks_fatfs_unmount(ez_ks_fatfs_t *k, uint8_t drive)
{
	char p[PATH_MAX_];
	if (drive >= EZ_DRIVES) return;
	(void)path(p, drive, "");
	f_mount(NULL, p, 0);
	k->mounted[drive] = false;
	ez_secure_zero(&k->fs[drive], sizeof k->fs[drive]);
}
