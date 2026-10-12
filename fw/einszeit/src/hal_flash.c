/*
 * hal_flash.c -- ez_flash_t over the drive 0 key partition of the QSPI
 * flash, and the check that it is protected (IMPL-DRV-003).
 *
 * Layout: board.h. With a partition table, the boot ROM maps the firmware's
 * own partition at the start of the XIP window (QMI ATRANS0), so the key
 * partition is not visible at its physical offset there. At boot we map it
 * into XIP window 1 (ATRANS1) and read it through the uncached alias, so
 * reads always see the flash itself. Erase and program use physical
 * offsets and go through flash_safe_execute(), which keeps the other core
 * and interrupts away from XIP while the flash is busy. Program is page-
 * wise: bytes outside the requested range are written as 0xFF, which leaves
 * them unchanged on NOR. The page buffer is cleared after use (SEC-FW-003).
 */
#include <string.h>

#include "pico/stdlib.h"
#include "pico/flash.h"
#include "pico/bootrom.h"
#include "hardware/flash.h"
#include "hardware/structs/qmi.h"
#include "hardware/regs/addressmap.h"
#include "boot/picobin.h"
#include "boot/bootrom_constants.h"

#include "board.h"
#include "ez_secure.h"
#include "hal_rp2350.h"

#ifdef XIP_NOCACHE_NOALLOC_BASE
#define XIP_READ_BASE XIP_NOCACHE_NOALLOC_BASE
#else
#define XIP_READ_BASE XIP_BASE
#endif

#define SECTOR 4096u

void hal_flash_init(void)
{
	/* XIP window 1 -> the key partition: base and size in 4 KiB units. */
	qmi_hw->atrans[1] = ((uint32_t)KEYPART_BLOCKS << QMI_ATRANS1_SIZE_LSB) |
	                    (KEYPART_OFFSET / SECTOR);
}

typedef struct { uint32_t off; const uint8_t *data; uint32_t len; } job_t;

static void do_erase(void *p) { job_t *j = p; flash_range_erase(j->off, FLASH_SECTOR_SIZE); }
static void do_program(void *p) { job_t *j = p; flash_range_program(j->off, j->data, j->len); }

static ez_status_t f_read(void *ctx, uint32_t addr, void *buf, uint32_t len)
{
	(void)ctx;
	if ((uint64_t)addr + len > (uint64_t)KEYPART_BLOCKS * EZ_FLASH_BLOCK) return EZ_ERR_RANGE;
	memcpy(buf, (const void *)(XIP_READ_BASE + KEYPART_WINDOW + addr), len);
	return EZ_OK;
}

static ez_status_t f_erase(void *ctx, uint32_t block)
{
	(void)ctx;
	if (block >= KEYPART_BLOCKS) return EZ_ERR_RANGE;
	job_t j = { KEYPART_OFFSET + block * EZ_FLASH_BLOCK, NULL, 0 };
	return flash_safe_execute(do_erase, &j, 1000) == PICO_OK ? EZ_OK : EZ_ERR_MEDIA;
}

static uint8_t page[FLASH_PAGE_SIZE];

static ez_status_t f_program(void *ctx, uint32_t addr, const void *buf, uint32_t len)
{
	(void)ctx;
	if ((uint64_t)addr + len > (uint64_t)KEYPART_BLOCKS * EZ_FLASH_BLOCK) return EZ_ERR_RANGE;
	const uint8_t *p = buf;
	ez_status_t st = EZ_OK;
	while (len && st == EZ_OK) {
		uint32_t base = addr & ~(FLASH_PAGE_SIZE - 1u), o = addr - base;
		uint32_t n = FLASH_PAGE_SIZE - o < len ? FLASH_PAGE_SIZE - o : len;
		memset(page, 0xFF, sizeof page);
		memcpy(page + o, p, n);
		job_t j = { KEYPART_OFFSET + base, page, FLASH_PAGE_SIZE };
		if (flash_safe_execute(do_program, &j, 1000) != PICO_OK) st = EZ_ERR_MEDIA;
		addr += n; p += n; len -= n;
	}
	ez_secure_zero(page, sizeof page);
	return st;
}

const ez_flash_t hal_flash = { NULL, KEYPART_BLOCKS, f_read, f_erase, f_program };

/* ---- IMPL-DRV-003: is the key partition protected? -------------------------
 * True only if the boot ROM has a partition table with a partition that
 * covers exactly the key partition, and that partition grants Secure read
 * and write and denies Non-secure and bootloader (picotool, UF2) access. */
static bool checked, protected_ok;
static const char *why = "not checked";
static uint8_t pt_work[3264] __attribute__((aligned(4)));

static bool check(void)
{
	uint32_t buf[3 + 2 * 16];
	int n = rom_get_partition_table_info(buf, sizeof buf / 4, PT_INFO_PT_INFO | PT_INFO_PARTITION_LOCATION_AND_FLAGS);
	if (n < 0) {                                  /* not loaded yet: load and retry */
		if (rom_load_partition_table(pt_work, sizeof pt_work, false) < 0) { why = "no partition table"; return false; }
		n = rom_get_partition_table_info(buf, sizeof buf / 4, PT_INFO_PT_INFO | PT_INFO_PARTITION_LOCATION_AND_FLAGS);
	}
	if (n < 4) { why = "no partition table"; return false; }
	/* buf[0] = flags returned; buf[1] = partition count (low byte);
	 * buf[2..3] = unpartitioned space; then 2 words per partition. */
	uint32_t count = buf[1] & 0xFFu;
	uint32_t first = KEYPART_OFFSET / SECTOR, last = first + KEYPART_BLOCKS - 1u;
	for (uint32_t i = 0; i < count && 4u + 2u * i + 1u < (uint32_t)n; i++) {
		uint32_t loc = buf[4 + 2 * i], flags = buf[5 + 2 * i];
		uint32_t f = (loc & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
		uint32_t l = (loc & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
		if (f > last || l < first) continue;      /* no overlap */
		if (f != first || l != last) { why = "a partition overlaps the key region without matching it"; return false; }
		uint32_t perm = loc | flags;              /* permission bits are carried in both words */
		const uint32_t deny = PICOBIN_PARTITION_PERMISSION_NS_R_BITS | PICOBIN_PARTITION_PERMISSION_NS_W_BITS |
		                      PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS | PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS;
		const uint32_t need = PICOBIN_PARTITION_PERMISSION_S_R_BITS | PICOBIN_PARTITION_PERMISSION_S_W_BITS;
		if (perm & deny) { why = "the key partition allows bootloader or Non-secure access"; return false; }
		if ((perm & need) != need) { why = "the key partition lacks Secure read/write"; return false; }
		why = "verified";
		return true;
	}
	why = "no partition covers the key region";
	return false;
}

bool hal_flash_protected(void *ctx)
{
	(void)ctx;
	if (!checked) { protected_ok = check(); checked = true; }   /* the table cannot change while running */
	return protected_ok;
}

const char *hal_flash_protection_reason(void) { hal_flash_protected(NULL); return why; }
