/*
 * hal_sdblk.c -- ez_blockdev_t over the microSD (SPI1) for the FatFs port.
 *
 * IMPL-ENG-010: the software check is authoritative. init() (on boot and on
 * every mount) records the card's CID; check() sends SEND_STATUS (CMD13)
 * and reads the CID again, and any difference -- or any failed command --
 * reports the card as removed until it is mounted again. Reads verify the
 * card's data CRC-16. SD_DET (active-high with the internal pull-down on V1,
 * measured in TR-03) is a hint only and is not consulted here; the shell
 * shows it.
 * EZ-SEC-001 traceability: SEC-HW-002, SEC-FW-003.
 */
#include <string.h>

#include "pico/stdlib.h"

#include "board.h"
#include "ez_sd.h"
#include "ez_secure.h"
#include "hal_rp2350.h"

static ez_sd_card_t s_card;
static uint8_t s_cid[16];
static bool s_ok;

bool hal_sd_present(void) { return s_ok; }
int  hal_sd_det_raw(void) { return ez_sd_det_raw(); }

void hal_sd_info(uint32_t *sectors, uint8_t cid[16])
{
	*sectors = s_ok ? s_card.block_count : 0;
	memcpy(cid, s_cid, 16);
}

static bool b_present(void *ctx) { (void)ctx; return true; }   /* decided by init/check */

static ez_status_t b_init(void *ctx)
{
	(void)ctx;
	/* Never reset a card that is working: a reset (CMD0) arriving while it
	 * still finishes a write can leave some cards unresponsive until power
	 * is cut (seen on V1 in TR-07). A card that was removed or swapped does
	 * not answer SEND_STATUS, and is initialised properly. */
	if (s_ok && ez_sd_alive()) return EZ_OK;
	ez_sd_initlog_t log;
	s_ok = false;
	if (!ez_sd_init(&s_card, &log)) { ez_sd_note_init(&log); return EZ_ERR_MEDIA_REMOVED; }
	memcpy(s_cid, s_card.cid, 16);
	s_ok = true;
	return EZ_OK;
}

static ez_status_t b_check(void *ctx)
{
	(void)ctx;
	uint8_t cid[16];
	if (!s_ok || !ez_sd_alive() || !ez_sd_read_cid(cid) || memcmp(cid, s_cid, 16) != 0) {
		s_ok = false;
		return EZ_ERR_MEDIA_REMOVED;
	}
	return EZ_OK;
}

static uint32_t b_count(void *ctx) { (void)ctx; return s_card.block_count; }

static ez_status_t b_read(void *ctx, uint32_t lba, uint8_t *buf, uint32_t n)
{
	(void)ctx;
	/* Damaged file system structures can point past the end: never send
	 * the card a command for a block it does not have. */
	if (!s_ok) { ez_secure_zero(buf, 512u * n); return EZ_ERR_MEDIA_REMOVED; }
	if ((uint64_t)lba + n > s_card.block_count) { ez_secure_zero(buf, 512u * n); return EZ_ERR_MEDIA; }
	for (uint32_t i = 0; i < n; i++) {
		bool crc_ok = false;
		if (!s_ok) { ez_secure_zero(buf, 512u * n); return EZ_ERR_MEDIA_REMOVED; }
		if (!ez_sd_read_block(lba + i, buf + 512u * i, &crc_ok) || !crc_ok) {
			ez_secure_zero(buf, 512u * n);
			/* A card that still answers had an error; one that does not is gone. */
			s_ok = ez_sd_alive();
			return s_ok ? EZ_ERR_MEDIA : EZ_ERR_MEDIA_REMOVED;
		}
	}
	return EZ_OK;
}

static ez_status_t b_write(void *ctx, uint32_t lba, const uint8_t *buf, uint32_t n)
{
	(void)ctx;
	if (!s_ok) return EZ_ERR_MEDIA_REMOVED;
	if ((uint64_t)lba + n > s_card.block_count) return EZ_ERR_MEDIA;
	for (uint32_t i = 0; i < n; i++) {
		if (!s_ok) return EZ_ERR_MEDIA_REMOVED;
		if (!ez_sd_write_block(lba + i, buf + 512u * i)) {
			s_ok = ez_sd_alive();                  /* card error, or card gone */
			return s_ok ? EZ_ERR_MEDIA : EZ_ERR_MEDIA_REMOVED;
		}
	}
	return EZ_OK;
}

static ez_status_t b_sync(void *ctx) { (void)ctx; return s_ok ? EZ_OK : EZ_ERR_MEDIA_REMOVED; }

const ez_blockdev_t hal_sdblk = { NULL, 512, b_present, b_init, b_check, b_count,
                                  b_read, b_write, b_sync, NULL };

/* The card was removed (SD_DET): forget it, so the next access or mount
 * initialises whatever card is inserted next. */
void hal_sd_forget(void) { s_ok = false; }
