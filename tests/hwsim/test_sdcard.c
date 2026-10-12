/*
 * test_sdcard.c -- the firmware's own SD driver, block layer and card module
 * (fw/einszeit/src/ez_sd.c, hal_sdblk.c, card.c) on the host, against an
 * emulated SD card (sim_sdcard). Reproduces what V1 showed in TR-07.
 */
#include <stdio.h>
#include <string.h>

#include "card.h"
#include "ez_ks_fatfs.h"
#include "ez_sd.h"
#include "ez_test.h"
#include "hal_rp2350.h"
#include "sim_sdcard.h"

ez_ks_fatfs_t cards;                      /* defined by app.c in the firmware */

static const sim_sd_cfg_t base = { 1u << 20, 200, 50, 0, false, -1 };   /* 512 MiB */

static void t_basics(void)
{
	sim_sd_init(&base);
	EZ_CHECK_EQ(hal_sdblk.init(NULL), EZ_OK);
	uint32_t n; uint8_t cid[16];
	hal_sd_info(&n, cid);
	EZ_CHECK_EQ(n, 1u << 20);
	static uint8_t w[512], r[512];
	for (int i = 0; i < 512; i++) w[i] = (uint8_t)(i * 3 + 1);
	EZ_CHECK_EQ(hal_sdblk.write(NULL, 1000, w, 1), EZ_OK);
	EZ_CHECK_EQ(hal_sdblk.read(NULL, 1000, r, 1), EZ_OK);
	EZ_CHECK(!memcmp(w, r, 512));
	EZ_CHECK_EQ(hal_sdblk.check(NULL), EZ_OK);
	EZ_CHECK_EQ(hal_sdblk.read(NULL, (1u << 20), r, 1), EZ_ERR_MEDIA);    /* beyond the end: no command */
	sim_sd_remove();
	EZ_CHECK_EQ(hal_sdblk.check(NULL), EZ_ERR_MEDIA_REMOVED);
	sim_sd_insert();
	EZ_CHECK_EQ(hal_sdblk.init(NULL), EZ_OK);
	EZ_CHECK_EQ(hal_sdblk.read(NULL, 1000, r, 1), EZ_OK);
	EZ_CHECK(!memcmp(w, r, 512));
}

static void t_format_two_copies(void)
{
	sim_sd_init(&base);
	card_init();
	card_verbose = 1;
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	card_verbose = 0;
	EZ_CHECK_EQ(card_copies(), 2);
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
	EZ_CHECK_EQ(card_mount(), EZ_OK);                    /* detected again from the MBR */
	EZ_CHECK_EQ(card_copies(), 2);
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
}

/* TR-07: after a whole-card ERASE this card keeps working in the
 * background for a minute; writes stay busy. Formatting must wait. */
static void t_background_erase(void)
{
	sim_sd_cfg_t cfg = base;
	cfg.erase_bg_us = 60u * 1000u * 1000u;
	sim_sd_init(&cfg);
	card_init();
	card_verbose = 1;
	EZ_CHECK_EQ(card_format(NULL, 1, 0x80 | 2), EZ_OK);          /* with whole-card erase */
	card_verbose = 0;
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
	/* and a second format right after, still inside the background work */
	EZ_CHECK_EQ(card_format(NULL, 1, 0x80 | 2), EZ_OK);
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	EZ_CHECK(!sim_sd_wedged());
}

/* TR-07: a reset (CMD0) sent while the card is busy leaves this card
 * unresponsive until power is cut. The driver waits for the card first, so
 * a busy card is not wedged; a card busy for longer than the driver waits
 * still is, and only a power cycle recovers it. */
static void t_reset_while_busy(void)
{
	sim_sd_cfg_t cfg = base;
	cfg.wedge_on_busy_reset = true;
	cfg.write_busy_us = 2u * 1000u * 1000u;               /* 2 s after every write */
	sim_sd_init(&cfg);
	EZ_CHECK_EQ(hal_sdblk.init(NULL), EZ_OK);
	static uint8_t w[512];
	memset(w, 0x5A, sizeof w);
	EZ_CHECK_EQ(hal_sdblk.write(NULL, 10, w, 1), EZ_OK);
	ez_sd_card_t card; ez_sd_initlog_t log;
	EZ_CHECK(ez_sd_init(&card, &log));                    /* a reset right after: waited, not wedged */
	EZ_CHECK(!sim_sd_wedged());
	/* busier than the driver's patience: wedged, until power is cut */
	cfg.write_busy_us = 60u * 1000u * 1000u;              /* beyond write limit + status wait + reset wait */
	sim_sd_init(&cfg);
	EZ_CHECK_EQ(hal_sdblk.init(NULL), EZ_OK);
	EZ_CHECK(hal_sdblk.write(NULL, 10, w, 1) != EZ_OK);   /* 10 s write limit */
	EZ_CHECK(!ez_sd_init(&card, &log));
	EZ_CHECK(sim_sd_wedged());
	sim_sd_power_cycle();
	EZ_CHECK(ez_sd_init(&card, &log));
	ez_test_note("a card busy for longer than the driver waits needs its power cut (DEV-23)");
}

/* TR-07: power lost while volume B's file system was being created. After
 * a power cycle the card is recognised as two copies with B unmountable;
 * card_repair recreates B and leaves A untouched. */
static void t_interrupted_format_repair(void)
{
	sim_sd_init(&base);
	card_init();
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	/* Volume B never formatted: its MBR entry exists, its boot sectors do
	 * not (FatFs writes them early, so a cut part-way through B usually
	 * leaves it mountable; this is the state V1's card was in). */
	uint8_t mbr[512], zero[512] = { 0 };
	sim_sd_raw_read(0, mbr);
	uint32_t b0 = (uint32_t)mbr[462 + 8] | (uint32_t)mbr[462 + 9] << 8 |
	              (uint32_t)mbr[462 + 10] << 16 | (uint32_t)mbr[462 + 11] << 24;
	for (uint32_t i = 0; i < 16; i++) sim_sd_raw_write(b0 + i, zero);
	sim_sd_power_cycle();
	card_init();
	EZ_CHECK_EQ(card_copies(), 2);                        /* the MBR says two copies */
	EZ_CHECK(card_volume_mounted(0) && !card_volume_mounted(1));
	card_service();                                       /* retrying does not help: B has no file system */
	EZ_CHECK(!card_volume_mounted(1));
	uint8_t n = 0;
	card_verbose = 1;
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);
	card_verbose = 0;
	EZ_CHECK_EQ(n, 1);
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);         /* healthy now: touches nothing */
	EZ_CHECK_EQ(n, 0);
}

/* TR-07 again: a slow card (busy for seconds after writes) while volume B is
 * recreated -- repair must be as patient as format -- and the periodic
 * remount must never block the main loop on a busy card. */
static void destroy_b(void)
{
	uint8_t mbr[512], zero[512] = { 0 };
	sim_sd_raw_read(0, mbr);
	uint32_t b0 = (uint32_t)mbr[470] | (uint32_t)mbr[471] << 8 | (uint32_t)mbr[472] << 16 | (uint32_t)mbr[473] << 24;
	for (uint32_t i = 0; i < 16; i++) sim_sd_raw_write(b0 + i, zero);
}

static void t_slow_card_repair(void)
{
	sim_sd_init(&base);
	card_init();
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	destroy_b();
	sim_sd_power_cycle();
	card_init();
	EZ_CHECK(!card_volume_mounted(1));
	/* the periodic retry while the card is busy: returns at once */
	sim_sd_make_busy(8u * 1000u * 1000u);
	uint64_t t0 = sim_now_us();
	card_service();
	EZ_CHECK(sim_now_us() - t0 < 1000);
	sim_sd_make_busy(0);
	t0 = sim_now_us();
	card_service();                                       /* within 30 s of the last try: skipped */
	EZ_CHECK(sim_now_us() - t0 < 1000);
	/* repair: the card busy for a minute first, then writes slower than
	 * the normal 10 s limit */
	sim_sd_make_busy(60u * 1000u * 1000u);
	sim_sd_slow_next_writes(3, 12u * 1000u * 1000u);
	uint8_t n = 0;
	card_verbose = 1;
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);
	card_verbose = 0;
	EZ_CHECK_EQ(n, 1);
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
}

/* TR-07: a card the size of V1's (61,849,600 sectors). Format and repair
 * must finish in a bounded number of writes: with FatFs's automatic
 * cluster size, a 15 GB volume took ~30,000 writes, minutes on V1. */
static void t_full_size_card(void)
{
	sim_sd_cfg_t cfg = base;
	cfg.blocks = 61849600u;
	cfg.write_busy_us = 1500;                             /* ~1.5 ms per block write */
	sim_sd_init(&cfg);
	card_init();
	unsigned long w0 = sim_sd_writes();
	uint64_t t0 = sim_now_us();
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	unsigned long wf = sim_sd_writes() - w0;
	uint64_t tf = (sim_now_us() - t0) / 1000000u;
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
	destroy_b();
	sim_sd_power_cycle();
	card_init();
	w0 = sim_sd_writes();
	t0 = sim_now_us();
	uint8_t n = 0;
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);
	unsigned long wr = sim_sd_writes() - w0;
	uint64_t tr = (sim_now_us() - t0) / 1000000u;
	ez_test_note("V1-size card: format %lu writes (%llu s simulated), repair of B %lu writes (%llu s)",
	             wf, (unsigned long long)tf, wr, (unsigned long long)tr);
	EZ_CHECK(wf < 16000 && wr < 8000);
	EZ_CHECK(tr < 60);
}

/* TR-07: repair interrupted after volume B's boot sector was written (B
 * would mount over incomplete FATs). The pending marker keeps it
 * unmounted until a repair completes. */
static void t_interrupted_repair(void)
{
	sim_sd_init(&base);
	card_init();
	EZ_CHECK_EQ(card_format(NULL, 1, 2), EZ_OK);
	destroy_b();
	sim_sd_power_cycle();
	card_init();
	sim_sd_cfg_t cfg = base;
	(void)cfg;
	sim_sd_slow_next_writes(0, 0);
	/* power lost 20 writes into recreating B: the MBR mark, then the boot
	 * sector and some of the FATs */
	extern void sim_sd_cut_after(long n);
	sim_sd_cut_after(20);
	uint8_t n = 0;
	EZ_CHECK(card_repair(NULL, 1, &n) != EZ_OK);
	sim_sd_power_cycle();
	card_init();
	EZ_CHECK(card_volume_mounted(0));
	EZ_CHECK(!card_volume_mounted(1));                    /* pending: not mounted */
	card_service();
	EZ_CHECK(!card_volume_mounted(1));
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);
	EZ_CHECK_EQ(n, 1);
	EZ_CHECK(card_volume_mounted(1));
	sim_sd_power_cycle();
	card_init();
	EZ_CHECK(card_volume_mounted(0) && card_volume_mounted(1));
	/* forced: recreate B even though it mounts */
	card_force_volume = 1;
	EZ_CHECK_EQ(card_repair(NULL, 1, &n), EZ_OK);
	card_force_volume = -1;
	EZ_CHECK_EQ(n, 1);
	EZ_CHECK(card_volume_mounted(1));
}

/* TR-07: a card (Transcend, on V1) whose periodic internal work, every
 * ~1,565 single-block writes, only progresses while it is released. Polled
 * continuously with CS low it never finishes; polled gently it does. */
static void t_needs_release(void)
{
	sim_sd_cfg_t cfg = base;
	cfg.stall_every = 1565;
	cfg.stall_us = 200000;                                /* 200 ms */
	sim_sd_init(&cfg);
	EZ_CHECK_EQ(hal_sdblk.init(NULL), EZ_OK);
	static uint8_t w[512];
	uint64_t t0 = sim_now_us();
	int i;
	for (i = 0; i < 3500; i++) {
		w[0] = (uint8_t)i;
		if (hal_sdblk.write(NULL, 600000u + (uint32_t)i, w, 1) != EZ_OK) break;
	}
	EZ_CHECK_EQ(i, 3500);
	ez_test_note("3,500 writes through two stalls in %llu ms (simulated)", (unsigned long long)((sim_now_us() - t0) / 1000u));
	EZ_CHECK(sim_now_us() - t0 < 30u * 1000u * 1000u);
}

static const ez_test_case_t cases[] = {
	{ "basics",            "SD driver on the host", t_basics },
	{ "format_two_copies", "IMPL-AV-007", t_format_two_copies },
	{ "background_erase",  "IMPL-AV-007 (TR-07: busy after erase)", t_background_erase },
	{ "reset_while_busy",  "TR-07: reset of a busy card", t_reset_while_busy },
	{ "slow_card_repair",  "IMPL-AV-004 (TR-07: repair on a slow card; shell froze)", t_slow_card_repair },
	{ "full_size_card",    "IMPL-AV-004/007 (TR-07: a 31.7 GB card)", t_full_size_card },
	{ "interrupted_repair", "IMPL-AV-004 (TR-07: repair cut short; B mounted over incomplete FATs)", t_interrupted_repair },
	{ "needs_release",     "TR-07: a card that needs releasing during busy", t_needs_release },
	{ "interrupted_format_repair", "IMPL-AV-004 (TR-07: volume B never formatted)", t_interrupted_format_repair },
};
EZ_TEST_MAIN(cases)
