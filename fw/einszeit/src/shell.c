/*
 * shell.c -- development image: the debug shell on CDC (EZ_DEV only).
 *
 * The production core (core/) on the real hardware drivers, with a CDC
 * debug shell for exercising it. NOT the production image: no HID, and the
 * shell can show plaintext. The three production images (HID, CDC,
 * composite) follow Phase 2.
 *
 * Kept from production rules even here: no command that reads key bytes
 * (SEC-FW-004), and the stdio reset interfaces stay disabled. One deliberate
 * exception for testing: `fw update` reboots into the UF2 bootloader. It is
 * compiled only with EZ_BRINGUP, which production images must never define
 * (IMPL-DRV-004, DEV-19).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "hardware/watchdog.h"
#include "tusb.h"
#include "pico/bootrom.h"

#include "board.h"
#include "ez_base64.h"
#include "ez_core.h"
#include "ez_dispatch.h"
#include "ez_engine.h"
#include "ez_entropy.h"
#include "ez_import.h"
#include "ez_keygen.h"
#include "ez_ks_fatfs.h"
#include "ez_ks_route.h"
#include "ez_secure.h"
#include "ez_sd.h"
#include "ez_store0.h"
#include "hal_rp2350.h"
#include "selftest.h"
#include "usb.h"
#include "app.h"
#include "tr05.h"
#include "card.h"




static char line[4096];

static int read_line(void)
{
	size_t n = 0;
	for (;;) {
		int ch = getchar_timeout_us(1000000);
		if (ch == PICO_ERROR_TIMEOUT) continue;
		if (ch == '\r' || ch == '\n') { putchar('\n'); line[n] = 0; return (int)n; }
		if ((ch == 8 || ch == 127) && n) { n--; printf("\b \b"); continue; }
		if (ch >= 32 && ch < 127 && n + 1 < sizeof line) { line[n++] = (char)ch; putchar(ch); }
	}
}

static bool confirm(const char *what)
{
	printf("%s\nType YES to confirm: ", what);
	read_line();
	bool ok = strcmp(line, "YES") == 0;
	if (!ok) printf("cancelled\n");
	return ok;
}

static const char *S(ez_status_t s) { return ez_status_name(s); }

static uint32_t hexarg(const char *s) { return s ? (uint32_t)strtoul(s, NULL, 16) : 0; }
static long numarg(const char *s, long def) { return s ? strtol(s, NULL, 0) : def; }

/* ---- commands --------------------------------------------------------------- */

static void cmd_info(void)
{
	pico_unique_board_id_t id;
	pico_get_unique_board_id(&id);
	printf("firmware      %s (bring-up, not production)\n", FW_VERSION);
	printf("board id      ");
	for (int i = 0; i < 8; i++) printf("%02x", id.id[i]);
	printf("\nuptime        %lu s\n", (unsigned long)hal_uptime_s());
	static const char *dev[] = { "UNINITIALISED (run init)", "valid", "FAULT (run init or repair)" };
	printf("metadata      %s, boot count %lu%s\n", dev[core.meta.dev], (unsigned long)core.meta.boot_count,
	       core.meta.boot_count_fault ? " (counter fault)" : "");
	printf("drive 0       %s; store %s, %lu table writes\n",
	       core.meta.drive0_enabled ? "enabled" : "disabled",
	       store0.fault ? "FAULT" : store0.mounted ? "mounted" : "not mounted",
	       store0.table_writes);
	uint32_t sec; uint8_t cid[16];
	hal_sd_info(&sec, cid);
	printf("drive 1 (SD)  card %s, %lu sectors, SD_DET=%d\n", hal_sd_present() ? "answering" : "absent",
	       (unsigned long)sec, hal_sd_det_raw());
	if (hal_sd_present())
		printf("              file system %s, %u cop%s\n",
		       card_fs_status() == EZ_OK ? "mounted" : "NOT mounted (unformatted or damaged: 'sd format 2')",
		       card_copies(), card_copies() == 1 ? "y" : "ies");
	if (hal_sd_present() && card_copies() == 2)
		printf("              volume A %s, volume B %s%s\n", card_volume_mounted(0) ? "mounted" : "NOT mounted",
		       card_volume_mounted(1) ? "mounted" : "NOT mounted",
		       card_volume_mounted(0) && card_volume_mounted(1) ? "" : " ('sd repair')");
	{
		static const char *why[] = { "a copy could not be repaired", "a critical key has no drive 0 copy",
		                             "some key data verifies in no copy", "a copy volume is unavailable" };
		uint32_t now = to_ms_since_boot(get_absolute_time());
		if (disp.job_running && disp.job == 4)
			printf("mirror        syncing (%s), %u%%\n", disp.sync_full ? "full check" : "quick check", core.progress / 10u);
		else if (core.health == EZ_HEALTH_DEGRADED) {
			printf("mirror        DEGRADED:");
			for (int b = 0; b < 4; b++) if (core.health_detail & (1u << b)) printf(" %s;", why[b]);
			printf(" recommend waiting for nominal state\n");
		} else
			printf("mirror        %s\n", core.health == EZ_HEALTH_OK ? "ok" : "not yet checked");
		printf("              last full check %s", disp.last_full_ms ? "" : "never");
		if (disp.last_full_ms) printf("%lu s ago", (unsigned long)((now - disp.last_full_ms) / 1000u));
		printf(", last quick check %s", disp.last_quick_ms ? "" : "never");
		if (disp.last_quick_ms) printf("%lu s ago", (unsigned long)((now - disp.last_quick_ms) / 1000u));
		printf("\n");
	}
	{
		printf("stack         core 0: at most %lu of %lu bytes used since boot\n", (unsigned long)app_core0_stack_used(), (unsigned long)app_stack_size());
		printf("              core 1: at most %lu of %lu bytes\n", (unsigned long)app_core1_stack_used(), (unsigned long)app_stack_size());
	}
	printf("trng profile  %u (SAMPLE_CNT1=%u, health tests on)\n", TRNG_PROFILE_ID, TRNG_SAMPLE_CNT1);
	printf("intent        %s\n", ez_core_intent_pending(&core) ? "PENDING" : "none");
	printf("usb           HID %s, job %s, %lu frame(s) dropped\n", tud_mounted() ? "configured" : "not configured",
	       disp.job_running ? "RUNNING" : "none", usb_hid_dropped);
}

static void cmd_ls(void)
{
	static const char *st[] = { "empty", "VALID", "EXHAUSTED", "QUARANTINED" };
	int any = 0;
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &core.meta.s[i];
		if (s->state == EZ_SS_EMPTY) continue;
		any = 1;
		printf("[%2d] %-15s key %08lX drive %u %-5s %s", i, s->identity ? s->label : "?",
		       (unsigned long)s->key_id, s->drive, s->role ? "bob" : "alice", st[s->state]);
		if (s->state == EZ_SS_QUARANTINED) printf(" (reason 0x%02x)", s->qreason);
		printf("\n");
		if (s->offsets)
			printf("     send: %lu bytes left%s   receive: %lu bytes left\n",
			       (unsigned long)ez_meta_tx_remaining(s), ez_meta_tx_low(s, 20) ? " (LOW)" : "",
			       (unsigned long)ez_meta_rx_remaining(s));
	}
	if (!any) printf("no sessions\n");
}

static void stress_busy(const char *what, uint32_t sec)
{
	printf("\r  card busy (%s) for %lu s   ", what, (unsigned long)sec);
}

/* One copy volume of the mirrored card (k = 0: A, 1: B). */
static void cmd_dir_copy(uint8_t k)
{
	char name[EZ_NAME_MAX];
	uint32_t size, i = 0;
	ez_status_t st;
	if (card_copies() < 2) { printf("this card is not mirrored (one copy)\n"); return; }
	while ((st = core.ks->list(core.ks->ctx, EZ_COPY(1, k), i, name, &size)) == EZ_OK) {
		printf("  %10lu  %s\n", (unsigned long)size, name);
		i++;
	}
	if (st != EZ_ERR_NOT_FOUND) printf("volume %c: %s\n", k ? 'B' : 'A', S(st));
	else printf("volume %c: %lu file(s)\n", k ? 'B' : 'A', (unsigned long)i);
}

static void cmd_dir(uint8_t drive)
{
	char name[EZ_NAME_MAX];
	uint32_t size;
	ez_status_t st = EZ_OK;
	uint32_t i = 0;
	for (; (st = ez_drive_list(&core, drive, i, name, &size)) == EZ_OK; i++)
		printf("  %10lu  %s\n", (unsigned long)size, name);
	if (st != EZ_ERR_NOT_FOUND) printf("drive %u: %s\n", drive, S(st));
	else printf("%lu file(s)\n", (unsigned long)i);
}

static ez_keygen_t kg;      /* large: kept off the stack */
static ez_import_t im;

static void cmd_keygen(long len, uint8_t drive)
{
	ez_status_t st = ez_keygen_start(&core, &kg, drive, (uint32_t)len);
	uint32_t last = 0;
	absolute_time_t t0 = get_absolute_time();
	while (st == EZ_PENDING) {
		st = ez_keygen_step(&core, &kg, 1);
		uint32_t p = ez_keygen_progress(&kg);
		if (st == EZ_PENDING && p / 50 != last / 50) { printf("  %lu.%lu%%\n", (unsigned long)p / 10, (unsigned long)p % 10); last = p; }
		if (getchar_timeout_us(0) == 27) { ez_keygen_cancel(&core, &kg); st = EZ_ERR_ABORTED; }
	}
	printf("keygen: %s; key %08lX; %lld s", S(st), (unsigned long)kg.key_id,
	       absolute_time_diff_us(t0, get_absolute_time()) / 1000000);
	if (st != EZ_OK && kg.fail) {
		static const char *bit[8] = { "monitor monobit", "monitor runs", "monitor autocorrelation",
		                              "acceptance monobit", "acceptance poker", "acceptance runs",
		                              "whole-key test", "storage/hardware/cancel" };
		printf("; failed:");
		for (int b = 0; b < 8; b++) if (kg.fail & (1u << b)) printf(" %s", bit[b]);
	}
	printf("\n");
	hal_trng_stats_t ts;
	hal_trng_get_stats(&ts);
	printf("trng: %lu collections, vn %lu, crngt %lu, autocorr %lu, timeouts %lu, faults %lu\n",
	       ts.collections, ts.vn_err, ts.crngt_err, ts.autocorr_err, ts.timeouts, ts.faults);
}

static void cmd_import(uint8_t drive, const char *file, uint32_t id, uint8_t role, const char *label)
{
	ez_status_t st = ez_import_start(&core, &im, drive, file, id, role, label);
	if (st == EZ_PENDING && !im.have_sum)
		printf("note: no integrity file came with this key; it is checked statistically and\n"
		       "      for duplicated blocks, but cannot be compared with the original.\n");
	while (st == EZ_PENDING) st = ez_import_step(&core, &im, 8);
	printf("import: %s", S(st));
	if (st == EZ_OK) printf(" (session %d)", im.slot);
	if (im.bad) printf(" (%lu damaged units, first %lu)", (unsigned long)im.bad, (unsigned long)im.first_bad);
	if (im.dups) printf(" (%lu duplicated blocks)", (unsigned long)im.dups);
	if (im.fail) printf(" (acceptance bits 0x%02x)", im.fail);
	printf("\n");
}

static uint8_t msgbuf[3200];
static char b64[4400];

static void cmd_enc(int slot, const char *text)
{
	uint32_t len = text ? (uint32_t)strlen(text) : 0;
	if (!len || len > 3000) { printf("usage: enc <slot> <text, 1..3000 chars>\n"); return; }
	uint8_t *p = ez_stage_plaintext(&core, len);
	if (!p) { printf("busy\n"); return; }
	memcpy(p, text, len);
	ez_secure_zero(line, sizeof line);                      /* plaintext in the line buffer */
	const uint8_t *o; uint32_t n;
	ez_status_t st = ez_encrypt_buffered(&core, slot, len, &o, &n);
	if (st == EZ_OK) {
		size_t m = ez_b64_encode(o, n, b64);
		b64[m] = 0;
		printf("%s\n", b64);
	} else {
		printf("enc: %s\n", S(st));
		if (st == EZ_ERR_KEY_DAMAGED && core.damage.valid)
			printf("damaged unit %lu; 'skip %d' moves past it\n", (unsigned long)core.damage.unit, slot);
	}
	ez_release(&core);
}

static void cmd_dec(int slot, const char *text)
{
	ez_b64_dec_t d;
	size_t n = 0;
	ez_b64_dec_init(&d);
	if (!text || ez_b64_dec_update(&d, text, strlen(text), msgbuf, &n) != EZ_OK ||
	    ez_b64_dec_final(&d) != EZ_OK || n > sizeof msgbuf) { printf("bad base64\n"); return; }
	uint8_t *p = ez_stage_message(&core, (uint32_t)n);
	if (!p) { printf("bad message size\n"); return; }
	memcpy(p, msgbuf, n);
	const uint8_t *o; uint32_t m;
	ez_status_t st = ez_decrypt_buffered(&core, slot, (uint32_t)n, &o, &m);
	if (st == EZ_OK) { fwrite(o, 1, m, stdout); printf("\n"); }
	else printf("dec: %s\n", S(st));
	ez_release(&core);                                        /* clears the plaintext */
}

static void cmd_trng(long bytes)
{
	static uint8_t buf[512];
	ez_monitor_t mon;
	ez_accept_t acc;
	ez_mon_init(&mon);
	ez_acc_init(&acc);
	absolute_time_t t0 = get_absolute_time();
	long done = 0;
	uint8_t mf = 0;
	ez_status_t st = EZ_OK;
	for (; done < bytes && st == EZ_OK; done += 512) {
		st = hal_trng.read(NULL, buf, 512);
		if (st == EZ_OK) { mf |= ez_mon_feed(&mon, buf, 512); ez_acc_feed(&acc, buf, 512); }
		if (done % 8192 == 0) printf("  %ld bytes\n", done);
	}
	ez_secure_zero(buf, sizeof buf);
	uint8_t af = ez_acc_finish(&acc);
	ez_mon_clear(&mon);
	long long us = absolute_time_diff_us(t0, get_absolute_time());
	hal_trng_stats_t ts;
	hal_trng_get_stats(&ts);
	printf("trng: %s, %ld bytes in %lld ms (%lld bit/s)\n", S(st), done, us / 1000,
	       us ? (long long)done * 8000000 / us : 0);
	printf("monitor bits 0x%02x, acceptance bits 0x%02x (0 = pass)\n", mf, af);
	printf("health: %lu collections, vn %lu, crngt %lu, autocorr %lu, timeouts %lu, faults %lu\n",
	       ts.collections, ts.vn_err, ts.crngt_err, ts.autocorr_err, ts.timeouts, ts.faults);
	printf("(test data only: these bytes are discarded, never key material)\n");
}

static void cmd_log(void)
{
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(&core.meta, ev, EZ_META_LOG_ENTRIES);
	for (int i = 0; i < n; i++)
		printf("#%lu boot %lu t=%lus type 0x%02x detail 0x%02x key %08lX arg %lu\n",
		       (unsigned long)ev[i].seq, (unsigned long)ev[i].boot, (unsigned long)ev[i].time,
		       ev[i].type, ev[i].detail, (unsigned long)ev[i].key_id, (unsigned long)ev[i].arg);
	if (!n) printf("log empty\n");
}

static void help(void)
{
	printf("Einszeit bring-up shell (%s). Destructive commands ask for YES.\n"
	       "  info | fram | ls | log | kat | trng [bytes] | reboot\n"
	       "  tr05 prep (YES) | tr05 status | tr05 disarm | tr05 wp (YES)   storage reliability test\n"
#ifdef EZ_BRINGUP
	       "  fw update                     reboot into the UF2 bootloader (bring-up only)\n"
#endif
	       "  init                          device erase: all keys and sessions (YES)\n"
	       "  repair                        rewrite a faulty device record (YES)\n"
	       "  sd mount | sd dir [a|b] | sd det | sd watch | sd test (YES) | sd format [1|2] [erase] (YES) | sd repair [a|b]\n"
	       "  sd stress [blocks] [pause ms] [SPI MHz] (YES)   write test (TR-07)\n"
	       "  d0 on (YES) | d0 off (YES) | d0 dir\n"
	       "  keygen <bytes> <drive>        multiple of 512, 8192..; ESC cancels\n"
	       "  copy <keyid> <from> <to>      copy a key and its .SUM, verified\n"
	       "  import <drive> <file> <keyid> <alice|bob> <label>\n"
	       "  create <keyid> <drive> <alice|bob|auto> <label>\n"
	       "  del <slot> [force] (YES) | skip <slot> (YES) | resolve <slot>\n"
	       "  enc <slot> <text>             prints the message in base64\n"
	       "  dec <slot|-> <base64>         prints the plaintext (bring-up only)\n", FW_VERSION);
}

/* Round 16: long work runs on the second core even from the console. The
 * console waits here, keeping USB serviced and showing the job's output. */
static ez_status_t run_job(uint8_t cmd, const uint8_t *req, uint32_t n)
{
	if (!ez_dispatch_submit(&disp, cmd, req, n)) return EZ_ERR_BUSY;
	while (disp.job_running) {
		usb_task();
		app_idle();                 /* USB requests meanwhile get BUSY */
		app_log_drain();
		sleep_ms(5);
	}
	app_log_drain();
	return disp.job_result;
}

static void dispatch(char *l)
{
	char *argv[8] = { 0 };
	int argc = 0;
	char *rest = NULL;
	for (char *t = strtok(l, " "); t && argc < 8; t = strtok(NULL, " ")) {
		argv[argc++] = t;
		if (argc == 2 && (strcmp(argv[0], "enc") == 0)) { rest = strtok(NULL, ""); break; }
	}
	if (!argc) return;
	const char *c = argv[0];
	/* A key generation or import started over USB owns the core's stage. */
	/* A job on core 1 owns the core, the card and F-RAM until it ends:
	 * only commands that touch none of them run meanwhile. */
	if (disp.job_running && strcmp(c, "info") && strcmp(c, "help")) {
		printf("busy: a job is running on the second core (see 'info'); try again when it ends\n");
		return;
	}
	if (!strcmp(c, "help")) help();
	else if (!strcmp(c, "info")) cmd_info();
	else if (!strcmp(c, "fram")) {
		uint8_t a, b;
		printf("F-RAM %s (SR idle 0x%02x, after WREN 0x%02x)\n",
		       hal_fram_probe(&a, &b) ? "present" : "NOT RESPONDING", a, b);
	}
	else if (!strcmp(c, "ls")) cmd_ls();
	else if (!strcmp(c, "log")) cmd_log();
	else if (!strcmp(c, "kat")) {
		ez_release(&core);
		bool ok = selftest_kat(&core, stage);
		printf("KAT %s\n", ok ? "PASS (3 vectors, encrypt and decrypt)" : "FAILED");
		app_boot();                                   /* also resets the dispatcher */
	}
	else if (!strcmp(c, "trng")) cmd_trng(numarg(argv[1], 65536));
#ifdef EZ_BRINGUP
	else if (!strcmp(c, "fw") && argv[1] && !strcmp(argv[1], "update")) {
		/* DEV-19: bring-up only. Production images have no software path
		 * into BOOTSEL (IMPL-DRV-004). */
		printf("rebooting into the UF2 bootloader: copy the new .uf2 to the RP2350 drive\n");
		ez_release(&core);
		stdio_flush();
		sleep_ms(200);
		reset_usb_boot(0, 0);
	}
#endif
	else if (!strcmp(c, "tr05")) {
		if (argc > 1 && !strcmp(argv[1], "prep") &&
		    !confirm("TR-05 DESTROYS everything on the card in the slot. Use a spare card (1 GB or more)."))
			return;
		if (argc > 1 && !strcmp(argv[1], "wp") &&
		    !confirm("TR-05 wp writes to a sector near the end of the card and changes its CSD. Spare card only."))
			return;
		tr05_cmd(argc, argv);
	}
	else if (!strcmp(c, "reboot")) { printf("rebooting\n"); sleep_ms(100); watchdog_reboot(0, 0, 10); for (;;) {} }
	else if (!strcmp(c, "init")) {
		if (confirm("ERASES all keys on drive 0 and the card, and all sessions."))
			{ printf("init: %s\n", S(ez_device_erase(&core))); app_boot(); }
	}
	else if (!strcmp(c, "repair")) {
		if (confirm("Rewrites the device record (drive 0 disabled)."))
			printf("repair: %s\n", S(ez_meta_repair(&core.meta)));
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "mount")) {
		ez_status_t st = card_mount();
		printf("mount: %s\n", S(st));
		if (st == EZ_OK) printf("media event: %s\n", S(ez_core_media_event(&core, 1)));
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "dir")) {
		if (argv[2] && (argv[2][0] == 'a' || argv[2][0] == 'A')) cmd_dir_copy(0);
		else if (argv[2] && (argv[2][0] == 'b' || argv[2][0] == 'B')) cmd_dir_copy(1);
		else cmd_dir(1);                                   /* the mirror's combined view */
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "stress")) {
		/* TR-07 diagnosis: sequential single-block writes near the end of
		 * the card (inside volume B), with a chosen pause and SPI clock,
		 * reporting where the card stops finishing writes. */
		uint32_t nblk = argv[2] ? (uint32_t)atoi(argv[2]) : 5000;
		uint32_t pause = argv[2] && argv[3] ? (uint32_t)atoi(argv[3]) : 0;
		uint32_t mhz = argv[2] && argv[3] && argv[4] ? (uint32_t)atoi(argv[4]) : 12;
		if (!mhz || mhz > 24) mhz = 12;
		if (!confirm("Overwrites blocks near the end of the card (inside volume B).")) return;
		if (!hal_sd_present() && hal_sdblk.init(NULL) != EZ_OK) { printf("init failed (%s)\n", ez_sd_last_error()); return; }
		uint32_t sec; uint8_t cid[16];
		hal_sd_info(&sec, cid);
		uint32_t base = sec - 131072u;                 /* the last 64 MiB */
		static uint8_t w[512];
		uint32_t actual = ez_sd_set_baud(mhz * 1000000u);
		printf("writing %lu blocks at %lu, %lu ms pause, SPI %lu Hz\n", (unsigned long)nblk,
		       (unsigned long)base, (unsigned long)pause, (unsigned long)actual);
		ez_sd_set_write_timeout_ms(600000);            /* 10 min: does the card ever finish? */
		ez_sd_wait_hook = stress_busy;
		uint64_t t0 = time_us_64(), tk = t0, worst = 0;
		uint32_t i;
		for (i = 0; i < nblk; i++) {
			for (int b = 0; b < 512; b++) w[b] = (uint8_t)(i + b);
			uint64_t a = time_us_64();
			ez_status_t st = hal_sdblk.write(NULL, base + i, w, 1);
			uint64_t d = time_us_64() - a;
			if (d > worst) worst = d;
			if (st != EZ_OK) {
				printf("\nSTOPPED at block %lu: %s (card: %s), after %lu s\n", (unsigned long)i, S(st),
				       ez_sd_last_error(), (unsigned long)((time_us_64() - t0) / 1000000u));
				break;
			}
			if (d > 2000000u)
				printf("\n  block %lu took %lu s, then the card continued\n", (unsigned long)i, (unsigned long)(d / 1000000u));
			if ((i + 1) % 100 == 0) {
				uint64_t now = time_us_64();
				printf("  %5lu blocks, last 100 in %lu ms, slowest so far %lu ms\n",
				       (unsigned long)(i + 1), (unsigned long)((now - tk) / 1000u), (unsigned long)(worst / 1000u));
				tk = now;
			}
			if (pause) sleep_ms(pause);
		}
		if (i == nblk) printf("done: %lu blocks in %lu s, slowest %lu ms\n", (unsigned long)nblk,
		                      (unsigned long)((time_us_64() - t0) / 1000000u), (unsigned long)(worst / 1000u));
		ez_sd_wait_hook = NULL;
		ez_sd_set_write_timeout_ms(10000);
		ez_sd_set_baud(SD_BAUD_DEFAULT);
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "test")) {
		/* Diagnostics: write and read back one scratch sector near the end. */
		if (confirm("Overwrites one sector near the end of the card.")) {
			uint32_t sec; uint8_t cid[16];
			if (!hal_sd_present() && hal_sdblk.init(NULL) != EZ_OK) { printf("init failed (%s)\n", ez_sd_last_error()); return; }
			hal_sd_info(&sec, cid);
			static uint8_t w[512], r[512];
			uint32_t lba = sec - 4096u;
			for (int i = 0; i < 512; i++) w[i] = (uint8_t)(i * 7 + 1);
			ez_status_t ws = hal_sdblk.write(NULL, lba, w, 1);
			printf("write sector %lu: %s (card: %s)\n", (unsigned long)lba, S(ws), ez_sd_last_error());
			ez_status_t rs = hal_sdblk.read(NULL, lba, r, 1);
			printf("read back: %s, %s\n", S(rs), rs == EZ_OK && !memcmp(w, r, 512) ? "matches" : "DIFFERS");
		}
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "repair")) {
		uint8_t n = 0;
		card_force_volume = argv[2] ? (argv[2][0] == 'a' || argv[2][0] == 'A' ? 0 : argv[2][0] == 'b' || argv[2][0] == 'B' ? 1 : -1) : -1;
		if (card_force_volume >= 0 &&
		    !confirm("Recreates that volume even though it mounts; its key copies are then restored with 'ez session repair'."))
			return;
		card_verbose = 1;
		ez_status_t st = run_job(EZ_CMD_DRIVE_REPAIR, (const uint8_t[]){ 1 }, 1);
		if (st == EZ_OK && disp.jres_n) n = disp.jres[0];
		card_verbose = 0;
		card_force_volume = -1;
		printf("sd repair: %s, %u volume(s) recreated%s\n", S(st), n,
		       n ? "; now 'ez session repair <label>' for each session" : "");
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "format")) {
		int copies = argv[2] ? atoi(argv[2]) : 2;
		if (argv[3] && !strcmp(argv[3], "erase")) copies |= 0x80;
		if (confirm("ERASES the whole card and formats it (TR-07). Sessions on it must be deleted first.")) {
			card_verbose = 1;
			ez_status_t st = run_job(EZ_CMD_DRIVE_FORMAT, (const uint8_t[]){ 1, (uint8_t)copies }, 2);
			card_verbose = 0;
			printf("sd format: %s; card now keeps %u cop%s\n", S(st), card_copies(), card_copies() == 1 ? "y" : "ies");
		}
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "det")) {
		int up, down;
		ez_sd_det_probe(&up, &down);
		printf("SD_DET with pull-up %d, with pull-down %d: %s\n", up, down,
		       up && !down ? "floating (switch open)" : up && down ? "driven high" :
		       !up && !down ? "driven low" : "inconsistent");
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "watch")) {
		/* OI-03: SD_DET read with pull-up and pull-down, and the authoritative
		 * card check; a card that fails the check is remounted when it
		 * answers again. Any key stops. */
		int lu = -1, ld = -1, lok = -1;
		printf("watching: remove and reinsert the card; any key stops\n");
		while (getchar_timeout_us(0) == PICO_ERROR_TIMEOUT) {
			int up, down;
			ez_sd_det_probe(&up, &down);
			int ok = cards.hal.check(&cards, 1) == EZ_OK;
			if (!ok && card_mount() == EZ_OK) {
				ez_core_media_event(&core, 1);
				ok = 2;                                   /* remounted */
			}
			if (up != lu || down != ld || (ok != 0) != (lok != 0) || ok == 2)
				printf("SD_DET up=%d down=%d   card: %s\n", up, down,
				       ok == 2 ? "inserted, remounted" : ok ? "present" : "absent");
			lu = up; ld = down; lok = ok;
			sleep_ms(500);
		}
	}
	else if (!strcmp(c, "d0") && argv[1] && !strcmp(argv[1], "on")) {
		if (confirm("Drive 0 is internal flash: anyone holding BOOT while connecting can read it\n"
		            "with picotool unless partition protection is verified (OI-02)."))
			printf("d0 on: %s\n", S(ez_drive_enable0(&core)));
	}
	else if (!strcmp(c, "d0") && argv[1] && !strcmp(argv[1], "off")) {
		if (confirm("ERASES all of drive 0."))
			printf("d0 off: %s\n", S(ez_drive_disable0(&core)));
	}
	else if (!strcmp(c, "d0") && argv[1] && !strcmp(argv[1], "dir")) cmd_dir(0);
	else if (!strcmp(c, "keygen") && argc >= 3) cmd_keygen(numarg(argv[1], 0), (uint8_t)numarg(argv[2], 1));
	else if (!strcmp(c, "copy") && argc >= 4)
		printf("copy: %s\n", S(ez_key_copy(&core, hexarg(argv[1]), (uint8_t)numarg(argv[2], 0), (uint8_t)numarg(argv[3], 0))));
	else if (!strcmp(c, "import") && argc >= 6)
		cmd_import((uint8_t)numarg(argv[1], 1), argv[2], hexarg(argv[3]),
		           !strcmp(argv[4], "alice") ? EZ_ROLE_ALICE : EZ_ROLE_BOB, argv[5]);
	else if (!strcmp(c, "create") && argc >= 5) {
		uint8_t role = !strcmp(argv[3], "alice") ? EZ_ROLE_ALICE : !strcmp(argv[3], "bob") ? EZ_ROLE_BOB : EZ_ROLE_DEFAULT;
		int slot = -1;
		ez_status_t st = ez_session_create(&core, hexarg(argv[1]), (uint8_t)numarg(argv[2], 1), role, argv[4], &slot);
		printf("create: %s", S(st));
		if (st == EZ_OK) printf(" (slot %d)", slot);
		if (st == EZ_ERR_NOT_FOUND) printf(" (no %08lX.KEY on drive %ld)", (unsigned long)hexarg(argv[1]), numarg(argv[2], 1));
		if (st == EZ_ERR_UNVERIFIED) printf(" (no .SUM beside the key: use 'import')");
		printf("\n");
	}
	else if (!strcmp(c, "del") && argc >= 2) {
		bool force = argv[2] && !strcmp(argv[2], "force");
		if (confirm(force ? "Removes the session WITHOUT erasing its key file. That file must never\n"
		                    "be used to start a new session: its first bytes have been used."
		                  : "Erases the session's key file and its .SUM. A copy made earlier must\n"
		                    "never be used to start a new session: its first bytes have been used."))
			printf("del: %s\n", S(ez_session_delete(&core, (int)numarg(argv[1], -1), force)));
	}
	else if (!strcmp(c, "skip") && argc >= 2) {
		if (confirm("Moves the send offset past the damaged part; the skipped key is wasted.")) {
			uint32_t units = 0;
			ez_status_t st = ez_session_skip(&core, (int)numarg(argv[1], -1), &units);
			printf("skip: %s (%lu units)\n", S(st), (unsigned long)units);
		}
	}
	else if (!strcmp(c, "resolve") && argc >= 2)
		printf("resolve: %s\n", S(ez_session_resolve(&core, (int)numarg(argv[1], -1))));
	else if (!strcmp(c, "enc") && argc >= 2) cmd_enc((int)numarg(argv[1], -1), rest);
	else if (!strcmp(c, "dec") && argc >= 3) cmd_dec(!strcmp(argv[1], "-") ? -1 : (int)numarg(argv[1], -1), argv[2]);
	else printf("unknown command; 'help'\n");
}

/* ---- round 17: the development commands, inside the terminal interface ------- */

/* Before app_boot(): TR-05's test mode takes over the device when armed. */
void dev_early(void)
{
	stdio_init_all();
	gpio_init(LED_PIN);
	gpio_set_dir(LED_PIN, GPIO_OUT);
	gpio_put(LED_PIN, 1);
	if (tr05_armed()) {           /* TR-05 test mode: no core, no HID service */
		usb_idle_hook = NULL;
		tr05_mode();              /* never returns */
	}
	usb_idle_hook = app_idle;
}

/* The CLI's fallback for commands it does not know: the development
 * shell's commands (sd test/stress/det/watch, fw update, tr05, ...). The
 * protocol answers BUSY meanwhile, as it did for the old console. */
bool dev_cli(void *ctx, int argc, char **argv)
{
	(void)ctx;
	char l[sizeof line];
	size_t k = 0;
	for (int i = 0; i < argc && k + 2 < sizeof l; i++) {
		if (i) l[k++] = ' ';
		for (const char *p = argv[i]; *p && k + 1 < sizeof l; p++) l[k++] = *p;
	}
	l[k] = 0;
	if (!strcmp(argv[0], "dev")) strcpy(l, "help");
	ez_dispatch_reset(&disp);
	app_console_busy = true;
	disp.external_busy = true;
	dispatch(l);
	fflush(stdout);
	app_console_busy = false;
	disp.external_busy = false;
	ez_secure_zero(l, sizeof l);
	return true;
}
