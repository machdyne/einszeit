/*
 * main.c -- Einszeit V1 bring-up firmware (EZ-PLAN-001 Phase 3, thin slice).
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

#define FW_VERSION "0.2.1-bringup"

static ez_store0_t   store0;
static ez_ks_fatfs_t cards;
static ez_ks_route_t route;
static ez_core_t     core;
static uint8_t       stage[EZ_STAGE_SIZE];

static uint32_t time_fn(void *ctx, bool *host) { (void)ctx; *host = false; return hal_uptime_s(); }

/* ---- the protocol over HID (EZ-IMPL-001 §9) --------------------------------
 * Frames are dispatched only while the console is idle (shell_busy false),
 * so a console command and a USB command never use the core at once. */
static ez_dispatch_t disp;
static const ez_devinfo_t devinfo = { FW_VERSION, 0x10, 1 };
static bool shell_busy;

static void hid_send(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	(void)ctx;
	if (!usb_hid_send(f, 2000)) ez_dispatch_reset(&disp);    /* host gone */
}

static void service_hid(void)
{
	uint8_t f[EZ_FRAME_SIZE];
	while (usb_hid_pop(f)) ez_dispatch_frame(&disp, f);
	ez_secure_zero(f, sizeof f);
	if (disp.job_running) ez_dispatch_poll(&disp, 1);
}

/* IMPL-ENG-011: a card inserted while the device runs is mounted
 * automatically. SD_DET (active-high on V1, TR-03) is the trigger; removal
 * is still detected by the authoritative card check on the next access. */
static absolute_time_t next_card_poll;
static void card_poll(void)
{
	if (absolute_time_diff_us(get_absolute_time(), next_card_poll) > 0) return;
	next_card_poll = make_timeout_time_ms(500);
	if (!hal_sd_present() && hal_sd_det_raw() == 1 && ez_ks_fatfs_mount(&cards, 1) == EZ_OK)
		ez_core_media_event(&core, 1);
}

static void idle(void)
{
	if (shell_busy) return;
	service_hid();
	if (!disp.rx_active && !disp.job_running) card_poll();
}

static void boot_core(void)
{
	core.meta.time_fn = time_fn;
	ez_store0_init(&store0, &hal_flash, &hal_fram, EZ_META_STORE0_SEL);
	ez_ks_fatfs_init(&cards, NULL, &hal_sdblk, NULL);
	ez_ks_fatfs_mount(&cards, 1);
	ez_ks_route_init(&route, &store0.hal, &cards.hal);
	ez_core_init(&core, &hal_fram, &route.hal, &hal_trng, stage, sizeof stage);
	ez_dispatch_init(&disp, &core, hid_send, NULL, &devinfo);
}

/* ---- line input ---------------------------------------------------------- */

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
	printf("drive 1 (SD)  %s, %lu sectors, SD_DET=%d\n", hal_sd_present() ? "mounted" : "absent",
	       (unsigned long)sec, hal_sd_det_raw());
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
#ifdef EZ_BRINGUP
	       "  fw update                     reboot into the UF2 bootloader (bring-up only)\n"
#endif
	       "  init                          device erase: all keys and sessions (YES)\n"
	       "  repair                        rewrite a faulty device record (YES)\n"
	       "  sd mount | sd dir | sd det | sd watch   (watch: any key stops)\n"
	       "  d0 on (YES) | d0 off (YES) | d0 dir\n"
	       "  keygen <bytes> <drive>        multiple of 512, 8192..; ESC cancels\n"
	       "  copy <keyid> <from> <to>      copy a key and its .SUM, verified\n"
	       "  import <drive> <file> <keyid> <alice|bob> <label>\n"
	       "  create <keyid> <drive> <alice|bob|auto> <label>\n"
	       "  del <slot> [force] (YES) | skip <slot> (YES) | resolve <slot>\n"
	       "  enc <slot> <text>             prints the message in base64\n"
	       "  dec <slot|-> <base64>         prints the plaintext (bring-up only)\n", FW_VERSION);
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
	if (disp.job_running && strcmp(c, "info") && strcmp(c, "ls") && strcmp(c, "log") && strcmp(c, "help")) {
		printf("busy: a job started over USB is running (see 'info')\n");
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
		boot_core();                                   /* also resets the dispatcher */
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
	else if (!strcmp(c, "reboot")) { printf("rebooting\n"); sleep_ms(100); watchdog_reboot(0, 0, 10); for (;;) {} }
	else if (!strcmp(c, "init")) {
		if (confirm("ERASES all keys on drive 0 and the card, and all sessions."))
			{ printf("init: %s\n", S(ez_device_erase(&core))); boot_core(); }
	}
	else if (!strcmp(c, "repair")) {
		if (confirm("Rewrites the device record (drive 0 disabled)."))
			printf("repair: %s\n", S(ez_meta_repair(&core.meta)));
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "mount")) {
		ez_status_t st = ez_ks_fatfs_mount(&cards, 1);
		printf("mount: %s\n", S(st));
		if (st == EZ_OK) printf("media event: %s\n", S(ez_core_media_event(&core, 1)));
	}
	else if (!strcmp(c, "sd") && argv[1] && !strcmp(argv[1], "dir")) cmd_dir(1);
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
			if (!ok && ez_ks_fatfs_mount(&cards, 1) == EZ_OK) {
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

int main(void)
{
	stdio_init_all();
	usb_init();
	usb_idle_hook = idle;
	gpio_init(LED_PIN);
	gpio_set_dir(LED_PIN, GPIO_OUT);
	gpio_put(LED_PIN, 1);
	hal_fram_init();
	boot_core();
	/* The protocol works without a terminal: serve HID until one connects. */
	while (!usb_cdc_connected()) { usb_task(); idle(); }
	absolute_time_t t = make_timeout_time_ms(200);
	while (absolute_time_diff_us(get_absolute_time(), t) > 0) { usb_task(); idle(); }
	printf("\nEinszeit %s -- 'help' for commands\n", FW_VERSION);
	cmd_info();
	for (;;) {
		printf("ez> ");
		fflush(stdout);
		shell_busy = false;
		read_line();
		shell_busy = true;
		dispatch(line);
		ez_secure_zero(line, sizeof line);
	}
}
