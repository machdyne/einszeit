/*
 * app.c -- see app.h.
 */
#include <string.h>

#include "pico/stdlib.h"

#include "app.h"
#include "board.h"
#include "card.h"
#include "pico/multicore.h"
#include <stdarg.h>
#include <stdio.h>
#include "ez_ks_route.h"
#include "ez_secure.h"
#include "hal_rp2350.h"
#include "usb.h"

static ez_ks_route_t route;
ez_store0_t   store0;
ez_ks_fatfs_t cards;
ez_core_t     core;
uint8_t       stage[EZ_STAGE_SIZE];

static uint32_t time_fn(void *ctx, bool *host) { (void)ctx; *host = false; return hal_uptime_s(); }

/* ---- the protocol over HID (EZ-IMPL-001 §9) --------------------------------
 * Frames are dispatched only while the console is idle (app_console_busy false),
 * so a console command and a USB command never use the core at once. */
ez_dispatch_t disp;
#ifdef EZ_DEV
static const ez_devinfo_t devinfo = { FW_VERSION, 0x10, 1, EZ_BUILD_DEVELOPMENT };
#else
static const ez_devinfo_t devinfo = { FW_VERSION, 0x01, 1, EZ_BUILD_PRODUCTION };
#endif
bool app_console_busy;

static void hid_send(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	(void)ctx;
	if (!usb_hid_send(f, 2000)) ez_dispatch_reset(&disp);    /* host gone */
}

void app_service_hid(void)
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
	if (!hal_sd_present() && hal_sd_det_raw() == 1 && card_mount() == EZ_OK) {
		ez_core_media_event(&core, 1);
		ez_dispatch_want_sync(&disp);                    /* a card arrived: check it fully */
	}
	/* A card removed is noticed at once, not at its next access (round 18:
	 * the export's card swap; round 16's degraded state). SD_DET is
	 * active-high on V1 (TR-03); two low readings 500 ms apart. */
	static int gone;
	if (hal_sd_present() && hal_sd_det_raw() == 0) {
		if (++gone >= 2) {
			gone = 0;
			hal_sd_forget();
			card_mount();                                /* fails: no card; clears the mount */
			ez_core_media_event(&core, 1);
			ez_dispatch_want_sync(&disp);
		}
	} else gone = 0;
}

/* ---- the second core: all long work (round 16) -------------------------------
 * Core 0 keeps USB, the console and fast commands; core 1 runs one job at a
 * time to completion. While a job runs the dispatcher answers only
 * read-only commands, so core 0 never touches the core, the card or F-RAM
 * at the same time. Flash writes (drive 0) pause the other core through
 * flash_safe_execute(), so both cores are lockout victims. */
extern uint32_t core1_stack_mem[];
static void core1_main(void)
{
	__asm volatile("msr msplim, %0" : : "r"(core1_stack_mem));   /* an overflow faults */
	multicore_lockout_victim_init();
	for (;;) {
		if (ez_dispatch_job_pending(&disp)) ez_dispatch_job_run(&disp);
		else sleep_us(500);
	}
}

/* Both cores' stacks: 16 KB each in main RAM (TR-09 round 23: core 0
 * reached 7.2 KB at boot, core 1 1.5 KB; the SDK's banks give 4 KB and
 * 2 KB). Each core's stack limit register (MSPLIM) is set to its stack's
 * bottom, so an overflow faults instead of overwriting memory. Painted so
 * the development image can report how deep each has been. */
#define STACK_WORDS 4096u
uint32_t core0_stack_mem[STACK_WORDS] __attribute__((aligned(8)));
uint32_t core1_stack_mem[STACK_WORDS] __attribute__((aligned(8)));
#define STACK_PAINT 0xA5A5A5A5u

static uint32_t stack_used_of(const uint32_t *m)
{
	uint32_t i = 0;
	while (i < STACK_WORDS && m[i] == STACK_PAINT) i++;
	return (STACK_WORDS - i) * 4u;
}
uint32_t app_core0_stack_used(void) { return stack_used_of(core0_stack_mem); }
uint32_t app_core1_stack_used(void) { return stack_used_of(core1_stack_mem); }
uint32_t app_stack_size(void) { return STACK_WORDS * 4u; }

/* Core 0: called first thing in main(); never returns. Moves the stack
 * (interrupts use the same one) to core0_stack_mem and runs fn there. The
 * stack is painted first, while nothing on it is in use. */
__attribute__((naked, noreturn)) static void on_stack(void (*fn)(void))
{
	__asm volatile(
	    "movs r2, #0\n"
	    "msr  msplim, r2\n"            /* no limit while SP moves */
	    "ldr  r1, =core0_stack_mem\n"
	    "ldr  r2, =core0_stack_mem + 16384\n"
	    "msr  msp, r2\n"
	    "isb\n"
	    "msr  msplim, r1\n"
	    "blx  r0\n"
	    "b    .\n");
}

void app_main_on_stack(void (*fn)(void))
{
	for (uint32_t i = 0; i < STACK_WORDS; i++) core0_stack_mem[i] = STACK_PAINT;
	on_stack(fn);
}

void app_start_worker(void)
{
	for (uint32_t i = 0; i < STACK_WORDS; i++) core1_stack_mem[i] = STACK_PAINT;
	multicore_lockout_victim_init();
	multicore_launch_core1_with_stack(core1_main, core1_stack_mem, sizeof core1_stack_mem);
}

/* Output from jobs (core 1) goes through a ring that core 0 empties:
 * the USB stack is not safe to call from two cores. */
static char logbuf[2048];
static volatile uint32_t log_w, log_r;
static int ring_printf(const char *fmt, ...)
{
	char t[160];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	for (int i = 0; i < n && i < (int)sizeof t - 1; i++)
		if (log_w - log_r < sizeof logbuf) { logbuf[log_w % sizeof logbuf] = t[i]; __sync_synchronize(); log_w++; }
	return n;
}

void app_log_drain(void)
{
	while (log_r != log_w) {
#ifdef EZ_DEV
		putchar(logbuf[log_r % sizeof logbuf]);
#endif
		log_r++;
	}
#ifdef EZ_DEV
	fflush(stdout);
#endif
}

void app_idle(void)
{
	if (app_console_busy) {                     /* answer USB requests with BUSY at once */
		uint8_t f[EZ_FRAME_SIZE];
		while (usb_hid_pop(f)) ez_dispatch_frame(&disp, f);
		ez_secure_zero(f, sizeof f);
		return;
	}
	app_service_hid();
	app_log_drain();
	if (!disp.rx_active && !disp.job_running) card_poll();
	ez_dispatch_idle(&disp, to_ms_since_boot(get_absolute_time()));   /* background sync */
}

void app_boot(void)
{
	hal_flash_init();
	core.drive0_guard = hal_flash_protected;            /* IMPL-DRV-003 */
	core.meta.time_fn = time_fn;
	ez_store0_init(&store0, &hal_flash, &hal_fram, EZ_META_STORE0_SEL);
	card_init();                                         /* plain or mirrored card (§2.8) */
	ez_ks_route_init(&route, &store0.hal, card_hal());
	core.format = card_format;                           /* IMPL-AV-007 */
	core.repair_volumes = card_repair;                   /* IMPL-AV-004 */
	ez_core_init(&core, &hal_fram, &route.hal, &hal_trng, stage, sizeof stage);
	ez_dispatch_init(&disp, &core, hid_send, NULL, &devinfo);
	disp.external_worker = true;                         /* jobs run on core 1 */
	card_printf = ring_printf;
	card_progress = &core.progress;
#ifdef EZ_DEV
	ez_core_mark_development(&core);              /* IMPL-MODE-002 */
#endif
}

/* ---- line input ---------------------------------------------------------- */
