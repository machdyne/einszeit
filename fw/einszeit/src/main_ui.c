/*
 * main_ui.c -- the images with a terminal (einszeit_cdc, einszeit_composite,
 * einszeit_dev): the terminal interface (EZ-UI-001) on core 0, over USB
 * CDC; long work on core 1 (round 16); the protocol over HID where the
 * image has it.
 */
#include <stdint.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#ifdef EZ_DEV
#include "pico/bootrom.h"
#endif

#include "app.h"
#include "card.h"
#include "ez_ui.h"
#include "hal_rp2350.h"
#include "usb.h"

#ifdef EZ_DEV
void dev_early(void);
bool dev_cli(void *ctx, int argc, char **argv);
#endif

static ez_ui_t ui;

static char text[EZ_UI_TEXT_CAP];               /* the editor's text (Send), uploads, downloads; wiped after use */

static void ui_write(void *ctx, const char *s, uint32_t n) { (void)ctx; usb_cdc_write(s, n); }
static void card_info(void *ctx, char *o, uint32_t cap) { (void)ctx; card_info_text(o, cap); }

static void ui_main(void)
{
	hal_fram_init();        /* before dev_early(): tr05_armed() reads F-RAM */
	usb_init();
#ifdef EZ_DEV
	dev_early();
#endif
	app_boot();
	app_start_worker();
	static char board[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
	pico_get_unique_board_id_string(board, sizeof board);
	ez_ui_env_t env = { ui_write, NULL, &core, &disp, FW_VERSION, board,
#ifdef EZ_DEV
	                    true, card_info, dev_cli, text, sizeof text };
#else
	                    false, card_info, NULL, text, sizeof text };
#endif
	ez_ui_init(&ui, &env);
	bool connected = false;
	uint32_t redraw_at = 0;
	for (;;) {
		usb_task();
		app_idle();
		bool now_connected = usb_cdc_connected();
		uint32_t ms = to_ms_since_boot(get_absolute_time());
		if (now_connected && !connected) {                 /* a terminal opened: reset it, draw it all */
			ez_ui_reset(&ui);
			redraw_at = ms + 300u;                          /* and again, in case it was not ready yet */
		}
		if (redraw_at && (int32_t)(ms - redraw_at) >= 0) { redraw_at = 0; if (now_connected) ez_ui_reset(&ui); }
		connected = now_connected;
		uint8_t b[64];
		int n = usb_cdc_read(b, sizeof b);
#ifdef EZ_DEV
		/* Development images: Ctrl-Y anywhere enters the bootloader (as on
		 * Blaustahl). Production images cannot (IMPL-DRV-004). */
		for (int i = 0; i < n; i++)
			if (b[i] == 0x19) { usb_cdc_write("\r\nbootloader\r\n", 14); sleep_ms(50); reset_usb_boot(0, 0); }
#endif
		if (n > 0) ez_ui_input(&ui, b, (uint32_t)n, ms);
		if (connected) ez_ui_tick(&ui, ms);
	}
}

int main(void)
{
	app_main_on_stack(ui_main);      /* a 16 KB stack (app.c); never returns */
}
