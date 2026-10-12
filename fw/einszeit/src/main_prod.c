/*
 * main_prod.c -- production image (EZ_PRODUCTION): the protocol over HID
 * and nothing else. No console, no software path into the bootloader
 * (IMPL-DRV-004): firmware updates need the BOOT button.
 */
#include "pico/stdlib.h"

#include "app.h"
#include "hal_rp2350.h"
#include "usb.h"

static void prod_main(void)
{
	usb_init();
	hal_fram_init();
	app_boot();
	app_start_worker();
	for (;;) {
		usb_task();
		app_idle();
	}
}

int main(void)
{
	app_main_on_stack(prod_main);    /* a 16 KB stack (app.c); never returns */
}
