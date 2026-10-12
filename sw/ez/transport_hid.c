/*
 * transport_hid.c -- ez_transport_t over USB HID through hidapi
 * (sw/hidapi.c: libusb/hidapi 0.15, BSD licence option, vendored upstream).
 *
 * Finds VID:PID 16d0:1475 and opens the interface whose usage page is
 * 0xFF00 (EZ-IMPL-001 §9.1: by usage page, not interface number). Reports
 * are 64 bytes with no report ID; hidapi takes a leading 0 on writes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hidapi.h"
#include "transport.h"

#define VID 0x16D0
#define PID 0x1475

static hid_device *dev;

static int w(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	(void)ctx;
	uint8_t b[EZ_FRAME_SIZE + 1];
	b[0] = 0;                                   /* no report ID */
	memcpy(b + 1, f, EZ_FRAME_SIZE);
	int r = hid_write(dev, b, sizeof b);
	memset(b, 0, sizeof b);
	return r == (int)sizeof b ? 0 : -1;
}

static int r(void *ctx, uint8_t f[EZ_FRAME_SIZE], int timeout_ms)
{
	(void)ctx;
	int n = hid_read_timeout(dev, f, EZ_FRAME_SIZE, timeout_ms);
	if (n < 0) return -1;
	if (n == 0) return 0;
	if (n != EZ_FRAME_SIZE) return -1;
	return 1;
}

int transport_hid_open(const char *serial, ez_transport_t *t, char *err, size_t errcap)
{
	if (hid_init() != 0) { snprintf(err, errcap, "hidapi initialisation failed"); return -1; }
	struct hid_device_info *list = hid_enumerate(VID, PID), *d, *pick = NULL;
	int found = 0;
	for (d = list; d; d = d->next) {
		if (d->usage_page != 0xFF00) continue;     /* the protocol interface only */
		found++;
		if (serial) {
			char s[64] = { 0 };
			if (d->serial_number) wcstombs(s, d->serial_number, sizeof s - 1);
			if (strcmp(s, serial) != 0) continue;
		}
		if (!pick) pick = d;
	}
	if (!pick) {
		hid_free_enumeration(list);
		snprintf(err, errcap, found ? "no Einszeit with serial %s" : "no Einszeit found (is it connected, and running a HID image?)",
		         serial ? serial : "");
		return -1;
	}
	if (!serial && found > 1) {
		hid_free_enumeration(list);
		snprintf(err, errcap, "%d Einszeit devices connected: choose one with --device <serial> ('ez device list')", found);
		return -1;
	}
	dev = hid_open_path(pick->path);
	hid_free_enumeration(list);
	if (!dev) {
		snprintf(err, errcap, "cannot open the device%s",
#ifdef __linux__
		         " (permissions? install sw/ez/99-einszeit.rules into /etc/udev/rules.d)"
#else
		         ""
#endif
		);
		return -1;
	}
	t->ctx = dev;
	t->write = w;
	t->read = r;
	return 0;
}

void transport_hid_list(void)
{
	if (hid_init() != 0) return;
	struct hid_device_info *list = hid_enumerate(VID, PID), *d;
	int n = 0;
	for (d = list; d; d = d->next) {
		if (d->usage_page != 0xFF00) continue;
		char s[64] = { 0 }, p[128] = { 0 };
		if (d->serial_number) wcstombs(s, d->serial_number, sizeof s - 1);
		if (d->product_string) wcstombs(p, d->product_string, sizeof p - 1);
		printf("%s  %s (bcdDevice %04x)\n", s, p, d->release_number);
		n++;
	}
	hid_free_enumeration(list);
	if (!n) printf("no Einszeit devices found\n");
}
