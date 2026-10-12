/*
 * usb.c -- TinyUSB device: descriptors, the console as a stdio driver over
 * CDC, and the HID frame queue. See usb.h.
 *
 * Descriptors follow EZ-IMPL-001 §9.1-9.2: VID:PID 16d0:1475, a bcdDevice
 * per variant, vendor usage page 0xFF00 / usage 0x01, 64-byte input and
 * output reports, no report IDs. No vendor reset interface (IMPL-DRV-004).
 */
#include <string.h>

#include "pico/stdlib.h"
#include "pico/stdio/driver.h"
#include "pico/unique_id.h"
#include "tusb.h"

#include "ez_secure.h"
#include "usb.h"

void (*usb_idle_hook)(void);
unsigned long usb_hid_dropped;

/* ---- descriptors ---------------------------------------------------------- */

static const tusb_desc_device_t dev_desc = {
	.bLength = sizeof(tusb_desc_device_t),
	.bDescriptorType = TUSB_DESC_DEVICE,
	.bcdUSB = 0x0200,
#if CFG_TUD_CDC
	.bDeviceClass = TUSB_CLASS_MISC,          /* IAD */
	.bDeviceSubClass = MISC_SUBCLASS_COMMON,
	.bDeviceProtocol = MISC_PROTOCOL_IAD,
#else
	.bDeviceClass = 0,                        /* defined per interface */
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
#endif
	.bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
	.idVendor = USB_VID,
	.idProduct = USB_PID,
	.bcdDevice = USB_BCD,
	.iManufacturer = 1,
	.iProduct = 2,
	.iSerialNumber = 3,
	.bNumConfigurations = 1,
};

uint8_t const *tud_descriptor_device_cb(void) { return (uint8_t const *)&dev_desc; }

#if CFG_TUD_HID
static const uint8_t hid_report[] = { TUD_HID_REPORT_DESC_GENERIC_INOUT(64) };

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) { (void)instance; return hid_report; }
#endif

#define EP_HID_OUT   0x03
#define EP_HID_IN    0x83
#if CFG_TUD_CDC && CFG_TUD_HID
enum { ITF_CDC = 0, ITF_CDC_DATA, ITF_HID, ITF_COUNT };
#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT   0x02
#define EP_CDC_IN    0x82
#define CONFIG_LEN   (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
static const uint8_t config_desc[] = {
	TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, 0x00, 100),
	TUD_CDC_DESCRIPTOR(ITF_CDC, 4, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
	TUD_HID_INOUT_DESCRIPTOR(ITF_HID, 5, HID_ITF_PROTOCOL_NONE, sizeof hid_report,
	                         EP_HID_OUT, EP_HID_IN, 64, 1),
};
#elif CFG_TUD_CDC
enum { ITF_CDC = 0, ITF_CDC_DATA, ITF_COUNT };
#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT   0x02
#define EP_CDC_IN    0x82
#define CONFIG_LEN   (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)
static const uint8_t config_desc[] = {
	TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, 0x00, 100),
	TUD_CDC_DESCRIPTOR(ITF_CDC, 4, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};
#else
enum { ITF_HID = 0, ITF_COUNT };
#define CONFIG_LEN   (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
static const uint8_t config_desc[] = {
	TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, 0x00, 100),
	TUD_HID_INOUT_DESCRIPTOR(ITF_HID, 5, HID_ITF_PROTOCOL_NONE, sizeof hid_report,
	                         EP_HID_OUT, EP_HID_IN, 64, 1),
};
#endif

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) { (void)index; return config_desc; }

static uint16_t str_buf[33];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
	(void)langid;
	char serial[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
	const char *s;
	switch (index) {
	case 0: str_buf[1] = 0x0409; str_buf[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4); return str_buf;
	case 1: s = "Machdyne"; break;
#ifdef EZ_DEV
	case 2: s = "Einszeit (development)"; break;
#else
	case 2: s = "Einszeit"; break;
#endif
	case 3: pico_get_unique_board_id_string(serial, sizeof serial); s = serial; break;
	case 4: s = "Einszeit console"; break;
	case 5: s = "Einszeit"; break;
	default: return NULL;
	}
	size_t n = strlen(s);
	if (n > 32) n = 32;
	for (size_t i = 0; i < n; i++) str_buf[1 + i] = (uint8_t)s[i];
	str_buf[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * n + 2));
	return str_buf;
}

#if CFG_TUD_HID
/* ---- HID ------------------------------------------------------------------ */

#define QLEN 32
static uint8_t q[QLEN][64];
static volatile uint32_t q_head, q_tail;

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type,
                           uint8_t const *buf, uint16_t n)
{
	(void)instance; (void)report_id; (void)type;
	if (n != 64) return;                         /* frames are exactly 64 bytes */
	uint32_t next = (q_tail + 1) % QLEN;
	if (next == q_head) { usb_hid_dropped++; return; }
	memcpy(q[q_tail], buf, 64);
	q_tail = next;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type,
                               uint8_t *buf, uint16_t reqlen)
{
	(void)instance; (void)report_id; (void)type; (void)buf; (void)reqlen;
	return 0;
}

int usb_hid_pop(uint8_t f[64])
{
	if (q_head == q_tail) return 0;
	memcpy(f, q[q_head], 64);
	ez_secure_zero(q[q_head], 64);               /* frames may carry plaintext */
	q_head = (q_head + 1) % QLEN;
	return 1;
}

bool usb_hid_send(const uint8_t f[64], uint32_t timeout_ms)
{
	absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
	while (!tud_hid_ready()) {
		tud_task();
		if (!tud_mounted() || absolute_time_diff_us(get_absolute_time(), deadline) < 0) return false;
	}
	return tud_hid_report(0, f, 64);
}

#else
int usb_hid_pop(uint8_t f[64]) { (void)f; return 0; }
bool usb_hid_send(const uint8_t f[64], uint32_t timeout_ms) { (void)f; (void)timeout_ms; return false; }
#endif

#if CFG_TUD_CDC
/* ---- console: a stdio driver over CDC -------------------------------------- */

static void cdc_out(const char *buf, int len)
{
	if (!tud_cdc_connected()) return;
	for (int i = 0; i < len;) {
		uint32_t k = tud_cdc_write(buf + i, (uint32_t)(len - i));
		i += (int)k;
		if (!k) {
			tud_cdc_write_flush();
			tud_task();
			if (!tud_cdc_connected()) return;
		}
	}
	/* Send now: unlike pico_stdio_usb there is no background flush, and
	 * the console echoes single characters without fflush(). */
	tud_cdc_write_flush();
}

#ifdef EZ_DEV
static void cdc_flush(void) { tud_cdc_write_flush(); tud_task(); }

static int cdc_in(char *buf, int len)
{
	tud_cdc_write_flush();
	tud_task();
	if (usb_idle_hook) usb_idle_hook();
	if (!tud_cdc_available()) return PICO_ERROR_NO_DATA;
	return (int)tud_cdc_read(buf, (uint32_t)len);
}

static stdio_driver_t cdc_stdio = {
	.out_chars = cdc_out,
	.out_flush = cdc_flush,
	.in_chars = cdc_in,
#if PICO_STDIO_ENABLE_CRLF_SUPPORT
	.crlf_enabled = true,
#endif
};
#endif /* EZ_DEV */

#endif

void usb_init(void)
{
	tusb_init();
#if CFG_TUD_CDC && defined(EZ_DEV)
	stdio_set_driver_enabled(&cdc_stdio, true);       /* printf: development commands only */
#endif
}

#if CFG_TUD_CDC
void usb_cdc_write(const char *s, uint32_t n) { cdc_out(s, (int)n); }
int usb_cdc_read(uint8_t *b, int n)
{
	if (!tud_cdc_available()) return 0;
	return (int)tud_cdc_read(b, (uint32_t)n);
}
#else
void usb_cdc_write(const char *s, uint32_t n) { (void)s; (void)n; }
int usb_cdc_read(uint8_t *b, int n) { (void)b; (void)n; return 0; }
#endif

void usb_task(void) { tud_task(); }
#if CFG_TUD_CDC
bool usb_cdc_connected(void) { return tud_cdc_connected(); }
#else
bool usb_cdc_connected(void) { return false; }
#endif
