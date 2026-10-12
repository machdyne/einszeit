/*
 * usb.h -- USB device for the Einszeit firmware: CDC console + vendor HID.
 *
 * HID OUT reports are queued here by the TinyUSB callback; the main loop
 * takes them with usb_hid_pop() and hands them to the dispatcher only when
 * no console command is running, so the two never use the core at once.
 */
#ifndef EZ_USB_H
#define EZ_USB_H

#include <stdbool.h>
#include <stdint.h>

#define USB_VID        0x16D0
#define USB_PID        0x1475
/* bcdDevice (EZ-IMPL-001 §9.1), distinct per image so a host never mixes
 * up their interface sets: 0x0101 HID, 0x0102 CDC, 0x0103 composite,
 * 0x0110 development. */
#if defined(EZ_DEV)
#define USB_BCD        0x0110
#elif EZ_USB_CDC && EZ_USB_HID
#define USB_BCD        0x0103
#elif EZ_USB_CDC
#define USB_BCD        0x0102
#else
#define USB_BCD        0x0101
#endif

void usb_init(void);
void usb_task(void);
bool usb_cdc_connected(void);
/* The terminal interface's raw I/O (CDC images; no-ops otherwise). */
void usb_cdc_write(const char *s, uint32_t n);
int  usb_cdc_read(uint8_t *b, int n);
/* 1 if a 64-byte frame was taken from the HID queue. */
int  usb_hid_pop(uint8_t frame[64]);
/* Send one 64-byte input report; false if the host does not take it in time. */
bool usb_hid_send(const uint8_t frame[64], uint32_t timeout_ms);
/* Called while the console waits for input (set by main). */
extern void (*usb_idle_hook)(void);
/* Frames dropped because the queue was full (diagnostics). */
extern unsigned long usb_hid_dropped;

#endif
