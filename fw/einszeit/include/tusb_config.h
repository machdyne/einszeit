/*
 * tusb_config.h -- TinyUSB configuration for the Einszeit firmware.
 * Device mode on the RP2350's USB controller: CDC-ACM (console) and one
 * vendor HID interface (the protocol, EZ-IMPL-001 §9.2).
 */
#ifndef TUSB_CONFIG_H
#define TUSB_CONFIG_H

#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined (pico-sdk tinyusb_device does this)
#endif

#define CFG_TUSB_RHPORT0_MODE   OPT_MODE_DEVICE
#define CFG_TUSB_OS             OPT_OS_PICO
#define CFG_TUD_ENDPOINT0_SIZE  64

/* The images (EZ-UI-001 §11): einszeit_hid (HID), einszeit_cdc (CDC),
 * einszeit_composite and einszeit_dev (both). Set per image in CMake. */
#ifndef EZ_USB_CDC
#define EZ_USB_CDC              0
#endif
#ifndef EZ_USB_HID
#define EZ_USB_HID              1
#endif
#define CFG_TUD_CDC             EZ_USB_CDC  /* the terminal interface */
#define CFG_TUD_HID             EZ_USB_HID  /* the protocol, for ez */
#define CFG_TUD_MSC             0
#define CFG_TUD_MIDI            0
#define CFG_TUD_VENDOR          0

#define CFG_TUD_CDC_RX_BUFSIZE  256
#define CFG_TUD_CDC_TX_BUFSIZE  256
#define CFG_TUD_HID_EP_BUFSIZE  64

#endif
