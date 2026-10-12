/*
 * board.h -- Einszeit V1 (RP2350A) board definition (production firmware)
 *
 * Forked from fw/test/include/board.h; pins are identical.
 *
 * Pin assignment supplied by the hardware author. Both SPI buses land on
 * their native hardware SPI functions, so no PIO is required:
 *
 *   GPIO18 = SPI0 SCK   GPIO19 = SPI0 TX   GPIO20 = SPI0 RX   GPIO21 = SPI0 CSn
 *   GPIO26 = SPI1 SCK   GPIO27 = SPI1 TX   GPIO28 = SPI1 RX   GPIO29 = SPI1 CSn
 *
 * Chip selects are driven as plain GPIO so that multi-byte transactions can
 * hold CS low across several spi_write_blocking() calls.
 */

/*
 * EZ-SEC-001 traceability:
 *   SEC-HW-003  the drive 0 key partition shares the QSPI flash with the
 *               firmware in a separate region (layout below); the partition
 *               table denies the bootloader and Non-secure code any access
 *               to it, which the firmware verifies before using drive 0
 *               (IMPL-DRV-003, hal_flash_protected()).
 *   SEC-HW-002  SD_DET is advisory only until its polarity is verified
 *               (OI-03); the software card check is authoritative.
 */
#ifndef EZ_BOARD_H
#define EZ_BOARD_H

#include "hardware/spi.h"

/* ---- FRAM (SPI0) ------------------------------------------------------- */
#define FRAM_SPI        spi0
#define FRAM_SCLK_PIN   18
#define FRAM_MOSI_PIN   19
#define FRAM_MISO_PIN   20
#define FRAM_SS_PIN     21      /* external 10K pull-up */

/* Conservative default; `fram bench` finds the real ceiling. */
#define FRAM_BAUD_DEFAULT   (8 * 1000 * 1000)
#define FRAM_BAUD_INIT      (1 * 1000 * 1000)

/* ---- microSD (SPI1) ---------------------------------------------------- */
#define SD_SPI          spi1
#define SD_DET_PIN      25
#define SD_SCLK_PIN     26      /* external 20K pull-up */
#define SD_MOSI_PIN     27      /* external 20K pull-up */
#define SD_MISO_PIN     28      /* external 20K pull-up */
#define SD_CSN_PIN      29      /* external 20K pull-up */

#define SD_BAUD_INIT    (400 * 1000)    /* card spec: 100-400 kHz during init */
#define SD_BAUD_DEFAULT (12 * 1000 * 1000)

/*
 * Card-detect polarity is not documented in the V1 schematic notes we were
 * given. `sd det` reports the raw level and watches for transitions so the
 * polarity can be determined empirically on the bench; set this once known.
 * 1 = pin reads low when a card is present (switch to GND, the common case).
 */
/* Measured on V1 (TR-03 step 7, OI-03 closed): the socket switch drives
 * SD_DET to 3.3 V with a card present and leaves it open without one;
 * there is no external pull. Active-high, with the internal pull-down. */
#ifndef SD_DET_ACTIVE_LOW
#define SD_DET_ACTIVE_LOW 0
#endif

/* ---- Status LED -------------------------------------------------------- */
#define LED_PIN         12

/* ---- Flash layout (partitions.json, EZ-IMPL-001 §11) --------------------
 *   0x000000  8 KiB     partition table
 *   0x002000  1016 KiB  firmware partition (images must fit: check_size.cmake)
 *   0x100000  3060 KiB  key partition = drive 0 (Secure read/write only)
 *   0x3FD000  12 KiB    unpartitioned (boot ROM erratum RP2350-E10 block)  */
#define FW_PART_LIMIT   (1016u * 1024u)
#define KEYPART_OFFSET  (1024u * 1024u)
#define KEYPART_BLOCKS  765u
#define KEYPART_WINDOW  0x400000u              /* XIP window 1 (ATRANS1) maps the key partition */

#endif /* EZ_BOARD_H */
