/*
 * board.h -- Einszeit V1 (RP2350A) board definition
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
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-HW-003  firmware storage and key data storage share no medium:
 *               firmware is in QSPI flash, key data is on the microSD.
 *   SEC-HW-002  SD_DET is the removal-detection input required by this
 *               requirement; its polarity is unconfirmed (gap G-02).
 *
 * Bench validation firmware. Not a production artifact.
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
#ifndef SD_DET_ACTIVE_LOW
#define SD_DET_ACTIVE_LOW 1
#endif

/* ---- Status LED -------------------------------------------------------- */
#define LED_PIN         12

/* ---- Capture buffer ---------------------------------------------------- */
/*
 * RP2350A has 520 KB of SRAM. 192 KB = 1,572,864 bits, comfortably above the
 * 1,000,000-sample floor NIST SP 800-90B asks for on a binary source, and
 * also enough for a full 1000x1000 restart matrix (125 KB).
 */
#define EZ_CAP_MAX      (192u * 1024u)

#endif /* EZ_BOARD_H */
