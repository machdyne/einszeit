/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-FW-004  the microSD is key data storage on V1; block contents are
 *               withheld from diagnostic output unless the build opts in (D-01)
 *   SEC-HW-002  callers check ez_guard_sd_present() before every operation
 *
 * Bench validation firmware. Not a production artifact.
 */

#ifndef EZ_SD_H
#define EZ_SD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SD_TYPE_NONE = 0,
    SD_TYPE_MMC,
    SD_TYPE_SDSC_V1,
    SD_TYPE_SDSC_V2,
    SD_TYPE_SDHC,      /* or SDXC; block addressed */
} ez_sd_type_t;

typedef struct {
    ez_sd_type_t type;
    bool     block_addressed;
    uint64_t capacity_bytes;
    uint32_t block_count;
    uint32_t ocr;
    uint8_t  cid[16];
    uint8_t  csd[16];

    /* Decoded CID */
    uint8_t  mid;
    char     oid[3];
    char     pnm[6];
    uint8_t  prv_major, prv_minor;
    uint32_t psn;
    uint16_t mdt_year;
    uint8_t  mdt_month;

    /* Decoded CSD */
    uint8_t  csd_structure;
    uint8_t  tran_speed;
} ez_sd_card_t;

typedef struct {
    int step;                /* last init step reached, for diagnosis */
    const char *step_name;
    uint8_t last_r1;
    uint32_t acmd41_iterations;
    uint32_t elapsed_ms;
} ez_sd_initlog_t;

/*
 * Card-detect policy.
 *
 * Not every microSD socket has a detect switch, and those that do differ in
 * polarity and in whether the switch is normally open or normally closed. A
 * compile-time guess is not good enough: if the net is unconnected the pin
 * simply follows its pull-up and every SD command is refused forever, which
 * is what happens on a board where CD is not wired.
 *
 * EZ-SEC-001 SEC-HW-002 wants removal of key media to abort the operation, so
 * IGNORE is not a mode to leave enabled on a device holding key material. On a
 * bench board with no detect switch it is the only workable setting.
 */
typedef enum {
    EZ_SD_DET_ACTIVE_LOW = 0,   /* pin reads 0 when a card is present */
    EZ_SD_DET_ACTIVE_HIGH,      /* pin reads 1 when a card is present */
    EZ_SD_DET_IGNORE,           /* no usable detect switch on this board */
} ez_sd_det_mode_t;

void ez_sd_set_det_mode(ez_sd_det_mode_t m);
ez_sd_det_mode_t ez_sd_get_det_mode(void);
const char *ez_sd_det_mode_name(ez_sd_det_mode_t m);

bool ez_sd_card_detected(void);
int  ez_sd_det_raw(void);

/* Reads SD_DET with the internal pull-up and then the pull-down engaged, the
 * same technique the pin test uses, so the net can be classified: 1/0 means
 * floating (no switch, or switch open), 0/0 means tied to ground, 1/1 means
 * tied high. */
void ez_sd_det_probe(int *with_pullup, int *with_pulldown);

/* Full SPI-mode bring-up. Returns false with `log` describing where it failed. */
bool ez_sd_init(ez_sd_card_t *card, ez_sd_initlog_t *log);

uint32_t ez_sd_set_baud(uint32_t baud);

/* Reads one 512-byte block. Verifies the data CRC-16 the card appends, which
 * is the cheapest available signal-integrity check at high clock rates. */
bool ez_sd_read_block(uint32_t lba, uint8_t *buf, bool *crc_ok);
bool ez_sd_write_block(uint32_t lba, const uint8_t *buf);

/* Sequential read throughput over `blocks` starting at `lba`. */
bool ez_sd_bench_read(uint32_t lba, uint32_t blocks, uint8_t *scratch,
                      uint32_t *bytes_per_sec, uint32_t *crc_errors);

void ez_sd_deselect(void);
const char *ez_sd_type_name(ez_sd_type_t t);

#endif /* EZ_SD_H */
