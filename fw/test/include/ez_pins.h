/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Supports SEC-HW-002  confirms the SD_DET net is intact before the
 *            removal-detection logic is relied upon.
 *
 * Bench validation firmware. Not a production artifact.
 */

#ifndef EZ_PINS_H
#define EZ_PINS_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    PIN_EXPECT_FLOAT,     /* no external bias: should follow internal pulls  */
    PIN_EXPECT_PULLUP,    /* external pull-up: should read 1 in both states  */
    PIN_EXPECT_UNKNOWN,   /* informational only (LED, card detect)           */
} ez_pin_expect_t;

typedef struct {
    uint8_t  gpio;
    const char *name;
    ez_pin_expect_t expect;
    uint8_t  read_pullup;     /* level with internal pull-up engaged   */
    uint8_t  read_pulldown;   /* level with internal pull-down engaged */
    bool     pass;
    const char *note;
} ez_pin_result_t;

/*
 * Drives each board pin through internal pull-up then pull-down and records
 * the level. A pin with an external pull-up (10K on FRAM_SS, 20K on the SD
 * lines) is far stronger than the RP2350's ~55K internal pull-down, so it
 * reads high in both states -- which is how we confirm the resistor is fitted
 * and the net is intact. A floating pin follows the internal pull instead.
 *
 * Run with no microSD card inserted; a card holds several of those lines.
 * Returns the number of pins checked and fills results[].
 */
int ez_pins_check(ez_pin_result_t *results, int max_results, bool *all_pass);

#endif /* EZ_PINS_H */
