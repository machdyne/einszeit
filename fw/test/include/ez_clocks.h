/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   N/A to EZ-SEC-001 requirements. Included because SEC-GEN-003 requires
 *   generation log entries to carry a timestamp, and this establishes what
 *   the always-on timer is actually worth as a time source on V1.
 *
 * Bench validation firmware. Not a production artifact.
 */

#ifndef EZ_CLOCKS_H
#define EZ_CLOCKS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t clk_sys_hz, clk_peri_hz, clk_usb_hz, clk_ref_hz, clk_adc_hz;
    uint32_t meas_pll_sys_khz, meas_pll_usb_khz;
    uint32_t meas_xosc_khz, meas_rosc_khz, meas_lposc_khz;
    uint32_t meas_clk_sys_khz, meas_clk_peri_khz, meas_clk_usb_khz, meas_clk_ref_khz;
    bool     xosc_stable;
    uint32_t xosc_startup_delay;
} ez_clock_info_t;

typedef struct {
    bool     running;
    bool     using_xosc;
    bool     using_lposc;
    bool     using_gpio_1hz;
    uint64_t ms_start, ms_end;
    uint64_t us_start, us_end;   /* system timer reference (XOSC-derived) */
    double   ratio;              /* aon_ms / expected_ms */
    double   ppm_error;
    uint32_t window_ms;
} ez_aon_result_t;

void ez_clocks_read(ez_clock_info_t *info);

/*
 * Measures the always-on timer against the system timer for `window_ms`.
 *
 * Both are ultimately derived from the same 12 MHz crystal when the AON tick
 * runs from XOSC, so a near-zero error there only proves the divider is right,
 * not that the crystal is accurate. When the tick runs from the internal LPOSC
 * the measured error is real and typically large (the LPOSC is untrimmed).
 * The report states which case applies.
 */
void ez_aon_measure(uint32_t window_ms, ez_aon_result_t *r);

const char *ez_aon_source_name(const ez_aon_result_t *r);

#endif /* EZ_CLOCKS_H */
