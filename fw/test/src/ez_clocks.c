/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Supports SEC-GEN-003 indirectly: characterises the timestamp source.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <string.h>

#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/xosc.h"
#include "hardware/structs/xosc.h"
#include "hardware/structs/powman.h"
#include "hardware/powman.h"
#include "hardware/regs/powman.h"

#include "ez_clocks.h"

void ez_clocks_read(ez_clock_info_t *info)
{
    memset(info, 0, sizeof(*info));

    info->clk_sys_hz  = clock_get_hz(clk_sys);
    info->clk_peri_hz = clock_get_hz(clk_peri);
    info->clk_usb_hz  = clock_get_hz(clk_usb);
    info->clk_ref_hz  = clock_get_hz(clk_ref);
    info->clk_adc_hz  = clock_get_hz(clk_adc);

    info->meas_pll_sys_khz  = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_PLL_SYS_CLKSRC_PRIMARY);
    info->meas_pll_usb_khz  = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_PLL_USB_CLKSRC_PRIMARY);
    info->meas_xosc_khz     = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_XOSC_CLKSRC);
    info->meas_rosc_khz     = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_ROSC_CLKSRC);
    info->meas_lposc_khz    = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_LPOSC_CLKSRC);
    info->meas_clk_sys_khz  = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_CLK_SYS);
    info->meas_clk_peri_khz = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_CLK_PERI);
    info->meas_clk_usb_khz  = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_CLK_USB);
    info->meas_clk_ref_khz  = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_CLK_REF);

    info->xosc_stable = (xosc_hw->status & XOSC_STATUS_STABLE_BITS) != 0;
    info->xosc_startup_delay = xosc_hw->startup & XOSC_STARTUP_DELAY_BITS;
}

void ez_aon_measure(uint32_t window_ms, ez_aon_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->window_ms = window_ms;

    uint32_t timer = powman_hw->timer;
    r->running        = (timer & POWMAN_TIMER_RUN_BITS) != 0;
    r->using_xosc     = (timer & POWMAN_TIMER_USING_XOSC_BITS) != 0;
    r->using_lposc    = (timer & POWMAN_TIMER_USING_LPOSC_BITS) != 0;
    r->using_gpio_1hz = (timer & POWMAN_TIMER_USING_GPIO_1HZ_BITS) != 0;

    if (!r->running) {
        /* Nothing has started the AON timer yet; start it on LPOSC so the
         * measurement below has something to look at. */
        powman_timer_set_1khz_tick_source_lposc();
        powman_timer_start();
        sleep_ms(10);
        timer = powman_hw->timer;
        r->running        = (timer & POWMAN_TIMER_RUN_BITS) != 0;
        r->using_xosc     = (timer & POWMAN_TIMER_USING_XOSC_BITS) != 0;
        r->using_lposc    = (timer & POWMAN_TIMER_USING_LPOSC_BITS) != 0;
        r->using_gpio_1hz = (timer & POWMAN_TIMER_USING_GPIO_1HZ_BITS) != 0;
        if (!r->running) return;
    }

    r->ms_start = powman_timer_get_ms();
    r->us_start = time_us_64();

    sleep_ms(window_ms);

    r->ms_end = powman_timer_get_ms();
    r->us_end = time_us_64();

    double aon_elapsed = (double)(r->ms_end - r->ms_start);
    double sys_elapsed = (double)(r->us_end - r->us_start) / 1000.0;

    if (sys_elapsed > 0.0) {
        r->ratio = aon_elapsed / sys_elapsed;
        r->ppm_error = (r->ratio - 1.0) * 1e6;
    }
}

const char *ez_aon_source_name(const ez_aon_result_t *r)
{
    if (r->using_gpio_1hz) return "external 1 Hz on GPIO";
    if (r->using_xosc)     return "XOSC (12 MHz crystal, divided)";
    if (r->using_lposc)    return "internal LPOSC (untrimmed ~32 kHz)";
    return "not running";
}
