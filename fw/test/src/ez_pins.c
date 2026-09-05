/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Supports SEC-HW-002.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include "pico/stdlib.h"
#include "hardware/gpio.h"

#include "board.h"
#include "ez_pins.h"

struct pin_spec {
    uint8_t gpio;
    const char *name;
    ez_pin_expect_t expect;
    const char *note;
};

static const struct pin_spec pins[] = {
    { FRAM_SCLK_PIN, "FRAM_SCLK", PIN_EXPECT_FLOAT,   "no external bias" },
    { FRAM_MOSI_PIN, "FRAM_MOSI", PIN_EXPECT_FLOAT,   "no external bias" },
    { FRAM_MISO_PIN, "FRAM_MISO", PIN_EXPECT_FLOAT,   "FRAM deselected, output Hi-Z" },
    { FRAM_SS_PIN,   "FRAM_SS",   PIN_EXPECT_PULLUP,  "external 10K pull-up" },
    { SD_DET_PIN,    "SD_DET",    PIN_EXPECT_UNKNOWN, "depends on socket and card" },
    { SD_SCLK_PIN,   "SD_SCLK",   PIN_EXPECT_PULLUP,  "external 20K pull-up" },
    { SD_MOSI_PIN,   "SD_MOSI",   PIN_EXPECT_PULLUP,  "external 20K pull-up" },
    { SD_MISO_PIN,   "SD_MISO",   PIN_EXPECT_PULLUP,  "external 20K pull-up" },
    { SD_CSN_PIN,    "SD_CSN",    PIN_EXPECT_PULLUP,  "external 20K pull-up" },
    { LED_PIN,       "LED",       PIN_EXPECT_UNKNOWN, "loaded by the LED" },
};

int ez_pins_check(ez_pin_result_t *results, int max_results, bool *all_pass)
{
    int n = (int)count_of(pins);
    if (n > max_results) n = max_results;
    *all_pass = true;

    for (int i = 0; i < n; i++) {
        uint8_t g = pins[i].gpio;

        /*
         * gpio_init() switches the pin to SIO, which tears down the SPI
         * function on the FRAM and SD buses. Without restoring it afterwards,
         * every peripheral command run after `pins` talks to a disconnected
         * pin: SPI0 RX sees nothing and every read returns 0x00, which looks
         * exactly like a dead device. Save what was there and put it back.
         */
        gpio_function_t saved_func = gpio_get_function(g);
        bool saved_pu = gpio_is_pulled_up(g);
        bool saved_pd = gpio_is_pulled_down(g);
        bool saved_dir = gpio_is_dir_out(g);
        bool saved_val = gpio_get_out_level(g);

        gpio_init(g);
        gpio_set_dir(g, GPIO_IN);

        gpio_pull_up(g);
        sleep_us(500);                  /* 20K + pin capacitance settles fast */
        uint8_t up = gpio_get(g) ? 1 : 0;

        gpio_pull_down(g);
        sleep_us(500);
        uint8_t dn = gpio_get(g) ? 1 : 0;

        /* Restore the pull configuration as well as the function; leaving a
         * previously biased input floating changes what later reads see. */
        if (saved_pu && !saved_pd)      gpio_pull_up(g);
        else if (saved_pd && !saved_pu) gpio_pull_down(g);
        else if (saved_pu && saved_pd)  gpio_set_pulls(g, true, true);
        else                            gpio_disable_pulls(g);

        /* Restore the pin to whatever it was doing before we probed it. */
        if (saved_func == GPIO_FUNC_SIO) {
            gpio_set_dir(g, saved_dir);
            if (saved_dir) gpio_put(g, saved_val);
        } else {
            gpio_set_function(g, saved_func);
        }

        results[i].gpio = g;
        results[i].name = pins[i].name;
        results[i].expect = pins[i].expect;
        results[i].note = pins[i].note;
        results[i].read_pullup = up;
        results[i].read_pulldown = dn;

        switch (pins[i].expect) {
        case PIN_EXPECT_PULLUP:
            /* External pull-up wins over the internal pull-down. */
            results[i].pass = (up == 1 && dn == 1);
            break;
        case PIN_EXPECT_FLOAT:
            results[i].pass = (up == 1 && dn == 0);
            break;
        default:
            results[i].pass = true;     /* informational */
            break;
        }
        if (!results[i].pass) *all_pass = false;
    }
    return n;
}
