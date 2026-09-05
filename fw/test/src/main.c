/*
 * Einszeit V1 hardware validation firmware
 *
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md for the full
 * matrix and docs/EZ-TEST-DEVIATIONS.md for the accepted deviations):
 *
 *   Supports  SEC-TEST-ENT-001  SP 800-22 suite over TRNG output
 *             SEC-TEST-ENT-003  AIS-31 characterisation
 *             SEC-ENTROPY-002   measures entropy per byte before any key
 *                               generation firmware can claim 8 bits
 *   Enforces  SEC-FW-002/003    ez_secure_zero() on every buffer handover
 *             SEC-FW-004        ez_guard_permit_storage() gates all storage
 *             SEC-HW-002        ez_guard_sd_present() before SD operations
 *   Exempt    SEC-ENC-*, SEC-DEC-*, SEC-KDF-001, SEC-ISO-*, SEC-DIST-*,
 *             SEC-UI-*: this firmware neither generates, stores, nor
 *             consumes Key material and implements no session layer.
 *
 * NOT A PRODUCTION ARTIFACT. This firmware deliberately bypasses the TRNG
 * hardware health tests and exposes storage test paths. It must never be
 * flashed to a provisioned device and must not be present in any build that
 * generates or handles Key material.
 *
 * A bring-up shell over USB CDC. Every command prints human-readable text and
 * terminates with a "[done rc=N]" marker so a host script can frame the
 * output; the tests that feed the entropy report also accept --json and emit a
 * single "#JSON {...}" line.
 *
 * This firmware is for bench validation only. It deliberately exposes the raw
 * noise source with the hardware health tests bypassed, which is the opposite
 * of what production firmware should ever do.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/stdio.h"
#include "pico/stdio_usb.h"
#include "pico/unique_id.h"
#include "pico/bootrom.h"
#include "hardware/adc.h"
#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "hardware/structs/sysinfo.h"
#include "hardware/watchdog.h"

#include "board.h"
#include "ez_clocks.h"
#include "ez_container.h"
#include "ez_guard.h"
#include "ez_secure.h"
#include "ez_fram.h"
#include "ez_pins.h"
#include "ez_sd.h"
#include "ez_trng.h"
#include "ez_xmodem.h"

#define FW_NAME    "einszeit-hwtest"
#define FW_VERSION "1.4.0"

/* ------------------------------------------------------------------ state */

static uint8_t  g_buf[EZ_HDR_BYTES + EZ_CAP_MAX];
static uint8_t *const g_payload = g_buf + EZ_HDR_BYTES;
static uint32_t g_payload_len = 0;
static char     g_meta[EZ_META_MAX];

/*
 * SEC-FW-003: the capture buffer doubles as scratch for the FRAM and SD
 * tests. Handing it between roles without clearing it leaves the previous
 * occupant's bytes in place, and (before this was fixed) left g_payload_len
 * claiming a capture that had since been overwritten, so `send` would
 * transmit corrupt data under a valid CRC. Every scratch user calls this.
 */
static void buffer_take_scratch(void)
{
    ez_secure_zero(g_payload, EZ_CAP_MAX);
    g_payload_len = 0;
    g_meta[0] = 0;
}

static ez_trng_cfg_t  g_trng_cfg;
static ez_fram_geom_t g_fram_geom;
static ez_sd_card_t   g_sd_card;
static bool           g_sd_ready = false;

/* -------------------------------------------------------------- utilities */

static void led_set(bool on) { gpio_put(LED_PIN, on); }

static float read_temp_c(void)
{
    adc_select_input(4);                       /* RP2350A: internal sensor */
    uint16_t raw = adc_read();
    const float conv = 3.3f / 4096.0f;
    float v = raw * conv;
    return 27.0f - (v - 0.706f) / 0.001721f;
}

static bool abort_requested(void)
{
    int c = getchar_timeout_us(0);
    return (c == 27 || c == 3 || c == 'q');    /* ESC, Ctrl-C, q */
}

static bool progress_cb(size_t done, size_t total)
{
    printf("# progress %u/%u\n", (unsigned)done, (unsigned)total);
    return !abort_requested();
}

static void fram_progress(uint32_t done, uint32_t total)
{
    printf("# progress %u/%u\n", (unsigned)done, (unsigned)total);
}

static void hexdump(const uint8_t *p, size_t len, uint32_t base)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("%08x  ", (unsigned)(base + i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", p[i + j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            putchar(isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

static bool has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 0; i < argc; i++) if (strcmp(argv[i], flag) == 0) return true;
    return false;
}

static uint32_t arg_u32(int argc, char **argv, int idx, uint32_t def)
{
    if (idx >= argc) return def;
    return (uint32_t)strtoul(argv[idx], NULL, 0);
}

/* ------------------------------------------------------------ info / pins */

/*
 * Device UUID.
 *
 * On RP2350 pico_get_unique_board_id() does not read the flash: it calls the
 * ROM get_sys_info(SYS_INFO_CHIP_INFO), which returns the OTP CHIPID0..3 rows.
 * That is a 64-bit random identifier programmed into the die at manufacture,
 * so it identifies the silicon rather than a replaceable flash part. The
 * datasheet describes it as a public device ID and treats it as unique.
 *
 * Do not confuse it with sysinfo_hw->chip_id, which carries manufacturer,
 * part number and revision and is identical on every RP2350.
 */
static void chip_id_string(char *out, size_t n)
{
    pico_unique_board_id_t id;
    pico_get_unique_board_id(&id);
    size_t k = 0;
    for (int i = 0; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES && k + 2 < n; i++)
        k += (size_t)snprintf(out + k, n - k, "%02x", id.id[i]);
}

static int cmd_info(int argc, char **argv)
{
    char uid[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1] = { 0 };
    chip_id_string(uid, sizeof(uid));

    uint32_t chip_id = sysinfo_hw->chip_id;
    unsigned mfr = chip_id & 0xfff;
    unsigned part = (chip_id >> 12) & 0xffff;
    unsigned rev = (chip_id >> 28) & 0xf;
    float t = read_temp_c();

    if (has_flag(argc, argv, "--json")) {
        printf("#JSON {\"fw\":\"%s\",\"version\":\"%s\",\"build\":\"%s %s\","
               "\"device_uuid\":\"%s\",\"uuid_source\":\"RP2350 OTP CHIPID\","
               "\"board_id\":\"%s\",\"part_id\":\"0x%08x\",\"mfr\":%u,\"part\":\"0x%04x\","
               "\"revision\":%u,\"clk_sys_hz\":%u,\"temp_c\":%.2f,\"cap_max\":%u}\n",
               FW_NAME, FW_VERSION, __DATE__, __TIME__, uid, uid,
               (unsigned)chip_id, mfr, part, rev,
               (unsigned)clock_get_hz(clk_sys), (double)t,
               (unsigned)EZ_CAP_MAX);
        return 0;
    }

    printf("firmware      : %s %s (%s %s)\n", FW_NAME, FW_VERSION, __DATE__, __TIME__);
    printf("sdk           : %s\n", PICO_SDK_VERSION_STRING);
    printf("device uuid   : %s  (OTP CHIPID, unique per die)\n", uid);
    printf("part id       : 0x%08x  (mfr 0x%03x, part 0x%04x, rev %u)\n",
           (unsigned)chip_id, mfr, part, rev);
    printf("                the part id is the same on every RP2350\n");
    printf("clk_sys       : %u Hz\n", (unsigned)clock_get_hz(clk_sys));
    printf("die temp      : %.2f C\n", (double)t);
    printf("capture buffer: %u bytes (%u held)\n", (unsigned)EZ_CAP_MAX, (unsigned)g_payload_len);
    return 0;
}

static int cmd_pins(int argc, char **argv)
{
    ez_pin_result_t res[16];
    bool all_pass = false;
    int n = ez_pins_check(res, 16, &all_pass);

    if (has_flag(argc, argv, "--json")) {
        printf("#JSON {\"all_pass\":%s,\"pins\":[", all_pass ? "true" : "false");
        for (int i = 0; i < n; i++) {
            printf("%s{\"gpio\":%u,\"name\":\"%s\",\"pullup\":%u,\"pulldown\":%u,\"pass\":%s}",
                   i ? "," : "", res[i].gpio, res[i].name,
                   res[i].read_pullup, res[i].read_pulldown,
                   res[i].pass ? "true" : "false");
        }
        printf("]}\n");
        return all_pass ? 0 : 1;
    }

    printf("gpio  name       pu pd  result   note\n");
    for (int i = 0; i < n; i++) {
        const char *verdict = (res[i].expect == PIN_EXPECT_UNKNOWN) ? "info"
                            : (res[i].pass ? "PASS" : "FAIL");
        printf("%-5u %-10s %u  %u   %-8s %s\n", res[i].gpio, res[i].name,
               res[i].read_pullup, res[i].read_pulldown, verdict, res[i].note);
    }
    printf("\nrun this with no microSD card inserted; a card biases SD_MISO/SD_DET\n");
    return all_pass ? 0 : 1;
}

static int cmd_led(int argc, char **argv)
{
    if (argc < 2) { printf("usage: led on|off|blink\n"); return 2; }
    if (strcmp(argv[1], "on") == 0)  { led_set(true);  return 0; }
    if (strcmp(argv[1], "off") == 0) { led_set(false); return 0; }
    if (strcmp(argv[1], "blink") == 0) {
        for (int i = 0; i < 10; i++) { led_set(true); sleep_ms(100); led_set(false); sleep_ms(100); }
        return 0;
    }
    printf("usage: led on|off|blink\n");
    return 2;
}

/* ---------------------------------------------------------------- clocks */

static int cmd_clock(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "aon") == 0) {
        uint32_t window = arg_u32(argc, argv, 2, 5000);
        printf("measuring AON timer for %u ms...\n", (unsigned)window);
        ez_aon_result_t r;
        ez_aon_measure(window, &r);

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"running\":%s,\"source\":\"%s\",\"window_ms\":%u,"
                   "\"aon_ms\":%llu,\"sys_ms\":%.3f,\"ratio\":%.9f,\"ppm\":%.1f}\n",
                   r.running ? "true" : "false", ez_aon_source_name(&r),
                   (unsigned)r.window_ms,
                   (unsigned long long)(r.ms_end - r.ms_start),
                   (double)(r.us_end - r.us_start) / 1000.0, r.ratio, r.ppm_error);
            return r.running ? 0 : 1;
        }

        printf("running       : %s\n", r.running ? "yes" : "no");
        printf("tick source   : %s\n", ez_aon_source_name(&r));
        printf("aon elapsed   : %llu ms\n", (unsigned long long)(r.ms_end - r.ms_start));
        printf("sys elapsed   : %.3f ms\n", (double)(r.us_end - r.us_start) / 1000.0);
        printf("ratio         : %.9f\n", r.ratio);
        printf("error         : %+.1f ppm\n", r.ppm_error);
        if (r.using_xosc)
            printf("\nnote: both timers derive from the same 12 MHz crystal, so this\n"
                   "      checks the AON divider, not crystal accuracy. Compare against\n"
                   "      an external reference to characterise the crystal itself.\n");
        if (r.using_lposc)
            printf("\nnote: the LPOSC is untrimmed; errors of several percent are normal\n"
                   "      and it is not suitable for timestamping key material.\n");
        return r.running ? 0 : 1;
    }

    ez_clock_info_t c;
    ez_clocks_read(&c);

    if (has_flag(argc, argv, "--json")) {
        printf("#JSON {\"clk_sys_hz\":%u,\"clk_peri_hz\":%u,\"clk_usb_hz\":%u,"
               "\"clk_ref_hz\":%u,\"clk_adc_hz\":%u,\"meas\":{\"pll_sys_khz\":%u,"
               "\"pll_usb_khz\":%u,\"xosc_khz\":%u,\"rosc_khz\":%u,\"lposc_khz\":%u,"
               "\"clk_sys_khz\":%u,\"clk_peri_khz\":%u,\"clk_usb_khz\":%u,\"clk_ref_khz\":%u},"
               "\"xosc_stable\":%s,\"xosc_startup_delay\":%u}\n",
               (unsigned)c.clk_sys_hz, (unsigned)c.clk_peri_hz, (unsigned)c.clk_usb_hz, (unsigned)c.clk_ref_hz, (unsigned)c.clk_adc_hz,
               (unsigned)c.meas_pll_sys_khz, (unsigned)c.meas_pll_usb_khz, (unsigned)c.meas_xosc_khz, (unsigned)c.meas_rosc_khz,
               (unsigned)c.meas_lposc_khz, (unsigned)c.meas_clk_sys_khz, (unsigned)c.meas_clk_peri_khz,
               (unsigned)c.meas_clk_usb_khz, (unsigned)c.meas_clk_ref_khz,
               c.xosc_stable ? "true" : "false", (unsigned)c.xosc_startup_delay);
        return 0;
    }

    printf("configured:\n");
    printf("  clk_sys   %10u Hz\n", (unsigned)c.clk_sys_hz);
    printf("  clk_peri  %10u Hz\n", (unsigned)c.clk_peri_hz);
    printf("  clk_usb   %10u Hz\n", (unsigned)c.clk_usb_hz);
    printf("  clk_ref   %10u Hz\n", (unsigned)c.clk_ref_hz);
    printf("  clk_adc   %10u Hz\n", (unsigned)c.clk_adc_hz);
    printf("measured (frequency counter, clk_ref reference):\n");
    printf("  pll_sys   %10u kHz\n", (unsigned)c.meas_pll_sys_khz);
    printf("  pll_usb   %10u kHz\n", (unsigned)c.meas_pll_usb_khz);
    printf("  xosc      %10u kHz\n", (unsigned)c.meas_xosc_khz);
    printf("  rosc      %10u kHz\n", (unsigned)c.meas_rosc_khz);
    printf("  lposc     %10u kHz\n", (unsigned)c.meas_lposc_khz);
    printf("  clk_sys   %10u kHz\n", (unsigned)c.meas_clk_sys_khz);
    printf("  clk_peri  %10u kHz\n", (unsigned)c.meas_clk_peri_khz);
    printf("  clk_usb   %10u kHz\n", (unsigned)c.meas_clk_usb_khz);
    printf("xosc stable : %s (startup delay %u)\n",
           c.xosc_stable ? "yes" : "NO", (unsigned)c.xosc_startup_delay);
    return c.xosc_stable ? 0 : 1;
}

/* ------------------------------------------------------------------ FRAM */

static int cmd_fram(int argc, char **argv)
{
    if (argc < 2) { printf("usage: fram id|size|test [--full]|bench|dump|write\n"); return 2; }

    if (strcmp(argv[1], "id") == 0) {
        ez_fram_id_t id;
        ez_fram_probe_t pr;
        bool present = ez_fram_probe(&pr);
        bool id_ok = ez_fram_read_id(&id);

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"present\":%s,\"rdid_supported\":%s,\"wel_toggles\":%s,"
                   "\"miso_alive\":%s,\"id\":\"", present ? "true" : "false",
                   pr.rdid_supported ? "true" : "false",
                   pr.wel_toggles ? "true" : "false",
                   pr.miso_alive ? "true" : "false");
            for (int i = 0; i < id.id_len; i++) printf("%02x", id.id[i]);
            printf("\",\"vendor\":\"%s\",\"part\":\"%s\",\"density_bytes\":%u,"
                   "\"sr_idle\":%u,\"sr_wren\":%u,\"sr_wrdi\":%u}\n",
                   id.vendor, id.part, (unsigned)id.density_bytes,
                   pr.sr_idle, pr.sr_wren, pr.sr_wrdi);
            return present ? 0 : 1;
        }

        printf("presence     : %s\n", present ? "PRESENT" : "NOT DETECTED");
        printf("  WEL toggle : %s (WREN->0x%02x, WRDI->0x%02x)\n",
               pr.wel_toggles ? "yes" : "NO", pr.sr_wren, pr.sr_wrdi);
        printf("  MISO active: %s\n", pr.miso_alive ? "yes" : "NO (stuck)");
        printf("status reg   : 0x%02x  (WEL=%u BP=%u%u WPEN=%u)\n", pr.sr_idle,
               (pr.sr_idle & FRAM_SR_WEL) ? 1 : 0, (pr.sr_idle & FRAM_SR_BP1) ? 1 : 0,
               (pr.sr_idle & FRAM_SR_BP0) ? 1 : 0, (pr.sr_idle & FRAM_SR_WPEN) ? 1 : 0);

        if (!id_ok) {
            printf("jedec id     : not supported by this part (RDID/0x9F)\n");
        } else {
            printf("jedec id     : ");
            for (int i = 0; i < id.id_len; i++) printf("%02x ", id.id[i]);
            printf("\n");
        }
        if (id_ok) {
            printf("vendor       : %s\npart         : %s\n", id.vendor, id.part);
            if (id.density_bytes)
                printf("density      : %u bytes (from ID table)\n", (unsigned)id.density_bytes);
        } else {
            printf("vendor       : not reported\n");
        }

        if (present && !id_ok) {
            /*
             * The important case. RDID (0x9F) is not universal: the original
             * Fujitsu MB85RS64 family, including the MB85RS64PNF used on
             * Blaustahl, has no Device ID command, so 0x9F clocks out nothing
             * and we read all zeroes. The part is fine.
             */
            printf("\nThe FRAM is responding: WREN set the write-enable latch and WRDI\n"
                   "cleared it, which needs a working bus in both directions.\n"
                   "It just does not implement RDID (0x9F). Older Fujitsu parts such\n"
                   "as the MB85RS64/MB85RS64PNF predate that command; the Blaustahl\n"
                   "driver does not use it either. This is not a fault.\n\n"
                   "Run 'fram size' to measure the density directly by address\n"
                   "aliasing, which does not depend on the ID. For an MB85RS64\n"
                   "expect 8192 bytes with 2-byte addressing.\n");
        } else if (!present) {
            printf("\nNo response. In order of likelihood:\n"
                   "  1. Did you run 'pins' or 'selftest' first? Before v1.1.1 the\n"
                   "     pin test left GPIO18-21 in SIO mode and never restored the\n"
                   "     SPI function, so every later read returned 0x00. Fixed now;\n"
                   "     if you are on an older build, power-cycle and retry 'fram id'\n"
                   "     as the first command.\n"
                   "  2. Check CS: GPIO%u should idle high via its 10K pull-up.\n"
                   "     'pins' reports 1/1 for FRAM_SS when the resistor is fitted.\n"
                   "  3. Check MISO on GPIO%u and FRAM supply.\n"
                   "  4. Try a slower clock: 'fram bench 256' starts at 1 MHz.\n",
                   FRAM_SS_PIN, FRAM_MISO_PIN);
        }
        return present ? 0 : 1;
    }

    if (strcmp(argv[1], "size") == 0) {
        /* SEC-FW-004 / SEC-PTR-002: destructive over the whole device. */
        if (!ez_guard_permit_storage("fram size (writes markers across the "
                                     "entire device)")) return 3;
        printf("probing address wrap (destructive)...\n");
        bool ok = ez_fram_detect_size(&g_fram_geom);
        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"ok\":%s,\"size_bytes\":%u,\"addr_bytes\":%u,\"confirmed\":%s}\n",
                   ok ? "true" : "false", (unsigned)g_fram_geom.size_bytes,
                   g_fram_geom.addr_bytes, g_fram_geom.size_confirmed ? "true" : "false");
            return ok ? 0 : 1;
        }
        if (!ok) { printf("no usable device found\n"); return 1; }
        printf("size       : %u bytes (%u Kbit)\n",
               (unsigned)g_fram_geom.size_bytes, (unsigned)g_fram_geom.size_bytes * 8u / 1024u);
        printf("addressing : %u-byte addresses\n", g_fram_geom.addr_bytes);
        if (!g_fram_geom.size_confirmed)
            printf("warning    : result not self-consistent, re-check addressing mode\n");
        return 0;
    }

    if (strcmp(argv[1], "test") == 0) {
        /* SEC-FW-004 / SEC-META-003: overwrites session records if present. */
        if (!ez_guard_permit_storage("fram test")) return 3;
        ez_fram_result_t r;
        bool ok;
        if (has_flag(argc, argv, "--full")) {
            if (!g_fram_geom.size_confirmed) ez_fram_detect_size(&g_fram_geom);
            printf("full destructive test over %u bytes...\n", (unsigned)g_fram_geom.size_bytes);
            ok = ez_fram_test_full(g_fram_geom.size_bytes, &r, fram_progress);
        } else {
            uint32_t len = arg_u32(argc, argv, 2, 4096);
            if (len > EZ_CAP_MAX / 2) len = EZ_CAP_MAX / 2;
            printf("testing %u bytes at 0x0000 (contents restored afterwards)...\n", (unsigned)len);
            buffer_take_scratch();
            ok = ez_fram_test_region(0, len, &r, g_payload, EZ_CAP_MAX);
        }

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"ok\":%s,\"id_ok\":%s,\"sr_ok\":%s,\"bus_ok\":%s,"
                   "\"patterns_ok\":%s,\"addressing_ok\":%s,\"bytes_tested\":%u,"
                   "\"errors\":%u,\"first_error_addr\":%u}\n",
                   ok ? "true" : "false", r.id_ok ? "true" : "false",
                   r.sr_ok ? "true" : "false", r.bus_ok ? "true" : "false",
                   r.patterns_ok ? "true" : "false", r.addressing_ok ? "true" : "false",
                   (unsigned)r.bytes_tested, (unsigned)r.error_count, (unsigned)r.first_error_addr);
            return ok ? 0 : 1;
        }

        printf("jedec id      : %s\n", r.id_ok ? "ok" : "FAIL");
        printf("WEL set/clear : %s\n", r.sr_ok ? "ok" : "FAIL");
        printf("bus activity  : %s\n", r.bus_ok ? "ok" : "FAIL (MISO stuck)");
        printf("patterns      : %s\n", r.patterns_ok ? "ok" : "FAIL");
        printf("addressing    : %s\n", r.addressing_ok ? "ok" : "FAIL");
        printf("bytes tested  : %u\n", (unsigned)r.bytes_tested);
        if (r.error_count)
            printf("errors        : %u, first at 0x%06x expected %02x got %02x\n",
                   (unsigned)r.error_count, (unsigned)r.first_error_addr,
                   r.first_error_expected, r.first_error_got);
        return ok ? 0 : 1;
    }

    if (strcmp(argv[1], "bench") == 0) {
        if (!ez_guard_permit_storage("fram bench (writes test patterns)")) return 3;
        static const uint32_t bauds[] = { 1000000, 4000000, 8000000, 16000000,
                                          20000000, 25000000, 32000000 };
        uint32_t len = arg_u32(argc, argv, 2, 4096);
        if (len > 16384) len = 16384;

        printf("baud(req)  baud(act)   write B/s    read B/s  verify\n");
        for (size_t i = 0; i < count_of(bauds); i++) {
            uint32_t act = ez_fram_set_baud(bauds[i]);
            uint32_t w = 0, rd = 0;
            bool vok = false;
            buffer_take_scratch();
            ez_fram_bench(0, len, g_payload, &w, &rd, &vok);
            printf("%9u  %9u  %10u  %10u  %s\n", (unsigned)bauds[i], (unsigned)act, (unsigned)w, (unsigned)rd, vok ? "ok" : "FAIL");
        }
        ez_fram_set_baud(FRAM_BAUD_DEFAULT);
        printf("\nThe highest rate that still verifies is your safe ceiling.\n"
               "Failures at the top of the sweep are expected on slower parts:\n"
               "the MB85RS64 family is rated to 20 MHz, the V/B/T generations\n"
               "to 25-33 MHz. A failure above the datasheet limit is not a\n"
               "board fault.\n");
        return 0;
    }

    if (strcmp(argv[1], "dump") == 0) {
#if !EZ_ENABLE_RAW_STORAGE_DUMP
        /*
         * SEC-FW-004 forbids any command that gives raw read access to key
         * storage, and SEC-UI-005 forbids OTP offsets appearing in diagnostic
         * output. Dumping FRAM over USB does both. Build with
         * -DEZ_ENABLE_RAW_STORAGE_DUMP=ON only against a board that has never
         * held key material; see docs/EZ-TEST-DEVIATIONS.md D-01.
         */
        printf("disabled: raw FRAM dump violates EZ-SEC-001 SEC-FW-004 and\n"
               "SEC-UI-005. Rebuild with -DEZ_ENABLE_RAW_STORAGE_DUMP=ON if\n"
               "this board has never held key material.\n");
        return 3;
#else
        if (!ez_guard_permit_storage("fram dump")) return 3;
        uint32_t addr = arg_u32(argc, argv, 2, 0);
        uint32_t len = arg_u32(argc, argv, 3, 256);
        if (len > 4096) len = 4096;
        buffer_take_scratch();
        ez_fram_read(addr, g_payload, len);
        hexdump(g_payload, len, addr);
        return 0;
#endif
    }

    if (strcmp(argv[1], "write") == 0) {
        /* SEC-PTR-002: an arbitrary FRAM write can roll an OTP offset back. */
        if (!ez_guard_permit_storage("fram write")) return 3;
        if (argc < 4) { printf("usage: fram write <addr> <hexbytes>\n"); return 2; }
        uint32_t addr = arg_u32(argc, argv, 2, 0);
        const char *hex = argv[3];
        size_t n = strlen(hex) / 2;
        if (n > 1024) n = 1024;
        buffer_take_scratch();
        for (size_t i = 0; i < n; i++) {
            char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
            g_payload[i] = (uint8_t)strtoul(b, NULL, 16);
        }
        ez_fram_write(addr, g_payload, n);
        printf("wrote %u bytes at 0x%06x\n", (unsigned)n, (unsigned)addr);
        return 0;
    }

    printf("unknown subcommand\n");
    return 2;
}

/* -------------------------------------------------------------------- SD */

static int cmd_sd(int argc, char **argv)
{
    if (argc < 2) { printf("usage: sd det|init|info|read|bench\n"); return 2; }

    if (strcmp(argv[1], "det") == 0) {
        /* Set the policy: sd det low|high|ignore */
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "low") == 0) {
                ez_sd_set_det_mode(EZ_SD_DET_ACTIVE_LOW);
                printf("card detect policy: active-low\n");
            } else if (strcmp(argv[i], "high") == 0) {
                ez_sd_set_det_mode(EZ_SD_DET_ACTIVE_HIGH);
                printf("card detect policy: active-high\n");
            } else if (strcmp(argv[i], "ignore") == 0) {
                ez_sd_set_det_mode(EZ_SD_DET_IGNORE);
                printf("card detect policy: IGNORED -- SD commands will run\n"
                       "without a presence check. EZ-SEC-001 SEC-HW-002 wants\n"
                       "removal of key media to abort an operation, so do not\n"
                       "leave this set on a device that holds key material.\n");
            }
        }

        if (has_flag(argc, argv, "--watch")) {
            printf("watching SD_DET (GPIO%u), press any key to stop\n", SD_DET_PIN);
            int last = -1;
            while (!abort_requested()) {
                int now = ez_sd_det_raw();
                if (now != last) { printf("SD_DET = %d\n", now); last = now; }
                sleep_ms(50);
            }
            return 0;
        }
        int pu = 0, pd = 0;
        ez_sd_det_probe(&pu, &pd);
        const char *net;
        if (pu == 1 && pd == 0)      net = "floating: nothing is driving it";
        else if (pu == 0 && pd == 0) net = "tied to ground";
        else if (pu == 1 && pd == 1) net = "tied high";
        else                         net = "inconsistent";

        printf("SD_DET (GPIO%u)   : %d with internal pull-up, %d with pull-down\n",
               SD_DET_PIN, pu, pd);
        printf("net              : %s\n", net);
        printf("policy           : %s\n", ez_sd_det_mode_name(ez_sd_get_det_mode()));
        printf("card present     : %s\n", ez_sd_card_detected() ? "yes" : "no");

        if (pu == 1 && pd == 0) {
            printf("\nThe pin follows the internal pull in both directions, so no\n"
                   "external switch is holding it. Either the socket has no detect\n"
                   "contact, the contact is open with no card inserted, or the net\n"
                   "is not connected.\n\n"
                   "Insert a card and re-run. If the reading does not change, the\n"
                   "board has no usable detect line: run 'sd det ignore' to stop\n"
                   "the presence check blocking SD commands.\n");
        } else if (pu == 0 && pd == 0) {
            printf("\nSomething is holding this pin at ground. With a card inserted\n"
                   "that means an active-low detect switch: run 'sd det low'.\n"
                   "With no card inserted it means the switch is normally closed:\n"
                   "run 'sd det high'.\n");
        }
        printf("\nUse 'sd det --watch', insert and remove a card, and set the\n"
               "policy to match. Make it permanent in board.h via\n"
               "SD_DET_ACTIVE_LOW once you know which it is.\n");
        return 0;
    }

    if (strcmp(argv[1], "init") == 0 || strcmp(argv[1], "info") == 0) {
        if (!ez_guard_sd_present("sd init")) return 3;   /* SEC-HW-002 */
        ez_sd_initlog_t log;
        bool ok = ez_sd_init(&g_sd_card, &log);
        g_sd_ready = ok;

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"ok\":%s,\"step\":%d,\"step_name\":\"%s\",\"last_r1\":%u,"
                   "\"acmd41_iterations\":%u,\"init_ms\":%u,\"type\":\"%s\","
                   "\"capacity_bytes\":%llu,\"blocks\":%u,\"ocr\":\"0x%08x\","
                   "\"oid\":\"%s\",\"pnm\":\"%s\",\"psn\":\"0x%08x\",\"mdt\":\"%04u-%02u\"}\n",
                   ok ? "true" : "false", log.step, log.step_name ? log.step_name : "",
                   log.last_r1, (unsigned)log.acmd41_iterations, (unsigned)log.elapsed_ms,
                   ez_sd_type_name(g_sd_card.type),
                   (unsigned long long)g_sd_card.capacity_bytes, (unsigned)g_sd_card.block_count,
                   (unsigned)g_sd_card.ocr, g_sd_card.oid, g_sd_card.pnm,
                   (unsigned)g_sd_card.psn, g_sd_card.mdt_year, g_sd_card.mdt_month);
            return ok ? 0 : 1;
        }

        if (!ok) {
            printf("init FAILED at step %d (%s), last R1 = 0x%02x\n",
                   log.step, log.step_name ? log.step_name : "?", log.last_r1);
            printf("\nR1 bit meanings: 0x01 idle, 0x04 illegal cmd, 0x08 crc error,\n"
                   "0xff = no response at all (check CS, power, card seating)\n");
            return 1;
        }

        printf("init          : ok in %u ms (%u ACMD41 iterations)\n",
               (unsigned)log.elapsed_ms, (unsigned)log.acmd41_iterations);
        printf("type          : %s (%s addressing)\n", ez_sd_type_name(g_sd_card.type),
               g_sd_card.block_addressed ? "block" : "byte");
        printf("capacity      : %llu bytes (%u blocks)\n",
               (unsigned long long)g_sd_card.capacity_bytes, (unsigned)g_sd_card.block_count);
        printf("ocr           : 0x%08x\n", (unsigned)g_sd_card.ocr);
        printf("manufacturer  : 0x%02x  oem \"%s\"\n", g_sd_card.mid, g_sd_card.oid);
        printf("product       : \"%s\" rev %u.%u\n", g_sd_card.pnm,
               g_sd_card.prv_major, g_sd_card.prv_minor);
        printf("serial        : 0x%08x\n", (unsigned)g_sd_card.psn);
        printf("manufactured  : %04u-%02u\n", g_sd_card.mdt_year, g_sd_card.mdt_month);
        printf("csd structure : v%u  tran_speed 0x%02x\n",
               g_sd_card.csd_structure + 1, g_sd_card.tran_speed);
        return 0;
    }

    if (strcmp(argv[1], "read") == 0) {
        if (!g_sd_ready) { printf("run 'sd init' first\n"); return 1; }
        if (!ez_guard_sd_present("sd read")) return 3;   /* SEC-HW-002 */
        uint32_t lba = arg_u32(argc, argv, 2, 0);
        buffer_take_scratch();
        bool crc_ok = false;
        if (!ez_sd_read_block(lba, g_payload, &crc_ok)) { printf("read failed\n"); return 1; }
        printf("lba %u, data CRC %s\n", (unsigned)lba, crc_ok ? "ok" : "MISMATCH");
        if (lba == 0 && g_payload[510] == 0x55 && g_payload[511] == 0xaa)
            printf("MBR signature present\n");
#if EZ_ENABLE_RAW_STORAGE_DUMP
        hexdump(g_payload, 512, 0);
#else
        /*
         * SEC-FW-004: the microSD is key data storage on V1, so hexdumping an
         * arbitrary LBA over USB is exactly the raw read path the requirement
         * prohibits. The block is still read and its CRC-16 still verified,
         * which is what the bus integrity check actually needs; only the
         * contents are withheld. See docs/EZ-TEST-DEVIATIONS.md D-01.
         */
        printf("block contents withheld (EZ-SEC-001 SEC-FW-004); the read and\n"
               "its CRC check still ran, which is what this test measures\n");
#endif
        ez_secure_zero(g_payload, 512);   /* SEC-FW-003 */
        return crc_ok ? 0 : 1;
    }

    if (strcmp(argv[1], "bench") == 0) {
        if (!g_sd_ready) { printf("run 'sd init' first\n"); return 1; }
        if (!ez_guard_sd_present("sd bench")) return 3;   /* SEC-HW-002 */
        uint32_t blocks = arg_u32(argc, argv, 2, 512);
        buffer_take_scratch();
        static const uint32_t bauds[] = { 1000000, 4000000, 12000000, 20000000, 25000000 };

        printf("baud(req)  baud(act)     read B/s  crc errors\n");
        for (size_t i = 0; i < count_of(bauds); i++) {
            uint32_t act = ez_sd_set_baud(bauds[i]);
            uint32_t bps = 0, crce = 0;
            if (ez_sd_bench_read(0, blocks, g_payload, &bps, &crce))
                printf("%9u  %9u  %11u  %10u\n", (unsigned)bauds[i], (unsigned)act, (unsigned)bps, (unsigned)crce);
            else
                printf("%9u  %9u  %11s  %10s\n", (unsigned)bauds[i], (unsigned)act, "FAIL", "-");
        }
        ez_sd_set_baud(SD_BAUD_DEFAULT);
        printf("\nany nonzero CRC error count means the bus is marginal at that rate\n");
        return 0;
    }

    if (strcmp(argv[1], "write") == 0) {
        if (!g_sd_ready) { printf("run 'sd init' first\n"); return 1; }
        if (!ez_guard_sd_present("sd write")) return 3;      /* SEC-HW-002 */
        if (!ez_guard_permit_storage("sd write")) return 3;   /* SEC-FW-004  */
        if (!has_flag(argc, argv, "--yes")) {
            printf("this overwrites a block. re-run with --yes to confirm.\n");
            return 2;
        }
        uint32_t lba = arg_u32(argc, argv, 2, 0);
        buffer_take_scratch();
        for (int i = 0; i < 512; i++) g_payload[i] = (uint8_t)(i ^ lba);
        if (!ez_sd_write_block(lba, g_payload)) { printf("write failed\n"); return 1; }
        uint8_t back[512];
        bool crc_ok = false;
        if (!ez_sd_read_block(lba, back, &crc_ok)) { printf("readback failed\n"); return 1; }
        bool match = (memcmp(back, g_payload, 512) == 0);
        printf("write+verify lba %u: %s (crc %s)\n", (unsigned)lba, match ? "ok" : "MISMATCH",
               crc_ok ? "ok" : "bad");
        return match ? 0 : 1;
    }

    printf("unknown subcommand\n");
    return 2;
}

/* ------------------------------------------------------------------ HRNG */

static void trng_cfg_from_args(int argc, char **argv, ez_trng_cfg_t *cfg)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "raw") == 0) {
            cfg->bypass_vnc = cfg->bypass_crngt = cfg->bypass_autocorr = true;
        } else if (strcmp(argv[i], "cond") == 0) {
            cfg->bypass_vnc = cfg->bypass_crngt = cfg->bypass_autocorr = false;
        } else if (strcmp(argv[i], "rosc") == 0 && i + 1 < argc) {
            cfg->rosc_len = (uint8_t)(strtoul(argv[i + 1], NULL, 0) & 3u);
        } else if (strcmp(argv[i], "cycled") == 0) {
            cfg->cycle_source = true;
        } else if (strcmp(argv[i], "continuous") == 0) {
            cfg->cycle_source = false;
        } else if (strcmp(argv[i], "sample") == 0 && i + 1 < argc) {
            cfg->sample_cnt = (uint32_t)strtoul(argv[i + 1], NULL, 0);
        }
    }
}

static void write_capture_meta(const char *mode, const ez_trng_cfg_t *cfg,
                               const ez_trng_stats_t *st, float t0, float t1,
                               const char *kind, uint32_t rows, uint32_t row_bytes)
{
    char uid[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1] = { 0 };
    chip_id_string(uid, sizeof(uid));
    double secs = (double)st->elapsed_us / 1e6;
    double bps = secs > 0 ? (double)st->bytes * 8.0 / secs : 0.0;

    int meta_len = snprintf(g_meta, sizeof(g_meta),
        "{\"key_material\":false,\"usage\":\"TEST ONLY - characterisation "
        "data, MUST NOT be used as key material (EZ-SEC-001 SEC-ENTROPY-001, "
        "SEC-DIST-001)\","
        "\"fw\":\"%s\",\"version\":\"%s\",\"kind\":\"%s\",\"mode\":\"%s\","
        "\"device_uuid\":\"%s\",\"board_id\":\"%s\","
        "\"rosc_len\":%u,\"sample_cnt\":%u,"
        "\"bypass_vnc\":%s,\"bypass_crngt\":%s,\"bypass_autocorr\":%s,"
        "\"bytes\":%llu,\"collections\":%u,\"vn_err\":%u,\"crngt_err\":%u,"
        "\"autocorr_err\":%u,\"resets\":%u,\"timeouts\":%u,\"elapsed_us\":%llu,"
        "\"bits_per_sec\":%.2f,\"temp_c_start\":%.2f,\"temp_c_end\":%.2f,"
        "\"clk_sys_hz\":%u,\"rows\":%u,\"row_bytes\":%u}",
        FW_NAME, FW_VERSION, kind, mode, uid, uid,
        (unsigned)cfg->rosc_len, (unsigned)cfg->sample_cnt,
        cfg->bypass_vnc ? "true" : "false",
        cfg->bypass_crngt ? "true" : "false",
        cfg->bypass_autocorr ? "true" : "false",
        (unsigned long long)st->bytes, (unsigned)st->collections,
        (unsigned)st->vn_err, (unsigned)st->crngt_err,
        (unsigned)st->autocorr_err, (unsigned)st->resets, (unsigned)st->timeouts,
        (unsigned long long)st->elapsed_us, bps, (double)t0, (double)t1,
        (unsigned)clock_get_hz(clk_sys), (unsigned)rows, (unsigned)row_bytes);

    /*
     * snprintf reports what it *would* have written. A truncated metadata
     * object is invalid JSON and the host rejects the whole transfer, so fail
     * loudly here rather than after the capture has been paid for.
     */
    if (meta_len < 0 || (size_t)meta_len >= sizeof(g_meta)) {
        printf("internal error: capture metadata needs %d bytes, header holds "
               "%u. Increase EZ_HDR_BYTES.\n", meta_len, (unsigned)sizeof(g_meta));
        g_meta[0] = 0;
    }
}

static int cmd_hrng(int argc, char **argv)
{
    if (argc < 2) { printf("usage: hrng info|cfg|health|cap|sweep|restart\n"); return 2; }

    if (strcmp(argv[1], "info") == 0) {
        ez_trng_regs_t r;
        ez_trng_read_regs(&r);

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"rng_isr\":%u,\"trng_config\":%u,\"sample_cnt1\":%u,"
                   "\"debug_control\":%u,\"busy\":%u,\"version\":%u,"
                   "\"autocorr_trys\":%u,\"autocorr_fails\":%u,"
                   "\"cfg\":{\"rosc_len\":%u,\"sample_cnt\":%u,\"bypass_vnc\":%s,"
                   "\"bypass_crngt\":%s,\"bypass_autocorr\":%s}}\n",
                   (unsigned)r.rng_isr, (unsigned)r.trng_config, (unsigned)r.sample_cnt1, (unsigned)r.trng_debug_control,
                   (unsigned)r.trng_busy, (unsigned)r.rng_version, (unsigned)r.autocorr_trys, (unsigned)r.autocorr_fails,
                   g_trng_cfg.rosc_len, (unsigned)g_trng_cfg.sample_cnt,
                   g_trng_cfg.bypass_vnc ? "true" : "false",
                   g_trng_cfg.bypass_crngt ? "true" : "false",
                   g_trng_cfg.bypass_autocorr ? "true" : "false");
            return 0;
        }

        printf("RNG_IMR            0x%08x\n", (unsigned)r.rng_imr);
        printf("RNG_ISR            0x%08x  (ehr_valid=%u autocorr=%u crngt=%u vn=%u)\n",
               (unsigned)r.rng_isr, (unsigned)r.rng_isr & 1u, (unsigned)(r.rng_isr >> 1) & 1u,
               (unsigned)(r.rng_isr >> 2) & 1u, (unsigned)(r.rng_isr >> 3) & 1u);
        printf("TRNG_CONFIG        0x%08x  (inverter chain select %u)\n",
               (unsigned)r.trng_config, (unsigned)r.trng_config & 3u);
        printf("TRNG_VALID         0x%08x\n", (unsigned)r.trng_valid);
        printf("RND_SOURCE_ENABLE  0x%08x\n", (unsigned)r.rnd_source_enable);
        printf("SAMPLE_CNT1        0x%08x  (%u clocks between samples)\n",
               (unsigned)r.sample_cnt1, (unsigned)r.sample_cnt1);
        printf("AUTOCORR_STATISTIC 0x%08x  (%u trials, %u failures)\n",
               (unsigned)r.autocorr_statistic, (unsigned)r.autocorr_trys, (unsigned)r.autocorr_fails);
        printf("TRNG_DEBUG_CONTROL 0x%08x  (vnc_bypass=%u crngt_bypass=%u autocorr_bypass=%u)\n",
               (unsigned)r.trng_debug_control, (unsigned)(r.trng_debug_control >> 1) & 1u,
               (unsigned)(r.trng_debug_control >> 2) & 1u, (unsigned)(r.trng_debug_control >> 3) & 1u);
        printf("TRNG_BUSY          0x%08x\n", (unsigned)r.trng_busy);
        printf("RNG_VERSION        0x%08x\n", (unsigned)r.rng_version);
        printf("RNG_BIST_CNTR      0x%08x 0x%08x 0x%08x\n",
               (unsigned)r.rng_bist[0], (unsigned)r.rng_bist[1], (unsigned)r.rng_bist[2]);
        printf("\nactive capture config: rosc_len=%u sample_cnt=%u mode=%s\n",
               g_trng_cfg.rosc_len, (unsigned)g_trng_cfg.sample_cnt,
               g_trng_cfg.bypass_vnc ? "raw" : "conditioned");
        return 0;
    }

    if (strcmp(argv[1], "cfg") == 0) {
        trng_cfg_from_args(argc > 2 ? argc - 2 : 0, argv + 2, &g_trng_cfg);
        printf("rosc_len=%u sample_cnt=%u vnc_bypass=%u crngt_bypass=%u autocorr_bypass=%u\n",
               g_trng_cfg.rosc_len, (unsigned)g_trng_cfg.sample_cnt, g_trng_cfg.bypass_vnc,
               g_trng_cfg.bypass_crngt, g_trng_cfg.bypass_autocorr);
        return 0;
    }

    if (strcmp(argv[1], "health") == 0) {
        uint32_t n = arg_u32(argc, argv, 2, 256);
        ez_trng_cfg_t cfg = g_trng_cfg;
        trng_cfg_from_args(argc > 2 ? argc - 2 : 0, argv + 2, &cfg);

        ez_trng_stats_t st;
        ez_trng_health(&cfg, n, &st);
        double secs = (double)st.elapsed_us / 1e6;
        double bps = secs > 0 ? (double)st.bytes * 8.0 / secs : 0.0;

        if (has_flag(argc, argv, "--json")) {
            printf("#JSON {\"collections\":%u,\"requested\":%u,\"bytes\":%llu,"
                   "\"elapsed_us\":%llu,\"bits_per_sec\":%.2f,\"vn_err\":%u,"
                   "\"crngt_err\":%u,\"autocorr_err\":%u,\"resets\":%u,\"timeouts\":%u,"
                   "\"mode\":\"%s\",\"rosc_len\":%u,\"sample_cnt\":%u}\n",
                   (unsigned)st.collections, (unsigned)n, (unsigned long long)st.bytes,
                   (unsigned long long)st.elapsed_us, bps, (unsigned)st.vn_err, (unsigned)st.crngt_err,
                   (unsigned)st.autocorr_err, (unsigned)st.resets, (unsigned)st.timeouts,
                   cfg.bypass_vnc ? "raw" : "conditioned", cfg.rosc_len, (unsigned)cfg.sample_cnt);
            return (st.collections == n) ? 0 : 1;
        }

        printf("collections   : %u of %u requested\n", (unsigned)st.collections, (unsigned)n);
        printf("throughput    : %.1f bit/s (%.1f byte/s)\n", bps, bps / 8.0);
        printf("vn errors     : %u  (32 identical bits in a row)\n", (unsigned)st.vn_err);
        printf("crngt errors  : %u  (repeated 16-bit block)\n", (unsigned)st.crngt_err);
        printf("autocorr fails: %u  (fatal, forced %u resets)\n", (unsigned)st.autocorr_err, (unsigned)st.resets);
        printf("timeouts      : %u\n", (unsigned)st.timeouts);
        return (st.collections == n) ? 0 : 1;
    }

    if (strcmp(argv[1], "cap") == 0) {
        uint32_t want = arg_u32(argc, argv, 2, 32768);
        if (want > EZ_CAP_MAX) want = EZ_CAP_MAX;
        ez_trng_cfg_t cfg = g_trng_cfg;
        trng_cfg_from_args(argc > 2 ? argc - 2 : 0, argv + 2, &cfg);

        printf("# capturing %u bytes, mode=%s rosc_len=%u sample_cnt=%u\n",
               (unsigned)want, cfg.bypass_vnc ? "raw" : "conditioned", cfg.rosc_len, (unsigned)cfg.sample_cnt);
        double est = ez_trng_estimate_bps(&cfg, clock_get_hz(clk_sys));
        printf("# predicted %.0f bit/s (%.0f byte/s), ETA %.1f s for %u bytes\n",
               est, est / 8.0, est > 0 ? (double)want * 8.0 / est : 0.0, (unsigned)want);
        if (est > 0 && (double)want * 8.0 / est > 600.0)
            printf("# that is %.1f minutes. SAMPLE_CNT1 is the lever: see 'hrng sweep'\n",
                   (double)want * 8.0 / est / 60.0);
        printf("# press ESC to abort\n");

        float t0 = read_temp_c();
        led_set(true);
        ez_trng_stats_t st;
        size_t got = ez_trng_capture(g_payload, want, &cfg, &st, progress_cb);
        led_set(false);
        float t1 = read_temp_c();

        g_payload_len = (uint32_t)got;
        write_capture_meta(cfg.bypass_vnc ? "raw" : "conditioned", &cfg, &st,
                           t0, t1, "capture", 0, 0);

        double secs = (double)st.elapsed_us / 1e6;
        printf("captured %u bytes in %.2f s (%.1f bit/s)\n", (unsigned)got, secs,
               secs > 0 ? (double)got * 8.0 / secs : 0.0);
        printf("errors: vn=%u crngt=%u autocorr=%u resets=%u timeouts=%u\n",
               (unsigned)st.vn_err, (unsigned)st.crngt_err, (unsigned)st.autocorr_err, (unsigned)st.resets, (unsigned)st.timeouts);
        printf("#JSON %s\n", g_meta);
        return (got == want) ? 0 : 1;
    }

    if (strcmp(argv[1], "restart") == 0) {
        uint32_t rows = arg_u32(argc, argv, 2, 1000);
        uint32_t row_bytes = arg_u32(argc, argv, 3, 125);
        if ((uint64_t)rows * row_bytes > EZ_CAP_MAX) {
            printf("rows*row_bytes exceeds the %u byte buffer\n", (unsigned)EZ_CAP_MAX);
            return 2;
        }
        ez_trng_cfg_t cfg = g_trng_cfg;
        trng_cfg_from_args(argc > 3 ? argc - 3 : 0, argv + 3, &cfg);

        printf("# restart matrix: %u rows x %u bytes, mode=%s\n",
               (unsigned)rows, (unsigned)row_bytes, cfg.bypass_vnc ? "raw" : "conditioned");
        float t0 = read_temp_c();
        led_set(true);
        ez_trng_stats_t st;
        size_t got = ez_trng_restart_matrix(g_payload, rows, row_bytes, &cfg, &st, progress_cb);
        led_set(false);
        float t1 = read_temp_c();

        g_payload_len = (uint32_t)got;
        write_capture_meta(cfg.bypass_vnc ? "raw" : "conditioned", &cfg, &st,
                           t0, t1, "restart", rows, row_bytes);

        printf("collected %u of %u bytes in %.2f s\n", (unsigned)got,
               (unsigned)(rows * row_bytes), (double)st.elapsed_us / 1e6);
        printf("#JSON %s\n", g_meta);
        return (got == rows * row_bytes) ? 0 : 1;
    }

    if (strcmp(argv[1], "sweep") == 0) {
        static const uint32_t samples[] = { 2, 4, 8, 16, 32, 64, 128, 256,
                                            1024, 4096, 16384, 65535 };
        uint32_t collections = arg_u32(argc, argv, 2, 64);
        bool raw = has_flag(argc, argv, "raw");

        printf("# sweep: rosc_len x sample_cnt, %u collections each, mode=%s\n",
               (unsigned)collections, raw ? "raw" : "conditioned");
        printf("rosc,sample_cnt,collections,bits_per_sec,vn_err,crngt_err,"
               "autocorr_err,timeouts,ones_fraction\n");

        for (uint8_t rl = 0; rl < 4; rl++) {
            for (size_t si = 0; si < count_of(samples); si++) {
                if (abort_requested()) { printf("# aborted\n"); return 1; }

                ez_trng_cfg_t cfg = g_trng_cfg;
                cfg.rosc_len = rl;
                cfg.sample_cnt = samples[si];
                cfg.bypass_vnc = cfg.bypass_crngt = cfg.bypass_autocorr = raw;

                ez_trng_stats_t st;
                size_t want = (size_t)collections * EZ_TRNG_EHR_BYTES;
                if (want > EZ_CAP_MAX) want = EZ_CAP_MAX;
                size_t got = ez_trng_capture(g_payload, want, &cfg, &st, NULL);

                uint32_t ones = 0;
                for (size_t i = 0; i < got; i++) ones += (uint32_t)__builtin_popcount(g_payload[i]);
                double frac = got ? (double)ones / (double)(got * 8) : 0.0;
                double secs = (double)st.elapsed_us / 1e6;

                printf("%u,%u,%u,%.1f,%u,%u,%u,%u,%.6f\n",
                       rl, (unsigned)samples[si], (unsigned)st.collections,
                       secs > 0 ? (double)got * 8.0 / secs : 0.0,
                       (unsigned)st.vn_err, (unsigned)st.crngt_err, (unsigned)st.autocorr_err, (unsigned)st.timeouts, frac);
            }
        }
        printf("# sweep complete\n");
        g_payload_len = 0;
        return 0;
    }

    printf("unknown subcommand\n");
    return 2;
}

/* ------------------------------------------------------- buffer transfer */

static int cmd_send(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (g_payload_len == 0) { printf("buffer is empty; run 'hrng cap' first\n"); return 1; }

    ez_container_write_header(g_buf, g_payload, g_payload_len, g_meta);
    uint32_t total = EZ_HDR_BYTES + g_payload_len;

    printf("xmodem-1k: %u bytes (%u header + %u payload)\n",
           (unsigned)total, (unsigned)EZ_HDR_BYTES, (unsigned)g_payload_len);
    printf("start your receiver now\n");
    stdio_flush();
    sleep_ms(50);

    /* Binary payload must not be mangled by LF -> CRLF expansion. */
    stdio_set_translate_crlf(&stdio_usb, false);
    ez_xm_stats_t st;
    ez_xm_result_t rc = ez_xmodem_send(g_buf, total, &st);
    stdio_set_translate_crlf(&stdio_usb, true);

    sleep_ms(50);
    if (rc != EZ_XM_OK) {
        printf("\ntransfer failed: %s\n", ez_xmodem_strerror(rc));
        return 1;
    }
    double secs = (double)st.elapsed_us / 1e6;
    printf("\nsent %u blocks in %.2f s (%.0f byte/s), %u retransmits, %s mode\n",
           (unsigned)st.blocks_sent, secs, secs > 0 ? total / secs : 0.0,
           (unsigned)st.retransmits, st.crc_mode ? "crc" : "checksum");
    return 0;
}

static int cmd_dump(int argc, char **argv)
{
    uint32_t n = arg_u32(argc, argv, 1, 256);
    if (n > g_payload_len) n = g_payload_len;
    if (n == 0) { printf("buffer is empty\n"); return 1; }
    hexdump(g_payload, n, 0);
    return 0;
}

static int cmd_guard(int argc, char **argv)
{
    ez_guard_status_t st;
    ez_guard_evaluate(&st);

    if (has_flag(argc, argv, "claim") && has_flag(argc, argv, "--force")) {
        /*
         * A board that this tool previously wrote test patterns to scans as
         * EZ_GUARD_OCCUPIED and locks itself out, which is a usability defect
         * the guard introduced. The override stays deliberate: it needs two
         * flags and states exactly what it is asserting.
         */
        if (!has_flag(argc, argv, "--no-key-material")) {
            printf("'guard claim --force' overrides the storage safety check.\n\n"
                   "Only do this if you can affirm that this board has never held\n"
                   "key material or session metadata. Overwriting an OTP offset\n"
                   "causes silent key reuse (EZ-SEC-001 SEC-PTR-002).\n\n"
                   "Re-run as: guard claim --force --no-key-material\n");
            return 2;
        }
        printf("override accepted; marking as a test board\n");
        ez_fram_write(0, (const uint8_t *)EZ_TEST_MARKER, EZ_TEST_MARKER_LEN);
        ez_guard_evaluate(&st);
        printf("device state  : %s\n", ez_guard_state_name(st.state));
        printf("storage tests : %s\n", st.storage_allowed ? "permitted" : "still refused");
        return st.storage_allowed ? 0 : 1;
    }

    if (has_flag(argc, argv, "claim")) {
        if (ez_guard_claim())
            printf("claimed: marker written, storage tests are now permitted\n");
        else
            printf("cannot claim: device is %s, not blank\n",
                   ez_guard_state_name(st.state));
        ez_guard_evaluate(&st);
    }

    if (has_flag(argc, argv, "--json")) {
        printf("#JSON {\"state\":\"%s\",\"storage_allowed\":%s,"
               "\"bytes_scanned\":%u,\"raw_dump_build\":%s}\n",
               ez_guard_state_name(st.state),
               st.storage_allowed ? "true" : "false",
               (unsigned)st.bytes_scanned,
               EZ_ENABLE_RAW_STORAGE_DUMP ? "true" : "false");
        return st.state == EZ_GUARD_NO_DEVICE ? 1 : 0;
    }

    printf("device state  : %s\n", ez_guard_state_name(st.state));
    printf("storage tests : %s\n", st.storage_allowed ? "permitted" : "REFUSED");
    printf("raw dump build: %s\n", EZ_ENABLE_RAW_STORAGE_DUMP ? "ENABLED" : "disabled");
    printf("fram scanned  : %u bytes\n", (unsigned)st.bytes_scanned);
    if (!st.storage_allowed && st.state == EZ_GUARD_OCCUPIED)
        printf("\nFRAM holds unrecognised data from 0x%06x. If this device has\n"
               "ever held key material, do not run storage tests on it.\n",
               (unsigned)st.first_unexpected_addr);
    if (st.state == EZ_GUARD_BLANK)
        printf("\nrun 'guard claim' to mark this as a test board\n");
    if (st.state == EZ_GUARD_OCCUPIED)
        printf("\nIf this tool wrote those bytes itself in an earlier session, and\n"
               "the board has never held key material, override with:\n"
               "  guard claim --force --no-key-material\n");
    return 0;
}

static int cmd_buf(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "zero") == 0) {
        /*
         * SEC-FW-003, and the same discipline SEC-GEN-001 demands of the
         * production generation path: do not leave sampled entropy sitting in
         * volatile memory once it is no longer needed.
         */
        bool ok = ez_secure_zero_verify(g_buf, sizeof(g_buf));
        g_payload_len = 0;
        g_meta[0] = 0;
        printf("buffer zeroised and verified: %s\n", ok ? "ok" : "FAILED");
        return ok ? 0 : 1;
    }
    printf("held      : %u bytes\n", (unsigned)g_payload_len);
    printf("capacity  : %u bytes\n", (unsigned)EZ_CAP_MAX);
    printf("crc32     : 0x%08x\n", (unsigned)ez_crc32(g_payload, g_payload_len));
    printf("metadata  : %s\n", g_meta[0] ? g_meta : "(none)");
    return 0;
}

/* --------------------------------------------------------------- selftest */

static int cmd_selftest(int argc, char **argv)
{
    bool json = has_flag(argc, argv, "--json");
    int failures = 0;

    ez_pin_result_t pins[16];
    bool pins_pass = false;
    ez_pins_check(pins, 16, &pins_pass);
    if (!pins_pass) failures++;

    ez_clock_info_t clk;
    ez_clocks_read(&clk);
    if (!clk.xosc_stable) failures++;

    ez_fram_id_t fid;
    ez_fram_probe_t fprobe;
    bool fram_id_ok = ez_fram_probe(&fprobe);   /* WEL toggle, not RDID */
    ez_fram_read_id(&fid);

    /* SEC-FW-004: the memory test writes to FRAM, so it only runs on a board
     * the guard has cleared. Identification is read-only and always runs. */
    ez_guard_status_t guard;
    ez_guard_evaluate(&guard);
    ez_fram_result_t fres;
    bool fram_tested = guard.storage_allowed;
    bool fram_ok = false;
    if (fram_tested) {
        buffer_take_scratch();
        fram_ok = ez_fram_test_region(0, 2048, &fres, g_payload, EZ_CAP_MAX);
        if (!fram_ok) failures++;
    }
    if (!fram_id_ok) failures++;

    ez_sd_initlog_t sdlog;
    bool sd_present = ez_sd_card_detected();
    bool sd_ok = sd_present && ez_sd_init(&g_sd_card, &sdlog);
    g_sd_ready = sd_ok;
    if (sd_present && !sd_ok) failures++;

    ez_trng_cfg_t cfg = g_trng_cfg;
    ez_trng_stats_t tst;
    ez_trng_health(&cfg, 64, &tst);
    bool trng_ok = (tst.collections == 64);
    if (!trng_ok) failures++;

    double secs = (double)tst.elapsed_us / 1e6;
    double bps = secs > 0 ? (double)tst.bytes * 8.0 / secs : 0.0;

    if (json) {
        printf("#JSON {\"failures\":%d,\"pins_pass\":%s,\"xosc_stable\":%s,"
               "\"clk_sys_hz\":%u,\"fram_id_ok\":%s,\"fram_test_ok\":%s,"
               "\"fram_vendor\":\"%s\",\"fram_part\":\"%s\","
               "\"guard_state\":\"%s\",\"fram_tested\":%s,\"sd_present\":%s,"
               "\"sd_init_ok\":%s,\"sd_capacity\":%llu,\"trng_ok\":%s,"
               "\"trng_bits_per_sec\":%.2f,\"temp_c\":%.2f}\n",
               failures, pins_pass ? "true" : "false",
               clk.xosc_stable ? "true" : "false", (unsigned)clk.clk_sys_hz,
               fram_id_ok ? "true" : "false", fram_ok ? "true" : "false",
               fid.vendor, fid.part,
               ez_guard_state_name(guard.state), fram_tested ? "true" : "false",
               sd_present ? "true" : "false",
               sd_ok ? "true" : "false",
               (unsigned long long)(sd_ok ? g_sd_card.capacity_bytes : 0),
               trng_ok ? "true" : "false", bps, (double)read_temp_c());
        return failures ? 1 : 0;
    }

    printf("pins          : %s\n", pins_pass ? "PASS" : "FAIL");
    printf("xosc          : %s (clk_sys %u Hz)\n",
           clk.xosc_stable ? "PASS" : "FAIL", (unsigned)clk.clk_sys_hz);
    printf("fram present  : %s (%s %s%s)\n", fram_id_ok ? "PASS" : "FAIL",
           fid.vendor, fid.part,
           fprobe.rdid_supported ? "" : ", no RDID support");
    printf("fram memory   : %s\n", !fram_tested ? "skipped (guard: device is occupied)"
                                                : (fram_ok ? "PASS" : "FAIL"));
    printf("sd card       : %s\n", !sd_present ? "not inserted"
                                 : (sd_ok ? "PASS" : "FAIL"));
    if (sd_ok) printf("                %s, %llu bytes\n",
                      ez_sd_type_name(g_sd_card.type),
                      (unsigned long long)g_sd_card.capacity_bytes);
    printf("trng          : %s (%.0f bit/s)\n", trng_ok ? "PASS" : "FAIL", bps);
    printf("\n%d subsystem(s) failed\n", failures);
    return failures ? 1 : 0;
}

/* ------------------------------------------------------------- dispatcher */

static int cmd_help(int argc, char **argv);

struct command {
    const char *name;
    int (*fn)(int argc, char **argv);
    const char *help;
};

static int cmd_reboot(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "bootsel") == 0) {
        printf("entering BOOTSEL; the port will disappear and the board will\n"
               "enumerate as RPI-RP2 mass storage. Copy a .uf2 to it.\n");
        printf("[done rc=0]\n");   /* the host is waiting for this marker */
        stdio_flush();
        sleep_ms(200);             /* let the CDC buffer drain first */

        /*
         * The first argument is a GPIO mask the bootrom flashes as an activity
         * indicator, so the status LED keeps blinking in the bootloader and
         * you can tell the board is alive rather than hung.
         */
        reset_usb_boot(1u << LED_PIN, 0);
        /* does not return */
    }

    printf("resetting\n");
    printf("[done rc=0]\n");
    stdio_flush();
    sleep_ms(200);
    watchdog_reboot(0, 0, 0);
    while (1) tight_loop_contents();
}

static const struct command commands[] = {
    { "help",  cmd_help,  "this list" },
    { "info",  cmd_info,  "chip, firmware and buffer status  [--json]" },
    { "pins",  cmd_pins,  "verify external pull-ups and pin integrity  [--json]" },
    { "led",   cmd_led,   "led on|off|blink" },
    { "clock", cmd_clock, "clock [--json] | clock aon [ms] -- clocks and AON timer" },
    { "fram",  cmd_fram,  "fram id|size|test [--full]|bench|dump <a> <n>|write <a> <hex>" },
    { "sd",    cmd_sd,    "sd det [low|high|ignore|--watch]|init|info|read|bench|write" },
    { "hrng",  cmd_hrng,  "hrng info|cfg|health [n]|cap <bytes> [raw]|sweep|restart <r> <n>" },
    { "guard", cmd_guard, "storage policy; 'guard claim [--force]' marks a test board" },
    { "buf",   cmd_buf,   "capture buffer status; 'buf zero' wipes it" },
    { "dump",  cmd_dump,  "hex dump of the capture buffer" },
    { "send",  cmd_send,  "transmit the capture buffer over XMODEM-1K" },
    { "selftest", cmd_selftest, "run every subsystem check  [--json]" },
    { "reboot", cmd_reboot, "reboot [bootsel] -- bootsel enters firmware update mode" },
};

static int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("Einszeit V1 hardware validation shell (%s)\n\n", FW_VERSION);
    for (size_t i = 0; i < count_of(commands); i++)
        printf("  %-9s %s\n", commands[i].name, commands[i].help);
    printf("\nentropy capture examples:\n");
    printf("  hrng cap 131072 cond           conditioned output, as production would use\n");
    printf("  hrng cap 131072 raw            health tests and VN balancer bypassed\n");
    printf("  hrng cap 65536 raw sample 16   raw, 16 clocks between ring-osc samples\n");
    printf("  hrng restart 1000 125          SP 800-90B restart matrix\n");
    printf("  send                           then receive with the host script\n");
    return 0;
}

#define MAX_ARGS 12

static void run_line(char *line)
{
    char *argv[MAX_ARGS];
    int argc = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, " \t", &save);
         tok && argc < MAX_ARGS;
         tok = strtok_r(NULL, " \t", &save)) {
        argv[argc++] = tok;
    }
    if (argc == 0) return;

    for (size_t i = 0; i < count_of(commands); i++) {
        if (strcmp(argv[0], commands[i].name) == 0) {
            int rc = commands[i].fn(argc, argv);
            printf("[done rc=%d]\n", rc);
            return;
        }
    }
    printf("unknown command '%s', try 'help'\n", argv[0]);
    printf("[done rc=127]\n");
}

/* ------------------------------------------------------------------ main */

int main(void)
{
    set_sys_clock_khz(150000, true);
    stdio_init_all();

    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    adc_init();
    adc_set_temp_sensor_enabled(true);

    ez_trng_cfg_default(&g_trng_cfg);
    ez_trng_init(&g_trng_cfg);
    ez_fram_init(FRAM_BAUD_DEFAULT);
    ez_fram_geom_defaults(&g_fram_geom);
    g_meta[0] = 0;

    /* Three quick flashes: firmware is alive even with no terminal attached. */
    for (int i = 0; i < 3; i++) { led_set(true); sleep_ms(60); led_set(false); sleep_ms(60); }

    while (!stdio_usb_connected()) {
        led_set(true);  sleep_ms(40);
        led_set(false); sleep_ms(960);
    }
    sleep_ms(200);

    ez_guard_status_t boot_guard;
    ez_guard_evaluate(&boot_guard);

    printf("\n%s %s -- 'help' for commands\n", FW_NAME, FW_VERSION);
    printf("BENCH TOOL, NOT PRODUCTION FIRMWARE. Bypasses TRNG health tests;\n"
           "never flash this to a device holding key material (EZ-SEC-001).\n");
    printf("device state: %s, storage tests %s\n",
           ez_guard_state_name(boot_guard.state),
           boot_guard.storage_allowed ? "permitted" : "REFUSED");
    printf("[done rc=0]\n");

    char line[256];
    size_t len = 0;
    printf("ez> ");
    stdio_flush();

    for (;;) {
        int c = getchar_timeout_us(100000);
        if (c == PICO_ERROR_TIMEOUT) { stdio_flush(); continue; }

        if (c == '\r' || c == '\n') {
            printf("\n");
            line[len] = 0;
            run_line(line);
            len = 0;
            printf("ez> ");
            stdio_flush();
        } else if (c == 8 || c == 127) {
            if (len > 0) { len--; printf("\b \b"); stdio_flush(); }
        } else if (c >= 32 && c < 127 && len < sizeof(line) - 1) {
            line[len++] = (char)c;
            putchar(c);
            stdio_flush();
        }
    }
}
