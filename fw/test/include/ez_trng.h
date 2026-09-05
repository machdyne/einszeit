/*
 * ez_trng.h -- direct access to the RP2350 TRNG (Arm CryptoCell-style block)
 *
 * The SDK's get_rand_*() functions run the TRNG output through a software
 * mixer, which is exactly what you do NOT want when characterising a noise
 * source. Everything here talks to the peripheral registers so that the bytes
 * that reach the host are the bytes the hardware produced.
 */

/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Supports SEC-ENTROPY-002  measures entropy per byte
 *   Deviates SEC-ENTROPY-003  raw mode bypasses hardware debiasing (D-02)
 *   Deviates SEC-ENTROPY-004  continues past health faults, counting them (D-03)
 *   Deviates SEC-GEN-001      bulk buffering of TRNG output (D-04)
 *
 * Bench validation firmware. Not a production artifact.
 */
#ifndef EZ_TRNG_H
#define EZ_TRNG_H

#include <stdbool.h>
#include <stdint.h>

/* Bytes produced per Entropy Holding Register collection (192 bits). */
#define EZ_TRNG_EHR_BYTES 24

typedef struct {
    uint8_t  rosc_len;      /* TRNG_CONFIG.RND_SRC_SEL, 0..3 (inverter chain) */
    uint32_t sample_cnt;    /* SAMPLE_CNT1: rng_clk cycles between samples    */
    bool     bypass_vnc;    /* bypass Von Neumann balancer + 32-identical test */
    bool     bypass_crngt;  /* bypass continuous RNG test                     */
    bool     bypass_autocorr; /* bypass autocorrelation test                  */
    bool     cycle_source;  /* stop and restart the source between EHR reads  */
} ez_trng_cfg_t;

/*
 * Throughput model, for sizing a capture before you start it.
 *
 *   raw sample rate  = clk_sys / (SAMPLE_CNT1 + 1)
 *   conditioned rate = raw / 4     (Von Neumann emits ~1 bit per 4 raw bits
 *                                   on an unbiased source; worse when biased)
 *
 * At the SAMPLE_CNT1 reset value of 65535 and clk_sys = 150 MHz that is
 * 2.3 kbit/s raw and roughly 572 bit/s conditioned. The reset value is a
 * power-on default, not a recommendation.
 */
double ez_trng_estimate_bps(const ez_trng_cfg_t *cfg, uint32_t clk_sys_hz);

typedef struct {
    uint32_t collections;   /* successful 192-bit EHR reads                   */
    uint32_t vn_err;        /* 32 consecutive identical bits seen             */
    uint32_t crngt_err;     /* two consecutive equal 16-bit blocks            */
    uint32_t autocorr_err;  /* autocorrelation failed 4x in a row (fatal)     */
    uint32_t resets;        /* SW resets issued to recover from the above     */
    uint32_t timeouts;      /* EHR never went valid                           */
    uint64_t elapsed_us;
    uint64_t bytes;
} ez_trng_stats_t;

/* Snapshot of every readable TRNG register, for the `hrng info` command. */
typedef struct {
    uint32_t rng_imr, rng_isr, trng_config, trng_valid;
    uint32_t rnd_source_enable, sample_cnt1, autocorr_statistic;
    uint32_t trng_debug_control, trng_busy, rng_version;
    uint32_t rng_bist[3];
    uint32_t autocorr_trys, autocorr_fails;
} ez_trng_regs_t;

/* Reasonable starting point: reset-value sample count, no bypasses. */
void ez_trng_cfg_default(ez_trng_cfg_t *cfg);

/* Full SW reset of the block, then apply cfg. Always call before a capture. */
void ez_trng_init(const ez_trng_cfg_t *cfg);

void ez_trng_read_regs(ez_trng_regs_t *r);
void ez_trng_clear_autocorr_statistic(void);

/*
 * Fill `buf` with `len` bytes straight from the EHR. Returns bytes written,
 * which is < len only if a fatal error could not be recovered from. `len` is
 * rounded down internally to a multiple of EZ_TRNG_EHR_BYTES; partial EHR
 * words are never emitted because a truncated collection would bias the tail
 * of the sample.
 *
 * progress_cb (may be NULL) is called every collection so the CLI can print a
 * progress bar and poll for an abort key; returning false aborts the capture.
 */
size_t ez_trng_capture(uint8_t *buf, size_t len, const ez_trng_cfg_t *cfg,
                       ez_trng_stats_t *st, bool (*progress_cb)(size_t done, size_t total));

/*
 * SP 800-90B section 3.1.4 restart test: `rows` restarts of the noise source,
 * `row_bytes` bytes collected after each. Data is written row-major into buf,
 * which must be at least rows*row_bytes. Each row begins with a TRNG SW reset.
 */
size_t ez_trng_restart_matrix(uint8_t *buf, uint32_t rows, uint32_t row_bytes,
                              const ez_trng_cfg_t *cfg, ez_trng_stats_t *st,
                              bool (*progress_cb)(size_t done, size_t total));

/* Measured throughput and health-test error rates for the current config. */
void ez_trng_health(const ez_trng_cfg_t *cfg, uint32_t collections, ez_trng_stats_t *st);

#endif /* EZ_TRNG_H */
