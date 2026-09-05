/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   Supports SEC-ENTROPY-002; deviations D-02, D-03, D-04.
 *
 * Bench validation firmware. Not a production artifact.
 */

#include <string.h>

#include "pico/stdlib.h"
#include "hardware/structs/trng.h"
#include "hardware/regs/trng.h"
#include "hardware/clocks.h"

#include "ez_trng.h"

/*
 * Collection sequence, per the Arm TRNG programming model:
 *
 *   1. RND_SOURCE_ENABLE = 0        (source must be off while reconfiguring)
 *   2. write TRNG_CONFIG / SAMPLE_CNT1 / TRNG_DEBUG_CONTROL
 *   3. clear RNG_ICR
 *   4. RND_SOURCE_ENABLE = 1
 *   5. poll TRNG_VALID.EHR_VALID
 *   6. read EHR_DATA0..5  (reading all six words releases the register)
 *   7. RND_SOURCE_ENABLE = 0, then back to step 3 for the next block
 *
 * Skipping step 7 works on this silicon but leaves the source free-running
 * while the CPU is busy, which makes the sample interval depend on host
 * timing. Cycling it keeps every 192-bit block statistically comparable,
 * which matters for the entropy estimate.
 */

static void trng_apply_cfg(const ez_trng_cfg_t *cfg)
{
    trng_hw->rnd_source_enable = 0;

    trng_hw->trng_config = cfg->rosc_len & TRNG_TRNG_CONFIG_RND_SRC_SEL_BITS;
    trng_hw->sample_cnt1 = cfg->sample_cnt;

    uint32_t dbg = 0;
    if (cfg->bypass_vnc)      dbg |= TRNG_TRNG_DEBUG_CONTROL_VNC_BYPASS_BITS;
    if (cfg->bypass_crngt)    dbg |= TRNG_TRNG_DEBUG_CONTROL_TRNG_CRNGT_BYPASS_BITS;
    if (cfg->bypass_autocorr) dbg |= TRNG_TRNG_DEBUG_CONTROL_AUTO_CORRELATE_BYPASS_BITS;
    trng_hw->trng_debug_control = dbg;

    /* Mask every interrupt; we poll. */
    trng_hw->rng_imr = 0xffffffffu;
    trng_hw->rng_icr = 0xffffffffu;
}

void ez_trng_cfg_default(ez_trng_cfg_t *cfg)
{
    cfg->rosc_len        = 0;
    cfg->sample_cnt      = 0xffffu;   /* SAMPLE_CNT1 reset value */
    cfg->bypass_vnc      = false;
    cfg->bypass_crngt    = false;
    cfg->bypass_autocorr = false;
    cfg->cycle_source    = false;   /* continuous: see trng_collect_one() */
}

double ez_trng_estimate_bps(const ez_trng_cfg_t *cfg, uint32_t clk_sys_hz)
{
    double raw = (double)clk_sys_hz / ((double)cfg->sample_cnt + 1.0);
    return cfg->bypass_vnc ? raw : raw / 4.0;
}

static void trng_sw_reset(const ez_trng_cfg_t *cfg)
{
    trng_hw->rnd_source_enable = 0;
    trng_hw->trng_sw_reset = 1;
    /* The reset is synchronous to rng_clk; a short spin is ample. */
    busy_wait_us(50);
    trng_apply_cfg(cfg);
}

void ez_trng_init(const ez_trng_cfg_t *cfg)
{
    trng_sw_reset(cfg);
    trng_hw->autocorr_statistic = 0;   /* any write clears the counters */
    trng_hw->rst_bits_counter = 1;
}

void ez_trng_clear_autocorr_statistic(void)
{
    trng_hw->autocorr_statistic = 0;
}

void ez_trng_read_regs(ez_trng_regs_t *r)
{
    r->rng_imr            = trng_hw->rng_imr;
    r->rng_isr            = trng_hw->rng_isr;
    r->trng_config        = trng_hw->trng_config;
    r->trng_valid         = trng_hw->trng_valid;
    r->rnd_source_enable  = trng_hw->rnd_source_enable;
    r->sample_cnt1        = trng_hw->sample_cnt1;
    r->autocorr_statistic = trng_hw->autocorr_statistic;
    r->trng_debug_control = trng_hw->trng_debug_control;
    r->trng_busy          = trng_hw->trng_busy;
    r->rng_version        = trng_hw->rng_version;
    for (int i = 0; i < 3; i++) r->rng_bist[i] = trng_hw->rng_bist_cntr[i];

    r->autocorr_trys  = (r->autocorr_statistic & TRNG_AUTOCORR_STATISTIC_AUTOCORR_TRYS_BITS)
                        >> TRNG_AUTOCORR_STATISTIC_AUTOCORR_TRYS_LSB;
    r->autocorr_fails = (r->autocorr_statistic & TRNG_AUTOCORR_STATISTIC_AUTOCORR_FAILS_BITS)
                        >> TRNG_AUTOCORR_STATISTIC_AUTOCORR_FAILS_LSB;
}

/*
 * Worst-case wait for one 192-bit collection. With the Von Neumann balancer
 * active the block consumes at least 2 raw bits per output bit and can consume
 * many more when the source is biased, so allow a wide margin before declaring
 * a timeout.
 */
static uint32_t collection_timeout_us(const ez_trng_cfg_t *cfg)
{
    uint64_t clk = clock_get_hz(clk_sys);
    if (clk == 0) clk = 150000000u;
    uint64_t cycles = (uint64_t)(cfg->sample_cnt + 1u) * 192u * 16u;
    uint64_t us = (cycles * 1000000u) / clk;
    if (us < 50000u)    us = 50000u;      /* never less than 50 ms  */
    if (us > 20000000u) us = 20000000u;   /* never more than 20 s   */
    return (uint32_t)us;
}

/* Returns true on success; on failure the caller decides whether to reset. */
static bool trng_collect_one(uint32_t out[6], uint32_t timeout_us,
                             ez_trng_stats_t *st, bool *fatal, bool cycle)
{
    *fatal = false;

    /*
     * Continuous mode is the default. After the last EHR word is read the
     * block immediately begins collecting the next 192 bits, so stopping and
     * restarting the source between collections buys nothing and costs real
     * throughput: Raspberry Pi's own pico_rand notes that writing these
     * registers "seems to restart the sampling, slowing things down".
     *
     * Measured cost at SAMPLE_CNT1 = 65535 is about 9%. At short sampling
     * intervals the restart latency dominates entirely, which is exactly the
     * regime you care about when sizing a key generation run.
     *
     * Cycled mode is kept because it makes every 192-bit block start from the
     * same source state, which is the more conservative choice when comparing
     * blocks across a sweep. Select it with `hrng cfg cycled`.
     */
    if (cycle) {
        trng_hw->rng_icr = 0xffffffffu;
        trng_hw->rnd_source_enable = TRNG_RND_SOURCE_ENABLE_RND_SRC_EN_BITS;
    } else if (!(trng_hw->rnd_source_enable & TRNG_RND_SOURCE_ENABLE_RND_SRC_EN_BITS)) {
        trng_hw->rng_icr = 0xffffffffu;
        trng_hw->rnd_source_enable = TRNG_RND_SOURCE_ENABLE_RND_SRC_EN_BITS;
    }

    absolute_time_t deadline = make_timeout_time_us(timeout_us);
    uint32_t isr = 0;
    bool valid = false;

    for (;;) {
        isr = trng_hw->rng_isr;
        if (isr & TRNG_RNG_ISR_EHR_VALID_BITS) { valid = true; break; }
        if (isr & TRNG_RNG_ISR_AUTOCORR_ERR_BITS) break;   /* block has halted */
        if (absolute_time_diff_us(get_absolute_time(), deadline) < 0) break;
        tight_loop_contents();
    }

    /* Latch health-test flags before they are cleared. */
    if (isr & TRNG_RNG_ISR_VN_ERR_BITS)    st->vn_err++;
    if (isr & TRNG_RNG_ISR_CRNGT_ERR_BITS) st->crngt_err++;
    if (isr & TRNG_RNG_ISR_AUTOCORR_ERR_BITS) {
        /* "RNG cease from functioning until next reset" -- must SW reset. */
        st->autocorr_err++;
        *fatal = true;
    }

    if (valid) {
        /* Reading all six words releases the EHR and restarts collection. */
        for (int i = 0; i < 6; i++) out[i] = trng_hw->ehr_data[i];
        if (!cycle) trng_hw->rng_icr = TRNG_RNG_ISR_EHR_VALID_BITS;
    } else if (!*fatal) {
        st->timeouts++;
    }

    if (cycle || !valid) trng_hw->rnd_source_enable = 0;
    return valid;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

size_t ez_trng_capture(uint8_t *buf, size_t len, const ez_trng_cfg_t *cfg,
                       ez_trng_stats_t *st, bool (*progress_cb)(size_t, size_t))
{
    memset(st, 0, sizeof(*st));
    len -= len % EZ_TRNG_EHR_BYTES;             /* whole collections only */

    ez_trng_init(cfg);
    uint32_t timeout_us = collection_timeout_us(cfg);

    uint64_t t0 = time_us_64();
    size_t done = 0;
    uint32_t consecutive_failures = 0;

    while (done < len) {
        uint32_t ehr[6];
        bool fatal = false;

        if (trng_collect_one(ehr, timeout_us, st, &fatal, cfg->cycle_source)) {
            for (int i = 0; i < 6; i++) put_le32(&buf[done + 4 * i], ehr[i]);
            done += EZ_TRNG_EHR_BYTES;
            st->collections++;
            consecutive_failures = 0;
        } else {
            if (++consecutive_failures > 16) break;   /* hardware is not responding */
        }

        if (fatal) { trng_sw_reset(cfg); st->resets++; }

        if (progress_cb && (st->collections % 64 == 0)) {
            if (!progress_cb(done, len)) break;
        }
    }

    st->elapsed_us = time_us_64() - t0;
    st->bytes = done;
    trng_hw->rnd_source_enable = 0;
    return done;
}

size_t ez_trng_restart_matrix(uint8_t *buf, uint32_t rows, uint32_t row_bytes,
                              const ez_trng_cfg_t *cfg, ez_trng_stats_t *st,
                              bool (*progress_cb)(size_t, size_t))
{
    memset(st, 0, sizeof(*st));
    uint32_t timeout_us = collection_timeout_us(cfg);
    size_t total = (size_t)rows * row_bytes;
    uint64_t t0 = time_us_64();
    size_t done = 0;

    for (uint32_t r = 0; r < rows; r++) {
        /*
         * A true SP 800-90B restart cycles power to the noise source. We can
         * only assert the block's own reset, which restarts the ring
         * oscillator sampling and clears all internal state but does not
         * power-gate the analogue source. The report flags this.
         */
        trng_sw_reset(cfg);
        st->resets++;

        uint32_t got = 0;
        uint32_t fails = 0;
        while (got < row_bytes) {
            uint32_t ehr[6];
            bool fatal = false;
            if (trng_collect_one(ehr, timeout_us, st, &fatal, cfg->cycle_source)) {
                uint8_t tmp[EZ_TRNG_EHR_BYTES];
                for (int i = 0; i < 6; i++) put_le32(&tmp[4 * i], ehr[i]);
                uint32_t n = row_bytes - got;
                if (n > EZ_TRNG_EHR_BYTES) n = EZ_TRNG_EHR_BYTES;
                memcpy(&buf[done + got], tmp, n);
                got += n;
                st->collections++;
                fails = 0;
            } else if (++fails > 16) {
                break;
            }
            if (fatal) { trng_sw_reset(cfg); st->resets++; }
        }
        done += got;
        if (got < row_bytes) break;

        if (progress_cb && (r % 16 == 0)) {
            if (!progress_cb(done, total)) break;
        }
    }

    st->elapsed_us = time_us_64() - t0;
    st->bytes = done;
    trng_hw->rnd_source_enable = 0;
    return done;
}

void ez_trng_health(const ez_trng_cfg_t *cfg, uint32_t collections, ez_trng_stats_t *st)
{
    memset(st, 0, sizeof(*st));
    ez_trng_init(cfg);
    uint32_t timeout_us = collection_timeout_us(cfg);

    uint64_t t0 = time_us_64();
    for (uint32_t i = 0; i < collections; i++) {
        uint32_t ehr[6];
        bool fatal = false;
        if (trng_collect_one(ehr, timeout_us, st, &fatal, cfg->cycle_source)) {
            st->collections++;
            st->bytes += EZ_TRNG_EHR_BYTES;
        }
        if (fatal) { trng_sw_reset(cfg); st->resets++; }
    }
    st->elapsed_us = time_us_64() - t0;
    trng_hw->rnd_source_enable = 0;
}
