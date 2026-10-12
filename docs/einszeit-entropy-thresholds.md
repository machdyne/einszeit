# Einszeit Entropy Test Thresholds

**Document ID:** EZ-ENT-THR-001  
**Implements:** EZ-IMPL-001 §7.2 (online monitoring) and §7.3 (per-key acceptance)  
**Code:** `core/src/ez_entropy.c`  
**Reproduce:** `tests/tools/derive_thresholds.py` (numpy, scipy)  
**Check against real data:** `build/tests/ez_entropy_check <capture.bin>`

These tests are statistical. They can detect a source that has failed or degraded; they cannot prove that output carries 8 bits of entropy per byte. That claim rests on the characterisation of the source (SP 800-90B, AIS-31), which is tracked separately as DEV-01. Every threshold below is set so that an ideal source is falsely rejected with a probability small enough not to matter in use, and the derivation is reproducible.

## 1. Online monitor (§7.2, EZ-SEC-001 §2.3)

The monitor runs during generation, over consecutive non-overlapping windows of 4,096 bits. A failure halts generation immediately (SEC-ENTROPY-004). A false alarm costs a retry; it never causes bad data to be accepted.

| Test | Statistic in each window | Fails when | False alarm per window |
|---|---|---|---|
| Monobit | number of ones (mean 2048, σ 32) | deviation > 200 (6.25 σ) | 4.1 × 10⁻¹⁰ |
| Runs | number of runs (mean 2048.5, σ ≈ 32) | deviation > 200 | 4.1 × 10⁻¹⁰ |
| Longest run | longest run of identical bits | ≥ 44 | 2.3 × 10⁻¹⁰ |
| Autocorrelation | agreements at lags 1–16 (mean pairs/2, σ ≈ 32) | any lag deviates > 200 | 6.6 × 10⁻⁹ |

The total is about 7.5 × 10⁻⁹ per window, or 1.5 × 10⁻⁵ per MiB generated.

Detection is verified by SEC-TEST-ENT-002 (`test_entropy/monitor_halts_within_one_window`, `test_keygen/monitor_halts`). The following each halt within the first window: P(1) = 0.60 or 0.40; a stuck output; a period-8 pattern; alternating bits; a bit-repeat probability of 0.75; a byte counter. A subtle bias (P(1) = 0.52) passes the monitor by design and is caught by acceptance (`test_keygen/acceptance_rejects`).

## 2. Per-key acceptance (§7.3, SEC-ENTROPY-002)

Acceptance runs over the complete key as read back from storage, before the key is marked valid by renaming it.

### 2.1 FIPS 140-2 §4.9.1 tests on every complete 20,000-bit block

An ideal source fails each FIPS test in roughly one block in 10,000. Rejecting a key on any single failed block would therefore reject 4% of 1 MiB keys on monobit alone (419 blocks). The ent001 characterisation itself shows one monobit failure in 5,040 blocks. Instead, failures are counted per test, and the key is rejected when the count reaches a Poisson bound.

| Test | Per-block false-failure rate for an ideal source | Rate used (ppm) |
|---|---|---|
| Monobit (9725 < X < 10275) | 1.035 × 10⁻⁴ (exact binomial) | 110 |
| Poker (2.16 < X < 46.17) | 9.92 × 10⁻⁵ (χ² approximation) | 105 |
| Runs (FIPS intervals) | ≈ 2.0 × 10⁻⁴ (Monte Carlo, 12 / 60,000; 99.9% upper bound 4.5 × 10⁻⁴) | 450 |
| Long run (≥ 26) | ≈ 3.0 × 10⁻⁴ (analytic 2.98 × 10⁻⁴; Monte Carlo 99.9% upper bound 5.2 × 10⁻⁴) | 520 |

**Rejection rule.** With `B` complete blocks and rate `p`, let λ = B·p. The key is rejected for a test when its failing-block count reaches the smallest `k` with P(Poisson(λ) ≥ k) ≤ 10⁻⁹. The table `lam_max_nano[]` holds, for k = 1…64, the largest λ (× 10⁹) satisfying that inequality. Using upper-bound rates makes false rejection rarer still, at a negligible cost in sensitivity.

Examples:
- An 8 KiB key (3 blocks): three failing blocks in one test reject it.
- A 1 MiB key (419 blocks): about five.
- The 64 MiB maximum (26,843 blocks) needs k ≈ 36 for the long-run test, well inside the 64-entry table. Keys larger than 64 MiB are refused at the start of generation, so the table cannot run out.

Real defects fail far more blocks than these bounds allow. In the planted-defect tests (`test_entropy/accept_each_test`), six of eight blocks fail.

### 2.2 Whole-key tests

| Test | Fails when | False rejection |
|---|---|---|
| Monobit over all n bits | \|2·ones − n\| > 7·√n | 2.6 × 10⁻¹² |
| Byte-frequency χ² (255 dof), keys ≥ 1,280 bytes | χ² ≥ 426 or χ² ≤ 136 | 10⁻¹⁰ per tail |

The lower χ² bound rejects output that is too uniform to be random, such as a counter (`test_entropy/accept_rejects_sources`). χ² is computed exactly in integers as Σ(256·cᵢ − N)² / (256·N).

**Overall:** about 4 × 10⁻⁹ false rejections per key.

## 3. To do with real data

These figures assume an ideal source. EZ-IMPL-001 §7.2 also requires checking the thresholds against the V1 characterisation data. Running `ez_entropy_check` on the ent001 conditioned capture should show no failing monitor windows and no rejected slices. Any failure means the source falls short of the ideal and must be recorded against DEV-01.

### 3.1 TR-01 — Entropy thresholds against ent001 data (EZ-IMPL-001 §7.2; DEV-01)

No hardware is needed: it uses the archived ent001 captures. It checks that the online monitor and acceptance thresholds, which are derived for an ideal source, do not reject real conditioned output.

1. `tests/run.sh` (also builds the tool).
2. `build/tests/ez_entropy_check <ent001 dir>/conditioned.bin`
3. Optionally `build/tests/ez_entropy_check <ent001 dir>/raw.bin`. Raw output is expected to fail; this shows the tests have teeth on real biased data.
4. Record the final three lines of each run, and any `FAILED` or `REJECTED` lines.

Expected for `conditioned.bin`: 0 failed windows and 0 rejected slices. Any failure is a finding against DEV-01, not a bug to be tuned away.
