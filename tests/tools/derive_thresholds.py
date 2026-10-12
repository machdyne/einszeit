#!/usr/bin/env python3
"""
derive_thresholds.py -- reproduce the statistical constants used by
core/src/ez_entropy.c (EZ-IMPL-001 §7.2, §7.3; docs/einszeit-entropy-thresholds.md).

Requires numpy and scipy. Prints:
  * per-block false-failure rates of the FIPS 140-2 §4.9.1 tests for an
    ideal source (monobit and poker exactly; runs and long run by Monte
    Carlo with a 99.9% upper confidence bound),
  * the Poisson table lam_max[k] (x 1e9) used for the block-failure
    rejection rule (P(false rejection) <= 1e-9 per test per key),
  * the byte-frequency chi-square bounds (255 dof, 1e-10 each tail),
  * the online-monitor false-alarm estimate.
"""
import numpy as np
from scipy import stats

N = 20000
lo = [2315, 1114, 527, 240, 103, 103]
hi = [2685, 1386, 723, 384, 209, 209]

p_mono = stats.binom.cdf(9725, N, 0.5) + stats.binom.sf(10274, N, 0.5)
p_poker = stats.chi2.cdf(2.16, 15) + stats.chi2.sf(46.17, 15)
print(f"monobit  p = {p_mono:.4e}  (exact)")
print(f"poker    p = {p_poker:.4e}  (chi-square approximation)")

rng = np.random.default_rng(1)
blocks, fr, fl = 60000, 0, 0
for _ in range(blocks // 2000):
    for row in rng.integers(0, 2, size=(2000, N), dtype=np.int8):
        edges = np.concatenate(([-1], np.flatnonzero(np.diff(row)), [N - 1]))
        lens, vals = np.diff(edges), row[edges[1:]]
        bad = False
        for v in (0, 1):
            c = np.bincount(np.minimum(lens[vals == v], 6), minlength=7)[1:]
            bad |= bool(np.any(c < lo) | np.any(c > hi))
        fr += bad
        fl += lens.max() >= 26
ub = lambda k: stats.beta.ppf(0.999, k + 1, blocks - k)
print(f"runs     p ~ {fr/blocks:.2e}, 99.9% upper bound {ub(fr):.3e}  ({fr}/{blocks})")
print(f"longrun  p ~ {fl/blocks:.2e}, 99.9% upper bound {ub(fl):.3e}  "
      f"(analytic approx {N*2**-26:.2e})")

def lam_max(k):
    a, b = 0.0, 1000.0
    for _ in range(200):
        m = (a + b) / 2
        a, b = (m, b) if stats.poisson.sf(k - 1, m) <= 1e-9 else (a, m)
    return a
print("lam_max_nano[64] =", [int(lam_max(k) * 1e9) for k in range(1, 65)])
print(f"chi2(255): upper {stats.chi2.isf(1e-10, 255):.1f}, lower {stats.chi2.ppf(1e-10, 255):.1f}")

# online monitor, 4096-bit window, +/-200 on counts with sigma 32
z = 200 / 32
p_tail = 2 * stats.norm.sf(z)
p_long = 4096 * 2.0 ** -44
print(f"monitor: monobit {p_tail:.2e}, runs {p_tail:.2e}, longest-run {p_long:.2e}, "
      f"autocorr (16 lags) {16*p_tail:.2e}; total ~{18*p_tail + p_long:.2e} per window")
