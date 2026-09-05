"""NIST SP 800-90B min-entropy estimation.

Scope and honesty about it
--------------------------
This is an independent reimplementation of the SP 800-90B (January 2018)
estimators, written so the numbers in the report are reproducible and so the
raw RP2350 noise source can be assessed on the bench. It is *not* a validated
implementation. For anything that has to stand up to a certification body, run
NIST's own EntropyAssessment tool; `assess()` accepts its output and will
prefer it when present.

What is implemented:

  * The full non-IID track (SP 800-90B 6.3), all ten estimators, on the bit
    sequence. The RP2350 TRNG is a binary source, so the bitstring assessment
    is the one that matters and H = min over the ten estimators.
  * The IID *indicators* from 5.2 (chi-square goodness of fit and independence,
    plus the longest-repeated-substring test). These can rule IID out. They
    cannot establish it -- that needs the 10,000-permutation test, which is
    deliberately not reimplemented here.
  * The restart test of 3.1.4, including the sanity check.

Deviations, all deliberate and noted in the report:

  * Ties in predictor scoreboards resolve to the lowest-indexed subpredictor.
  * LZ78Y does not enforce the 65,536-entry dictionary cap; with the capture
    sizes used here the cap is not reached in practice.
  * The initial-state probabilities in the Markov estimator carry the same
    99% upper bound as the transition probabilities. This can only lower the
    entropy estimate, so it errs safe.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np
from scipy import stats

Z = 2.576  # two-sided 99%, as used throughout SP 800-90B


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _upper_bound(p_hat: float, n: int) -> float:
    if n <= 1:
        return 1.0
    return min(1.0, p_hat + Z * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1)))


def tuple_ids(sym: np.ndarray, w: int, k: int) -> np.ndarray:
    """Sliding window of `w` symbols packed into one integer per position."""
    n = sym.size - w + 1
    if n <= 0:
        return np.empty(0, dtype=np.uint64)
    if k ** w > 2 ** 63:
        raise ValueError(f"tuple width {w} over alphabet {k} does not fit in 64 bits")
    ids = np.zeros(n, dtype=np.uint64)
    kk = np.uint64(k)
    for j in range(w):
        ids = ids * kk + sym[j : j + n].astype(np.uint64)
    return ids


def _group_running(ctx: np.ndarray, values: np.ndarray):
    """Per-position running state within each context group.

    Returns (exclusive_sum, occurrence_index) where exclusive_sum is the sum of
    `values` over all *earlier* positions sharing the same context, and
    occurrence_index counts how many earlier positions shared it. This turns
    the online "most common successor so far" bookkeeping that the MMC and
    LZ78Y predictors need into two sorts and a cumulative sum.
    """
    order = np.argsort(ctx, kind="stable")
    sorted_ctx = ctx[order]
    vals = values[order].astype(np.int64)

    cs = np.cumsum(vals)
    new_group = np.empty(sorted_ctx.size, dtype=bool)
    new_group[0] = True
    np.not_equal(sorted_ctx[1:], sorted_ctx[:-1], out=new_group[1:])

    start_idx = np.flatnonzero(new_group)
    sizes = np.diff(np.append(start_idx, sorted_ctx.size))
    starts_expanded = np.repeat(start_idx, sizes)

    base = np.where(starts_expanded == 0, 0, cs[np.maximum(starts_expanded - 1, 0)])
    inclusive = cs - base
    exclusive = inclusive - vals
    occ = np.arange(sorted_ctx.size) - starts_expanded

    out_sum = np.empty_like(exclusive)
    out_occ = np.empty_like(occ)
    out_sum[order] = exclusive
    out_occ[order] = occ
    return out_sum, out_occ


def _run_prob(r: int, n: int, p: float) -> float:
    """P(no run of r consecutive successes in n Bernoulli(p) trials).

    Feller's closed form, the same approximation NIST's reference code uses.
    """
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    q = 1.0 - p
    try:
        pr = p ** r
    except OverflowError:  # pragma: no cover
        return 1.0
    x = 1.0
    for _ in range(65):
        x_new = 1.0 + q * pr * (x ** (r + 1))
        if not math.isfinite(x_new):
            return 1.0
        x = x_new
    denom = (r + 1 - r * x) * q
    if denom == 0 or x <= 0:
        return 1.0
    try:
        return (1.0 - p * x) / denom * (x ** (-(n + 1)))
    except (OverflowError, ZeroDivisionError):  # pragma: no cover
        return 1.0


def _p_local(r: int, n: int) -> float:
    """Largest p whose longest-run distribution is still consistent with r."""
    lo, hi = 0.0, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if _run_prob(r, n, mid) > 0.99:
            lo = mid
        else:
            hi = mid
    return hi


def _predictor_entropy(correct: np.ndarray, name: str, hmax: float = 1.0) -> "Estimate":
    """Common scoring for the four SP 800-90B predictors (6.3.7 - 6.3.10)."""
    n = int(correct.size)
    if n < 2:
        return Estimate(name, 0.0, {"note": "not enough data"})

    c = int(correct.sum())
    p_global = c / n
    if c == 0:
        p_prime = 1.0 - 0.01 ** (1.0 / n)
    else:
        p_prime = _upper_bound(p_global, n)

    # r = 1 + length of the longest run of correct predictions
    if c == 0:
        r = 1
    else:
        idx = np.flatnonzero(np.diff(np.concatenate(([0], correct.view(np.uint8), [0]))))
        runs = idx[1::2] - idx[0::2]
        r = int(runs.max()) + 1 if runs.size else 1

    p_loc = _p_local(r, n)
    p = max(p_prime, p_loc)
    p = min(max(p, 1e-12), 1.0)
    # A predictor that is reliably *wrong* carries no more entropy than the
    # alphabet allows; without this clamp an anti-correlated source reports
    # an absurd figure.
    h = min(max(-math.log2(p), 0.0), hmax)
    return Estimate(
        name,
        h,
        {
            "predictions": n,
            "correct": c,
            "p_global": p_global,
            "p_global_upper": p_prime,
            "longest_correct_run": r - 1,
            "p_local": p_loc,
        },
    )


def _ensemble(make_correct, nsub: int, n: int, warmup: int) -> np.ndarray:
    """Scoreboard combination of `nsub` subpredictors, without holding them all.

    Each subpredictor's correctness is independent of which one is selected, so
    the winner at every step can be derived from cumulative scores. Two passes
    keep peak memory at a few arrays rather than nsub of them.
    """
    best = np.full(n, -1, dtype=np.int64)
    winner = np.zeros(n, dtype=np.int16)

    for d in range(nsub):
        c = make_correct(d)
        score = np.empty(n, dtype=np.int64)
        score[0] = 0
        np.cumsum(c[:-1], out=score[1:])
        upd = score > best
        best[upd] = score[upd]
        winner[upd] = d

    out = np.zeros(n, dtype=bool)
    for d in range(nsub):
        c = make_correct(d)
        m = winner == d
        out[m] = c[m].astype(bool)
    return out[warmup:]


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------

@dataclass
class Estimate:
    name: str
    h_min: float
    detail: dict = field(default_factory=dict)


@dataclass
class Assessment:
    n_bits: int
    estimates: list = field(default_factory=list)
    h_min: float = 0.0
    limiting: str = ""
    iid_indicators: dict = field(default_factory=dict)
    source: str = "builtin"
    notes: list = field(default_factory=list)
    detail_ceiling: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "n_bits": self.n_bits,
            "h_min_per_bit": self.h_min,
            "limiting_estimator": self.limiting,
            "source": self.source,
            "estimates": [
                {"name": e.name, "h_min": e.h_min, "detail": e.detail}
                for e in self.estimates
            ],
            "iid_indicators": self.iid_indicators,
            "estimator_ceiling": self.detail_ceiling,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------
# 6.3.1 Most Common Value
# --------------------------------------------------------------------------

def est_mcv(sym: np.ndarray, k: int) -> Estimate:
    n = sym.size
    counts = np.bincount(sym, minlength=k)
    p_hat = counts.max() / n
    p_u = _upper_bound(p_hat, n)
    return Estimate("Most Common Value", -math.log2(p_u),
                    {"p_hat": float(p_hat), "p_upper": float(p_u),
                     "most_common_symbol": int(counts.argmax())})


# --------------------------------------------------------------------------
# 6.3.2 Collision (binary only)
# --------------------------------------------------------------------------

def _collision_expectation(p: float) -> float:
    """Mean samples drawn before the first repeat, for a binary source.

    A run ends after two samples if they match and after three otherwise,
    since three binary samples must contain a repeat:
        E[T] = 2(p^2 + q^2) + 3(2pq) = 2 + 2pq
    """
    q = 1.0 - p
    return 2.0 + 2.0 * p * q


def est_collision(sym: np.ndarray) -> Estimate:
    """Mean number of samples drawn before the first repeat."""
    n = sym.size
    times = []
    i = 0
    s = sym
    while i + 1 < n:
        if s[i] == s[i + 1]:
            times.append(2)
            i += 2
        elif i + 2 < n:
            times.append(3)
            i += 3
        else:
            break

    v = len(times)
    if v < 2:
        return Estimate("Collision", 1.0, {"note": "too few collision events"})

    t = np.asarray(times, dtype=np.float64)
    mean = float(t.mean())
    sd = float(t.std(ddof=1))
    lower = mean - Z * sd / math.sqrt(v)

    if lower >= _collision_expectation(0.5):
        return Estimate("Collision", 1.0,
                        {"v": v, "mean": mean, "mean_lower": lower,
                         "p": 0.5, "note": "bounded at maximum entropy"})

    lo, hi = 0.5, 1.0 - 1e-12
    for _ in range(80):
        mid = (lo + hi) / 2.0
        if _collision_expectation(mid) > lower:
            lo = mid
        else:
            hi = mid
    p = lo
    return Estimate("Collision", -math.log2(p),
                    {"v": v, "mean": mean, "mean_lower": lower, "p": p})


# --------------------------------------------------------------------------
# 6.3.3 Markov (binary only)
# --------------------------------------------------------------------------

def est_markov(sym: np.ndarray) -> Estimate:
    n = sym.size
    c0 = int((sym == 0).sum())
    c1 = n - c0

    pairs = sym[:-1].astype(np.int64) * 2 + sym[1:].astype(np.int64)
    tc = np.bincount(pairs, minlength=4)
    c00, c01, c10, c11 = (int(x) for x in tc)

    def bound(num: int, den: int) -> float:
        if den == 0:
            return 1.0
        p = num / den
        return min(1.0, p + Z * math.sqrt(max(p * (1 - p), 0.0) / den))

    p0 = min(1.0, c0 / n + Z * math.sqrt(max((c0 / n) * (1 - c0 / n), 0.0) / max(n - 1, 1)))
    p1 = min(1.0, c1 / n + Z * math.sqrt(max((c1 / n) * (1 - c1 / n), 0.0) / max(n - 1, 1)))

    p00 = bound(c00, c00 + c01)
    p01 = bound(c01, c00 + c01)
    p10 = bound(c10, c10 + c11)
    p11 = bound(c11, c10 + c11)

    # Most probable 128-step path through the two-state chain.
    v0, v1 = p0, p1
    for _ in range(127):
        v0, v1 = max(v0 * p00, v1 * p10), max(v0 * p01, v1 * p11)
    p_max = max(v0, v1)
    if p_max <= 0:
        h = 1.0
    else:
        h = min(1.0, -math.log2(p_max) / 128.0)

    return Estimate("Markov", h,
                    {"P0": p0, "P1": p1, "P00": p00, "P01": p01,
                     "P10": p10, "P11": p11, "p_max_128": p_max})


# --------------------------------------------------------------------------
# 6.3.4 Compression (Maurer-like)
# --------------------------------------------------------------------------

_G_CACHE: dict = {}


def _g_tables(nblocks: int):
    """t and log2(t) for one capture size, reused across the binary search."""
    cached = _G_CACHE.get(nblocks)
    if cached is None:
        t = np.arange(1, nblocks + 1, dtype=np.float64)
        cached = (t, np.log2(t))
        _G_CACHE.clear()          # only ever one size in flight
        _G_CACHE[nblocks] = cached
    return cached


def _compression_G(z: float, d: int, nblocks: int, v: int, b: int) -> float:
    """Expected mean log2 distance for a symbol of probability z.

    Written as a single cumulative sum rather than the double sum in the
    specification, which would be O(L^2).
    """
    if z <= 0.0:
        return 0.0
    w = 1.0 - z
    t, logt = _g_tables(nblocks)

    with np.errstate(under="ignore"):
        wpow = np.power(w, t - 1.0) if w > 0 else np.where(t == 1, 1.0, 0.0)
        # S(t) = sum_{u=1}^{t-1} log2(u) (1-z)^(u-1)
        inner = logt * wpow
        S = np.concatenate(([0.0], np.cumsum(inner)[:-1]))
        term = z * z * S + logt * z * wpow

    return float(term[d:].sum() / v)


def est_compression(bits: np.ndarray, b: int = 6, d: int = 1000) -> Estimate:
    nblocks = bits.size // b
    if nblocks <= d + 100:
        return Estimate("Compression", 1.0,
                        {"note": f"need more than {(d + 100) * b} bits"})

    blocks = np.packbits(
        np.pad(bits[: nblocks * b].reshape(nblocks, b), ((0, 0), (8 - b, 0))),
        axis=1,
    ).ravel().astype(np.int64)

    # Distance to the previous occurrence of each block value. Sorting by
    # (value, position) puts repeats of a value adjacent in index order, so the
    # gaps fall out of a single diff. The obvious Python loop over blocks cost
    # about a minute at 30 Mbit, which matters for the 10^8-bit runs
    # SEC-TEST-ENT-001 asks for.
    idx = np.arange(nblocks, dtype=np.int64)
    order = np.argsort(blocks, kind="stable")
    sorted_vals = blocks[order]
    sorted_pos = idx[order]

    first_of_value = np.empty(nblocks, dtype=bool)
    first_of_value[0] = True
    np.not_equal(sorted_vals[1:], sorted_vals[:-1], out=first_of_value[1:])

    gaps = np.empty(nblocks, dtype=np.int64)
    gaps[0] = 0
    np.subtract(sorted_pos[1:], sorted_pos[:-1], out=gaps[1:])
    # A value's first appearance has no predecessor: the spec uses i itself,
    # counting from 1.
    gaps[first_of_value] = sorted_pos[first_of_value] + 1

    dist = np.empty(nblocks, dtype=np.float64)
    dist[order] = gaps

    sample = np.log2(dist[d:])
    v = sample.size
    mean = float(sample.mean())
    sd = float(sample.std(ddof=1))
    lower = mean - Z * sd / math.sqrt(v)

    def total(z: float) -> float:
        q = (1.0 - z) / (2 ** b - 1)
        return _compression_G(z, d, nblocks, v, b) + (2 ** b - 1) * _compression_G(q, d, nblocks, v, b)

    z_min = 1.0 / (2 ** b)
    if total(z_min) <= lower:
        return Estimate("Compression", 1.0,
                        {"mean": mean, "mean_lower": lower,
                         "note": "bounded at maximum entropy"})

    lo, hi = z_min, 1.0 - 1e-9
    for _ in range(32):
        mid = (lo + hi) / 2.0
        if total(mid) > lower:
            lo = mid
        else:
            hi = mid
    p = lo
    return Estimate("Compression", min(1.0, -math.log2(p) / b),
                    {"mean": mean, "mean_lower": lower, "p": p,
                     "blocks": nblocks, "block_bits": b})


# --------------------------------------------------------------------------
# 6.3.5 t-Tuple and 6.3.6 LRS
# --------------------------------------------------------------------------

def est_ttuple_lrs(sym: np.ndarray, k: int) -> tuple:
    n = sym.size
    max_w = 62 if k == 2 else 7

    # t = largest tuple length whose most common tuple still appears >= 35 times
    t = 0
    counts_cache = {}
    for w in range(1, max_w + 1):
        ids = tuple_ids(sym, w, k)
        if ids.size == 0:
            break
        _, cnt = np.unique(ids, return_counts=True)
        counts_cache[w] = (ids, cnt)
        if cnt.max() < 35:
            break
        t = w

    if t == 0:
        tt = Estimate("t-Tuple", 1.0, {"note": "no tuple reaches 35 occurrences"})
    else:
        p_max = 0.0
        for w in range(1, t + 1):
            _, cnt = counts_cache[w]
            p_w = cnt.max() / (n - w + 1)
            p_max = max(p_max, p_w ** (1.0 / w))
        p_u = _upper_bound(p_max, n)
        tt = Estimate("t-Tuple", -math.log2(p_u),
                      {"t": t, "p_hat": p_max, "p_upper": p_u})

    # LRS: from u = t+1 up to the longest repeated substring
    u = t + 1
    v = u - 1
    for w in range(u, max_w + 1):
        if w in counts_cache:
            ids, cnt = counts_cache[w]
        else:
            ids = tuple_ids(sym, w, k)
            if ids.size == 0:
                break
            _, cnt = np.unique(ids, return_counts=True)
            counts_cache[w] = (ids, cnt)
        if cnt.max() < 2:
            break
        v = w

    if v < u:
        lrs = Estimate("LRS", float("nan"),
                       {"note": "not applicable: every tuple up to the packing "
                                "limit repeats at least 35 times, so there is "
                                "no window between t and the LRS length"})
    else:
        p_max = 0.0
        for w in range(u, v + 1):
            _, cnt = counts_cache[w]
            total_pairs = (n - w + 1) * (n - w) / 2.0
            if total_pairs <= 0:
                continue
            colliding = (cnt.astype(np.float64) * (cnt - 1) / 2.0).sum()
            p_w = colliding / total_pairs
            if p_w > 0:
                p_max = max(p_max, p_w ** (1.0 / w))
        p_u = _upper_bound(p_max, n)
        lrs = Estimate("LRS", -math.log2(p_u) if p_u > 0 else 1.0,
                       {"u": u, "v": v, "p_hat": p_max, "p_upper": p_u})

    return tt, lrs, v


# --------------------------------------------------------------------------
# 6.3.7 - 6.3.10 predictors
# --------------------------------------------------------------------------

def est_multimcw(sym: np.ndarray) -> Estimate:
    """Most common value in a sliding window; four window sizes race."""
    windows = [63, 255, 1023, 4095]
    n = sym.size
    warmup = max(windows)
    if n <= warmup + 100:
        return Estimate("MultiMCW", 1.0, {"note": "too short"})

    cs = np.concatenate(([0], np.cumsum(sym, dtype=np.int64)))

    def make(d: int) -> np.ndarray:
        w = windows[d]
        out = np.zeros(n, dtype=np.uint8)
        idx = np.arange(w, n)
        wsum = cs[idx] - cs[idx - w]
        pred = (2 * wsum > w).astype(np.uint8)  # windows are odd: no ties
        out[idx] = (pred == sym[idx]).astype(np.uint8)
        return out

    correct = _ensemble(make, len(windows), n, warmup)
    return _predictor_entropy(correct, "MultiMCW")


def est_lag(sym: np.ndarray, nlags: int = 128) -> Estimate:
    """Subpredictor d guesses that the current symbol repeats the one d back."""
    n = sym.size
    if n <= nlags + 100:
        return Estimate("Lag", 1.0, {"note": "too short"})

    def make(d: int) -> np.ndarray:
        lag = d + 1
        out = np.zeros(n, dtype=np.uint8)
        out[lag:] = (sym[lag:] == sym[:-lag]).astype(np.uint8)
        return out

    correct = _ensemble(make, nlags, n, nlags)
    return _predictor_entropy(correct, "Lag")


def _mmc_layer(sym: np.ndarray, d: int, k: int):
    """For context length d: (prediction, context_seen_before) per position."""
    n = sym.size
    ids = tuple_ids(sym, d, k)           # context starting at each position
    ctx = ids[: n - d]                   # context preceding position d..n-1
    target = sym[d:]

    if k == 2:
        signed = (target.astype(np.int64) * 2 - 1)
        running, occ = _group_running(ctx, signed)
        pred = (running > 0).astype(np.uint8)      # ties resolve to 0
    else:
        # Track the most common successor with one pass per symbol value.
        best = np.full(target.size, -1, dtype=np.int64)
        pred = np.zeros(target.size, dtype=np.uint8)
        occ = None
        for v in range(k):
            counts, o = _group_running(ctx, (target == v).astype(np.int64))
            if occ is None:
                occ = o
            upd = counts > best
            best[upd] = counts[upd]
            pred[upd] = v

    seen = occ > 0
    return pred, seen, target


def est_multimmc(sym: np.ndarray, k: int, dmax: int = 16) -> Estimate:
    n = sym.size
    if n <= dmax + 200:
        return Estimate("MultiMMC", 1.0, {"note": "too short"})
    dmax = min(dmax, 62 if k == 2 else 7)

    cache: dict[int, np.ndarray] = {}

    def make(idx: int) -> np.ndarray:
        d = idx + 1
        if d not in cache:
            pred, seen, target = _mmc_layer(sym, d, k)
            out = np.zeros(n, dtype=np.uint8)
            out[d:] = (seen & (pred == target)).astype(np.uint8)
            cache[d] = out
        return cache[d]

    correct = _ensemble(make, dmax, n, dmax)
    return _predictor_entropy(correct, "MultiMMC")


def est_lz78y(sym: np.ndarray, k: int, b: int = 16) -> Estimate:
    """Predict from the longest previously seen context, up to b symbols."""
    n = sym.size
    b = min(b, 62 if k == 2 else 7)
    if n <= b + 200:
        return Estimate("LZ78Y", 1.0, {"note": "too short"})

    correct = np.zeros(n, dtype=bool)
    chosen = np.zeros(n, dtype=bool)

    for d in range(b, 0, -1):
        pred, seen, target = _mmc_layer(sym, d, k)
        idx = np.arange(d, n)
        avail = seen & ~chosen[idx]
        hit = avail & (pred == target)
        correct[idx[hit]] = True
        chosen[idx[avail]] = True

    return _predictor_entropy(correct[b:], "LZ78Y")


# --------------------------------------------------------------------------
# 5.2 IID indicators
# --------------------------------------------------------------------------

def iid_indicators(sym: np.ndarray, k: int, lrs_v: int) -> dict:
    n = sym.size
    counts = np.bincount(sym, minlength=k).astype(np.float64)

    # Goodness of fit against the observed distribution over 10 sub-blocks.
    nblocks = 10
    size = n // nblocks
    gof_stat, gof_p = float("nan"), float("nan")
    if size > 10 * k:
        expected = counts / n * size
        keep = expected >= 5
        if keep.sum() >= 2:
            stat = 0.0
            for i in range(nblocks):
                obs = np.bincount(sym[i * size : (i + 1) * size], minlength=k).astype(np.float64)
                stat += (((obs[keep] - expected[keep]) ** 2) / expected[keep]).sum()
            dof = (nblocks - 1) * (int(keep.sum()) - 1)
            gof_stat = float(stat)
            gof_p = float(stats.chi2.sf(stat, dof)) if dof > 0 else float("nan")

    # Independence: observed vs expected frequencies of adjacent pairs.
    ind_stat, ind_p = float("nan"), float("nan")
    pairs = sym[:-1].astype(np.int64) * k + sym[1:].astype(np.int64)
    obs = np.bincount(pairs, minlength=k * k).astype(np.float64)
    p = counts / n
    exp = np.outer(p, p).ravel() * (n - 1)
    keep = exp >= 5
    if keep.sum() >= 2:
        ind_stat = float((((obs[keep] - exp[keep]) ** 2) / exp[keep]).sum())
        dof = int(keep.sum()) - k
        ind_p = float(stats.chi2.sf(ind_stat, dof)) if dof > 0 else float("nan")

    # LRS length under IID: 2*log_k(n) is the rough expectation.
    lrs_expected = 2.0 * math.log(n, k) if n > 1 else 0.0

    verdict = "consistent with IID"
    if (gof_p == gof_p and gof_p < 0.001) or (ind_p == ind_p and ind_p < 0.001):
        verdict = "IID rejected"

    return {
        "chi2_goodness_of_fit": gof_stat,
        "chi2_goodness_of_fit_p": gof_p,
        "chi2_independence": ind_stat,
        "chi2_independence_p": ind_p,
        "lrs_length": lrs_v,
        "lrs_expected_iid": lrs_expected,
        "verdict": verdict,
        "note": ("These indicators can reject IID but cannot establish it. "
                 "A formal IID claim requires the 10,000-permutation test "
                 "from SP 800-90B 5.1, which is not reimplemented here."),
    }


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------

def estimator_ceiling(n_bits: int, seed: int = 0x5A17, trials: int = 5) -> dict:
    """Highest each estimator can report on ideal data of this length.

    Several SP 800-90B estimators are biased low at finite sample sizes, the
    compression estimator badly so: its expected-value curve is nearly flat
    near maximum entropy, so the 99% confidence subtraction moves the implied
    probability a long way. Reporting a raw figure without this reference
    invites reading estimator bias as a hardware fault.

    Generating a same-length ideal sample and running the same code over it
    gives the ceiling directly, which is the only fair comparison.
    """
    # These estimators have real run-to-run spread at finite n: the compression
    # estimator's standard deviation on ideal data is about 0.026 at 524k bits
    # and 0.017 at 1.5M. A single reference run would therefore mislabel good
    # hardware as deficient roughly half the time, so average several and
    # return the spread with them.
    out = {"n_bits": n_bits, "trials": trials}
    samples = {"Compression": [], "Most Common Value": [], "Markov": [],
               "Collision": [], "LRS": []}
    for t in range(trials):
        rng = np.random.default_rng(seed + t)
        ideal = rng.integers(0, 2, n_bits, dtype=np.uint8)
        samples["Compression"].append(est_compression(ideal).h_min)
        samples["Most Common Value"].append(est_mcv(ideal, 2).h_min)
        samples["Markov"].append(est_markov(ideal).h_min)
        samples["Collision"].append(est_collision(ideal).h_min)
        _, lrs, _ = est_ttuple_lrs(ideal, 2)
        samples["LRS"].append(lrs.h_min)

    for name, vals in samples.items():
        arr = np.asarray([v for v in vals if v == v])
        if arr.size:
            out[name] = float(arr.mean())
            out[name + "_sd"] = float(arr.std(ddof=1)) if arr.size > 1 else 0.0
    return out


def assess_bits(bits: np.ndarray, quick: bool = False) -> Assessment:
    """Full non-IID track on a binary sequence."""
    sym = np.ascontiguousarray(bits.astype(np.uint8))
    n = sym.size
    ests: list[Estimate] = []
    notes: list[str] = []

    if n < 1_000_000:
        notes.append(
            f"SP 800-90B asks for at least 1,000,000 samples; this assessment "
            f"used {n:,}. Estimates from short captures are noisy and the "
            f"predictors in particular tend to overstate entropy."
        )

    ests.append(est_mcv(sym, 2))
    ests.append(est_collision(sym))
    ests.append(est_markov(sym))
    ests.append(est_compression(sym))

    tt, lrs, lrs_v = est_ttuple_lrs(sym, 2)
    ests.append(tt)
    ests.append(lrs)

    if quick:
        notes.append("Predictor estimators (6.3.7-6.3.10) were skipped in quick mode.")
    else:
        ests.append(est_multimcw(sym))
        ests.append(est_lag(sym))
        ests.append(est_multimmc(sym, 2))
        ests.append(est_lz78y(sym, 2))

    valid = [e for e in ests if e.h_min == e.h_min]
    limiting = min(valid, key=lambda e: e.h_min)

    return Assessment(
        n_bits=n,
        estimates=ests,
        h_min=max(0.0, min(1.0, limiting.h_min)),
        limiting=limiting.name,
        iid_indicators=iid_indicators(sym, 2, lrs_v),
        notes=notes,
    )


def assess_bytes(data: bytes) -> Assessment:
    """Supplementary byte-symbol view. Not the governing number."""
    sym = np.frombuffer(data, dtype=np.uint8)
    ests = [est_mcv(sym, 256)]
    tt, lrs, lrs_v = est_ttuple_lrs(sym, 256)
    ests += [tt, lrs]

    valid = [e for e in ests if e.h_min == e.h_min]
    limiting = min(valid, key=lambda e: e.h_min)
    return Assessment(
        n_bits=sym.size * 8,
        estimates=ests,
        h_min=max(0.0, min(8.0, limiting.h_min)),
        limiting=limiting.name,
        iid_indicators=iid_indicators(sym, 256, lrs_v),
        notes=["Byte-symbol assessment is supplementary. The RP2350 TRNG is a "
               "binary source, so the bit-level result governs."],
    )


# --------------------------------------------------------------------------
# 3.1.4 restart test
# --------------------------------------------------------------------------

def restart_test(matrix: np.ndarray, h_original: float, alpha: float = 0.000005) -> dict:
    """`matrix` is rows x cols of bits, one row per restart of the source."""
    rows, cols = matrix.shape

    row_counts = np.maximum((matrix == 1).sum(axis=1), (matrix == 0).sum(axis=1))
    col_counts = np.maximum((matrix == 1).sum(axis=0), (matrix == 0).sum(axis=0))
    f_max = int(max(row_counts.max(), col_counts.max()))

    p = min(1.0, 2.0 ** (-h_original)) if h_original > 0 else 1.0
    bound = int(stats.binom.ppf(1.0 - alpha, cols, p)) + 1
    sanity_pass = f_max <= bound

    row_major = matrix.reshape(-1)
    col_major = matrix.T.reshape(-1)

    a_rows = assess_bits(row_major, quick=True)
    a_cols = assess_bits(col_major, quick=True)
    h_r = min(a_rows.h_min, a_cols.h_min)

    return {
        "rows": int(rows),
        "cols": int(cols),
        "max_row_col_count": f_max,
        "sanity_bound": bound,
        "sanity_pass": bool(sanity_pass),
        "h_rows": a_rows.h_min,
        "h_cols": a_cols.h_min,
        "h_restart": h_r,
        "h_original": h_original,
        "h_final": min(h_original, h_r),
        "row_counts": row_counts.tolist(),
        "col_counts": col_counts.tolist(),
        "note": ("The firmware restarts the noise source with TRNG_SW_RESET, "
                 "not by power-cycling it. This clears the block's internal "
                 "state and restarts ring-oscillator sampling, but the "
                 "analogue source keeps running, so this is weaker than the "
                 "restart the specification intends."),
    }
