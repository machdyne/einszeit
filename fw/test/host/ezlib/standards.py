"""BSI AIS-31 and FIPS 140-2 test procedures.

Both are named in the RP2350 TRNG's compliance claims, so both are checked
here directly rather than inferred from the SP 800-22 results.

AIS-31 note: this implements the test procedures A (T0-T5) and B (T6-T8) from
AIS 31 version 2.0 (2011). BSI published a substantially revised AIS 20/31
version 3.0 in 2024 which restructures the classes and replaces several of
these tests. A pass here is evidence against the 2011 procedures, which is
what the RP2350 documentation refers to.

FIPS 140-2 note: the four power-up RNG tests of section 4.9.1 were removed in
the 2002 change notice and do not appear in FIPS 140-3 at all. They remain a
useful, cheap, widely understood smoke test.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np


@dataclass
class Check:
    name: str
    passed: bool
    value: float = float("nan")
    bounds: tuple = ()
    detail: dict = field(default_factory=dict)
    skipped: str = ""


def _runs_by_length(bits: np.ndarray) -> dict:
    """Counts of runs of each length, split by bit value, capped at 6+."""
    change = np.flatnonzero(np.diff(bits)) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [bits.size]))
    lengths = ends - starts
    values = bits[starts]
    out = {0: np.zeros(7, dtype=np.int64), 1: np.zeros(7, dtype=np.int64)}
    for v in (0, 1):
        sel = lengths[values == v]
        if sel.size:
            capped = np.minimum(sel, 6)
            out[v][: 7] = np.bincount(capped, minlength=7)[:7]
    return out


# --------------------------------------------------------------------------
# FIPS 140-2 section 4.9.1
# --------------------------------------------------------------------------

FIPS_RUNS_BOUNDS = {1: (2315, 2685), 2: (1114, 1386), 3: (527, 723),
                    4: (240, 384), 5: (103, 209), 6: (103, 209)}

# Per-block false-positive rate of each subtest on ideal data.
#
# FIPS 140-2 4.9.1 is a power-up self-test: one 20,000-bit block, once, at
# startup. Its acceptance intervals are set for a false-positive rate around
# 1e-4 on that single trial. Applying it to every block of a large capture and
# demanding that all of them pass is therefore guaranteed to fail: a 100 Mbit
# capture is 5,040 blocks, and a handful of them will fall outside the
# intervals by chance no matter how good the source is.
#
# These rates are measured over 20,000 blocks of ideal data, and cross-checked
# analytically where the distribution is tractable:
#   monobit  2*Phi(-275/sqrt(5000))  = 1.0e-4
#   poker    chi2.sf(46.17, 15)      = 5.0e-5
#   long run ~2*20000*2^-27          = 3.0e-4
FIPS_FALSE_POSITIVE_RATE = {
    "monobit": 1.0e-4,
    "poker": 1.0e-4,
    "runs": 3.5e-4,
    "long_run": 2.0e-4,
}


def fips_140_2(bits: np.ndarray, nblocks: int = 0) -> dict:
    """Runs the four power-up tests over as many 20000-bit blocks as fit."""
    block_bits = 20000
    avail = bits.size // block_bits
    if avail == 0:
        return {"blocks": 0, "pass": False,
                "note": "needs at least 20000 bits"}
    if nblocks:
        avail = min(avail, nblocks)

    results = {"monobit": 0, "poker": 0, "runs": 0, "long_run": 0}
    failures = []

    for b in range(avail):
        blk = bits[b * block_bits : (b + 1) * block_bits]

        ones = int(blk.sum())
        mono_ok = 9725 < ones < 10275

        nibbles = blk.reshape(5000, 4)
        vals = nibbles[:, 0] * 8 + nibbles[:, 1] * 4 + nibbles[:, 2] * 2 + nibbles[:, 3]
        f = np.bincount(vals, minlength=16).astype(np.float64)
        x = (16.0 / 5000.0) * float((f ** 2).sum()) - 5000.0
        poker_ok = 2.16 < x < 46.17

        runs = _runs_by_length(blk)
        runs_ok = True
        for length, (lo, hi) in FIPS_RUNS_BOUNDS.items():
            for v in (0, 1):
                if not (lo <= int(runs[v][length]) <= hi):
                    runs_ok = False

        change = np.flatnonzero(np.diff(blk)) + 1
        starts = np.concatenate(([0], change))
        ends = np.concatenate((change, [blk.size]))
        longest = int((ends - starts).max())
        long_ok = longest < 26

        for key, ok in (("monobit", mono_ok), ("poker", poker_ok),
                        ("runs", runs_ok), ("long_run", long_ok)):
            if ok:
                results[key] += 1
            elif len(failures) < 20:
                failures.append({"block": b, "test": key,
                                 "ones": ones, "poker_x": x, "longest_run": longest})

    # Judge each subtest by whether its block failure count is consistent with
    # the false-positive rate the intervals were designed around, rather than
    # demanding a clean sweep.
    from scipy import stats as sps

    per_test = {}
    all_pass = True
    for key, passed in results.items():
        observed = avail - passed
        rate = FIPS_FALSE_POSITIVE_RATE[key]
        expected = avail * rate
        # Upper tail: how surprising is this many failures on a good source?
        p_value = float(sps.binom.sf(observed - 1, avail, rate)) if observed else 1.0
        ok = p_value >= 0.001
        all_pass = all_pass and ok
        per_test[key] = {
            "blocks_passed": passed, "blocks_failed": observed,
            "expected_failures": expected, "p_value": p_value,
            "pass": ok,
        }

    return {
        "blocks": avail,
        "passed_per_test": results,
        "per_test": per_test,
        "pass": all_pass,
        "failures": failures,
        "note": ("FIPS 140-2 4.9.1 is a power-up self-test on a single 20,000-bit "
                 "block. Applied across a large capture, a few blocks fall "
                 "outside its intervals by chance, so each subtest is judged on "
                 "whether its failure count matches the expected false-positive "
                 "rate rather than on a clean sweep. Removed from FIPS 140-2 by "
                 "the 2002 change notice and absent from FIPS 140-3."),
    }


# --------------------------------------------------------------------------
# AIS-31 procedure A: T0 - T5
# --------------------------------------------------------------------------

def t0_disjointness(bits: np.ndarray) -> Check:
    need = 65536 * 48
    if bits.size < need:
        return Check("T0 disjointness", True, skipped=f"needs {need:,} bits")
    seqs = bits[:need].reshape(65536, 48)
    weights = (1 << np.arange(47, -1, -1)).astype(np.int64)
    vals = seqs.astype(np.int64) @ weights
    unique = np.unique(vals).size
    return Check("T0 disjointness", unique == 65536, float(unique),
                 (65536, 65536), {"unique_sequences": int(unique)})


def t1_monobit(bits: np.ndarray) -> Check:
    if bits.size < 20000:
        return Check("T1 monobit", True, skipped="needs 20000 bits")
    ones = int(bits[:20000].sum())
    return Check("T1 monobit", 9654 < ones < 10346, float(ones), (9654, 10346))


def t2_poker(bits: np.ndarray) -> Check:
    if bits.size < 20000:
        return Check("T2 poker", True, skipped="needs 20000 bits")
    nib = bits[:20000].reshape(5000, 4)
    vals = nib[:, 0] * 8 + nib[:, 1] * 4 + nib[:, 2] * 2 + nib[:, 3]
    f = np.bincount(vals, minlength=16).astype(np.float64)
    x = (16.0 / 5000.0) * float((f ** 2).sum()) - 5000.0
    return Check("T2 poker", 1.03 < x < 57.4, x, (1.03, 57.4))


AIS_RUNS_BOUNDS = {1: (2267, 2733), 2: (1079, 1421), 3: (502, 748),
                   4: (223, 402), 5: (90, 223), 6: (90, 223)}


def t3_runs(bits: np.ndarray) -> Check:
    if bits.size < 20000:
        return Check("T3 runs", True, skipped="needs 20000 bits")
    runs = _runs_by_length(bits[:20000])
    detail, ok = {}, True
    for length, (lo, hi) in AIS_RUNS_BOUNDS.items():
        for v in (0, 1):
            c = int(runs[v][length])
            key = f"len{length}_val{v}"
            inside = lo <= c <= hi
            detail[key] = {"count": c, "bounds": [lo, hi], "pass": inside}
            ok = ok and inside
    return Check("T3 runs", ok, detail=detail)


def t4_long_run(bits: np.ndarray) -> Check:
    if bits.size < 20000:
        return Check("T4 long run", True, skipped="needs 20000 bits")
    blk = bits[:20000]
    change = np.flatnonzero(np.diff(blk)) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [blk.size]))
    longest = int((ends - starts).max())
    return Check("T4 long run", longest < 34, float(longest), (0, 33),
                 {"longest_run": longest})


def t5_autocorrelation(bits: np.ndarray) -> Check:
    if bits.size < 30000:
        return Check("T5 autocorrelation", True, skipped="needs 30000 bits")
    # Find the worst lag using the first 10000 bits, then test fresh bits.
    head = bits[:10000].astype(np.int64)
    best_tau, best_dev = 1, -1.0
    for tau in range(1, 5001):
        z = int(np.bitwise_xor(head[:5000], head[tau : tau + 5000]).sum())
        dev = abs(z - 2500)
        if dev > best_dev:
            best_dev, best_tau = dev, tau

    tail = bits[10000:].astype(np.int64)
    if tail.size < 5000 + best_tau:
        return Check("T5 autocorrelation", True, skipped="not enough fresh bits")
    # Confirmation uses 5000 fresh XOR pairs at the worst lag found above,
    # which is what the 2326/2674 acceptance interval is centred on.
    z_star = int(np.bitwise_xor(tail[:5000], tail[best_tau : best_tau + 5000]).sum())
    return Check("T5 autocorrelation", 2326 < z_star < 2674, float(z_star),
                 (2326, 2674), {"tau": best_tau, "search_deviation": best_dev})


# --------------------------------------------------------------------------
# AIS-31 procedure B: T6 - T8
# --------------------------------------------------------------------------

def t6_uniform(bits: np.ndarray) -> Check:
    n = min(bits.size, 100_000)
    if n < 100_000:
        return Check("T6 uniform distribution", True, skipped="needs 100000 bits")
    frac = float(bits[:n].mean())
    ok_a = abs(frac - 0.5) <= 0.025

    pairs = bits[: (n // 2) * 2].reshape(-1, 2)
    vals = pairs[:, 0] * 2 + pairs[:, 1]
    props = np.bincount(vals, minlength=4) / vals.size
    ok_b = bool(np.all(np.abs(props - 0.25) <= 0.02))

    return Check("T6 uniform distribution", ok_a and ok_b, frac, (0.475, 0.525),
                 {"T6a_ones_fraction": frac, "T6a_pass": ok_a,
                  "T6b_pair_proportions": props.tolist(), "T6b_pass": ok_b})


def t7_comparative(bits: np.ndarray, word: int = 8) -> Check:
    """Chi-square comparison of the symbol distribution across two halves."""
    need = 2 * 100_000 * word
    if bits.size < need:
        return Check("T7 comparative multinomial", True,
                     skipped=f"needs {need:,} bits")
    nwords = bits.size // word
    vals = np.zeros(nwords, dtype=np.int64)
    trimmed = bits[: nwords * word].reshape(nwords, word)
    for j in range(word):
        vals = vals * 2 + trimmed[:, j]

    half = nwords // 2
    a = np.bincount(vals[:half], minlength=1 << word).astype(np.float64)
    b = np.bincount(vals[half : 2 * half], minlength=1 << word).astype(np.float64)
    both = a + b
    keep = both > 0
    chi2 = float((((a[keep] - b[keep]) ** 2) / both[keep]).sum())
    dof = int(keep.sum()) - 1
    from scipy import stats as sps
    p = float(sps.chi2.sf(chi2, dof)) if dof > 0 else float("nan")
    return Check("T7 comparative multinomial", p >= 0.0001, chi2,
                 detail={"chi2": chi2, "dof": dof, "p": p, "words": nwords})


def t8_entropy(bits: np.ndarray, L: int = 8, q: int = 2560,
               k: int = 256000) -> Check:
    """Coron's entropy test. Passes when the estimate exceeds 7.976 bits.

    Coron's statistic is not Maurer's. Maurer averages log2 of the distance to
    the previous occurrence and converges to 7.1837 for ideal 8-bit blocks;
    Coron averages g(i) = H(i-1)/ln2, which converges to the entropy itself,
    which is why the AIS-31 threshold sits just under 8.
    """
    need = (q + k) * L
    scaled = False
    if bits.size < need:
        k = bits.size // L - q
        scaled = True
        if k < 10000:
            return Check("T8 entropy (Coron)", True,
                         skipped=f"needs {need:,} bits, have {bits.size:,}")

    nblocks = q + k
    blocks = bits[: nblocks * L].reshape(nblocks, L).astype(np.int64)
    weights = (1 << np.arange(L - 1, -1, -1)).astype(np.int64)
    vals = blocks @ weights

    # g(i) = (1/ln2) * sum_{j=1}^{i-1} 1/j, tabulated once.
    harmonic = np.concatenate(([0.0], np.cumsum(1.0 / np.arange(1, nblocks + 1))))
    g = harmonic / math.log(2.0)

    table = np.zeros(1 << L, dtype=np.int64)
    for i in range(q):
        table[vals[i]] = i + 1

    total = 0.0
    for i in range(q, nblocks):
        v = vals[i]
        prev = table[v]
        dist = (i + 1 - prev) if prev else (i + 1)
        total += g[dist - 1]
        table[v] = i + 1

    f = total / k
    ok = f > 7.976

    if scaled:
        # The 7.976 acceptance threshold is calibrated for K = 256,000. Running
        # with a smaller K and reporting the outcome as a pass would be a false
        # claim of conformance, so this is reported as not run instead, with
        # the computed value kept for information.
        return Check("T8 entropy (Coron)", True, f, (7.976, 8.0),
                     skipped=(f"needs {(2560 + 256000) * L:,} bits, had "
                              f"{bits.size:,}; value {f:.4f} at reduced K="
                              f"{k:,} is indicative only"),
                     detail={"L": L, "Q": q, "K": k, "scaled": True,
                             "indicative_value": f})

    return Check("T8 entropy (Coron)", ok, f, (7.976, 8.0),
                 {"L": L, "Q": q, "K": k, "scaled": False})


def ais31(bits: np.ndarray) -> dict:
    proc_a = [t0_disjointness(bits), t1_monobit(bits), t2_poker(bits),
              t3_runs(bits), t4_long_run(bits), t5_autocorrelation(bits)]
    proc_b = [t6_uniform(bits), t7_comparative(bits), t8_entropy(bits)]

    def pack(checks):
        return [{"name": c.name, "pass": c.passed, "value": c.value,
                 "bounds": list(c.bounds), "detail": c.detail,
                 "skipped": c.skipped} for c in checks]

    ran = [c for c in proc_a + proc_b if not c.skipped]
    return {
        "procedure_a": pack(proc_a),
        "procedure_b": pack(proc_b),
        "ran": len(ran),
        "skipped": len(proc_a) + len(proc_b) - len(ran),
        "failed": [c.name for c in ran if not c.passed],
        "pass": all(c.passed for c in ran),
        "note": ("Implements AIS 31 v2.0 (2011). BSI's AIS 20/31 v3.0 (2024) "
                 "restructures these procedures; a v3.0 evaluation needs "
                 "different tests."),
    }
