"""General-purpose statistics on a capture.

Nothing here is a compliance test; these are the descriptive numbers that make
a failure interpretable. If a standard test fails, the bit-position bias and
autocorrelation plots usually say why.
"""

from __future__ import annotations

import bz2
import lzma
import math
import zlib
from dataclasses import dataclass, field

import numpy as np
from scipy import stats


def unpack_bits(data: bytes) -> np.ndarray:
    """Bytes to a uint8 array of bits, MSB first within each byte."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


@dataclass
class BasicStats:
    nbytes: int
    nbits: int
    ones: int
    ones_fraction: float
    bit_bias: float
    shannon_bit: float
    shannon_byte: float
    min_entropy_byte_mcv: float
    byte_chi2: float
    byte_chi2_p: float
    arithmetic_mean: float
    monte_carlo_pi: float
    monte_carlo_error: float
    serial_correlation: float
    compression: dict = field(default_factory=dict)
    bit_position_bias: list = field(default_factory=list)
    autocorrelation: list = field(default_factory=list)
    byte_histogram: list = field(default_factory=list)
    run_lengths: dict = field(default_factory=dict)
    longest_run_ones: int = 0
    longest_run_zeros: int = 0


def shannon(counts: np.ndarray) -> float:
    total = counts.sum()
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def analyse(data: bytes, period: int = 192) -> BasicStats:
    """`period` is the bit length of one hardware collection (192 for the EHR).

    Bias that repeats with that period is a structural artefact of the block
    rather than of the noise source, which is worth seeing separately.
    """
    arr = np.frombuffer(data, dtype=np.uint8)
    bits = unpack_bits(data)
    n = bits.size
    ones = int(bits.sum())

    byte_counts = np.bincount(arr, minlength=256).astype(np.int64)
    expected = arr.size / 256.0
    chi2 = float(((byte_counts - expected) ** 2 / expected).sum()) if arr.size else 0.0
    chi2_p = float(stats.chi2.sf(chi2, 255)) if arr.size else 0.0

    # ent-style Monte Carlo pi: 6-byte coordinate pairs in the unit square.
    npairs = arr.size // 6
    mc_pi, mc_err = float("nan"), float("nan")
    if npairs > 100:
        coords = arr[: npairs * 6].reshape(npairs, 6).astype(np.float64)
        scale = np.array([65536.0, 256.0, 1.0])
        x = (coords[:, 0:3] * scale).sum(axis=1) / 16777216.0
        y = (coords[:, 3:6] * scale).sum(axis=1) / 16777216.0
        inside = ((x * x + y * y) <= 1.0).sum()
        mc_pi = 4.0 * inside / npairs
        mc_err = abs(mc_pi - math.pi) / math.pi

    # Serial correlation over bytes, as ent reports it.
    sc = float("nan")
    if arr.size > 2:
        a = arr.astype(np.float64)
        b = np.roll(a, -1)
        num = (a * b).mean() - a.mean() * b.mean()
        den = a.var()
        sc = float(num / den) if den > 0 else float("nan")

    # Bias per bit position within a collection: a ring oscillator sampled too
    # fast tends to show a repeating pattern here.
    pos_bias = []
    if n >= period * 4:
        usable = (n // period) * period
        grid = bits[:usable].reshape(-1, period)
        pos_bias = (grid.mean(axis=0) - 0.5).tolist()

    # Autocorrelation of the +-1 mapped bit sequence.
    ac = []
    if n > 4096:
        x = bits.astype(np.float64) * 2.0 - 1.0
        x -= x.mean()
        denom = float((x * x).sum())
        max_lag = min(256, n // 4)
        if denom > 0:
            for lag in range(1, max_lag + 1):
                ac.append(float((x[:-lag] * x[lag:]).sum() / denom))

    runs = _run_lengths(bits)

    return BasicStats(
        nbytes=arr.size,
        nbits=n,
        ones=ones,
        ones_fraction=ones / n if n else 0.0,
        bit_bias=(ones / n - 0.5) if n else 0.0,
        shannon_bit=shannon(np.bincount(bits, minlength=2)),
        shannon_byte=shannon(byte_counts),
        min_entropy_byte_mcv=(
            float(-math.log2(byte_counts.max() / arr.size)) if arr.size else 0.0
        ),
        byte_chi2=chi2,
        byte_chi2_p=chi2_p,
        arithmetic_mean=float(arr.mean()) if arr.size else 0.0,
        monte_carlo_pi=mc_pi,
        monte_carlo_error=mc_err,
        serial_correlation=sc,
        compression=_compression_ratios(data),
        bit_position_bias=pos_bias,
        autocorrelation=ac,
        byte_histogram=byte_counts.tolist(),
        run_lengths=runs["dist"],
        longest_run_ones=runs["longest_ones"],
        longest_run_zeros=runs["longest_zeros"],
    )


def _run_lengths(bits: np.ndarray) -> dict:
    if bits.size == 0:
        return {"dist": {}, "longest_ones": 0, "longest_zeros": 0}
    change = np.flatnonzero(np.diff(bits)) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [bits.size]))
    lengths = ends - starts
    values = bits[starts]

    dist: dict[str, dict[int, int]] = {"0": {}, "1": {}}
    for v in (0, 1):
        sel = lengths[values == v]
        if sel.size:
            counts = np.bincount(sel)
            dist[str(v)] = {int(i): int(c) for i, c in enumerate(counts) if c}
    return {
        "dist": dist,
        "longest_ones": int(lengths[values == 1].max()) if (values == 1).any() else 0,
        "longest_zeros": int(lengths[values == 0].max()) if (values == 0).any() else 0,
    }


def _compression_ratios(data: bytes) -> dict:
    """A compressible capture is a failed capture; this is a cheap smoke test."""
    if not data:
        return {}
    sample = data[: 1 << 20]
    out = {}
    for name, fn in (
        ("zlib", lambda d: zlib.compress(d, 9)),
        ("bz2", lambda d: bz2.compress(d, 9)),
        ("lzma", lambda d: lzma.compress(d, preset=6)),
    ):
        try:
            out[name] = len(fn(sample)) / len(sample)
        except Exception:  # pragma: no cover
            pass
    return out


def chunk_entropy(data: bytes, nchunks: int = 64) -> list:
    """Per-chunk Shannon entropy, to spot drift partway through a long run."""
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size < nchunks * 256:
        return []
    size = arr.size // nchunks
    out = []
    for i in range(nchunks):
        block = arr[i * size : (i + 1) * size]
        out.append(shannon(np.bincount(block, minlength=256)))
    return out
