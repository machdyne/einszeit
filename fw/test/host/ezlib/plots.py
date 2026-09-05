"""Figures for the validation report.

Each function returns a base64 PNG so the report is a single self-contained
file that can be archived or emailed without losing its images.
"""

from __future__ import annotations

import base64
import io
import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

INK = "#14181A"
RULE = "#C9D0D3"
ACCENT = "#2D5BA8"
PASS = "#1F7A5C"
WARN = "#B37400"
FAIL = "#B3261E"
MUTED = "#7C888C"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": RULE,
    "axes.labelcolor": INK,
    "axes.titlesize": 10,
    "axes.titleweight": "medium",
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "font.size": 9,
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans"],
    "legend.fontsize": 8,
    "legend.frameon": False,
    "grid.color": "#EAEEEF",
    "axes.grid": True,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def _encode(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def estimator_chart(assessment) -> str:
    ests = [e for e in assessment.estimates if e.h_min == e.h_min]
    names = [e.name for e in ests]
    vals = [e.h_min for e in ests]
    limiting = assessment.limiting

    # The limiting estimator is not a failure, it is simply the smallest, and
    # colouring it red said "broken" to every reader. Red is now reserved for
    # a measurement that sits below what ideal data scores at this length,
    # which is the only case that indicates a real deficit.
    ceil = getattr(assessment, "detail_ceiling", None) or {}
    real_deficit = bool(ceil) and not ceil.get("at_ceiling", True)

    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    colors = []
    for n in names:
        if n != limiting:
            colors.append(ACCENT)
        else:
            colors.append(FAIL if real_deficit else WARN)
    y = np.arange(len(names))
    ax.barh(y, vals, color=colors, height=0.62)
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("min-entropy, bits per bit")
    ax.axvline(1.0, color=MUTED, linestyle=":", linewidth=1)
    for i, v in enumerate(vals):
        ax.text(v + 0.012, i, f"{v:.4f}", va="center", fontsize=8, color=INK)
    # Show what ideal data of the same length scores, so a low bar can be read
    # as estimator convergence rather than a hardware problem.
    if ceil.get("ideal_score") is not None:
        try:
            row = names.index(limiting)
            ax.plot([ceil["ideal_score"]], [row], marker="|", markersize=16,
                    markeredgewidth=2, color=INK, zorder=5)
            ax.text(ceil["ideal_score"] + 0.012, row - 0.42,
                    f"ideal data scores {ceil['ideal_score']:.3f}",
                    fontsize=7.5, color=INK)
        except ValueError:
            pass

    label = ("limiting, and below the ideal-data score"
             if real_deficit else "limiting, at the ceiling for this sample size")
    ax.set_title(f"SP 800-90B estimators \u2014 the smallest governs ({label})")
    ax.grid(axis="y", visible=False)
    return _encode(fig)


def byte_histogram(counts: list) -> str:
    counts = np.asarray(counts, dtype=np.float64)
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    ax.bar(np.arange(256), counts, width=1.0, color=ACCENT, linewidth=0)
    mean = counts.mean()
    ax.axhline(mean, color=FAIL, linewidth=1, linestyle="--",
               label=f"uniform expectation ({mean:.0f})")
    ax.set_xlim(-1, 256)
    ax.set_xlabel("byte value")
    ax.set_ylabel("count")
    ax.legend(loc="upper right")
    ax.set_title("Byte value distribution")
    return _encode(fig)


def bit_position_bias(bias: list, period: int) -> str:
    b = np.asarray(bias, dtype=np.float64)
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    ax.bar(np.arange(b.size), b, width=1.0,
           color=np.where(np.abs(b) > 0.01, FAIL, ACCENT), linewidth=0)
    ax.axhline(0, color=MUTED, linewidth=0.8)
    ax.set_xlabel(f"bit position within one {period}-bit hardware collection")
    ax.set_ylabel("P(1) - 0.5")
    ax.set_title("Bias by bit position: structure here is an artefact of the "
                 "block, not the noise source")
    lim = max(0.02, float(np.abs(b).max()) * 1.2)
    ax.set_ylim(-lim, lim)
    return _encode(fig)


def autocorrelation(ac: list) -> str:
    a = np.asarray(ac, dtype=np.float64)
    n = a.size
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    ax.vlines(np.arange(1, n + 1), 0, a, color=ACCENT, linewidth=1.1)
    ax.axhline(0, color=MUTED, linewidth=0.8)
    ax.set_xlabel("lag, bits")
    ax.set_ylabel("correlation")
    ax.set_title("Autocorrelation")
    ax.set_xlim(0, n + 1)
    return _encode(fig)


def spectrum(bits: np.ndarray) -> str:
    n = min(bits.size, 1 << 20)
    x = bits[:n].astype(np.float64) * 2.0 - 1.0
    x -= x.mean()
    mag = np.abs(np.fft.rfft(x))
    # Bin down so the plot is readable rather than a solid block of ink.
    nbins = 1000
    edges = np.linspace(0, mag.size, nbins + 1).astype(int)
    binned = np.array([mag[edges[i]:edges[i + 1]].mean()
                       for i in range(nbins) if edges[i + 1] > edges[i]])
    freq = np.linspace(0, 0.5, binned.size)

    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    ax.plot(freq, binned, color=ACCENT, linewidth=0.7)
    ax.set_xlabel("frequency, cycles per bit")
    ax.set_ylabel("mean magnitude")
    ax.set_title("Power spectrum: a peak means a periodic component in the bitstream")
    return _encode(fig)


def bitmap(bits: np.ndarray, side: int = 384) -> str:
    need = side * side
    if bits.size < need:
        side = int(math.sqrt(bits.size))
        need = side * side
    img = bits[:need].reshape(side, side)
    fig, ax = plt.subplots(figsize=(4.2, 4.2))
    ax.imshow(img, cmap="binary", interpolation="nearest")
    ax.set_xticks([])
    ax.set_yticks([])
    ax.grid(False)
    ax.set_title(f"First {need:,} bits, {side}x{side}")
    return _encode(fig)


def run_lengths(dist: dict) -> str:
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    maxlen = 20
    xs = np.arange(1, maxlen + 1)
    for val, color, label in (("0", ACCENT, "runs of 0"), ("1", WARN, "runs of 1")):
        d = dist.get(val, {})
        ys = np.array([d.get(str(i), d.get(i, 0)) for i in xs], dtype=np.float64)
        total = sum(d.values()) if d else 1
        ax.plot(xs, ys / total, marker="o", markersize=3, color=color, label=label)
    ideal = 0.5 ** xs
    ax.plot(xs, ideal, color=MUTED, linestyle=":", label="ideal 2^-k")
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xlabel("run length, bits")
    ax.set_ylabel("proportion")
    ax.legend()
    ax.set_title("Run-length distribution")
    return _encode(fig)


def entropy_drift(chunks: list) -> str:
    c = np.asarray(chunks, dtype=np.float64)
    fig, ax = plt.subplots(figsize=(7.2, 2.2))
    ax.plot(np.arange(c.size), c, color=ACCENT, linewidth=1.2)
    ax.axhline(8.0, color=MUTED, linestyle=":", linewidth=1, label="8 bits/byte")
    ax.set_xlabel("chunk, in capture order")
    ax.set_ylabel("Shannon entropy, bits/byte")
    ax.legend()
    ax.set_title("Entropy across the capture: a trend here suggests drift or warm-up")
    return _encode(fig)


def sts_pvalues(results: list) -> str:
    names, ps = [], []
    for r in results:
        if r.skipped or not r.p_values:
            continue
        for p in r.p_values:
            names.append(r.name)
            ps.append(p)
    if not ps:
        return ""

    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    labels = sorted(set(names))
    idx = [labels.index(n) for n in names]
    colors = [FAIL if p < 0.01 else ACCENT for p in ps]
    ax.scatter(ps, idx, c=colors, s=22, zorder=3)
    ax.axvline(0.01, color=FAIL, linestyle="--", linewidth=1, label="alpha = 0.01")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.set_xlim(-0.02, 1.02)
    ax.set_xlabel("p-value")
    ax.legend(loc="lower right")
    ax.set_title("SP 800-22 p-values")
    ax.grid(axis="y", visible=False)
    return _encode(fig)


def restart_heat(matrix: np.ndarray, rows_shown: int = 200) -> str:
    m = matrix[:rows_shown, : min(matrix.shape[1], 400)]
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    ax.imshow(m, cmap="binary", aspect="auto", interpolation="nearest")
    ax.set_xlabel("bit index within a restart")
    ax.set_ylabel("restart number")
    ax.grid(False)
    ax.set_title("Restart matrix: vertical banding would mean the source "
                 "starts in a predictable state")
    return _encode(fig)


def sweep_chart(rows: list) -> str:
    """rows: dicts with rosc, sample_cnt, bits_per_sec, ones_fraction."""
    if not rows:
        return ""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.6, 2.8))
    by_rosc: dict = {}
    for r in rows:
        by_rosc.setdefault(r["rosc"], []).append(r)

    palette = [ACCENT, PASS, WARN, FAIL]
    for i, (rosc, items) in enumerate(sorted(by_rosc.items())):
        items = sorted(items, key=lambda x: x["sample_cnt"])
        xs = [x["sample_cnt"] for x in items]
        ax1.plot(xs, [x["bits_per_sec"] for x in items], marker="o", markersize=3,
                 color=palette[i % 4], label=f"chain {rosc}")
        ax2.plot(xs, [abs(x["ones_fraction"] - 0.5) for x in items], marker="o",
                 markersize=3, color=palette[i % 4], label=f"chain {rosc}")

    for ax, ylab, title in ((ax1, "bits per second", "Throughput"),
                            (ax2, "|P(1) - 0.5|", "Bias")):
        ax.set_xscale("log")
        ax.set_xlabel("SAMPLE_CNT1")
        ax.set_ylabel(ylab)
        ax.set_title(title)
    ax2.set_yscale("log")
    ax1.legend()
    fig.suptitle("Sampling interval trade-off: faster sampling costs independence",
                 fontsize=10, y=1.04)
    return _encode(fig)
