"""Runs every analysis over a capture and assembles the report context."""

from __future__ import annotations

import json
import math
import pathlib
import subprocess
import sys
import time

import numpy as np

from . import basic, plots, report, sp80022, sp80090b, standards
from .container import Capture, read_sidecar


def _log(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr, flush=True)


def analyse_capture(cap: Capture, quick: bool = False,
                    nist_tool: str | None = None,
                    sequences: int = 0, entropy_bits: int = 8_000_000,
                    sts_whole_bits: int = 20_000_000) -> dict:
    data = cap.payload
    bits = basic.unpack_bits(data)
    meta = cap.meta or {}
    period = 192  # bits per EHR collection

    t0 = time.time()
    _log(f"descriptive statistics over {bits.size:,} bits")
    b = basic.analyse(data, period=period)

    # SP 800-90B needs 10^6 samples; SEC-TEST-ENT-001 needs 10^8 for SP 800-22.
    # Running the predictors over 10^8 bits costs hours and gigabytes for no
    # gain, so the entropy assessment uses a prefix unless told otherwise.
    ebits = bits
    if entropy_bits and bits.size > entropy_bits:
        ebits = bits[:entropy_bits]
        _log(f"SP 800-90B min-entropy estimators on the first "
             f"{entropy_bits:,} bits of {bits.size:,}")
    else:
        _log("SP 800-90B min-entropy estimators")
    assessment = sp80090b.assess_bits(ebits, quick=quick)
    if ebits.size < bits.size:
        assessment.notes.append(
            f"Assessed on the first {ebits.size:,} bits of a {bits.size:,}-bit "
            f"capture. SP 800-90B asks for at least 1,000,000 samples and the "
            f"predictors scale badly beyond a few million; SP 800-22 below was "
            f"run over the full capture. Override with --entropy-bits.")

    if nist_tool:
        ext = _run_nist_tool(nist_tool, data)
        if ext is not None:
            assessment.notes.append(
                f"NIST EntropyAssessment reported {ext:.6f} bit/bit; the "
                f"built-in estimators reported {assessment.h_min:.6f}. The "
                f"lower of the two is used."
            )
            if ext < assessment.h_min:
                assessment.h_min = ext
                assessment.limiting = "NIST EntropyAssessment"
            assessment.source = "builtin + NIST EntropyAssessment"

    if assessment.limiting in ("Compression", "LRS", "Collision"):
        _log(f"calibrating the {assessment.limiting} estimator against ideal "
             f"data of the same length")
        ceiling = sp80090b.estimator_ceiling(ebits.size)
        cap_val = ceiling.get(assessment.limiting)
        sd = ceiling.get(assessment.limiting + "_sd", 0.0)
        if cap_val is not None:
            gap = cap_val - assessment.h_min
            # Only call it a real deficit when the measurement sits more than
            # three standard deviations below the ideal mean.
            threshold = max(3.0 * sd, 0.02)
            assessment.detail_ceiling = {
                "estimator": assessment.limiting,
                "ideal_score": cap_val,
                "ideal_sd": sd,
                "measured": assessment.h_min,
                "gap": gap,
                "threshold": threshold,
                "at_ceiling": gap < threshold,
            }

    # The whole-capture pass builds int64 index arrays the length of the
    # capture: at 10^8 bits that is roughly 0.8 GB per call and several GB
    # peak. The multi-sequence pass below covers the full capture and is the
    # result SEC-TEST-ENT-001 actually calls for, so cap this one.
    wbits = bits
    if sts_whole_bits and bits.size > sts_whole_bits:
        wbits = bits[:sts_whole_bits]
        _log(f"SP 800-22 whole-capture pass on the first {sts_whole_bits:,} "
             f"bits (the {sequences or 0}-sequence pass covers all "
             f"{bits.size:,})")
    else:
        _log("SP 800-22 statistical test suite")
    sts = sp80022.run_all(wbits, skip_slow=quick)
    sts_summary = sp80022.summarise(sts)
    sts_summary["bits"] = int(wbits.size)

    multi = None
    if sequences:
        _log(f"SP 800-22 across {sequences} sequences "
             f"(the form the specification is written for)")
        multi = sp80022.run_multi(bits, nseq=sequences, skip_slow=quick)

    _log("AIS-31 and FIPS 140-2")
    ais = standards.ais31(bits)
    fips = standards.fips_140_2(bits)

    _log("figures")
    figs = {
        "estimators": plots.estimator_chart(assessment),
        "byte_hist": plots.byte_histogram(b.byte_histogram),
        "autocorr": plots.autocorrelation(b.autocorrelation) if b.autocorrelation else "",
        "spectrum": plots.spectrum(bits),
        "bitmap": plots.bitmap(bits),
        "runs": plots.run_lengths(b.run_lengths),
        "sts": plots.sts_pvalues(sts),
    }
    if b.bit_position_bias:
        figs["bitpos"] = plots.bit_position_bias(b.bit_position_bias, period)
    drift = basic.chunk_entropy(data)
    if drift:
        figs["drift"] = plots.entropy_drift(drift)

    _log(f"analysis finished in {time.time() - t0:.1f}s")

    return {
        "basic": b,
        "assessment": assessment,
        "sts": sts,
        "sts_summary": sts_summary,
        "ais": ais,
        "fips": fips,
        "figures": figs,
        "meta": meta,
        "sts_multi": multi,
        "ent001": ent001_status(bits.size, sts, multi),
    }


# Minimum capture size for each test that has a hard bit requirement.
# Tests absent from this table are conditional on the data, not on its size.
BIT_REQUIREMENTS = {
    "Binary matrix rank": 38_912,
    "Longest run of ones": 6_272,
    "Overlapping template": 10_320,
    "Linear complexity": 100_000,
    "Maurer universal": 387_840,
    "T0 disjointness": 3_145_728,
    "T7 comparative multinomial": 1_600_000,
    "T8 entropy (Coron)": 2_068_480,
    "T5 autocorrelation": 30_000,
    "T6 uniform distribution": 100_000,
}

# Tests that are conditional on a property of the data rather than its length.
# SP 800-22 defines both random excursion tests as applicable only when the
# cumulative-sum walk produces at least 500 zero-crossing cycles. A biased walk
# is transient, so its cycle count saturates: collecting more data does not
# make these applicable, removing the bias does.
CONDITIONAL_TESTS = {
    "Random excursions": "needs >= 500 zero-crossing cycles in the +-1 walk",
    "Random excursions variant": "needs >= 500 zero-crossing cycles in the +-1 walk",
}


def coverage(ctx: dict, nbits: int, capture_bits: int = 0) -> list:
    """What did not run, why, and what it would take to run it."""
    rows = []
    seen = set()

    def add(name, skipped):
        if name in seen or not skipped:
            return
        seen.add(name)
        need = BIT_REQUIREMENTS.get(name)
        if name in CONDITIONAL_TESTS:
            rows.append({"test": name, "reason": "conditional",
                         "detail": CONDITIONAL_TESTS[name], "need_bits": None,
                         "rounds": None})
        elif need:
            extra = max(0, need - nbits)
            rounds = math.ceil(need / capture_bits) if capture_bits else None
            rows.append({"test": name, "reason": "sample too small",
                         "detail": f"needs {need:,} bits, had {nbits:,}",
                         "need_bits": need, "short_by": extra, "rounds": rounds})
        else:
            rows.append({"test": name, "reason": "not run", "detail": skipped,
                         "need_bits": None, "rounds": None})

    for r in ctx.get("sts", []):
        if r.skipped:
            add(r.name, r.skipped)
    for grp in ("procedure_a", "procedure_b"):
        for c in ctx.get("ais", {}).get(grp, []):
            if c.get("skipped"):
                add(c["name"], c["skipped"])
    return rows


# SEC-TEST-ENT-001: "SP 800-22 statistical test suite (all 15 tests) MUST be
# run against a minimum of 10^8 bits of TRNG output for each hardware
# revision."
ENT001_MIN_BITS = 100_000_000
ENT001_TESTS = 15


def ent001_status(nbits: int, sts: list, multi: dict | None) -> dict:
    """Does this analysis satisfy SEC-TEST-ENT-001, and if not, what is missing."""
    checks = []

    checks.append({
        "requirement": f"At least {ENT001_MIN_BITS:,} bits of TRNG output",
        "met": nbits >= ENT001_MIN_BITS,
        "actual": f"{nbits:,} bits"
                  + ("" if nbits >= ENT001_MIN_BITS
                     else f", short by {ENT001_MIN_BITS - nbits:,}"),
    })

    if multi and not multi.get("error"):
        ran = [t for t in multi["tests"] if t.get("ran", 0) > 0]
        failed = multi.get("failed", [])
        nseq = multi.get("sequences", 0)
        checks.append({"requirement": f"All {ENT001_TESTS} tests executed",
                       "met": len(ran) >= ENT001_TESTS,
                       "actual": f"{len(ran)} of {ENT001_TESTS} produced a result"})
        checks.append({"requirement": "All tests pass",
                       "met": not failed,
                       "actual": "all pass" if not failed else f"failed: {', '.join(failed)}"})
        # Not mandated by the requirement text, but the suite's own acceptance
        # criteria are only meaningful at these sequence counts.
        checks.append({"requirement": "Proportion criterion meaningful (m >= 100)",
                       "met": nseq >= 100,
                       "actual": f"{nseq} sequences"})
        checks.append({"requirement": "p-value uniformity applicable (m >= 50)",
                       "met": nseq >= 50,
                       "actual": f"{nseq} sequences"})
    else:
        ran = [r for r in sts if not r.skipped]
        checks.append({"requirement": f"All {ENT001_TESTS} tests executed",
                       "met": len(ran) >= ENT001_TESTS,
                       "actual": f"{len(ran)} of {ENT001_TESTS} produced a result"})
        checks.append({"requirement": "Assessed across multiple sequences",
                       "met": False,
                       "actual": "single-sequence analysis; re-run with --sequences 100"})

    met = all(c["met"] for c in checks)
    return {
        "requirement_id": "SEC-TEST-ENT-001",
        "met": met,
        "checks": checks,
        "note": ("This is a conformance statement from an independent "
                 "reimplementation of SP 800-22. For the formal record, run "
                 "NIST's sts-2.1.2 against the archived capture and cite that "
                 "result; see EZ-TEST-DEVIATIONS.md G-04."),
    }


def _run_nist_tool(tool: str, data: bytes) -> float | None:
    """Optionally defer to NIST's own EntropyAssessment binary."""
    import re
    import tempfile

    exe = pathlib.Path(tool)
    if not exe.exists():
        _log(f"NIST tool not found at {tool}, skipping")
        return None
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        _log(f"running {exe.name} (this can take a while)")
        out = subprocess.run([str(exe), path, "1"], capture_output=True,
                             text=True, timeout=3600)
        m = re.findall(r"min\(H_original,\s*8\s*X\s*H_bitstring\)\s*=\s*([0-9.]+)",
                       out.stdout)
        if not m:
            m = re.findall(r"H_bitstring\s*[:=]\s*([0-9.]+)", out.stdout)
        return float(m[-1]) if m else None
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        _log(f"NIST tool failed: {exc}")
        return None
    finally:
        pathlib.Path(path).unlink(missing_ok=True)


def add_restart(ctx: dict, cap: Capture) -> None:
    meta = cap.meta or {}
    rows = int(meta.get("rows", 0))
    row_bytes = int(meta.get("row_bytes", 0))
    if not rows or not row_bytes:
        _log("restart capture has no row geometry in its metadata, skipping")
        return
    bits = basic.unpack_bits(cap.payload)
    per_row = row_bytes * 8
    usable = (bits.size // per_row) * per_row
    matrix = bits[:usable].reshape(-1, per_row)

    _log(f"restart test over {matrix.shape[0]} restarts x {matrix.shape[1]} bits")
    ctx["restart"] = sp80090b.restart_test(matrix, ctx["assessment"].h_min)
    ctx["figures"]["restart"] = plots.restart_heat(matrix)


def add_sweep(ctx: dict, csv_path: pathlib.Path) -> None:
    rows = []
    for line in csv_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("rosc,"):
            continue
        f = line.split(",")
        if len(f) < 9:
            continue
        try:
            rows.append({
                "rosc": int(f[0]), "sample_cnt": int(f[1]),
                "collections": int(f[2]), "bits_per_sec": float(f[3]),
                "vn_err": int(f[4]), "crngt_err": int(f[5]),
                "autocorr_err": int(f[6]), "timeouts": int(f[7]),
                "ones_fraction": float(f[8]),
            })
        except ValueError:
            continue
    if rows:
        ctx["figures"]["sweep"] = plots.sweep_chart(rows)
        ctx["sweep"] = rows


def build_report(ctx: dict, out_path: pathlib.Path, device: dict | None = None,
                 title_line: str = "") -> None:
    ctx = dict(ctx)
    ctx["device"] = device or {}
    ctx["generated"] = report.timestamp()
    ctx["title_line"] = title_line
    report.write(out_path, ctx)

    js = out_path.with_suffix(".json")
    js.write_text(json.dumps({
        "generated": ctx["generated"],
        "meta": ctx.get("meta", {}),
        "entropy": ctx["assessment"].as_dict(),
        "basic": {k: v for k, v in vars(ctx["basic"]).items()
                  if k not in ("byte_histogram", "autocorrelation",
                               "bit_position_bias", "run_lengths")},
        "sp800_22_multi": ctx.get("sts_multi"),
        "sp800_22": {
            "summary": ctx["sts_summary"],
            "tests": [{"name": r.name, "p_values": r.p_values,
                       "pass": r.passed, "skipped": r.skipped}
                      for r in ctx["sts"]],
        },
        "ais31": ctx["ais"],
        "fips140_2": ctx["fips"],
        "restart": ctx.get("restart"),
        "device": ctx["device"],
    }, indent=2, default=str))


def load_capture(path: pathlib.Path) -> Capture:
    return read_sidecar(path)
