#!/usr/bin/env python3
"""Einszeit V1 hardware validation: collect from the board, analyse, report.

Typical use:

    ./ez_validate.py collect --port /dev/ttyACM0 --out runs/board-01
    ./ez_validate.py analyze runs/board-01
    ./ez_validate.py all --port /dev/ttyACM0 --out runs/board-01

`selftest` runs the whole analysis pipeline against synthetic sources of known
entropy, which is how you check the tooling before trusting what it says about
your hardware.
"""

from __future__ import annotations

import argparse
import math
import pathlib
import sys

from ezlib import analyze
from ezlib.container import Capture, read_sidecar


# AIS-31 T0 disjointness needs 65536 x 48 = 3,145,728 bits and is the largest
# single requirement in the suite. Sizing exactly to it leaves no headroom: a
# capture that comes up even one EHR collection short silently drops T0. The
# margin is one device buffer round, which costs about 20 seconds.
FULL_STANDARDS_BYTES = 3_145_728 // 8 + 24_576


def cmd_collect(args) -> int:
    from ezlib import collect

    outdir = pathlib.Path(args.out)
    if getattr(args, "full_standards", False):
        args.raw_bytes = FULL_STANDARDS_BYTES
        args.cond_bytes = FULL_STANDARDS_BYTES
        args.rounds = 1
        eff = args.sample_cnt if args.sample_cnt is not None else 65535
        rate = 150e6 / (eff + 1) / 4
        print(f"full standards coverage: {FULL_STANDARDS_BYTES:,} bytes each "
              f"({FULL_STANDARDS_BYTES * 8:,} bits)", file=sys.stderr)
        print(f"conditioned capture alone will take about "
              f"{FULL_STANDARDS_BYTES * 8 / rate / 60:.0f} min at "
              f"SAMPLE_CNT1={eff}", file=sys.stderr)
    collect.collect(
        args.port, outdir,
        cond_bytes=args.cond_bytes,
        raw_bytes=args.raw_bytes,
        rounds=args.rounds,
        sweep=args.sweep,
        restart=args.restart,
        skip_device_tests=args.no_device_tests,
        allow_storage=args.allow_storage,
        sd_detect=args.sd_detect,
        sample_cnt=args.sample_cnt,
        rosc=args.rosc,
        verbose=args.verbose,
    )
    print(f"\ncaptures written to {outdir}", file=sys.stderr)
    return 0


def cmd_analyze(args) -> int:
    import json

    path = pathlib.Path(args.path)
    outdir = path if path.is_dir() else path.parent

    if path.is_dir():
        primary = path / "raw.bin"
        if not primary.exists():
            primary = path / "conditioned.bin"
        if not primary.exists():
            candidates = sorted(path.glob("*.bin"))
            if not candidates:
                print(f"no .bin captures in {path}", file=sys.stderr)
                return 1
            primary = candidates[0]
    else:
        primary = path

    print(f"analysing {primary.name}", file=sys.stderr)
    cap = read_sidecar(primary)
    print(f"  {cap.describe()}", file=sys.stderr)

    ctx = analyze.analyse_capture(cap, quick=args.quick, nist_tool=args.nist_tool,
                                  sequences=args.sequences,
                                  entropy_bits=args.entropy_bits,
                                  sts_whole_bits=args.sts_whole_bits)

    restart_file = outdir / "restart.bin"
    if restart_file.exists():
        analyze.add_restart(ctx, read_sidecar(restart_file))

    sweep_file = outdir / "sweep.csv"
    if sweep_file.exists():
        analyze.add_sweep(ctx, sweep_file)

    device = {}
    dev_file = outdir / "device.json"
    if dev_file.exists():
        raw = json.loads(dev_file.read_text())
        device = {
            "pins": raw.get("pins"),
            "clock": raw.get("clock"),
            "aon": raw.get("aon"),
            "fram": raw.get("fram"),
            "sd": raw.get("sd"),
        }
        device = {k: v for k, v in device.items() if v}

    out = pathlib.Path(args.report) if args.report else outdir / "report.html"
    title = (f"{primary.name} \u00b7 {cap.nbits:,} bits \u00b7 "
             f"{cap.meta.get('mode', 'unknown')} mode")
    analyze.build_report(ctx, out, device=device, title_line=title)

    a = ctx["assessment"]
    _interpret(ctx, primary)

    print(f"\n  min-entropy: {a.h_min:.6f} bit/bit (limited by {a.limiting})",
          file=sys.stderr)
    ceil = getattr(a, "detail_ceiling", None) or {}
    if ceil:
        verdict = ("at the estimator ceiling for this sample size"
                   if ceil["at_ceiling"] else "below the ceiling: likely real")
        print(f"    ideal data of the same length scores "
              f"{ceil['ideal_score']:.4f} -> {verdict}", file=sys.stderr)
    summ = ctx["sts_summary"]
    scope = (f"first {summ['bits']:,} bits" if summ.get("bits")
             and summ["bits"] < cap.nbits else "whole capture")
    label = ("SP 800-22 single-sequence" if ctx.get("sts_multi")
             else "SP 800-22")
    print(f"  {label} ({scope}): ran {summ['ran']}, "
          f"failed {summ['failed'] or 'none'}", file=sys.stderr)
    if ctx.get("sts_multi") and summ["failed"]:
        print("    supplementary, not the conformance result; the "
              "multi-sequence assessment below governs", file=sys.stderr)
    print(f"  AIS-31:      {'pass' if ctx['ais']['pass'] else 'FAILED: ' + ', '.join(ctx['ais']['failed'])}",
          file=sys.stderr)
    multi = ctx.get("sts_multi")
    if multi and not multi.get("error"):
        lo, hi = multi["proportion_bounds"]
        print(f"\n  SP 800-22 across {multi['sequences']} sequences of "
              f"{multi['bits_per_sequence']:,} bits "
              f"(accept proportion >= {lo:.3f}):", file=sys.stderr)
        for r in multi["tests"]:
            if r["ran"] == 0:
                print(f"    {r['test']:<30s} {r['verdict']}", file=sys.stderr)
                continue
            subs = r.get("subtests", 1)
            sub = f" x{subs}" if subs > 1 else "   "
            note = (f" ({r['skipped']} seq n/a)" if r["skipped"] else "")
            flag = ""
            if r["verdict"] == "marginal":
                flag = "  MARGINAL (within one sequence of the bound)"
            elif r["verdict"] == "fail":
                flag = f"  FAIL ({r.get('n_failing_subtests', 1)} of {subs})"
            print(f"    {r['test']:<28s}{sub} worst {r['passed']}/{r['ran']} "
                  f"= {r['proportion']:.3f} vs {r['bounds'][0]:.3f}{note}{flag}",
                  file=sys.stderr)
        print(f"  overall: {'PASS' if multi['pass'] else 'FAIL ' + str(multi['failed'])}",
              file=sys.stderr)

        if multi.get("weak_criterion"):
            print(f"  note: with only {multi['sequences']} sequences the "
                  f"proportion criterion is coarse and the\n"
                  f"        p-value uniformity criterion does not apply "
                  f"(it needs 10+). Treat this\n"
                  f"        as a weak pass and read the p-values above.",
                  file=sys.stderr)
        if multi.get("marginal"):
            print(f"  marginal (shortfall smaller than one sequence, i.e. the "
                  f"integer coarseness\n        of the acceptance bound rather "
                  f"than evidence): {', '.join(multi['marginal'])}",
                  file=sys.stderr)

        # The whole-capture run has more data and so more power. When the two
        # views disagree, the more sensitive one is usually right.
        whole_failed = set(ctx["sts_summary"]["failed"])
        seq_passed = {r["test"] for r in multi["tests"]
                      if r.get("verdict") == "pass"}
        disagree = sorted(whole_failed & seq_passed)
        if disagree:
            print(f"\n  Disagreement: {', '.join(disagree)} failed on the full "
                  f"{cap.nbits:,}-bit\n  capture but passed per-sequence. This "
                  f"is not a contradiction. Test power grows\n  with sequence "
                  f"length, so a small consistent deviation can sit just inside\n"
                  f"  the threshold on each {multi['bits_per_sequence']:,}-bit "
                  f"sequence and clear it on the\n  whole. The full-capture "
                  f"result is the more sensitive of the two.", file=sys.stderr)
    elif multi:
        print(f"\n  multi-sequence run skipped: {multi['error']}", file=sys.stderr)

    ent = ctx.get("ent001")
    if ent:
        mark = "MET" if ent["met"] else "NOT MET"
        print(f"\n  SEC-TEST-ENT-001: {mark}", file=sys.stderr)
        for c in ent["checks"]:
            print(f"    [{'x' if c['met'] else ' '}] {c['requirement']:<48s} "
                  f"{c['actual']}", file=sys.stderr)

    cov = analyze.coverage(ctx, cap.nbits, capture_bits=cap.nbits)
    if cov:
        print(f"\n  {len(cov)} test(s) did not run:", file=sys.stderr)
        for r in cov:
            print(f"    {r['test']:<32s} {r['detail']}", file=sys.stderr)
        sized = [r for r in cov if r.get("need_bits")]
        if sized:
            worst = max(r["need_bits"] for r in sized)
            need_rounds = math.ceil(worst / cap.nbits)
            print(f"\n  Collect {need_rounds} rounds to satisfy all size-limited "
                  f"tests ({worst:,} bits):", file=sys.stderr)
            print(f"    ez_validate.py collect --port ... --out runs/rN "
                  f"--rounds {need_rounds}", file=sys.stderr)
        if any(r["reason"] == "conditional" for r in cov):
            print(f"\n  The random excursion tests are conditional, not "
                  f"size-limited: more\n  data will not make them apply. They "
                  f"need the +-1 walk to return to\n  zero 500 times, and a "
                  f"biased walk is transient. Remove the bias\n  (analyse the "
                  f"conditioned capture) and they run.", file=sys.stderr)

    print(f"\nreport: {out}\njson:   {out.with_suffix('.json')}", file=sys.stderr)

    # The pairing is the point: raw shows the source, conditioned shows what
    # production firmware would actually emit. Analysing only one hides half
    # the picture, so in directory mode do both and compare.
    other = outdir / "conditioned.bin" if primary.name == "raw.bin" else outdir / "raw.bin"
    if path.is_dir() and other.exists() and not args.no_pair:
        print(f"\nalso analysing {other.name} for comparison", file=sys.stderr)
        cap2 = read_sidecar(other)
        ctx2 = analyze.analyse_capture(cap2, quick=True, nist_tool=None)
        out2 = outdir / f"report-{other.stem}.html"
        analyze.build_report(ctx2, out2, device=device,
                             title_line=f"{other.name} \u00b7 {cap2.nbits:,} bits")
        _interpret(ctx2, other)
        print(f"\n  {'capture':<14s} {'H_min':>9s}  {'bias':>10s}  SP 800-22",
              file=sys.stderr)
        for name, c in ((primary.stem, ctx), (other.stem, ctx2)):
            s2 = c["sts_summary"]
            print(f"  {name:<14s} {c['assessment'].h_min:9.4f}  "
                  f"{c['basic'].bit_bias:+10.6f}  "
                  f"{s2['ran'] - len(s2['failed'])}/{s2['ran']} pass",
                  file=sys.stderr)
        print(f"\nreport: {out2}", file=sys.stderr)
    return 0


def _interpret(ctx, path) -> None:
    """Say what the results mean before dumping numbers at the user."""
    mode = (ctx.get("meta") or {}).get("mode", "")
    failed = set(ctx["sts_summary"]["failed"])
    b = ctx["basic"]

    bias_tests = {"Frequency (monobit)", "Block frequency", "Runs",
                  "Cumulative sums", "Serial", "Approximate entropy",
                  "Non-overlapping template", "Overlapping template"}
    structure_tests = {"DFT (spectral)", "Binary matrix rank",
                       "Maurer universal", "Linear complexity",
                       "Longest run of ones"}

    if not failed:
        return

    bias_failed = failed & bias_tests
    structure_failed = failed & structure_tests

    print("", file=sys.stderr)
    if bias_failed and not structure_failed:
        print(f"  Every failing test is bias-sensitive; the correlation-sensitive "
              f"tests\n  ({', '.join(sorted(structure_tests - failed))}) all passed.",
              file=sys.stderr)
        print(f"  Measured P(1) = {b.ones_fraction:.6f}, bias = {b.bit_bias:+.6f} "
              f"({b.bit_bias * 100:+.3f}%).", file=sys.stderr)
        if mode == "raw":
            print("  This is a RAW capture with the Von Neumann balancer bypassed.\n"
                  "  DC bias is the expected behaviour of a directly sampled ring\n"
                  "  oscillator and is precisely what the balancer removes. SP 800-22\n"
                  "  is a test for RNG *output*, not for a raw noise source: run it\n"
                  "  against the conditioned capture instead.", file=sys.stderr)
    elif structure_failed:
        print("  Correlation-sensitive tests failed, which bias alone does not\n"
              "  explain. Check the autocorrelation and spectrum plots, and try a\n"
              "  longer sampling interval or a different inverter chain length.",
              file=sys.stderr)


def cmd_all(args) -> int:
    rc = cmd_collect(args)
    if rc:
        return rc
    args.path = args.out
    return cmd_analyze(args)


def cmd_guard(args) -> int:
    """Inspect or release the on-device storage and card-detect policies."""
    from ezlib.link import Device

    with Device(args.port, verbose=False) as dev:
        dev.sync()

        if args.sd_detect:
            r = dev.command(f"sd det {args.sd_detect}", timeout=15)
            print(r.text)

        if args.release:
            print("Releasing the storage guard.\n"
                  "This asserts that this board has never held key material or\n"
                  "session metadata. Overwriting an OTP offset causes silent key\n"
                  "reuse (EZ-SEC-001 SEC-PTR-002).", file=sys.stderr)
            r = dev.command("guard claim --force --no-key-material", timeout=30)
            print(r.text)
            if r.rc != 0:
                return 1

        r = dev.command("guard", timeout=20)
        print(r.text)
        r = dev.command("sd det", timeout=20)
        print(r.text)
    return 0


def cmd_bootsel(args) -> int:
    """Put the board into firmware update mode."""
    from ezlib.link import Device, DeviceError

    try:
        with Device(args.port, verbose=False) as dev:
            dev.sync()
            print(f"sending {args.port} to BOOTSEL", file=sys.stderr)
            try:
                dev.command("reboot bootsel", timeout=5)
            except DeviceError:
                # The device resets mid-reply, so a truncated response here is
                # the expected outcome rather than a failure.
                pass
    except Exception as exc:
        print(f"could not reach the device: {exc}", file=sys.stderr)
        print("If the firmware is unresponsive, hold BOOTSEL while plugging in,\n"
              "or run: picotool reboot -f -u", file=sys.stderr)
        return 1

    print("\nThe board should now enumerate as RPI-RP2 mass storage.\n"
          "Copy build/einszeit_hwtest.uf2 to it, or run:\n"
          "  picotool load -x build/einszeit_hwtest.uf2", file=sys.stderr)
    return 0


PUBLISH_README = """# Einszeit V1 entropy source characterisation data

## What this is

Raw and conditioned output from the RP2350 TRNG on an Einszeit V1 board,
captured for entropy source characterisation, together with the analysis
reports generated from it.

## What this is NOT

**This is not key material and must never be used as any.** Every capture is
tagged `"key_material": false` in its metadata. It was produced by bench
firmware that deliberately bypasses the TRNG hardware health tests, and it has
crossed a USB link to a host computer. EZ-SEC-001 SEC-ENTROPY-001 requires key
bytes to come exclusively from the TRNG on the device itself, and SEC-DIST-001
prohibits electronic transmission of key material.

The board these captures came from is a characterisation board. It has never
held key material and never will.

## Why it is published

The min-entropy figures in the reports were produced by an independent
reimplementation of the SP 800-90B estimators, not a validated one. Publishing
the underlying data is what makes those numbers checkable: anyone can run
NIST's own EntropyAssessment and sts-2.1.2 against these files and compare.

A claim about an entropy source that cannot be independently verified is not
worth much, particularly for a one-time-pad device whose entire security
argument rests on it.

## Files

`*.bin`      raw capture bytes, exactly as the device produced them
`*.json`     capture metadata: mode, SAMPLE_CNT1, inverter chain, health-test
             error counts, die temperature, board ID, throughput
`report.*`   generated analysis, HTML and machine-readable JSON
`SHA256SUMS` checksums tying the reports to the data they describe

`raw.bin` is the noise source with the Von Neumann balancer, the continuous RNG
test and the autocorrelation test all bypassed. It is expected to be biased;
that is what makes it the right input for an SP 800-90B assessment.
`conditioned.bin` is what production firmware would actually emit.

## Reproducing the analysis

```
git clone <this repo> && cd fw/test/host
pip install -r requirements.txt
python3 ez_validate.py analyze <this directory>/conditioned.bin --sequences 3
```

Or with NIST's validated tools:

```
ea_non_iid -i -a -v raw.bin 1        # SP 800-90B
assess 1000000 < conditioned.bin      # SP 800-22, sts-2.1.2
```

If your numbers disagree with the published reports, that is a finding worth
raising as an issue.
"""


def cmd_publish(args) -> int:
    """Assemble a publishable evidence bundle from a run directory."""
    import hashlib
    import json
    import shutil

    src = pathlib.Path(args.path)
    dst = pathlib.Path(args.out)
    if not src.is_dir():
        print(f"{src} is not a directory", file=sys.stderr)
        return 1
    dst.mkdir(parents=True, exist_ok=True)

    wanted, board_ids = [], set()
    for pat in ("*.bin", "*.json", "report*.html", "sweep.csv"):
        wanted.extend(sorted(src.glob(pat)))

    # Validate everything before copying anything, so a refusal never leaves a
    # half-assembled bundle that someone might publish by mistake.
    for f in wanted:
        if f.suffix != ".json":
            continue
        try:
            meta = json.loads(f.read_text())
        except json.JSONDecodeError:
            meta = {}
        if "mode" in meta and meta.get("key_material") is not False:
            print(f"refusing to bundle: {f.name} does not carry "
                  f'"key_material": false in its metadata.', file=sys.stderr)
            print("Captures from firmware older than 1.2.0 predate that tag. "
                  "Re-capture\nwith current firmware rather than adding the "
                  "tag by hand: the tag is meant\nto certify how the data was "
                  "produced, not to be asserted after the fact.",
                  file=sys.stderr)
            return 1
        uuid = meta.get("device_uuid") or meta.get("board_id")
        if uuid:
            board_ids.add(uuid)

    for f in wanted:
        shutil.copy2(f, dst / f.name)

    lines = []
    for f in sorted(dst.iterdir()):
        if f.name in ("SHA256SUMS", "README.md"):
            continue
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        lines.append(f"{h}  {f.name}")
    (dst / "SHA256SUMS").write_text("\n".join(lines) + "\n")

    readme = PUBLISH_README
    if board_ids:
        readme += ("\n## Provenance\n\nCaptured from device UUID(s): "
                   + ", ".join(f"`{b}`" for b in sorted(board_ids))
                   + "\n\nThis is the RP2350 OTP CHIPID, a 64-bit per-die "
                     "identifier that the datasheet\ndescribes as a public "
                     "device ID. It is recorded so these captures can be tied "
                     "to\nthe specific silicon that produced them.\n")
    (dst / "README.md").write_text(readme)

    print(f"bundled {len(lines)} files into {dst}", file=sys.stderr)
    if board_ids:
        print(f"device UUID(s): {', '.join(sorted(board_ids))}", file=sys.stderr)
    print("\nBefore publishing, confirm this board has never held key material\n"
          "and never will. Record it as a characterisation board.", file=sys.stderr)
    return 0


def cmd_ports(args) -> int:
    from ezlib.link import find_ports

    ports = find_ports()
    if not ports:
        print("no serial ports found", file=sys.stderr)
        return 1
    for p in ports:
        tag = " <- Raspberry Pi USB vendor ID" if p.vid == 0x2E8A else ""
        print(f"{p.device:20s} {p.description}{tag}")
    return 0


def cmd_selftest(args) -> int:
    """Check the analysis against sources whose entropy we already know."""
    import numpy as np
    from ezlib import basic, sp80090b, standards

    rng = np.random.default_rng(20260902)
    n = args.bits

    cases = [
        ("uniform", rng.integers(0, 2, n, dtype=np.uint8), 1.000),
        ("biased p=0.70", (rng.random(n) < 0.70).astype(np.uint8), 0.515),
        ("biased p=0.60", (rng.random(n) < 0.60).astype(np.uint8), 0.737),
        ("period-8 pattern", np.tile(
            np.array([1, 1, 0, 1, 0, 0, 0, 1], dtype=np.uint8), n // 8), 0.000),
    ]

    print(f"{'source':20s} {'H_true':>8s} {'H_est':>8s} {'limiting':>22s}  verdict")
    ok = True
    for name, bits, h_true in cases:
        a = sp80090b.assess_bits(bits, quick=args.quick)
        # A min-entropy estimator must not overstate; understating is safe.
        good = a.h_min <= h_true + 0.06
        ok = ok and good
        print(f"{name:20s} {h_true:8.3f} {a.h_min:8.3f} {a.limiting:>22s}  "
              f"{'ok' if good else 'OVERSTATES'}")

    uni = cases[0][1]
    ais = standards.ais31(uni)
    fips = standards.fips_140_2(uni)
    print(f"\nAIS-31 on uniform data:      "
          f"{'pass' if ais['pass'] else 'FAILED ' + str(ais['failed'])}")
    print(f"FIPS 140-2 on uniform data:  "
          f"{'pass' if fips['pass'] else 'FAILED'}")
    ok = ok and ais["pass"] and fips["pass"]

    print("\nself-test", "passed" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_collect_args(p):
        p.add_argument("--port", required=True, help="serial device, e.g. /dev/ttyACM0")
        p.add_argument("--out", required=True, help="output directory")
        p.add_argument("--raw-bytes", type=int, default=196608,
                       help="raw capture size per round (default: fills the buffer)")
        p.add_argument("--cond-bytes", type=int, default=65536,
                       help="conditioned capture size, 0 to skip")
        p.add_argument("--full-standards", action="store_true",
                       help="size both captures so every size-limited test "
                            "runs: 393,216 bytes each, set by AIS-31 T0")
        p.add_argument("--sample-cnt", type=int, default=None,
                       help="TRNG SAMPLE_CNT1: clocks between ROSC samples. "
                            "Default is the hardware reset value of 65535. "
                            "Lower is faster and may carry less entropy per bit")
        p.add_argument("--rosc", type=int, default=None, choices=[0, 1, 2, 3],
                       help="TRNG_CONFIG inverter chain length")
        p.add_argument("--rounds", type=int, default=1,
                       help="raw capture rounds, concatenated (use 2+ for AIS-31 T0)")
        p.add_argument("--sweep", action="store_true",
                       help="sweep inverter chain length against sample interval")
        p.add_argument("--restart", action="store_true",
                       help="collect the SP 800-90B restart matrix (slow)")
        p.add_argument("--allow-storage", action="store_true",
                       help="release the storage guard before testing. Asserts "
                            "this board has never held key material "
                            "(EZ-SEC-001 SEC-FW-004, SEC-PTR-002)")
        p.add_argument("--sd-detect", choices=["low", "high", "ignore"],
                       default=None,
                       help="card-detect polarity, or 'ignore' for boards with "
                            "no detect switch")
        p.add_argument("--no-device-tests", action="store_true",
                       help="skip the board subsystem checks (pins, clocks, "
                            "AON timer, FRAM, microSD) and capture entropy "
                            "only. Device identity and telemetry still travel "
                            "inside each capture; this only omits the "
                            "subsystem test results and device.json")
        p.add_argument("-v", "--verbose", action="store_true")

    def add_analyze_args(p):
        p.add_argument("--report", help="output HTML path")
        p.add_argument("--sequences", type=int, default=0, metavar="M",
                       help="also run SP 800-22 across M independent sequences "
                            "and score by proportion passing, which is how the "
                            "specification intends the suite to be used and the "
                            "only way the random excursion tests reliably apply")
        p.add_argument("--entropy-bits", type=int, default=8_000_000,
                       metavar="N",
                       help="cap the SP 800-90B assessment at N bits "
                            "(default 8,000,000). SP 800-22 always runs over "
                            "the whole capture. Set 0 for no cap")
        p.add_argument("--sts-whole-bits", type=int, default=20_000_000,
                       metavar="N",
                       help="cap the single-sequence SP 800-22 pass at N bits "
                            "(default 20,000,000) to bound memory. The "
                            "--sequences pass always covers the whole capture")
        p.add_argument("--no-pair", action="store_true",
                       help="do not also analyse the other capture in the directory")
        p.add_argument("--quick", action="store_true",
                       help="skip the slowest estimators and tests")
        p.add_argument("--nist-tool",
                       help="path to NIST ea_non_iid; its result is preferred "
                            "when it is more conservative")

    p = sub.add_parser("collect", help="run the board tests and pull captures")
    add_collect_args(p)
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("analyze", help="analyse a capture directory or file")
    p.add_argument("path")
    add_analyze_args(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("all", help="collect then analyse")
    add_collect_args(p)
    add_analyze_args(p)
    p.set_defaults(func=cmd_all)

    p = sub.add_parser("publish",
                       help="bundle a run into publishable evidence with checksums")
    p.add_argument("path", help="run directory, e.g. runs/r3")
    p.add_argument("--out", required=True, help="output directory for the bundle")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("bootsel", help="reboot the board into firmware update mode")
    p.add_argument("--port", required=True)
    p.set_defaults(func=cmd_bootsel)

    p = sub.add_parser("guard", help="inspect or release device safety policies")
    p.add_argument("--port", required=True)
    p.add_argument("--release", action="store_true",
                   help="mark the board as a test board so storage tests run")
    p.add_argument("--sd-detect", choices=["low", "high", "ignore"], default=None)
    p.set_defaults(func=cmd_guard)

    p = sub.add_parser("ports", help="list candidate serial ports")
    p.set_defaults(func=cmd_ports)

    p = sub.add_parser("selftest", help="validate the analysis on known sources")
    p.add_argument("--bits", type=int, default=400_000)
    p.add_argument("--quick", action="store_true")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
