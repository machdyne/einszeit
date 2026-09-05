"""Drives a board through the full validation sequence and archives the output."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import time

from .container import Capture, write_sidecar
from .link import Device, DeviceError


def _say(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _bar(done: int, total: int) -> None:
    if not total:
        return
    frac = done / total
    width = 34
    filled = int(frac * width)
    sys.stderr.write(f"\r    [{'#' * filled}{'.' * (width - filled)}] "
                     f"{frac * 100:5.1f}%  {done:,}/{total:,} B")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\n")


DEVICE_BUFFER_BYTES = 196608   # EZ_CAP_MAX; confirmed from `info --json`


def _capture_total(dev, total_bytes, mode, sample_cnt, rosc, buffer_bytes,
                   partial_path=None):
    """Collect `total_bytes` in as many device-buffer-sized rounds as needed.

    The device buffer caps a single capture at 192 KB, but AIS-31 T0 alone
    wants 3,145,728 bits (393,216 bytes), so anything approaching full
    standards coverage has to be assembled from several captures.
    """
    import math

    rounds = max(1, math.ceil(total_bytes / buffer_bytes))
    chunks, meta, got = [], {}, 0

    # A 10^8-bit capture runs for hours. Persisting each round as it lands
    # means a USB glitch at round 60 costs one round, not the whole night.
    fh = open(partial_path, "wb") if partial_path else None

    try:
        for i in range(rounds):
            want = min(buffer_bytes, total_bytes - got)
            if want <= 0:
                break
            if rounds > 1:
                pct = 100.0 * got / total_bytes
                _say(f"  round {i + 1}/{rounds}, {want:,} bytes "
                     f"({pct:.1f}% of the capture done)")
            try:
                cap = dev.capture(want, mode=mode, sample_cnt=sample_cnt,
                                  rosc=rosc, on_progress=_bar)
            except Exception as exc:
                _say(f"\n  ! round {i + 1} failed: {exc}")
                if fh and got:
                    _say(f"  {got:,} bytes from earlier rounds are saved at "
                         f"{partial_path}")
                raise
            chunks.append(cap.payload)
            meta = cap.meta
            got += cap.nbytes
            if fh:
                fh.write(cap.payload)
                fh.flush()
                os.fsync(fh.fileno())
    finally:
        if fh:
            fh.close()

    joined = Capture(payload=b"".join(chunks), meta=dict(meta))
    joined.meta["rounds"] = len(chunks)
    joined.meta["total_bytes"] = joined.nbytes
    joined.meta["concatenated"] = len(chunks) > 1
    return joined


def run_device_tests(dev: Device, sample_cnt=None, rosc=None) -> dict:
    """Everything that is not an entropy capture."""
    out: dict = {}

    # `hrng health` reports throughput and health-test error rates. Left at the
    # boot default it would describe SAMPLE_CNT1=65535 while the capture beside
    # it in the same report ran at something else, which makes the two figures
    # silently incomparable. Apply the capture's configuration first.
    if sample_cnt is not None or rosc is not None:
        cfg = "hrng cfg"
        if rosc is not None:
            cfg += f" rosc {rosc}"
        if sample_cnt is not None:
            cfg += f" sample {sample_cnt}"
        _say(f"  {cfg}")
        dev.command(cfg, timeout=15)
        out["trng_cfg_applied"] = {"sample_cnt": sample_cnt, "rosc": rosc}

    steps = [
        ("info", "info --json", 15),
        ("pins", "pins --json", 20),
        ("clock", "clock --json", 20),
        ("aon", "clock aon 5000 --json", 30),
        ("fram_id", "fram id --json", 15),
        ("fram_test", "fram test 4096 --json", 60),
        ("sd", "sd info --json", 60),
        ("hrng_info", "hrng info --json", 15),
        ("hrng_health", "hrng health 128 --json", 300),
    ]

    for key, cmd, timeout in steps:
        _say(f"  {cmd}")
        try:
            resp = dev.command(cmd, timeout=timeout)
        except DeviceError as exc:
            _say(f"    ! {exc}")
            out[key] = {"error": str(exc)}
            continue
        out[key] = resp.json if resp.json else {"text": resp.text, "rc": resp.rc}
        if resp.rc == 3:
            # rc=3 is a policy refusal, not a hardware failure. Say which.
            if key.startswith("sd"):
                _say("    ! refused: no card detected. If this board has no "
                     "detect switch,")
                _say("      re-run with --sd-detect ignore (check with "
                     "'sd det' on the device)")
            else:
                _say("    ! refused by the storage guard: the FRAM is not blank "
                     "and is not")
                _say("      marked as a test board. If it has never held key "
                     "material, re-run")
                _say("      with --allow-storage")
        elif resp.rc != 0:
            _say(f"    ! returned rc={resp.rc}")

    # Fold the two FRAM results into one section for the report.
    fram = {}
    if isinstance(out.get("fram_id"), dict):
        fram.update({k: v for k, v in out["fram_id"].items() if k != "text"})
    if isinstance(out.get("fram_test"), dict):
        fram.update({f"test_{k}": v for k, v in out["fram_test"].items()
                     if k != "text"})
    out["fram"] = fram
    return out


def collect(port: str, outdir: pathlib.Path, *, cond_bytes: int = 65536,
            raw_bytes: int = 196608, rounds: int = 1, sweep: bool = False,
            restart: bool = False, restart_rows: int = 1000,
            restart_row_bytes: int = 125, skip_device_tests: bool = False,
            sample_cnt: int = None, rosc: int = None,
            allow_storage: bool = False, sd_detect: str = None,
            verbose: bool = False) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"port": port, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "sample_cnt": sample_cnt, "rosc": rosc,
                      "device_tests_run": not skip_device_tests}

    with Device(port, verbose=verbose) as dev:
        _say(f"connecting to {port}")
        dev.sync()
        _say("device is responding")

        # Policy first: both of these otherwise refuse every storage command
        # and there is no point discovering that halfway through a run.
        if sd_detect:
            _say(f"\nsetting card-detect policy: {sd_detect}")
            dev.command(f"sd det {sd_detect}", timeout=15)
        if allow_storage:
            _say("releasing the storage guard (asserting no key material)")
            r = dev.command("guard claim --force --no-key-material", timeout=30)
            if r.rc != 0:
                _say(f"  ! guard release failed rc={r.rc}: {r.text.strip()[:200]}")
            else:
                _say("  storage tests permitted")

        if not skip_device_tests:
            _say("\nboard subsystem tests")
            manifest["device"] = run_device_tests(dev, sample_cnt, rosc)
            (outdir / "device.json").write_text(
                json.dumps(manifest["device"], indent=2))

        # -- raw noise source, the capture the entropy claim rests on ------
        if raw_bytes:
            total = raw_bytes * max(1, rounds)
            _say(f"\nraw noise capture, {total:,} bytes")
            _say("  health tests and the Von Neumann balancer are bypassed;")
            _say("  bias in this data is expected and is the point")
            joined = _capture_total(dev, total, "raw", sample_cnt, rosc,
                                    DEVICE_BUFFER_BYTES,
                                    partial_path=outdir / "raw.bin.partial")
            write_sidecar(outdir / "raw.bin", joined)
            (outdir / "raw.bin.partial").unlink(missing_ok=True)
            manifest["raw"] = {"bytes": joined.nbytes, "file": "raw.bin"}
            _say(f"  received {joined.nbytes:,} bytes ({joined.nbytes * 8:,} bits)")

        # -- conditioned output, for comparison ----------------------------
        if cond_bytes:
            eff = sample_cnt if sample_cnt is not None else 65535
            rate = 150e6 / (eff + 1) / 4
            _say(f"\nconditioned capture, {cond_bytes:,} bytes")
            _say(f"  SAMPLE_CNT1={eff}: about {rate:.0f} bit/s, "
                 f"ETA {cond_bytes * 8 / rate / 60:.1f} min")
            cap = _capture_total(dev, cond_bytes, "cond", sample_cnt, rosc,
                                 DEVICE_BUFFER_BYTES,
                                 partial_path=outdir / "conditioned.bin.partial")
            write_sidecar(outdir / "conditioned.bin", cap)
            (outdir / "conditioned.bin.partial").unlink(missing_ok=True)
            manifest["conditioned"] = {"bytes": cap.nbytes, "file": "conditioned.bin"}
            _say(f"  received {cap.nbytes:,} bytes ({cap.nbytes * 8:,} bits)")

        # -- restart matrix -------------------------------------------------
        if restart:
            _say(f"\nrestart matrix, {restart_rows} x {restart_row_bytes} bytes")
            cap = dev.restart_matrix(restart_rows, restart_row_bytes,
                                     mode="raw", on_progress=_bar)
            write_sidecar(outdir / "restart.bin", cap)
            manifest["restart"] = {"bytes": cap.nbytes, "file": "restart.bin"}

        # -- sampling sweep -------------------------------------------------
        if sweep:
            _say("\nsampling interval sweep (4 chain lengths x 12 intervals)")
            resp = dev.command("hrng sweep 48 raw", timeout=3600)
            (outdir / "sweep.csv").write_text(resp.text + "\n")
            manifest["sweep"] = {"file": "sweep.csv"}
            _say("  written to sweep.csv")

    manifest["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest
