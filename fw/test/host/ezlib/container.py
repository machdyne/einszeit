"""Parsing for the EZTB transfer container written by the firmware.

Layout (little-endian), mirroring firmware/include/ez_container.h:

    0    8    magic b"EZTB0001"
    8    4    header_len (512)
    12   4    payload_len
    16   4    payload CRC-32 (IEEE, reflected)
    20   4    meta_len
    24   ...  metadata, JSON, ASCII
    512  ...  payload

The header exists because XMODEM pads its final block to a 128- or 1024-byte
boundary with 0x1A. Those pad bytes are not entropy and must never reach an
estimator, so the exact length travels with the data.
"""

from __future__ import annotations

import json
import struct
import zlib
from dataclasses import dataclass, field

MAGIC = b"EZTB0001"
HDR_BYTES = 1024          # 512 in firmware 1.0.0; header_len is authoritative
HDR_MIN = 24


class ContainerError(Exception):
    pass


@dataclass
class Capture:
    payload: bytes
    meta: dict = field(default_factory=dict)
    crc_ok: bool = True
    declared_crc: int = 0
    computed_crc: int = 0

    @property
    def nbytes(self) -> int:
        return len(self.payload)

    @property
    def nbits(self) -> int:
        return len(self.payload) * 8

    def describe(self) -> str:
        m = self.meta
        bits = f"{self.nbits:,} bits"
        mode = m.get("mode", "?")
        rosc = m.get("rosc_len", "?")
        samp = m.get("sample_cnt", "?")
        return f"{bits}, mode={mode}, rosc_len={rosc}, sample_cnt={samp}"


def parse(blob: bytes) -> Capture:
    """Parse a received container, trimming XMODEM padding."""
    if len(blob) < HDR_MIN:
        raise ContainerError(f"too short: {len(blob)} bytes, need at least {HDR_MIN}")
    if blob[:8] != MAGIC:
        raise ContainerError(f"bad magic {blob[:8]!r}, expected {MAGIC!r}")

    header_len, payload_len, crc, meta_len = struct.unpack_from("<IIII", blob, 8)
    # header_len is authoritative so captures from either firmware revision
    # parse; only reject values that cannot be real.
    if header_len < HDR_MIN or header_len > len(blob):
        raise ContainerError(f"implausible header length {header_len}")
    if meta_len > header_len - HDR_MIN:
        raise ContainerError(f"metadata length {meta_len} overruns the header")

    end = header_len + payload_len
    if end > len(blob):
        raise ContainerError(
            f"payload claims {payload_len} bytes but only "
            f"{len(blob) - header_len} arrived"
        )

    payload = blob[header_len:end]
    computed = zlib.crc32(payload) & 0xFFFFFFFF

    meta = {}
    if meta_len:
        raw = blob[24 : 24 + meta_len].decode("ascii", errors="replace")
        try:
            meta = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ContainerError(f"metadata is not valid JSON: {exc}") from exc

    return Capture(
        payload=payload,
        meta=meta,
        crc_ok=(computed == crc),
        declared_crc=crc,
        computed_crc=computed,
    )


def write_sidecar(path, cap: Capture) -> None:
    """Save the payload as .bin with its metadata alongside as .json."""
    import pathlib

    p = pathlib.Path(path)
    p.write_bytes(cap.payload)
    meta = dict(cap.meta)
    meta["_container"] = {
        "declared_crc32": f"0x{cap.declared_crc:08x}",
        "computed_crc32": f"0x{cap.computed_crc:08x}",
        "crc_ok": cap.crc_ok,
        "payload_bytes": cap.nbytes,
    }
    p.with_suffix(".json").write_text(json.dumps(meta, indent=2))


def read_sidecar(path) -> Capture:
    import pathlib

    p = pathlib.Path(path)
    payload = p.read_bytes()
    meta = {}
    mp = p.with_suffix(".json")
    if mp.exists():
        meta = json.loads(mp.read_text())
    return Capture(payload=payload, meta=meta, crc_ok=True)
