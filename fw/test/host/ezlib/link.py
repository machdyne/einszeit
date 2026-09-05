"""Drives the firmware's CLI over USB CDC.

The firmware terminates every command with a `[done rc=N]` line, so a response
can be read to completion without guessing at timeouts, and emits structured
results as a single `#JSON {...}` line. Progress lines start with `#`.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from . import container, xmodem_rx

DONE_RE = re.compile(rb"^\[done rc=(-?\d+)\]\s*$")
PROMPT = b"ez> "


@dataclass
class Response:
    rc: int
    text: str
    json: Optional[dict] = None
    progress: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.rc == 0


class DeviceError(Exception):
    pass


class Device:
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 1.0,
                 verbose: bool = False):
        try:
            import serial
        except ImportError as exc:  # pragma: no cover
            raise DeviceError(
                "pyserial is required: pip install pyserial"
            ) from exc

        # USB CDC ignores the baud rate, but pyserial insists on one.
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.verbose = verbose
        self.port = port
        time.sleep(0.2)
        self.ser.reset_input_buffer()

    def close(self) -> None:
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- primitives -------------------------------------------------------

    def _readline(self, timeout: float) -> Optional[bytes]:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            b = self.ser.read(1)
            if not b:
                continue
            if b == b"\n":
                return bytes(buf).rstrip(b"\r")
            if b == b"\r":
                continue
            buf.extend(b)
            # The prompt arrives without a newline; treat it as a line.
            if bytes(buf).endswith(PROMPT):
                return bytes(buf)
        return None

    def sync(self, attempts: int = 3) -> None:
        """Get to a known state: send a bare newline and drain to the prompt."""
        for _ in range(attempts):
            self.ser.reset_input_buffer()
            self.ser.write(b"\r\n")
            self.ser.flush()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                line = self._readline(0.5)
                if line is None:
                    break
                if line.endswith(PROMPT):
                    return
        raise DeviceError(
            f"no prompt from {self.port}. Is the validation firmware running? "
            "A fresh RP2350 in BOOTSEL enumerates as mass storage, not CDC."
        )

    def command(self, cmd: str, timeout: float = 30.0,
                on_progress=None) -> Response:
        """Run one command and collect output up to the `[done]` marker."""
        if self.verbose:
            print(f"  > {cmd}", file=sys.stderr)

        self.ser.reset_input_buffer()
        self.ser.write(cmd.encode() + b"\r")
        self.ser.flush()

        lines: list[str] = []
        payload: Optional[dict] = None
        progress: list = []
        deadline = time.monotonic() + timeout
        echo_seen = False

        while time.monotonic() < deadline:
            raw = self._readline(min(2.0, max(0.2, deadline - time.monotonic())))
            if raw is None:
                continue

            m = DONE_RE.match(raw)
            if m:
                return Response(int(m.group(1)), "\n".join(lines), payload, progress)

            text = raw.decode("utf-8", errors="replace")
            if not echo_seen and text.strip() == cmd.strip():
                echo_seen = True  # the shell echoes what we typed
                continue
            if text.startswith(PROMPT.decode()):
                continue

            if text.startswith("#JSON "):
                try:
                    payload = json.loads(text[6:])
                except json.JSONDecodeError:
                    lines.append(text)
                continue

            if text.startswith("# progress "):
                try:
                    done, total = text.split()[2].split("/")
                    progress.append((int(done), int(total)))
                    if on_progress:
                        on_progress(int(done), int(total))
                except (ValueError, IndexError):
                    pass
                continue

            lines.append(text)

        raise DeviceError(f"timed out after {timeout}s waiting for '{cmd}' to finish")

    # -- capture ----------------------------------------------------------

    def capture(self, nbytes: int, mode: str = "cond", rosc: Optional[int] = None,
                sample_cnt: Optional[int] = None, timeout: float = 3600.0,
                on_progress=None) -> container.Capture:
        """Run `hrng cap` then `send`, and return the parsed container."""
        cmd = f"hrng cap {nbytes} {mode}"
        if rosc is not None:
            cmd += f" rosc {rosc}"
        if sample_cnt is not None:
            cmd += f" sample {sample_cnt}"

        resp = self.command(cmd, timeout=timeout, on_progress=on_progress)
        if resp.rc != 0 and not resp.json:
            raise DeviceError(f"capture failed:\n{resp.text}")

        return self.fetch_buffer()

    def restart_matrix(self, rows: int = 1000, row_bytes: int = 125,
                       mode: str = "raw", timeout: float = 7200.0,
                       on_progress=None) -> container.Capture:
        resp = self.command(f"hrng restart {rows} {row_bytes} {mode}",
                            timeout=timeout, on_progress=on_progress)
        if resp.rc != 0 and not resp.json:
            raise DeviceError(f"restart matrix failed:\n{resp.text}")
        return self.fetch_buffer()

    def fetch_buffer(self, timeout: float = 300.0) -> container.Capture:
        """Trigger `send` and receive the container over XMODEM."""
        self.ser.reset_input_buffer()
        self.ser.write(b"send\r")
        self.ser.flush()

        # Wait for the firmware's "start your receiver now" line, then hand the
        # port to the XMODEM state machine. Anything still buffered would be
        # mistaken for line noise, so drain first.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            line = self._readline(1.0)
            if line and b"start your receiver" in line:
                break
        else:
            raise DeviceError("firmware did not offer a transfer; is the buffer empty?")

        blob = xmodem_rx.receive(self.ser, timeout=timeout)
        cap = container.parse(blob)

        # Drain the trailing summary so the next command starts clean.
        time.sleep(0.2)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            line = self._readline(0.5)
            if line is None or DONE_RE.match(line):
                break

        if not cap.crc_ok:
            raise DeviceError(
                f"payload CRC mismatch: device said 0x{cap.declared_crc:08x}, "
                f"received data hashes to 0x{cap.computed_crc:08x}"
            )
        return cap


def find_ports() -> list:
    """Candidate CDC ports, Raspberry Pi VID first."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    ports = list(list_ports.comports())
    ports.sort(key=lambda p: (p.vid != 0x2E8A, p.device))
    return ports
