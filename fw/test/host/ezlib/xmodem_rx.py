"""XMODEM / XMODEM-1K receiver.

Implemented here rather than pulled from PyPI so the only dependency is
pyserial, and so the framing quirks that matter for this device (1K blocks,
CRC-16 preferred, duplicate-block tolerance) are visible and adjustable.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

SOH = 0x01
STX = 0x02
EOT = 0x04
ACK = 0x06
NAK = 0x15
CAN = 0x18


class XmodemError(Exception):
    pass


def _crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def receive(
    ser,
    timeout: float = 120.0,
    progress: Optional[Callable[[int], None]] = None,
    max_errors: int = 20,
) -> bytes:
    """Receive one XMODEM stream and return the raw bytes, padding included.

    The caller trims padding using the container header; doing it here would
    require guessing, and guessing wrong corrupts the tail of a capture.
    """
    ser.reset_input_buffer()

    chunks: list[bytes] = []
    expected = 1
    errors = 0
    started = False
    deadline = time.monotonic() + timeout

    # Poll with 'C' until the sender starts, which requests CRC-16 mode.
    last_poll = 0.0
    while not started:
        if time.monotonic() > deadline:
            raise XmodemError("sender never started (no SOH/STX seen)")
        if time.monotonic() - last_poll > 1.0:
            ser.write(b"C")
            ser.flush()
            last_poll = time.monotonic()
        head = ser.read(1)
        if head and head[0] in (SOH, STX):
            started = True
            break
        if head and head[0] == CAN:
            raise XmodemError("sender cancelled during handshake")

    while True:
        if head is None or not head:
            head = ser.read(1)
            if not head:
                errors += 1
                if errors > max_errors:
                    _cancel(ser)
                    raise XmodemError("timed out waiting for a block header")
                ser.write(bytes([NAK]))
                ser.flush()
                continue

        tok = head[0]
        head = None

        if tok == EOT:
            ser.write(bytes([ACK]))
            ser.flush()
            break
        if tok == CAN:
            raise XmodemError("sender cancelled the transfer")
        if tok not in (SOH, STX):
            continue  # line noise between blocks

        size = 1024 if tok == STX else 128
        body = _read_exact(ser, 2 + size + 2)
        if body is None:
            errors += 1
            if errors > max_errors:
                _cancel(ser)
                raise XmodemError("truncated block")
            ser.write(bytes([NAK]))
            ser.flush()
            continue

        blk, blk_inv = body[0], body[1]
        data = body[2 : 2 + size]
        crc = (body[2 + size] << 8) | body[2 + size + 1]

        if (blk ^ blk_inv) != 0xFF or _crc16(data) != crc:
            errors += 1
            if errors > max_errors:
                _cancel(ser)
                raise XmodemError("too many corrupt blocks")
            ser.write(bytes([NAK]))
            ser.flush()
            continue

        if blk == ((expected - 1) & 0xFF):
            # The sender missed our ACK and resent; acknowledge, discard.
            ser.write(bytes([ACK]))
            ser.flush()
            continue
        if blk != (expected & 0xFF):
            _cancel(ser)
            raise XmodemError(f"block out of sequence: got {blk}, expected {expected & 0xFF}")

        chunks.append(data)
        expected += 1
        ser.write(bytes([ACK]))
        ser.flush()
        if progress:
            progress(len(chunks) * 0 + sum(len(c) for c in chunks))

    return b"".join(chunks)


def _read_exact(ser, n: int, timeout: float = 5.0) -> Optional[bytes]:
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n:
        part = ser.read(n - len(buf))
        if part:
            buf.extend(part)
        elif time.monotonic() > deadline:
            return None
    return bytes(buf)


def _cancel(ser) -> None:
    ser.write(bytes([CAN] * 5))
    ser.flush()
