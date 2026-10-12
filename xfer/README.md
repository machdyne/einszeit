# File transfer protocols (xfer/)

Einszeit is a security tool that may meet a terminal supporting only one
transfer protocol, so it supports several. Each lives in its own module,
written for Einszeit from the protocol's description, with no code taken
from elsewhere, and is tested on its own:

| Module | Protocol | Status |
|---|---|---|
| `ez_xmodem` | XMODEM, XMODEM-CRC, XMODEM-1K | Round 21 |
| `ez_ymodem` | YMODEM (batch, file length) | Planned |
| `ez_zmodem` | ZMODEM (CRC-16/32, ZRPOS recovery, escaping, one file each way) | Round 22 |
| `ez_xfer` | Detection: picks XMODEM or ZMODEM by what the other side does | Round 22 |
| `ez_kermit` | Kermit | Planned |

**Common shape:**
- portable C11, no heap, never blocking;
- bytes go in through `*_input()` and out through an `out()` callback;
- `*_tick()` handles the timeouts, with a millisecond clock supplied by the caller;
- received data goes to a `sink()` callback.

**Tests:**
- `tests/unit/test_<module>.c`: the module on its own, two instances over a simulated line with simulated time and injected faults (corruption, loss, cancels, timeouts).
- `tests/xfer/test_interop.py`: the module against lrzsz (`sx`/`rx`, and `sb`/`rb`, `sz`/`rz` later), an independent implementation. lrzsz is a test tool only; nothing from it is in Einszeit.
- `tests/ui/test_ui.py`: transfers through the terminal interface, against lrzsz.

**Detection (`ez_xfer`):**
- **Receiving:** one ZMODEM `ZRINIT` (terminals such as Tera Term may open their upload dialog by themselves), then quiet, answering only a ZMODEM sender's `ZRQINIT`. After 6 s without one, it asks with `C` as an XMODEM receiver.
- **Why in that order:**
  - Asking with `C` first makes lrzsz's `sz` fall back to YMODEM.
  - Repeating `ZRINIT` cancels XMODEM senders: every ZMODEM header carries a CAN, and two cancel lrzsz's `sx`.
- **Sending:** as a ZMODEM sender (`rz\r` and `ZRQINIT`, so terminals start their receiver by themselves), switching to XMODEM when the receiver asks with `C` or NAK.
- **On the Receive screen,** a ZMODEM upload the terminal starts on its own is recognised by `ZPAD ZDLE` (neither byte is base64). From then on the device writes nothing to the screen: the terminal's ZMODEM program reads everything, and `sz` took the `C` in a "Ctrl-X" prompt for an XMODEM receiver.

**ZMODEM security:** `ZCOMMAND` (run a command) is never executed; it aborts the transfer. A file over the receiver's limit is refused with `ZSKIP`; further files in a batch are skipped.

**XMODEM's limit:** it carries no file length. The sender pads the last block with SUB (0x1A), and Einszeit strips trailing SUB bytes from an upload (so a binary file that genuinely ends in 0x1A loses them). `ez decrypt` strips them from a downloaded message. YMODEM carries the length.
