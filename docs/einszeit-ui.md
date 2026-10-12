# Einszeit V1 — User Interface

**Document:** EZ-UI-001
**Status:** Rev 3, 2026-10-12. Describes the interface as built and tested on V1 hardware. The decisions from review are in §15.
**Related:** EZ-SEC-001 (security requirements), EZ-IMPL-001 (implementation)

---

## Terms

These words are used the same way on every screen, in `ez`, in the CLI and in these documents. The technical names in the right-hand column appear only in `ez`, the CLI and the specifications.

| Term | Meaning | Technical name |
|---|---|---|
| **Card** | The microSD card. Normally a **mirrored** card: it holds two copies of every key. | drive 1 |
| **Card copy A, B** | The two copies of the card's keys, each in its own volume on the card. One damaged copy loses nothing; the device repairs it from the other. | copy volumes 0 and 1 |
| **Card mirror** (Mirror) | Keeping copies A and B the same. Its state: `ok`, `syncing`, `DEGRADED`. The device checks and repairs it by itself, in the background. | health ok / syncing / degraded |
| **Internal storage** (Internal) | Flash memory inside the device, protected from the bootloader (TR-06). Keys can live here alone, or as spare copies. | drive 0 |
| **Spare copy** | An extra copy of a card key in internal storage, so the key survives a lost or failed card. Turned on when a key is made, or later with P on the Keys screen. | critical (`EZ_SESS_CRITICAL`, `SESSION_CRITICAL`) |
| **Transfer card** | A second card that carries a key to the other party (export and import). Keys leave the device only this way. | |
| **Key** | One key and what it is used for: its label, role, and how much is left to send and to receive. | session |

"Backup" is not used: it suggests a copy on a computer, and keys never leave the device except on a card.

## 1. Goals

1. **The device is usable with nothing but a terminal program.** PuTTY, screen, minicom or Tera Term, as with Blaustahl. No host software is needed to send or receive a message, or to manage keys.
2. **An average user never sees the CLI.** The first thing on screen is Home: the logo, the menu and the device's live status. Everything a user needs is reachable from the menu with the arrow keys and Enter.
3. **The CLI is for advanced users, diagnostics and development.** It's reachable from the menu, with a short, consistent grammar (§12).
4. **The interface never freezes.** All long work runs on the second core (IMPL-JOB-001). The interface shows progress and stays responsive.
5. **Pure VT100.** Cursor addressing, inverse video and bold, and nothing else: no colour, no line-drawing set, no Unicode. Emphasis is inverse video.
6. **`ez` (HID) keeps working unchanged** for scripts and power users.

## 2. Security constraints the interface must respect

| # | Constraint | Consequence for the interface |
|---|---|---|
| UI-S1 | Key material never crosses USB (EZ-SEC-001; verified by the key-byte scan in `test_proto`) | A key leaves the device **only on a transfer card** (§2.9 of EZ-IMPL-001), never by a file transfer. Import is from a card. |
| UI-S2 | The terminal is the host: it sees all plaintext and ciphertext | Same trust as `ez`. Plaintext buffers on the device are wiped when a screen is left, on timeout (§10) and on disconnect. |
| UI-S3 | Every use of key material is confirmed (SEC-UI-003) | Encrypting shows the key's label and how many bytes it will consume, and needs an explicit `y`. |
| UI-S4 | Production images have no path into the bootloader (IMPL-DRV-004) | The production terminal has no `fw update`, raw storage access, TR-05 or `sd stress`. The post-link check (`check_production.cmake`) rejects the development commands' functions. |
| UI-S5 | Plaintext is written out only after verification (IMPL-CLI-003) | Receive shows nothing of a message until its integrity check has passed. |

## 3. Screen layout (80×24)

```
 Home  Send  Receive  Keys  Device  CLI  Help                        [Einszeit]
--------------------------------------------------------------------------------

                          (content area: rows 3 to 23)

 Keys 3 | Mirror ok | Card 31.7 GB, 2 copies | Internal on | idle
```

- **Row 1, the menu bar.** The selected item is in inverse video. Left/Right move along it and Enter opens an item; a letter opens one directly: H Home, S Send, R Receive, K Keys, D Device, C CLI, `?` Help. Esc returns to the bar.
- **Screens with nothing to operate** (Home, Device, Help) leave the arrow keys on the menu bar. On the others, Left/Right go back to the bar one step along.
- **Row 2** is a line of ASCII dashes.
- **Row 24, the status line,** in inverse video. It is redrawn when it changes (checked every second) and shows the number of keys, the card mirror, the card, internal storage and the current job with its progress.
- Ctrl-L redraws the screen.

## 4. Home

```
 Home  Send  Receive  Keys  Device  CLI  Help                        [Einszeit]
--------------------------------------------------------------------------------

      ________________________________
     |  _|   |   |  _|_  |  _|  |_   _|
     |  _|   |   |_  |  _|  _|   |   |
     |___|___|_|_|___|___|___|___|___|


     Device   9bae095b4556f8f4          Mirror   ok
     Keys     3 (1 with a spare copy)   Card     31.7 GB, 2 copies
     Internal on, protected             Job      idle
     Firmware 0.4.1-dev                 DEVELOPMENT: never for real secrets

     Left/Right and Enter, or press a letter:  H S R K D C ?    Esc: the menu
 Keys 3 | Mirror ok | Card 31.7 GB, 2 copies | Internal on | idle
```

- **Home is where the device starts** (the terminal is reset on connect), and the menu's first item returns to it from anywhere.
- **Home shows everything that needs attention.** Less important detail (metadata, failovers, check times) lives under Device.
- **It updates by itself:** a card inserted or removed appears within a second, the mirror goes through `syncing` to `ok`, and a job shows its progress.
- **Warnings appear here,** in inverse video:
  - the card mirror DEGRADED, with the reason in plain words ("one of the card's two copies is unavailable", "a key's spare copy is missing", and so on);
  - development firmware;
  - the outcome of a key generated in the background ("Key 'x' is ready").

## 5. Send

1. **Choose the key.** Only if more than one key can send: a pick list with each key's label and what it has left to send.
2. **Write the message** in the editor (Zetta, §9), full screen, with the key and what it has left in the title.
   - Type or paste text.
   - Or **upload a file** with Ctrl-O. ZMODEM or XMODEM is detected by itself (§11a). The file is encrypted after a confirmation with its size, without being shown.
3. **Encrypt** with Ctrl-E. The confirmation reads *"Encrypt 1284 bytes for 'alice'? 63226 bytes of key will remain."* (`y`/`n`).
4. **The message** is shown as base64 in a read-only view:
   - **C** shows it plainly, with no frame, for copying from the terminal;
   - **D** downloads it as `message.ez` (ZMODEM, or XMODEM if the terminal asks for it);
   - **Enter** wipes it and clears the screen and scrollback.

The plaintext is wiped as soon as encryption succeeds, and on Esc, Ctrl-X, timeout or disconnect.

## 6. Receive

1. **Paste the message** (base64). A capture mode decodes it as it arrives, ignoring line breaks and anything that isn't base64; a counter shows the bytes received. The first bytes are checked, so a wrong paste is recognised almost at once.
   - **Or upload the message file:** start a ZMODEM upload from the terminal (recognised with no key press), or press Ctrl-R (ZMODEM or XMODEM).
2. **The key is chosen automatically** by the Key ID in the message header.
3. **Decrypt.** The plaintext appears **only after** the integrity check passes (UI-S5), in the same read-only view as Send: C copy view, D download as `message.txt`, Enter done.
4. **Errors are in plain words,** and the screen is then ready for the next paste:
   - "Changed or damaged in transit"; nothing is shown and no key is used;
   - "Already received";
   - an unknown key, or a message for the other direction.

## 7. Message size

**The terminal handles messages up to 64 KiB, in both directions** (decided). That is the device's stage size, so the terminal uses the same buffered, verified path as `ez`: a decrypted message is checked in full before any of it is shown. Larger messages are sent and received with `ez`, which streams them; the interface says so.

## 8. Keys (the key manager)

```
 Home  Send  Receive  Keys  Device  CLI  Help                        [Einszeit]
--------------------------------------------------------------------------------
  Label        Key ID    Where        Role  Send left        Receive left
> alice        99042149  card+spare   alice [#######.]   12K [########]   16K
  d0           9445F6EE  internal     alice [########]   32K [########]   32K
  bob-old      1A2B3C4D  card         bob   QUARANTINED


 Enter details  N new  I import  X export  P spare  D delete  S skip  Q resolve
 Keys 3 | Mirror ok | Card 31.7 GB, 2 copies | Internal on | idle
```

- **Where** is `card`, `internal` or `card+spare`.
- **Up/Down** selects a key and **Enter** shows its details: Key ID, size, where, role, state, what is left.
- **N, new key:** size (64 KiB to 2 MiB, each with how much it can send and how long it takes), label, and where: *On the card*, *On the card, with a spare copy*, or *Internal storage only*. A key for the card is generated in internal storage when it is on, then copied to the card in one burst. Esc continues in the background, and C cancels.
- **I, import:** from the card; lists key files that no key uses, then asks for a label and the role.
- **X, export:** to a **transfer card** (UI-S1). The key is held in internal storage while you swap the cards: remove yours, insert the transfer card, copy and verify, remove it, reinsert yours.
- **P, spare copy:** turns a card key's spare copy in internal storage on or off.
- **D, delete:** the label must be typed. Deletion is never blocked by a degraded card mirror.
- **S, skip** past damaged key units, and **Q, resolve** a quarantine, each with confirmation. "Key missing" quarantines lift themselves.

## 9. The editor: Zetta

Zetta (Zeitlos `sw/common/zetta.c`) is vendored in `third_party/zetta/`, its code unmodified. It suits this use:
- **Embedded and event-driven:** the interface feeds it bytes with `zetta_key()`; it never reads the terminal itself.
- **No heap:** the text buffer is the interface's, so Einszeit can wipe it.
- **App actions** appear in its help bar and Esc menu: Encrypt (Ctrl-E), Upload a file (Ctrl-O), Cancel.
- **Dialogs** (`zetta_confirm`) for the confirmations.

This copy of Zetta is licensed under BSD-1-Clause (`third_party/zetta/LICENSE.md`).

**Wiping:** the editor buffer and Zetta's state are zeroed when Send is left, and after encryption.

## 10. Timeout and screen privacy

- **After 10 minutes without input,** an open editor, message or capture is closed and wiped, and the device returns to Home.
- **A screen lock (deferred, decided):** a PIN or passphrase to unlock the interface, later, with its own security requirements (attempt limits, storage in F-RAM).

## 11. Images and USB

| Image | USB interfaces | `bcdDevice` | Terminal |
|---|---|---|---|
| `einszeit_hid` (production) | HID (`ez`) | 0x0101 | none |
| `einszeit_cdc` (production) | CDC | 0x0102 | the interface; `ez` cannot connect |
| `einszeit_composite` (production) | CDC + HID | 0x0103 | the interface, and `ez` |
| `einszeit_dev` (development) | CDC + HID | 0x0110 | the same, plus the development commands (`fw update`, `sd stress`, TR-05, Ctrl-Y into the bootloader) |

The production images pass a post-link check that rejects the development commands' functions and any path into the bootloader. Windows 10 and 11 should load the CDC and HID class drivers without an installer (OI-05, still to be tested).

### 11a. File transfers

Each protocol is its own module in `xfer/`, written from its protocol description with no outside code, and tested on its own and against lrzsz (see `xfer/README.md`). `xfer/ez_xfer` detects the protocol, so users need not know what their terminal speaks:
- **Uploads to the device:** it listens for ZMODEM first, then asks for XMODEM after 6 seconds.
- **Downloads:** it starts as ZMODEM, so many terminals begin receiving by themselves, and switches to XMODEM if the terminal asks.

YMODEM and Kermit are planned as further modules.

## 12. The CLI

### 12.1 Commands

| Command | Short | Purpose |
|---|---|---|
| `keys` | `k` | List keys |
| `key <label> [info\|check]` | | One key: details, or check every copy |
| `ls [card\|a\|b\|internal]` | `l` | List files: the card (`1`), one card copy (`a`, `b`), internal storage (`0`) |
| `status` | `s` | Device, storage, card mirror, job |
| `mirror [check]` | | The card mirror's health; `check` starts a full check |
| `card format [1\|2] [erase]` | | Format the card, with one or two copies (asks for `YES`) |
| `erase` | | Erase the device (asks for `YES`) |
| `log` | | The event log |
| `menu` / Esc | | Back to the menu |
| *development image only:* `info`, `fw update`, `sd stress`, `sd test`, `tr05 …` | | Development and test (`dev` lists them) |

- **No encrypt or decrypt in the CLI** (decided): large pastes are accepted in one place, the Send and Receive screens.
- **Long commands run as jobs** on core 1; the CLI prints the result when the job ends.
- **Drive names:** `internal` = `0` = drive 0, and `card` = `1` = drive 1, as in `ez` (`--drive 0`, `--drive 1`). The CLI also accepts the older `flash` and `sd`.

## 13. Internal storage on by default

Internal storage is enabled by default **when its protection is verified** (the partition table is installed, TR-06). Without verified protection it stays off, and Home says why. This reverses DEV-04's default now that TR-06 has passed, and it makes generating keys in internal storage (IMPL-AV-006) the normal path.

## 14. Architecture

```
ui/include/ez_ui.h, ui/src/ez_ui.c   the interface: menu bar, status line, screens, dialogs,
                                     flows, CLI; portable C, no heap
xfer/                                ez_xmodem, ez_zmodem, ez_xfer (detection)
third_party/zetta/                   the editor (vendored)
fw/einszeit/src/main_ui.c            the terminal images' main loop (core 0)
fw/einszeit/src/main_prod.c          einszeit_hid's main loop
fw/einszeit/src/app.c                boot, the second core, stacks
sw/vdev/                             ez-vdev: the virtual device, with --term for the interface
```

- **All interface code runs on core 0;** all long work runs on core 1 as jobs (IMPL-JOB-001). The interface calls the same dispatcher as `ez`, so both share one tested path into the core. A job's result is kept under its ticket, so a background sync can't overwrite it.
- **Stacks:** each core has a 16 KB stack in main RAM, with its stack-limit register set, so an overflow faults instead of overwriting memory (IMPL-JOB-003). The development image's `info` reports the deepest each has been.
- **It's portable:** the interface reads input bytes and writes output bytes through two functions.
- **Host testing:** `ez-vdev --term` serves the interface on a socket. `tests/ui/test_ui.py` drives it with a VT100 emulator (`pyte`) and compares screens; `--worker` runs jobs on a second thread, as on the device.

## 15. Decisions from review

| # | Question | Decision |
|---|---|---|
| 1 | Menu items | **Home**, Send, Receive, Keys, **Device**, CLI, Help. Home returns to the welcome screen. Device holds what shouldn't clutter Home; Home shows all critical information. |
| 2 | How keys leave the device | Only on a card. |
| 3 | Message size on the terminal | 64 KiB, both directions; larger messages with `ez`. |
| 4 | Screen lock | Later. |
| 5 | Encrypt and decrypt in the CLI | Removed: one place accepts large pastes. |
| 6 | Colour | None. Pure VT100, with inverse video for emphasis. |
| 7 | Separator and Home | ASCII dashes under the menu bar; Home shows the logo only, no tagline. |
| 8 | Terms | **Internal storage** for drive 0, **spare copy** for a critical key's copy there; "backup" is not used (see Terms). |
