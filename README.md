# Einszeit

Einszeit is an open-source security device intended to provide information-theoretically secure (one-time-pad based) encryption between two or more paired devices over any communications medium.

![Einszeit UI Screenshot](https://github.com/machdyne/einszeit/blob/322f3ac8f39f7a85bbcb756dacbb4696dd5df2d2/ss.png)

![Einszeit](https://github.com/machdyne/einszeit/blob/a18252655b3a970fcdf45a9b7ed6dc5c5770965d/einszeit.png)

> **Project status:** V1 hardware is in active development. See [Hardware Status](#hardware-status) and [Software Status](#software-status) below before using this project for anything beyond bench testing.

## Hardware Status

**V1: design complete, hardware tested.** Built around the RP2350 microcontroller. Boards have been fabricated, bench validated and entropy-tested. The design files are in `pcb/einszeit_v1` (schematic: `pcb/einszeit_v1.pdf`).

### Architecture

V1 is built around the **RP2350** microcontroller, chosen primarily for its documented, dedicated TRNG peripheral.

- **Entropy source:** RP2350's built-in TRNG block (Arm IP), which samples an internal free-running ring oscillator and claims compliance with FIPS 140-2, BSI AIS-31, and NIST SP 800-90B. Nominal entropy rate is ~7.5 kb/s at 150 MHz core clock.
- **Key storage:** key material never leaves the device, except on a microSD card, which is also how keys are exchanged.

### Why a raw TRNG

One-time-pad key material needs close to full entropy in every output bit. The random number generator of a typical secure element is not a raw entropy tap: it is the output of an internal DRBG (deterministic random bit generator), seeded periodically from a physical noise source. Its output entropy is bounded by the infrequently refreshed seed, not by the number of bytes read out, so it is architecturally unsuited to one-time-pad keys. Einszeit therefore uses the RP2350's TRNG, whose raw output can be tested directly.

One limitation remains: the TRNG is closed Arm IP, so its internal construction cannot be independently validated.

A secondary, physically independent entropy source (e.g. a discrete noise circuit) is not currently planned, but remains a possible future defense-in-depth addition if the RP2350 TRNG's characteristics warrant it.

Full entropy source documentation, extraction method, and validation results have been published alongside V1 firmware.

## Software Status

V1 software is complete enough for bench use with two devices, and is being tested on V1 hardware. It is not yet audited: do not use it for real secrets.

- **The device's terminal interface.** Connect any terminal program (PuTTY, screen, minicom, Tera Term) to the device's USB serial port:
  - Home shows the device at a glance;
  - Keys is a key manager: new keys, import and export on a transfer card, spare copies, delete;
  - Send and Receive encrypt and decrypt messages of up to 64 KiB, typed or pasted, or transferred as files by ZMODEM or XMODEM (detected automatically).

  See the [user interface document](docs/einszeit-ui.md) (EZ-UI-001).
- **`ez`, the host CLI** (`sw/ez`), over USB HID: scripting, and messages above 64 KiB. Build with `cmake -S sw -B build/sw && cmake --build build/sw`.
- **Firmware images** (`fw/einszeit`):
  - `einszeit_composite`: the terminal interface plus `ez`;
  - `einszeit_cdc`: the terminal interface only;
  - `einszeit_hid`: `ez` only.

  None of them has a software path into the bootloader; this is checked at build time. `einszeit_dev` adds development commands and hardware tests, and must never be used for real secrets.
- **Where keys are kept:**
  - on the **card** (microSD), in two copies, which the device checks and repairs by itself (the card mirror);
  - in the device's **internal storage**, alone or as a **spare copy** of a card key.

  Every 4 KiB of key is checked against its integrity tag before use, so a damaged or wrong card can cost a key but never secrecy. Keys leave the device only on a card.
- **A portable core** (`core/`), shared by the firmware and the host tests: offsets committed to F-RAM before any key byte is used, quarantine, an event log, key generation with online entropy monitoring, and buffered and streaming encryption.
- **Testing:**
  - on the host (`tests/run.sh`) against simulated hardware, with power loss, bit flips and card removal at every step;
  - an SD card emulator running the firmware's own driver;
  - screen tests of the terminal interface;
  - interoperability tests of the file transfers against lrzsz;
  - fuzzing.

  See [tests/README.md](tests/README.md).

Still open: the entropy assessment (OI-04), Windows support (OI-05), and an audit. See the [open items](docs/einszeit-implementation-spec.md#13-open-items).

Specifications and records: [security requirements](docs/einszeit-security-requirements.md) (EZ-SEC-001), [implementation specification](docs/einszeit-implementation-spec.md) (EZ-IMPL-001), [user interface](docs/einszeit-ui.md) (EZ-UI-001), [entropy thresholds](docs/einszeit-entropy-thresholds.md), [deviations](docs/einszeit-deviations.md) (EZ-DEV-001), [traceability](docs/einszeit-traceability.md) (EZ-TRACE-001).

## Security Model

Einszeit's core claim is that, given genuine full-entropy key material and correct one-time use, message confidentiality is information-theoretically secure — i.e., secure regardless of an adversary's computational power. This claim depends entirely on:

1. The entropy source(s) actually delivering full min-entropy per output bit (not merely passing statistical randomness tests, which a well-built DRBG would also pass).
2. Conditioning/extraction functions that don't reintroduce a computational-hardness dependency where an information-theoretic one is claimed (e.g., preferring universal-hash/Leftover-Hash-Lemma-based extraction over hash-based conditioning where the strict claim matters).
3. Correct one-time use of key material and secure erasure after use.

## AI Disclosure

This project makes use of LLMs for documentation, specifications, firmware and software. Once the project is stable, a human audit will be performed resulting in a code freeze that must not be directly modified by any LLM without an additional human audit. See our [GenAI session summaries](docs/genai).

## Funding

This project was partially funded through the NGI0 Commons Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme.

## License

The contents of this repo are released under the [CERN-OHL-P](LICENSE.txt) license with the following exceptions:

 * The hidapi library (`sw/hidapi.c`, `sw/hidapi.h`) is BSD licensed.
 * The FatFs library (`third_party/fatfs`) is released under the FatFs license by ChaN, a 1-clause BSD-style license; see [third_party/fatfs/LICENSE.txt](third_party/fatfs/LICENSE.txt).
 * The Zetta editor (`third_party/zetta`) is released under the BSD-1-Clause license; see [third_party/zetta/LICENSE.md](third_party/zetta/LICENSE.md).
