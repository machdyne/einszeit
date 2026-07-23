# Einszeit

Einszeit is an open-source security device intended to provide information-theoretically secure (one-time-pad based) encryption between two or more paired devices over any communications medium.

> **Project status:** V1 hardware is in active development. See [Hardware Status](#hardware-status) and [Software Status](#software-status) below before using this project for anything beyond bench testing.

## Hardware Status

| Version | Status |
|---|---|
| V0 | **Deprecated.** Based on the ATSHA204A secure element. See [Why V0 was deprecated](#why-v0-was-deprecated). No longer maintained or recommended for use. |
| V1 | **Design complete, not yet fabricated.** Redesigned around the RP2350 microcontroller. Boards have not yet been fabricated, bench validated, entropy-tested, or used to generate production key material. |

### Why V0 was deprecated

V0 relied on the ATSHA204A secure element's `Random` command as its sole entropy source. While this was suitable for a functional prototype, it is not a raw entropy tap — it is the output of an internal DRBG (deterministic random bit generator) seeded periodically from a physical noise source. This means:

- Output entropy is bounded by the (infrequently refreshed) internal seed, not by the number of bytes read out.
- The construction is architecturally unsuited to one-time-pad key material, which requires each output bit to carry close to full entropy.
- The DRBG design is closed and proprietary, offering no way to independently validate its internal construction.

None of this made the ATSHA204A insecure for its intended purpose (it's a perfectly reasonable secure element), but it made it the wrong building block for Einszeit's core security claim. V1 replaces it entirely.

### V1 architecture (hardware)

V1 is built around the **RP2350** microcontroller, chosen primarily for its documented, dedicated TRNG peripheral:

- **Entropy source:** RP2350's built-in TRNG block (Arm IP), which samples an internal free-running ring oscillator and claims compliance with FIPS 140-2, BSI AIS-31, and NIST SP 800-90B. Nominal entropy rate is ~7.5 kb/s at 150 MHz core clock.
- **Key storage:** unchanged in concept from V0 — key material is written directly to flash and never persisted on the host beyond a transient in-memory buffer during transfer.

A secondary, physically independent entropy source (e.g. a discrete noise circuit) is not currently planned, but remains a possible future defense-in-depth addition if the RP2350 TRNG's characteristics warrant it.

Full entropy source documentation, extraction method, and validation results will be published alongside V1 firmware.

## Software Status

The `ez` utility (originally written against V0's alice/bob device model) is **not yet compatible with V1**.

- V1 introduces a **multi-key model**, replacing the fixed alice/bob key-pair scheme with support for an arbitrary number of paired devices and key slots.
- `ez` will require updated firmware-side commands and a corresponding rewrite of its identity, key-copy, and read/write logic to address multiple key slots rather than a single fixed pair.
- New V1 firmware (implementing the TRNG-based generation pipeline and multi-key metadata format) is in progress and not yet released.

**Until firmware and `ez` are updated, V1 boards should be treated as hardware prototypes only.** Do not use V1 boards for generating or exchanging production key material.

## Security Model

Einszeit's core claim is that, given genuine full-entropy key material and correct one-time use, message confidentiality is information-theoretically secure — i.e., secure regardless of an adversary's computational power. This claim depends entirely on:

1. The entropy source(s) actually delivering full min-entropy per output bit (not merely passing statistical randomness tests, which a well-built DRBG would also pass).
2. Conditioning/extraction functions that don't reintroduce a computational-hardness dependency where an information-theoretic one is claimed (e.g., preferring universal-hash/Leftover-Hash-Lemma-based extraction over hash-based conditioning where the strict claim matters).
3. Correct one-time use of key material and secure erasure after use.

Documentation accompanying the V1 firmware release will state precisely which parts of the pipeline carry an information-theoretic guarantee and which (if any) rely on a cryptographic hardness assumption, so users can evaluate the claim rather than take it on faith.

## Roadmap

- [ ] Fabricate V1 boards
- [ ] Bench validation of V1 hardware (power, TRNG readout)
- [ ] Independent SP 800-90B-style min-entropy estimation of the RP2350 TRNG
- [ ] V1 firmware: TRNG readout and multi-key metadata format
- [ ] `ez` utility rewrite for multi-key model
- [ ] Publish entropy source validation results and extractor design

## License

The contents of this repo are released under the [Lone Dynamics Open License](LICENSE.md).

Note: You can use these designs for commercial purposes but we ask that instead of producing exact clones, that you either replace our trademarks and logos with your own or add your own next to ours.
