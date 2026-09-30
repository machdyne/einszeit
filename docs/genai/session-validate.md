# Einszeit V1 Hardware Validation — Session Summary

## Requested

Test firmware for an assembled Einszeit V1 board (RP2350A) to validate the
HRNG, clock, FRAM and SD interfaces, with a CLI over USB CDC and XMODEM
transfer, plus a Python script producing a detailed report covering entropy
quality, plots, and compliance with the standards the RP2350 TRNG claims.

This grew during the session into an audit against the EZ-SEC-001 security
requirements specification, repackaging as `fw/test/`, and driving the tooling
through real bring-up on hardware.

## Produced

**Firmware** — C, pico-sdk 2.1.1, RP2350A, builds clean under `-Wall -Wextra`.
CLI shell with raw and conditioned TRNG capture read straight from the EHR
registers, FRAM and microSD drivers, clock and AON-timer measurement, a
pin-integrity check that verifies the external pull-ups, XMODEM-1K transfer
with a CRC-32 container, and a storage guard that refuses to touch a board
that might hold key material.

**Host tooling** — Python. Serial driver, XMODEM receiver, SP 800-90B non-IID
estimators, the full SP 800-22 suite with multi-sequence scoring, AIS-31
T0–T8, FIPS 140-2 §4.9.1, and a self-contained HTML report.

**Audit documents** — `EZ-TEST-TRACEABILITY.md`, classifying all 51
requirement IDs with evidence, and `EZ-TEST-DEVIATIONS.md`, recording 5
deviations and 6 gaps.

## Findings from hardware testing

- The FRAM was healthy throughout. The MB85RS64 has no RDID command, and the
  tooling was misreporting that as a dead bus.
- The board passed SEC-TEST-ENT-001 at 100,800,000 bits.
- `SAMPLE_CNT1` must move well off its reset value of 65535 for usable
  throughput; 16384 emerged as the candidate operating point.

## Code quality note

Roughly a dozen defects were found in the analysis code during the session,
most surfaced by inspection of real output rather than by testing: the
collision formula, Coron versus Maurer in AIS-31 T8, a scaled T8 reporting a
false pass, composite-test scoring that failed healthy hardware, FIPS 140-2
reporting FAIL on perfect data, the pin test tearing down the SPI bus
configuration, and the report contradicting itself on the Runs test.

Each appeared when real data at a new scale met an assumption that had not
been checked. This is the concrete argument for gap G-04: run NIST's
`sts-2.1.2` and `ea_non_iid` against the archived captures before recording
conformance.
