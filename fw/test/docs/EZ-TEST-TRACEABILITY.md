# EZ-SEC-001 Traceability Matrix — Test Firmware

**Artifact:** `fw/test/` — Einszeit V1 hardware validation firmware and host analysis tooling
**Document ID:** EZ-TEST-TRACE-001
**Governing spec:** EZ-SEC-001 (Einszeit Security Requirements Specification)
**Status:** Audit record. Companion to `EZ-TEST-DEVIATIONS.md`.

---

## Summary

EZ-SEC-001 §Scope covers "all Einszeit hardware, firmware, software, interfaces,
and documentation", so this artifact is in scope. It is **not fully compliant,
and it must not be**. Three requirements are deliberately inverted because
inverting them is the tool's entire function: you cannot characterise a noise
source whose hardware health tests halt it, and you cannot assess raw entropy
that has already been debiased. Those inversions are recorded as deviations
D-02, D-03 and D-04 rather than as compliance.

Of the 51 requirement IDs in EZ-SEC-001:

| Disposition | Count | Meaning |
| --- | --- | --- |
| Satisfied | 9 | Implemented and demonstrated in this artifact |
| Supports | 6 | This artifact is the instrument by which a production requirement is measured |
| Not applicable | 27 | The artifact has no Key material, no session layer and no crypto path |
| Deviation | 5 | Deliberate, justified, mitigated — see `EZ-TEST-DEVIATIONS.md` |
| Gap | 4 | Cannot be met by this artifact as it stands — see `EZ-TEST-DEVIATIONS.md` |

The single most important control added by this audit is **`ez_guard.c`**: the
firmware refuses every storage read, write and erase path unless the FRAM is
demonstrably blank or carries this tool's own test marker. On Einszeit V1 the
FRAM is metadata storage, which holds the OTP offsets. A bench tool that can
overwrite or roll back an offset causes silent key reuse — the one failure mode
EZ-SEC-001 §0 says is irrecoverable.

§11 requires that no requirement be marked satisfied by documentation alone.
The Evidence column below names a passing test or an inspectable artifact for
every "Satisfied" row.

---

## §2 Entropy and Key Generation

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-ENTROPY-001 | N/A + control | No key generation here. Control: every capture carries `"key_material": false` and a usage string naming this requirement (`write_capture_meta()`, `src/main.c`); the host report renders it as a warning banner (`host/ezlib/report.py`). |
| SEC-ENTROPY-002 | Supports | This artifact is how the 8 bits/byte figure gets measured. `host/ezlib/sp80090b.py` implements the SP 800-90B non-IID track; `ez_validate.py selftest` demonstrates no estimator overstates entropy on four sources of known entropy. Production per-key testing is **G-05**. |
| SEC-ENTROPY-003 | Deviation **D-02** | Raw mode sets all three bypass bits in `TRNG_DEBUG_CONTROL`, producing output well below 8 bits/byte by design. Never used as key material. |
| SEC-ENTROPY-004 | Deviation **D-03** | The tool continues past CRNGT, Von Neumann and autocorrelation faults instead of halting, and counts them. Counts appear in capture metadata and in the report. Conditioned mode leaves all health tests enabled. |
| SEC-GEN-001 | Deviation **D-04** | 192 KB of TRNG output is held in volatile memory for the duration of a capture. Mitigated by `ez_secure_zero()` on every buffer handover and the `buf zero` command. |
| SEC-GEN-002 | N/A | No key writes. The same read-back discipline is applied to the FRAM and SD tests (`ez_fram_test_region()`, `ez_sd_write_block()` + verify). |
| SEC-GEN-003 | N/A | No generation events. |
| §2.3 online monitoring | Supports | `hrng health` reports monobit-equivalent bias, runs behaviour and the hardware's own autocorrelation counters. Firmware-side rolling-window monitoring is production work; see **G-05**. |

## §3 Storage Architecture

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-STORE-001 | Satisfied (negative) | This firmware performs no erase policy of its own on a provisioned device: `ez_guard_permit_storage()` refuses. Evidence: `guard --json` reports `storage_allowed:false` on any board whose FRAM is not blank or test-marked. |
| SEC-STORE-002 | N/A | No Key IDs are created. |
| SEC-META-001 | N/A | No session records. Format not yet defined; see **G-01**. |
| SEC-META-002 | N/A | No offset updates. |
| SEC-META-003 | Satisfied (negative) | The tool cannot cause a session record to be silently reset, because it refuses to write FRAM that it does not recognise as blank. `src/ez_guard.c`, `EZ_GUARD_OCCUPIED` path. |
| SEC-META-004 | N/A | No record allocation. |
| SEC-PTR-001 | N/A | No offsets read or written. |
| SEC-PTR-002 | Satisfied (negative) | `fram write`, `fram test`, `fram size` and `fram bench` — every path that could roll an offset backwards — are gated on `ez_guard_permit_storage()`. Inspect `src/main.c`, `cmd_fram()`. |
| SEC-PTR-003 | N/A | No ciphertext output. |

## §4 Key Distribution

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-DIST-001 | Deviation **D-05** | Entropy captures cross a USB link to a host. They are characterisation data, not key material, and are tagged as such in the container metadata. |
| SEC-DIST-002/003/004/005 | N/A | No Key distribution. |

## §5 Encryption, Decryption, Derivation, Isolation

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-ENC-001..004 | N/A | No encryption path exists in this artifact. |
| SEC-DEC-001..004 | N/A | No decryption path. |
| SEC-KDF-001 | N/A + note | No key derivation. Note: the SHA-256 and DCP blocks are never touched by this firmware, which is the posture SEC-KDF-001 wants preserved into production. |
| SEC-ISO-001/002 | N/A | No sessions. |

## §6 Transmission

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-TX-001/002 | N/A | No ciphertext, no message headers. |

## §7 User Interface

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-UI-001..004 | N/A | No session UI. |
| SEC-UI-005 | Satisfied | No OTP offset or key length can reach diagnostic output: raw FRAM dump is compile-time disabled (`EZ_ENABLE_RAW_STORAGE_DUMP=OFF` by default) and additionally guard-gated. `sd read` verifies the block CRC but withholds contents. Evidence: default build, `fram dump` returns rc=3 with a refusal citing SEC-UI-005. |

## §8 Hardware Design

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-HW-001 | Satisfied | No OTP operation is delegated to the host. The host performs statistical analysis only, on data explicitly tagged as non-key material. |
| SEC-HW-002 | Partially satisfied | `ez_guard_sd_present()` refuses `sd init`, `sd read`, `sd bench` and `sd write` when no card is detected. Removal *during* a long operation is not detected: **G-02**. |
| SEC-HW-003 | Satisfied by architecture | Firmware lives in QSPI flash; key data storage on V1 is the microSD. Different media, no overlap possible. `CMakeLists.txt` records this. |

## §9 Firmware and Software

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-FW-001 | Partially satisfied | C, so the "identified and remediated by code review" branch applies. A review was performed for this audit; three defects were found and fixed (see Code Review Record below). The tree builds clean under `-Wall -Wextra`. No static analysis, sanitizer or fuzzing coverage yet: **G-03**. |
| SEC-FW-002 | Satisfied | `ez_secure_zero()` uses `volatile` stores plus a compiler memory barrier, defeating dead-store elimination. `src/ez_secure.c`. |
| SEC-FW-003 | Satisfied | The capture buffer is cleared on every role change via `buffer_take_scratch()`, at nine call sites. `buf zero` performs a verified wipe. Before this audit the buffer was silently reused — see Code Review Record, finding 1. |
| SEC-FW-004 | Satisfied, with a build-time escape hatch | All storage access routes through `ez_guard_permit_storage()`. Raw dump paths are compiled out by default. With `-DEZ_ENABLE_RAW_STORAGE_DUMP=ON` the requirement is knowingly violated: **D-01**. CMake emits a warning in that configuration. |

## §10 Testing Requirements

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| SEC-TEST-ENT-001 | Gap **G-04** | All 15 SP 800-22 tests are implemented (`host/ezlib/sp80022.py`) and demonstrated on uniform and biased sources. The 10⁸-bit sample size is not yet achievable in one run: the device buffer is 1.57 Mbit, so 64 capture rounds are needed, and the Python suite has not been profiled at that size. |
| SEC-TEST-ENT-002 | Gap **G-05** | Requires online monitoring to exist first. The host `selftest` does inject known-bad streams and confirms detection, which is the analysis-side half of this requirement. |
| SEC-TEST-ENT-003 | Satisfied | AIS-31 procedures A and B (T0–T8) implemented in `host/ezlib/standards.py`; verified against uniform data (all pass, Coron T8 = 7.9995) and biased data (T1, T2, T6 fail as expected). Caveat: implements AIS 31 v2.0 (2011), not v3.0 (2024). |
| SEC-TEST-PTR-001/002/003 | Gap **G-06** | Requires the metadata and session layer, which does not exist yet. |
| SEC-TEST-ENC-001/002/003 | Gap **G-06** | Requires the encryption layer. |
| SEC-TEST-ISO-001/002 | Gap **G-06** | Requires the session layer. |
| SEC-TEST-REPLAY-001 | Gap **G-06** | Requires the message layer. |
| SEC-TEST-MEDIA-001 | Partially satisfied | Pre-operation removal detection is implemented and testable by removing the card and running `sd read`. Mid-operation abort is **G-02**. |

## §11 Requirements Traceability

| ID | Disposition | Evidence / rationale |
| --- | --- | --- |
| §11 | Satisfied | Every firmware source and header carries an `EZ-SEC-001 traceability` block naming the requirement IDs it satisfies, supports, or is exempt from. This matrix names evidence for every satisfied row. |

---

## Code Review Record (SEC-FW-001)

A manual memory-safety and correctness review of all 3,100 lines of C was
performed for this audit. Bounds on every array write were traced to their
clamping site. Three defects were found by review and two more on hardware:

**Finding 1 — stale capture length after buffer reuse (correctness, security-relevant).**
The 192 KB capture buffer doubled as scratch for the FRAM and SD tests at nine
call sites, none of which reset `g_payload_len`. Running `fram bench` after
`hrng cap` left the length claiming a capture that had been overwritten with
test patterns; `send` would then transmit that scratch data under a valid
CRC-32 and correct-looking metadata, and the host would analyse FRAM test
patterns as if they were entropy. Fixed by `buffer_take_scratch()`, which
zeroises and invalidates. This also brings the artifact into compliance with
SEC-FW-003.

**Finding 2 — FRAM addressing mode left corrupted after failed detection.**
`ez_fram_detect_size()` sets the global address width to 2 then 3 while
probing. On a device that failed both probes it returned with the width left at
3, so every subsequent read and write on a 2-byte-addressed part silently
targeted the wrong address. Fixed by restoring the previous width on failure.

**Finding 3 — negative argument count passed to a parser.**
`hrng restart` with no arguments computed `argc - 3 = -1` and passed it with
`argv + 3`. The loop guard made it harmless in practice, but the pointer
arithmetic and the negative count were both unsound. Clamped at all three call
sites.

**Also found during this audit, in the metadata path:** adding the
non-key-material tag pushed the JSON metadata past the 488-byte header budget.
`snprintf` would have truncated it silently, producing invalid JSON that the
host rejects only *after* a capture costing minutes to hours. The header is now
1024 bytes, truncation is detected and reported, and the host reads `header_len`
from the container so captures from either firmware revision parse.

**Finding 4 — pin test destroyed the SPI pin functions (found on hardware).**
`ez_pins_check()` calls `gpio_init()` on every board pin, which switches it to
SIO. It never restored the previous function, so GPIO18-21 were left as plain
inputs and every subsequent FRAM transfer read 0x00 — indistinguishable from a
dead part. `selftest` runs the pin check before the FRAM check, so it hit this
too. Fixed by saving and restoring function, direction and output level per
pin. Firmware 1.1.1.

**Finding 5 — FRAM presence was inferred from RDID alone.**
`fram id` treated an all-zero response to opcode 0x9F as a dead bus. RDID is
not universal: the original Fujitsu MB85RS64 family has no Device ID command,
so a healthy part reports all zeroes. Replaced with `ez_fram_probe()`, which
toggles the write-enable latch via WREN/WRDI and reads it back through RDSR --
supported by every SPI FRAM, non-destructive, and conclusive in both bus
directions. Firmware 1.1.1.

**Finding 4 — pin test destroyed the SPI bus configuration (found on hardware).**
`ez_pins_check()` calls `gpio_init()` on GPIO18-21 and GPIO26-29 to drive the
internal pulls, which switches each pin to SIO and tears down its SPI function.
It never restored them. Any FRAM or SD command run after `pins` — including
everything in `selftest`, which runs the pin test first — therefore talked to
disconnected pins, and every read returned 0x00. This presented as a dead FRAM
on hardware that was working correctly. Fixed by saving `gpio_get_function()`,
direction and output level per pin and restoring them after the probe.

**Finding 5 — presence was inferred from an optional command (found on hardware).**
`fram id` treated an all-zero RDID response as "dead bus". Not every SPI FRAM
implements RDID (0x9F): the Fujitsu MB85RS64 family, which is the part on
Blaustahl, has no Device ID command at all. Presence is now established by the
WREN/WRDI write-enable-latch toggle, which every SPI FRAM supports and which is
non-destructive. Absence of RDID is reported as a property of the part.

**Not covered:** no static analysis, no sanitizer build, no fuzzing of the
XMODEM or CLI parsers. Both parsers consume untrusted-ish input from the host
link. Recorded as **G-03**.

---

## Verification performed for this audit

| Check | Result |
| --- | --- |
| Firmware builds, default configuration | clean, 0 warnings under `-Wall -Wextra` |
| Bench findings 4 and 5 fixed and rebuilt | clean |
| Firmware builds, `-DEZ_ENABLE_RAW_STORAGE_DUMP=ON` | clean, CMake emits the required warning |
| Host analysis self-test, 4 sources of known entropy | pass, no estimator overstates |
| AIS-31 on uniform data | all 9 tests pass |
| FIPS 140-2 §4.9.1 on uniform data | 160/160 blocks pass all four tests |
| SP 800-22 on uniform data | 13 ran, 13 pass (2 skipped for insufficient excursion cycles) |
| SP 800-22 on 2% biased data | 10 of 13 fail, as expected |
| Container round-trip, both header revisions | pass, XMODEM padding trimmed correctly |

Firmware footprint: 71,872 B text, 202,848 B BSS on a 520 KB part.
