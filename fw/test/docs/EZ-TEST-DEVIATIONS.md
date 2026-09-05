# EZ-SEC-001 Deviations and Gaps — Test Firmware

**Artifact:** `fw/test/`
**Document ID:** EZ-TEST-DEV-001
**Governing spec:** EZ-SEC-001
**Status:** Open items. Companion to `EZ-TEST-TRACEABILITY.md`.

Two classes of item are recorded here.

**Deviations (D-nn)** are places where this artifact knowingly does not comply
and where compliance would defeat its purpose. Each is justified, mitigated,
and bounded. They are not scheduled for remediation; they are scheduled for
*containment* — the containment measure is named in each entry.

**Gaps (G-nn)** are places where compliance is intended but not yet achieved.
Each has an owner-facing action.

The one-line summary: **this artifact must never be flashed to a device that
holds key material, and must never be present in a build that generates it.**
Every deviation below is safe only under that condition, and `ez_guard.c`
enforces the first half of it in software.

---

## Deviations

### D-01 — Optional raw storage read paths violate SEC-FW-004 and SEC-UI-005

**Requirement:** SEC-FW-004 ("MUST NOT expose a command, interface, or debug
path that allows raw read access to key data storage"), SEC-UI-005 (OTP offsets
must not appear in diagnostic output).

**Deviation:** `fram dump` and the block hexdump in `sd read` are raw read paths
into metadata storage and key data storage respectively. On V1 the microSD *is*
key data storage, so hexdumping an arbitrary LBA is precisely what SEC-FW-004
prohibits.

**Why it exists:** bringing up an SPI bus without being able to see the bytes on
it is considerably harder. The capability has genuine diagnostic value on a bare
board.

**Containment:**
- Both paths are compiled out by default (`EZ_ENABLE_RAW_STORAGE_DUMP=OFF`).
- In the default build, `fram dump` returns rc=3 and cites this requirement.
- In the default build, `sd read` still performs the read and verifies the
  card's data CRC-16 — which is what the bus integrity test actually needs —
  and withholds only the contents.
- When the option is enabled, CMake emits a warning naming both requirement IDs,
  and the paths remain gated on `ez_guard_permit_storage()`.

**Residual risk:** a binary built with the option ON is non-compliant and
indistinguishable from a compliant one at a glance. **Action:** if this
concerns you, remove the option entirely and keep a private branch for bring-up.

---

### D-02 — Raw capture mode disables hardware debiasing (SEC-ENTROPY-003)

**Requirement:** SEC-ENTROPY-003 — TRNG output must not be conditioned in a way
that introduces determinism; hardware debiasing must not reduce per-byte entropy
below 8 bits.

**Deviation:** raw mode sets `VNC_BYPASS`, `TRNG_CRNGT_BYPASS` and
`AUTO_CORRELATE_BYPASS`, producing output that will be well below 8 bits per
byte.

**Why it exists:** SP 800-90B assesses the *noise source*, not the conditioned
output. Assessing post-conditioning data measures the conditioner. This is the
same reasoning the project README already gives for deprecating V0's ATSHA204A
DRBG output.

**Containment:** raw captures are tagged `"key_material": false`, the report
prints a banner saying so, and conditioned mode (health tests enabled) is
captured alongside for comparison.

**Note for the spec, not for this artifact:** SEC-ENTROPY-003's second sentence
is worth revisiting. The Von Neumann balancer *is* hardware debiasing, and its
purpose is to *raise* entropy density, not preserve it. As written the sentence
reads as though debiasing is a risk to be bounded; in practice V1's ability to
meet SEC-ENTROPY-002 will depend on it. Consider rewording to require that
post-debiasing output achieve 8 bits/byte, with the raw-source min-entropy
documented separately.

---

### D-03 — The tool continues past TRNG health-test faults (SEC-ENTROPY-004)

**Requirement:** SEC-ENTROPY-004 — generation must halt and raise an auditable
fault if the entropy source is degraded.

**Deviation:** `ez_trng_capture()` records CRNGT, Von Neumann and autocorrelation
faults, recovers from the fatal autocorrelation case with a software reset, and
keeps going.

**Why it exists:** a fail-safe source cannot be characterised, because the
failure being characterised is the thing that stops the run. The fault *rate* is
itself a measurement.

**Containment:** every fault count is carried in the capture metadata and
rendered in the report. Conditioned mode leaves all three tests enabled, so the
production configuration can be observed behaving correctly.

**Action for production firmware:** SEC-ENTROPY-004 requires an auditable fault.
This artifact demonstrates that the fault bits are readable and that the
autocorrelation fault is genuinely fatal in hardware ("RNG cease from
functioning until next reset"), which production firmware must handle rather
than hang on.

---

### D-04 — Bulk buffering of TRNG output (SEC-GEN-001)

**Requirement:** SEC-GEN-001 — key bytes must not be buffered in volatile memory
longer than needed to write a single block.

**Deviation:** up to 192 KB of TRNG output is held in RAM for the duration of a
capture and a transfer.

**Why it exists:** entropy assessment needs contiguous samples; SP 800-90B wants
at least 10⁶.

**Containment:** the data is not key material. `ez_secure_zero()` clears the
buffer at every role change and `buf zero` performs a verified wipe on demand.

---

### D-05 — Entropy leaves the device electronically (SEC-DIST-001)

**Requirement:** SEC-DIST-001 — electronic transmission of key material over any
network is prohibited.

**Deviation:** captures are transferred over USB CDC to a host for analysis.

**Why it exists:** the analysis cannot run on the device.

**Containment:** the transferred bytes are never used as key material, are tagged
as such in the container metadata, and the generated report carries a warning
banner. The USB link is point-to-point, not a network.

**Residual risk:** the tagging is advisory. Nothing physically prevents someone
piping a `.bin` into a key slot. **Action:** if V1 firmware ever gains a key
import path, it must reject files carrying `"key_material": false` and must not
accept key material over USB at all.

---

## Gaps

### G-01 — Metadata record format is undefined, so the guard heuristic is provisional

**Blocks:** SEC-META-001 through SEC-META-004, and the reliability of
`ez_guard.c`.

`ez_guard_evaluate()` classifies a board by scanning the first 4 KB of FRAM: it
permits storage tests only when the region is uniformly 0x00/0xFF or carries the
`EZ-TESTBOARD-001` marker. This is conservative and fails closed, but it is a
heuristic standing in for a real check because the production session record
format does not exist yet.

**Action:** once EZ-IMPL-001 defines the session record, give it a magic number
and have the guard test for that magic specifically. Until then a board whose
FRAM happens to be uniformly 0xFF *and* holds live sessions would be
misclassified — unlikely, but not impossible if session records are stored
elsewhere in the device.

**Owner:** whoever defines the metadata format. Update `EZ_TEST_MARKER` handling
in `src/ez_guard.c` at the same time.

---

### G-02 — Media removal is detected before an operation, not during it

**Blocks:** SEC-HW-002, SEC-TEST-MEDIA-001.

`ez_guard_sd_present()` is checked before each SD command. A card pulled during
a 512-block benchmark is not noticed until the command finishes. SEC-HW-002
requires the operation not to *continue* after removal.

**Complication:** `SD_DET` polarity is not documented in the material available
and is currently assumed active-low in `board.h`. The check cannot be trusted
until that is confirmed on the bench with `sd det --watch`.

**Action:** (1) confirm polarity and fix `SD_DET_ACTIVE_LOW`; (2) poll `SD_DET`
inside `ez_sd_bench_read()` and the multi-block read loop, aborting on change.
For production, this belongs on a GPIO interrupt, not a poll.

---

### G-03 — No static analysis, sanitizer or fuzzing coverage

**Blocks:** full satisfaction of SEC-FW-001.

The manual review recorded in the traceability matrix found and fixed three
defects, and the tree builds clean under `-Wall -Wextra`. That is the minimum,
not the bar. The XMODEM receiver state machine and the CLI line parser both
consume input from the host link.

**Action:** add `-fanalyzer` or `clang --analyze` to CI; build the container,
CRC and XMODEM logic as a native host target under ASan/UBSan; fuzz the CLI
tokeniser and the XMODEM framing. None of this needs hardware.

---

### G-04 — SP 800-22 has not been run at the required 10⁸-bit sample size

**Blocks:** SEC-TEST-ENT-001, which requires all 15 tests on a minimum of 10⁸
bits per hardware revision.

Two obstacles, both surmountable:

1. **Collection.** The device buffer is 1.57 Mbit, so 10⁸ bits needs 64 rounds
   (`ez_validate.py collect --rounds 64`). At the reset `SAMPLE_CNT1` of 65535
   the conditioned TRNG yields roughly 2.3 kbit/s, which puts a 10⁸-bit
   conditioned capture at about 12 hours. Raw mode at a short sample interval is
   far faster but is a different measurement. The sweep (`--sweep`) is what
   tells you which operating point to certify.
2. **Analysis runtime.** `host/ezlib/sp80022.py` has been exercised at 10⁶ bits
   (about 9 seconds). It has not been profiled at 10⁸. The binary matrix rank
   test and the random excursions tests both iterate in Python and will need a
   vectorisation pass or a subsampling strategy.

**Action:** for the formal SEC-TEST-ENT-001 record, run NIST's own `sts-2.1.2`
against the archived `.bin` rather than this implementation, and cite it. The
built-in suite stays useful for fast iteration. Note also that two of the
fifteen tests (random excursions and its variant) are conditional on the number
of zero-crossing cycles; at 10⁸ bits this will not be a problem, but the
condition must be recorded as met rather than assumed.

---

### G-05 — Online entropy monitoring and per-key post-generation testing are unbuilt

**Blocks:** SEC-ENTROPY-002 (the "post-generation statistical testing MUST be
performed on every generated key" clause), SEC-TEST-ENT-002.

This artifact measures the source offline. It does not implement the on-device
monitoring described in EZ-SEC-001 §2.3, and it cannot: those tests must run
inside the generation path.

**Action for production firmware:** implement monobit, runs and autocorrelation
on a rolling window, halting on failure (§2.3), plus a per-key acceptance test
before a key is marked valid. The thresholds should be derived from the
characterisation this tool produces, not from textbook values — that is the main
reason to run this tool before writing the generation firmware. SEC-TEST-ENT-002
then requires injecting a known-bad stream and confirming a halt within one
window; `host/ezlib/sp80090b.py` already contains generators for biased and
correlated streams suitable for that harness.

---

### G-06 — The §10.2 through §10.6 test harnesses do not exist

**Blocks:** SEC-TEST-PTR-001/002/003, SEC-TEST-ENC-001/002/003,
SEC-TEST-ISO-001/002, SEC-TEST-REPLAY-001.

Every one of these tests targets the OTP offset layer, the encryption layer or
the session layer. None of those exist in V1 firmware yet, so none can be
tested. This is not a defect in this artifact; it is a scope boundary.

**Action:** these belong in a second harness, `fw/test/` sibling or otherwise,
written alongside the session layer. Several are cheap and worth writing *first*
as executable specifications — particularly SEC-TEST-PTR-001, which needs
simulated power loss at each stage of the metadata write sequence, and is much
easier to design for than to retrofit.

Note that SEC-TEST-ENC-001 requires known-answer tests on **every firmware
build**, which implies host-side CI rather than on-device testing. Worth setting
that up before there is code to test.

---

## Disposition summary

| Item | Type | Blocking production? | Owner action |
| --- | --- | --- | --- |
| D-01 | Deviation | No (default build compliant) | Optional: delete the build option |
| D-02 | Deviation | No | Consider rewording SEC-ENTROPY-003 |
| D-03 | Deviation | No | Production must handle the fatal autocorrelation fault |
| D-04 | Deviation | No | None |
| D-05 | Deviation | No | Reject tagged files if a key import path is ever added |
| G-01 | Gap | No, but degrades the guard | Define the session record magic |
| G-02 | Gap | No | Confirm SD_DET polarity, then poll during transfers |
| G-03 | Gap | No | Add analysis and fuzzing to CI |
| G-04 | Gap | **Yes** — SEC-TEST-ENT-001 is a hard requirement per revision | Collect 10⁸ bits, run NIST sts-2.1.2 |
| G-05 | Gap | **Yes** — SEC-ENTROPY-002 is a hard requirement | Build online monitoring and per-key testing |
| G-06 | Gap | **Yes** — §10.2–10.6 are hard requirements | Write the harness with the session layer |

G-04, G-05 and G-06 block a compliant *product*. None of them block using this
tool for bench validation, which is what it is for.
