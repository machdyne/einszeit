# Einszeit Security Requirements Specification

**Document ID:** EZ-SEC-001  
**Status:** Normative  
**Revision:** 1.4 (see §12 Revision History)  
**Scope:** All Einszeit hardware, firmware, software, interfaces, and documentation

---

## 0. Foundational Principle

One-Time Pad (OTP) encryption provides **information-theoretic (perfect) secrecy** if and only if three invariants hold simultaneously:

1. **Key length ≥ plaintext length** — the key is never shorter than the data it encrypts.
2. **Key is truly random** — key material is generated from a true random source, not a PRNG.
3. **Key is never reused** — each key byte is consumed exactly once, across all sessions, devices, and time.

Any violation of any invariant completely and irrecoverably destroys secrecy. All requirements in this document exist to enforce these three invariants at every layer of the system.

> **Physical and host security scope:** This specification does not address attacks that require physical access to the device or a compromised host. If an attacker controls the host machine, they can read plaintext directly (e.g., via keylogger). While devices may have some physical security features, protection against such attacks is ultimately the user's responsibility.

> **Authentication scope:** This specification covers encryption and decryption only. Message authentication — verifying that a message was produced by the expected party — is out of scope. The Key ID is a coordination identifier, not a secret, and MUST NOT be used as an authenticator or as evidence of message origin.

---

## 1. Definitions

| Term | Meaning |
|---|---|
| **Key** | A block of OTP key material generated once, distributed physically, and consumed over its lifetime. Identified by a Key ID. |
| **Key ID** | A TRNG-generated unique identifier associated with a Key at creation time. Not a secret. Used to differentiate between multiple shared keys, and by the device to identify sessions locally. |
| **Session** | A device's local record of its use of a specific Key, referenced by Key ID. Stores the TX offset, RX offset, role, drive index, human-readable name, and session status. Each Key has exactly one session per device; multiple sessions on one device correspond to multiple distinct Keys. |
| **Session status** | A flag stored in the session record indicating the session's operational state. Valid values: `VALID` (healthy and operational), `QUARANTINED` (integrity check failed; locked pending user action), `EXHAUSTED` (all key bytes consumed). Additional implementation-defined states (e.g. for optional features) may exist; see EZ-IMPL-001. |
| **Role** | A per-session designation of `alice` or `bob`, determining which half of the key the party uses in each direction. Alice encrypts from the first half and decrypts from the second half; bob encrypts from the second half and decrypts from the first half (see TX range and RX range). The key generator defaults to alice; the recipient defaults to bob. |
| **TX range** | The half of a Key from which a party encrypts: `[0, L/2)` for alice and `[L/2, L)` for bob, where `L` is the key length in bytes. |
| **RX range** | The half of a Key from which a party decrypts. It is always the peer's TX range: `[L/2, L)` for alice and `[0, L/2)` for bob. |
| **OTP offset** | A byte position within a Key. Each session holds two, both stored in metadata storage: the **TX offset**, the next unconsumed byte of the session's TX range, and the **RX offset**, the lowest byte of the session's RX range not yet consumed by decryption. |
| **Key data storage** | Non-volatile storage holding key material (e.g., flash or removable media). |
| **Metadata storage** | High-endurance non-volatile storage holding session state (offsets, IDs, names). Logically and physically separate from key data storage. |
| **Plaintext** | Data before encryption. |
| **Ciphertext** | `Plaintext XOR key_bytes_at_offset`. |
| **TRNG** | True Random Number Generator — hardware entropy source producing non-deterministic output. |
| **PRNG** | Pseudo-Random Number Generator — a software algorithm producing deterministic output from a seed. **Never** used to generate key material. |
| **DRNG** | Deterministic Random Number Generator — a hardware component that produces output deterministically from a seed, regardless of how the seed was obtained. Produces pseudo-random, not truly random, output. **Never** used to generate key material. |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator — a software algorithm producing deterministic output from a seed, designed to be computationally unpredictable. **Never** used to generate key material. |
| **Party** | One of the two endpoints sharing a Key. |

---

## 2. Entropy and Key Generation

### 2.1 Source Requirements

- **SEC-ENTROPY-001:** Key bytes MUST be generated exclusively from a hardware TRNG. Key material MUST NOT contain contributions from DRNGs, PRNGs, or CSPRNGs, regardless of whether they are implemented in hardware or software.
- **SEC-ENTROPY-002:** The TRNG MUST produce a minimum of 8 bits of entropy per output byte. Post-generation statistical testing MUST be performed on every generated key before it is marked valid and made available for use (see §9.1). A key MUST NOT be marked valid unless it passes these tests. If testing fails, the key MUST be discarded and the generation event logged as failed.
- **SEC-ENTROPY-003:** TRNG output MUST NOT be conditioned or whitened by any algorithm that could introduce determinism. If hardware debiasing is applied, it MUST NOT reduce per-byte entropy below 8 bits.
- **SEC-ENTROPY-004:** The TRNG MUST fail safe: generation MUST halt and raise an auditable fault if the entropy source is detected as degraded or unavailable. The system MUST NOT fall back to any software source.

### 2.2 Generation Process

- **SEC-GEN-001:** Key bytes MUST be transferred from the TRNG to key data storage without buffering in volatile memory longer than necessary to write a single block. Volatile buffers MUST be cleared immediately after each write.
- **SEC-GEN-002:** Key data MUST be verified by read-back immediately after writing, within the same generation session.
- **SEC-GEN-003:** Each generation event MUST produce a new Key ID (TRNG-generated) and record a generation log entry (timestamp, Key ID, byte length, test results) in metadata storage. The log entry MUST record whether the key was marked valid or rejected.

### 2.3 Online Entropy Monitoring (Recommended)

Online monitoring during generation is not required if the firmware guarantees that no key can be marked valid without passing post-generation tests (SEC-ENTROPY-002). It is RECOMMENDED as a way to detect TRNG degradation early and minimise wasted generation time.

If implemented, online monitoring SHOULD apply at minimum the following tests on a rolling window, halting generation immediately on failure:

- Monobit frequency test (proportion of 1s in the window)
- Runs test (length of consecutive identical bits)
- Autocorrelation test (correlation of output with a shifted copy of itself)

---

## 3. Storage Architecture

The system uses two logically and physically distinct storage tiers with strictly separated roles:

| Tier | Contents |
|---|---|
| Key data storage | Key material — raw random bytes only; Key ID is associated out-of-band via filename or manual exchange |
| Metadata storage | Session records: Key ID, role, drive index, OTP offset, session status, human-readable name |

These tiers MUST NOT be swapped. Key material MUST NOT be written to metadata storage. Session metadata MUST NOT be written to key data storage. Integrity values computed over key data (SEC-STORE-004) are stored in key data storage beside the Key they protect; they are not session metadata, and because they are derived from key material they MUST NOT be written to metadata storage.

### 3.1 Key Data Storage

- **SEC-STORE-001:** Key data storage MUST support erasure under firmware control. The firmware is solely responsible for all write and erase policies.
- **SEC-STORE-002:** Each Key MUST have a Key ID associated with it at creation time. The Key ID MUST be generated by the TRNG and MUST NOT be derived from or related to the key material bytes. The Key ID is conveyed out-of-band (via filename convention or manual exchange) and is not embedded in the key file. It is used to differentiate between multiple shared keys and to correlate key data with a session record in metadata storage. The Key ID MUST be non-zero; the value `0x00000000` is reserved and MUST be rejected at session creation.
- **SEC-STORE-004:** Before any key byte is used for encryption or decryption, it MUST be verified against an integrity value bound to the Key ID and to the byte's position in the Key, and the bytes used MUST be exactly the bytes that were verified. Any failure or misbehaviour of key data storage (removal, corruption, a different medium, a different Key under the same Key ID) MUST result in refusal of the operation; it MUST NOT result in the use of unverified key bytes. Integrity values are derived from key material and MUST be handled as key material: never transmitted electronically (SEC-DIST-001), never written to logs or metadata storage, and erased together with the Key (SEC-PTR-004).
- **SEC-STORE-005:** A Key received without integrity values from the device that generated it MUST, before any session may use it, pass the post-generation statistical tests of SEC-ENTROPY-002 and contain no two identical blocks of the size over which integrity values are computed. Its integrity values are then computed from it as received.
- **SEC-STORE-003:** Key length MUST be a non-zero, even number of bytes, so that the TX and RX ranges are of equal size. Session creation MUST be rejected for any other key length.

### 3.2 Metadata Storage

Metadata storage MUST support byte-level or word-level writes with high endurance, making OTP offset updates atomic and efficient. The choice of medium is an implementation decision; the requirements below apply regardless.

- **SEC-META-001:** Each session record MUST contain at minimum: Key ID, role, drive index, key length, the TX offset and the RX offset (each held in two offset slots with an offset selector), session status, human-readable name, and integrity protection such that corruption of any field is detected. Integrity protection MAY be divided between independently written parts of the record (for example one check over the fields written at creation and one per offset slot), provided every field is covered.
- **SEC-META-002:** Updates to either OTP offset MUST be written atomically. Power loss during an update MUST leave the offset in either the pre-update or post-update state — never in a partially updated state.
- **SEC-META-003:** On every power-on, all session records MUST be read and their integrity verified before any session operation is permitted. A session with a corrupt record MUST be set to `QUARANTINED` and flagged to the user. It MUST NOT silently reset its offsets. Quarantining a record whose integrity check fails MUST NOT recompute or rewrite that integrity check, since doing so would validate the corrupted contents; the quarantine state of such a record MAY instead be held in volatile memory and re-established on every power-on.
- **SEC-META-004:** Before allocating a new session record, the firmware MUST verify that its address range does not overlap any existing session record. Allocation MUST be rejected if a conflict is detected.

### 3.3 OTP Offset Integrity

The OTP offset is the most security-critical piece of metadata. Its corruption or rollback directly enables key reuse.

- **SEC-PTR-001:** Each OTP offset MUST be stored with integrity protection per SEC-META-001. A corrupt offset MUST be detected on read and MUST NOT be silently treated as zero or any other default value.
- **SEC-PTR-002:** Each OTP offset MUST only advance forward. Any command or request to set an offset to a value less than or equal to its current verified value MUST be rejected and logged.
- **SEC-PTR-004:** Deleting a session MUST erase its key file, and the Key's integrity values, from the device in the same operation, after warning the user and obtaining confirmation; the warning MUST tell the user that a copy of the key made before deletion must never be used to start a new session. Before erasure begins, the session MUST be made unusable (quarantined), so that an interrupted erasure never leaves a usable session over a partly erased key; the key file MUST then be erased before the session record is removed, so that an interruption never leaves the key without its record of consumption. The same rule applies whenever a key file in use by a session is erased. If the key file cannot be erased (for example the medium is absent or the record's integrity cannot be verified), the session MUST NOT be deleted unless the user explicitly overrides after a further warning; an override MUST be recorded in the event log.
- **SEC-PTR-003:** The TX offset MUST be advanced and the update committed atomically before ciphertext is output: no ciphertext byte may be output before a verified commit covers it. An encryption MAY commit in several steps (for example once per transport frame) provided this holds for every byte. If an update cannot be verified, the operation MUST be aborted and no further ciphertext output.

---

### 3.4 Availability of Key Data

Perfect secrecy is the overriding requirement. But keys that are regularly lost make a device that depends on meeting in person useless, so storage must also protect the *availability* of keys, without ever trading away secrecy. Consumer storage media can corrupt data well outside the area being written when power is lost during a write (EZ-DEV-001 DEV-22).

- **SEC-AVAIL-001:** Encryption, decryption and reading device or session status MUST NOT write to key data storage. Writes to key data storage are confined to maintenance operations: key generation, copying, importing, deletion and repair.
- **SEC-AVAIL-002:** Before a maintenance operation writes to key data storage, the user MUST be warned that loss of power or removal of the medium during the operation can destroy keys on that medium, and told when it is safe again.
- **SEC-AVAIL-003:** The device MUST be able to keep more than one copy of a Key, in independent storage regions or media, so that damage to one copy does not prevent use while another copy verifies (SEC-STORE-004). Every copy is key material: SEC-PTR-004 applies to all of them.
- **SEC-AVAIL-004:** Copies of the same Key MUST NOT be written at the same time. Each is written and verified before the next is written, so that one interrupted write can damage at most one copy.

## 4. Key Distribution

- **SEC-DIST-001:** Keys MUST be distributed via physical transfer only. Electronic transmission of key material over any network is PROHIBITED.
- **SEC-DIST-002:** A Key SHOULD be shared between exactly one alice and one bob. Distributing to multiple bobs is possible but they MUST be treated as read-only recipients — multiple bobs share the same offset range and any bob encrypting from it would cause immediate key reuse and irrecoverable loss of secrecy for all recipients. In a multi-bob scenario, any bob can also impersonate alice by encrypting from alice's offset range, and other bobs have no way to detect this. More broadly, any party holding key material can misuse it in this way; limiting distribution limits exposure.
- **SEC-DIST-003:** Upon receiving a Key, the recipient SHOULD verify the Key ID matches the expected value before importing it into a session. Mismatches SHOULD be investigated before proceeding.
- **SEC-DIST-004:** Unintended duplication of a Key creates additional parties who can decrypt all messages encrypted under that Key. The system cannot prevent duplication; users are responsible for controlling how many copies of a Key exist.
- **SEC-DIST-005:** If a medium carrying a Key shows evidence of unexpected access or tampering, the user MUST be warned. The decision to proceed or discard is the user's.

---

## 5. Encryption and Decryption

### 5.1 Encryption Operation

- **SEC-ENC-001:** Encryption MUST be performed as `C[i] = P[i] XOR K[offset + i]` for each byte `i` of the plaintext, where `offset` is the session's current TX offset. Every key byte used MUST lie within the session's TX range; an encryption that would exceed the TX range MUST be rejected before any key byte is read. The TX offset initially equals the start of the TX range (0 for alice, `key_length / 2` for bob).
- **SEC-ENC-002:** The TX offset MUST be advanced and committed before ciphertext is output (SEC-PTR-003).
- **SEC-ENC-003:** Plaintext MUST NOT be written to any persistent storage. Plaintext buffers in volatile memory MUST be cleared immediately after ciphertext is produced.
- **SEC-ENC-004:** The message header MUST include the OTP offset at which encryption began, so the receiver can locate the correct key bytes. The offset is not a secret. Whether to include a Key ID in the header is a protocol decision left to the implementation.

### 5.2 Decryption Operation

- **SEC-DEC-001:** Decryption MUST be performed as `P[i] = C[i] XOR K[offset + i]`, where `offset` is taken from the message header. The range `[offset, offset + message_length)` MUST lie entirely within the session's RX range; otherwise the message MUST be rejected before any key bytes are read.
- **SEC-DEC-002:** If a Key ID is present in the message header, the receiver MUST verify it matches the session's Key before reading any key bytes. If no Key ID is present, session selection is the responsibility of the operator or higher-level protocol.
- **SEC-DEC-003:** Replay detection: the receiver MUST reject any message whose offset is below the session's RX offset. All bytes of the RX range below the RX offset are treated as consumed, including bytes skipped when messages are delivered out of order. Rejection MUST occur before any key bytes are read or output is produced.
- **SEC-DEC-004:** After successful decryption, meaning after the message's integrity check has been verified, the receiver's RX offset MUST advance to `max(RX offset, message_offset + message_length)`. Decryption MUST NOT modify the TX offset. A decryption that fails or is interrupted MUST NOT advance the RX offset.

### 5.3 Key Derivation Prohibition

- **SEC-KDF-001:** Key derivation functions, key stretching, or any algorithmic transformation of key material MUST NOT be used to produce the key stream. Key bytes MUST be used directly as the key stream. Computing integrity values over key material (SEC-STORE-004) is permitted, provided they are never used as, or mixed into, the key stream.

### 5.4 Session Isolation

- **SEC-ISO-001:** Key bytes from one session MUST NOT be accessible during an operation belonging to another session. The firmware MUST enforce session boundaries so that loading key bytes for session A never reads from the offset range of session B. Within a session, encryption MUST read key bytes only from the TX range and decryption only from the RX range.
- **SEC-ISO-002:** It is PROHIBITED for two sessions on the same device to share the same Key ID. Importing a Key whose Key ID already exists in a session record MUST be rejected.

---

## 6. Transmission

- **SEC-TX-001:** Ciphertext MAY be transmitted over any channel. Channel confidentiality is not required.
- **SEC-TX-002:** The message header MUST carry the OTP offset (SEC-ENC-004). No plaintext, key material, or session state beyond what is required by the header MUST appear in transmitted data.

---

## 7. User Interface

- **SEC-UI-001:** The UI MUST display the remaining key capacity for each session. Remaining capacity is half the total key length minus bytes consumed, since each party (alice or bob) has access to only their half of the key. When remaining capacity falls below a configurable threshold (default: 20%), a persistent warning MUST be shown. When a session is fully exhausted, the UI MUST notify the user and mark the session inactive.
- **SEC-UI-002:** Plaintext MUST NOT be retained in any scrollback buffer, clipboard, or undo history after the user dismisses the message view.
- **SEC-UI-003:** The UI MUST require explicit user confirmation before any encryption operation that advances the TX offset, to prevent accidental key consumption. Confirmation MAY be given interactively (answering a prompt, or typing `YES` on a console) or by an explicit confirmation option supplied with the command (for example `--yes`). Invoking an encryption command without such an option is not confirmation. Confirmation is an obligation of the user interface; the device protocol is not required to enforce it.
- **SEC-UI-004:** Quarantined sessions (SEC-META-003) MUST be visually distinguished from healthy sessions and MUST NOT be usable for encryption or decryption until the user explicitly resolves or deletes them.
- **SEC-UI-005:** OTP offset values and remaining key length MUST NOT appear in any log file or diagnostic output accessible to a remote party. Key IDs may appear in logs as they are not secret.

---

## 8. Hardware Design Requirements

- **SEC-HW-001:** All OTP operations (generation, encryption, decryption) MUST be performed on the dedicated Einszeit device. These operations MUST NOT be delegated to or performed on a host computer.
- **SEC-HW-002:** If removable media is used as key data storage during active sessions, its removal is equivalent to loss of key material for those sessions. The firmware MUST detect removal (by a card-detect input, by failure of any storage access, or by a change of card identity) and MUST NOT continue an in-progress encryption or decryption operation after removal is detected.
- **SEC-HW-003:** If key data storage and firmware storage share the same physical medium, they MUST occupy non-overlapping address regions. A firmware write or update operation MUST NOT be able to reach the key data region.

---

## 9. Firmware and Software Requirements

- **SEC-FW-001:** All firmware MUST be written in a memory-safe language, or all memory safety vulnerabilities MUST be identified and remediated by code review.
- **SEC-FW-002:** All variables holding plaintext or key bytes MUST be handled in a way that prevents compiler optimization from eliding clearing operations (e.g., `volatile`-qualified writes or explicit memory barrier calls in C).
- **SEC-FW-003:** Any memory region that held key bytes or plaintext MUST be cleared before it is reused for any other purpose.
- **SEC-FW-004:** The firmware MUST NOT expose a command, interface, or debug path that allows raw read access to key data storage. All key data access MUST go through the session management layer, which enforces offset advancement.

---

- **SEC-FW-005:** Firmware MUST exist as separate production and development images. A production image MUST NOT provide any software path into the bootloader, nor any debug or test feature that can read, write or reveal key material or plaintext. A development image MUST identify itself as such to the host. It MUST leave a persistent mark on the device that only device erase removes, and production firmware MUST warn when it finds that mark.

## 10. Testing Requirements

### 10.1 Entropy Testing

- **SEC-TEST-ENT-001:** TRNG output MUST pass the NIST SP 800-22 statistical test suite (all 15 tests) on a minimum sample of 10⁸ bits, performed on each hardware revision and after any modification to the entropy source.
- **SEC-TEST-ENT-002:** If online entropy monitoring is implemented (§2.3), it MUST be verified by injecting a known-bad (biased) byte stream and confirming it triggers halt within one rolling window.
- **SEC-TEST-ENT-003:** The AIS-31 (BSI) test suite MUST be applied to characterise the TRNG output on each hardware revision.

### 10.2 OTP Offset Tests

- **SEC-TEST-PTR-001:** A test harness MUST verify, for both the TX and RX offsets, that offset advancement is monotonic under normal operation, simulated power loss at each stage of the metadata write sequence, and concurrent session access attempts.
- **SEC-TEST-PTR-002:** A test harness MUST verify that a corrupt session record (bit-flip injection into metadata storage) is detected on power-on and causes the session to be quarantined rather than silently used.
- **SEC-TEST-PTR-003:** A test harness MUST verify that offset rollback attempts (by command or simulated storage manipulation) are rejected.
- **SEC-TEST-PTR-004:** A test harness MUST verify that deleting a session makes the session unusable, then erases its key file, then removes the record, under simulated power loss and interrupted erasure at each stage; that deletion is refused when the key file cannot be erased; and that an override deletes the record and is logged.

### 10.3 Encryption Correctness Tests

- **SEC-TEST-ENC-001:** Known-answer tests (KATs) MUST be run on every firmware build: given a fixed key and plaintext, verify ciphertext byte-for-byte.
- **SEC-TEST-ENC-002:** A test MUST verify that encrypting the same plaintext at two different OTP offsets produces different ciphertexts.
- **SEC-TEST-ENC-003:** A test MUST verify that re-encrypting at the same offset is impossible because the offset has already advanced.

### 10.4 Session Isolation Tests

- **SEC-TEST-ISO-001:** A test MUST verify that importing a Key whose Key ID already exists in a session record is rejected (SEC-ISO-002).
- **SEC-TEST-ISO-002:** A test with two active sessions MUST verify that a read for session A never returns bytes from session B's offset range.
- **SEC-TEST-ISO-003:** A test MUST verify that decryption never modifies the TX offset, that encryption never reads key bytes outside the TX range, and that a message whose range is not entirely within the RX range is rejected before any key bytes are read.

### 10.5 Replay Tests

- **SEC-TEST-REPLAY-001:** A test MUST verify that a message with a previously consumed offset range, or with an offset below the RX offset, is rejected before any key bytes are read or output is produced.

### 10.6 Removable Media Tests

- **SEC-TEST-MEDIA-001:** A test MUST verify that removing key storage media during an in-progress operation causes the operation to be aborted cleanly, with no output after the removal is detected, and that:
  - (a) for an encryption that outputs ciphertext only after a single commit, removal before that commit results in no ciphertext output and no offset advancement;
  - (b) for an encryption that commits in several steps, every ciphertext byte output before the abort is covered by a committed TX offset, and no offset is rolled back;
  - (c) for decryption, the RX offset is not advanced.

### 10.7 Key Parameter and Storage Integrity Tests

- **SEC-TEST-STORE-001:** A test MUST verify that session creation is rejected for Key ID `0x00000000` and for key lengths that are zero or odd.
- **SEC-TEST-STORE-002:** A randomised test MUST run sessions between two devices over key data storage that misbehaves arbitrarily (persistent corruption of key data and of integrity values, substitution of a different Key under the same Key ID, transient read errors, removal at any storage access, power loss at any metadata write) and MUST verify after every operation that every ciphertext byte output equals the plaintext byte XOR the true key byte at its position within the sender's TX range, that no key position is output in two messages, and that every decryption reported as successful returns the original plaintext.
- **SEC-TEST-STORE-003:** A test MUST verify that a Key imported with integrity values is refused if any block fails verification, and that a Key imported without them is refused if it fails the statistical tests or contains duplicated blocks.

---

### 10.8 Availability and Image Tests

- **SEC-TEST-AVAIL-001:** A test MUST cut power repeatedly during maintenance writes and record, for each interruption, whether copies or data other than those being written were damaged. Its results MUST be reported as measured rates for the media tested; they cannot prove the absence of failures.
- **SEC-TEST-FW-005:** The build MUST fail if a production image contains a call that enters the bootloader, or development or test features.

## 11. Requirements Traceability

Every implementation artifact (hardware schematic, firmware module, test case, user manual section) MUST reference the requirement IDs it satisfies. No requirement may be marked satisfied by documentation alone; each MUST be demonstrated by a passing test (§10) or a physical inspection record.

---

## 12. Revision History

| Rev | Date | Changes |
|---|---|---|
| 1.0 | 2026-09 | Initial normative release. |
| 1.1 | 2026-10 | Clarifications and amendments listed below. |
| 1.2 | 2026-10 | SEC-PTR-004 and SEC-TEST-PTR-004 (session deletion erases the key). |
| 1.4 | 2026-10 | SEC-AVAIL-001..004 and SEC-TEST-AVAIL-001 (availability of key data); SEC-FW-005 and SEC-TEST-FW-005 (production and development images). |
| 1.3 | 2026-10 | SEC-STORE-004/005 and SEC-TEST-STORE-002/003 (key data verified before use); SEC-KDF-001 and §3 clarified. |

**Rev 1.1 changes.** Each entry states why the change does not reduce device security.

1. **TX and RX ranges (Definitions, SEC-META-001/002, SEC-PTR-001/002/003, SEC-ENC-001/002, SEC-DEC-001/003/004, SEC-ISO-001, SEC-TEST-PTR-001, new SEC-TEST-ISO-003).** Rev 1.0 defined a single OTP offset per session. Read literally, SEC-DEC-004 then advanced the offset used for encryption to the end of a decrypted message from the peer's half, after which encryption would reuse the peer's key bytes; and messages from the lower half never triggered replay rejection. Rev 1.1 makes explicit that each party encrypts only from its own half and decrypts only from the peer's half, with a separate, independently committed offset for each. *Security effect:* removes a key-reuse path and makes replay detection effective in both directions.
2. **Replay rule (SEC-DEC-003, SEC-TEST-REPLAY-001).** Replay detection is defined by the RX offset (a high-water mark). This also rejects messages delivered out of order once a later message has been decrypted. *Security effect:* stricter than Rev 1.0; never accepts a message Rev 1.0 would reject.
3. **Decryption commit (SEC-DEC-004).** States that a failed or interrupted decryption does not advance the RX offset. *Security effect:* none on secrecy; decrypting the same ciphertext again reveals nothing new.
4. **Incremental commit (SEC-PTR-003).** Permits an encryption to commit in several steps, provided no ciphertext byte is output before a verified commit covers it. This is what streaming encryption of large inputs requires. *Security effect:* none; the invariant that every output byte is covered by a committed offset is unchanged and now stated per byte.
5. **Removable media test (SEC-TEST-MEDIA-001).** Split into single-commit encryption (Rev 1.0 behaviour retained), multi-step encryption, and decryption. For multi-step encryption, ciphertext already output before removal is permitted because a committed offset covers it. *Security effect:* none; key bytes behind output ciphertext are never reused, and the Rev 1.0 guarantee is retained wherever an operation commits once.
6. **Removal detection (SEC-HW-002).** Names acceptable detection methods so that removal can be detected when no card-detect switch is fitted or reliable. *Security effect:* broadens detection; does not relax the abort obligation.
7. **Quarantine without re-validation (SEC-META-003).** Forbids rewriting the integrity check of a corrupt record when quarantining it. *Security effect:* closes a path by which quarantine itself could validate corrupted offsets.
8. **Non-zero Key ID and even key length (SEC-STORE-002, new SEC-STORE-003, new SEC-TEST-STORE-001).** A zero Key ID could not identify a key file and could not coexist with SEC-ISO-002; an odd key length leaves the halves unequal. *Security effect:* removes ambiguity in key selection and range arithmetic.
9. **Confirmation (SEC-UI-003).** States which forms of confirmation are acceptable and that the obligation rests with the user interface. *Security effect:* clarification only.
10. **Divided integrity protection (SEC-META-001).** Rev 1.0 required one check covering the entire record. A single check over a record that includes the offsets must be rewritten on every offset update, and a power loss between the offset write and the check write then makes a healthy session appear corrupt. Rev 1.1 allows independently written parts of the record to carry their own checks, provided every field remains covered. *Security effect:* none on detection, since every field is still covered; makes atomic offset updates (SEC-META-002) achievable without a recovery step. The scheme used and its verification are in EZ-IMPL-001 §3.2–3.5 and the host test suite.

**Rev 1.2 changes.**

11. **Session deletion erases the key (new SEC-PTR-004, SEC-TEST-PTR-004).** Under Rev 1.1, deleting a session left its key file in place, and a new session for the same file restarted the TX offset at the beginning of its range. Every byte already consumed was then used a second time. SEC-ISO-002 prevents only two sessions existing at once. Rev 1.2 makes deletion quarantine the session, erase the key, and only then remove the record. Quarantining first matters because erasure on a real filesystem proceeds block by block: an interruption would otherwise leave a usable session over a key whose bytes are partly zero, and XOR with zero outputs the plaintext. Users who must keep a key (for example to recover from a damaged session) can copy it before deleting; the warning tells them a copy must never be used to start a new session. *Security effect:* closes a key-reuse path. The override for an inaccessible key file is a user decision, recorded in the event log, and covered by SEC-DIST-004.

**Rev 1.3 changes.**

12. **Verify before use (new SEC-STORE-004, SEC-TEST-STORE-002).** Rev 1.2 protected the metadata that records consumption, but not the key bytes themselves: if a card returned wrong bytes for a position (zeroed data, another Key's data after filesystem corruption, data from elsewhere in the same Key), the device would use them. Zero bytes output plaintext; another Key's bytes, or bytes from elsewhere in the same Key, are key reuse. Rev 1.3 requires every key byte to be verified against an integrity value bound to its Key and position before use, and requires refusal on any storage failure. Together with the existing offset requirements this makes the guarantee independent of storage reliability: storage failure can cost availability, never secrecy. SEC-TEST-STORE-002 tests exactly that invariant against arbitrary misbehaviour. *Security effect:* closes key-reuse and plaintext-exposure paths through storage faults.
13. **Keys without integrity values (new SEC-STORE-005, SEC-TEST-STORE-003).** Integrity values computed on arrival protect a Key only from then on. A Key damaged before arrival in ways that matter (blank regions, duplicated blocks) is refused by statistical and duplicate checks. *Security effect:* rejects keys whose damage would otherwise be locked in as valid.
14. **SEC-KDF-001 clarified.** Its wording forbade "any algorithmic transformation of key material", which also covers computing a hash for verification. The intent, that the key stream be the key bytes themselves, is unchanged and now stated precisely. *Security effect:* none on the key stream.
15. **Integrity values are key material for handling purposes (§3, SEC-STORE-004, SEC-PTR-004).** A hash of key bytes carries information about them. Stored beside the Key it reveals nothing to someone who does not already hold the Key, but on its own it would weaken the information-theoretic claim. It is therefore handled exactly like the Key. *Security effect:* prevents a new leak path.

**Rev 1.4 changes.**

16. **Availability (new §3.4).** Hardware testing (TR-03, TR-04) showed that pulling an SD card during a write can destroy both FAT copies, losing every key on the card. Secrecy held throughout, since verification refused the missing key, but a device whose keys can only be replaced by meeting again has to protect their availability too. SEC-AVAIL-001 records a property the design already has: normal use never writes. SEC-AVAIL-002 makes the remaining risk explicit to the user. SEC-AVAIL-003 and SEC-AVAIL-004 require independent copies written one at a time. *Security effect:* none on secrecy; all copies are key material under SEC-PTR-004.
17. **Production and development images (new SEC-FW-005).** A compromised host that can put the device into its bootloader can load firmware that reads every key, on the card as well as in flash. Production images therefore have no software path into the bootloader, and the build verifies that on the binary. Development images, which do have one for convenience, identify themselves and mark the device. *Security effect:* closes the remote bootloader path for production devices, and makes the use of development firmware visible afterwards.

---

*End of EZ-SEC-001*
