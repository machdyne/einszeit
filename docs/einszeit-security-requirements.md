# Einszeit Security Requirements Specification

**Document ID:** EZ-SEC-001  
**Status:** Normative  
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
| **Session** | A device's local record of its use of a specific Key, referenced by Key ID. Stores the current offset, role, drive index, human-readable name, and session status. Each Key has exactly one session per device; multiple sessions on one device correspond to multiple distinct Keys. |
| **Session status** | A flag stored in the session record indicating the session's operational state. Valid values: `VALID` (healthy and operational), `QUARANTINED` (integrity check failed; locked pending user action), `EXHAUSTED` (all key bytes consumed). Additional implementation-defined states (e.g. for optional features) may exist; see EZ-IMPL-001. |
| **Role** | A per-session designation of `alice` or `bob`, determining which half of the key the party consumes. Alice consumes from offset 0; bob consumes from `key_length / 2`. The key generator defaults to alice; the recipient defaults to bob. |
| **OTP offset** | The byte position of the next unconsumed key byte within a Key. Stored per-session in metadata storage. |
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

These tiers MUST NOT be swapped. Key material MUST NOT be written to metadata storage. Session metadata MUST NOT be written to key data storage.

### 3.1 Key Data Storage

- **SEC-STORE-001:** Key data storage MUST support erasure under firmware control. The firmware is solely responsible for all write and erase policies.
- **SEC-STORE-002:** Each Key MUST have a Key ID associated with it at creation time. The Key ID MUST be generated by the TRNG and MUST NOT be derived from or related to the key material bytes. The Key ID is conveyed out-of-band (via filename convention or manual exchange) and is not embedded in the key file. It is used to differentiate between multiple shared keys and to correlate key data with a session record in metadata storage.

### 3.2 Metadata Storage

Metadata storage MUST support byte-level or word-level writes with high endurance, making OTP offset updates atomic and efficient. The choice of medium is an implementation decision; the requirements below apply regardless.

- **SEC-META-001:** Each session record MUST contain at minimum: Key ID, role, drive index, key length, two OTP offset slots, an offset selector, session status, human-readable name, and a CRC or equivalent integrity check covering the entire record.
- **SEC-META-002:** OTP offset updates MUST be written atomically. Power loss during an update MUST leave the offset in either the pre-update or post-update state — never in a partially updated state.
- **SEC-META-003:** On every power-on, all session records MUST be read and their integrity verified before any session operation is permitted. A session with a corrupt record MUST be set to `QUARANTINED` and flagged to the user. It MUST NOT silently reset its offset.
- **SEC-META-004:** Before allocating a new session record, the firmware MUST verify that its address range does not overlap any existing session record. Allocation MUST be rejected if a conflict is detected.

### 3.3 OTP Offset Integrity

The OTP offset is the most security-critical piece of metadata. Its corruption or rollback directly enables key reuse.

- **SEC-PTR-001:** The OTP offset MUST be stored with integrity protection per SEC-META-001. A corrupt offset MUST be detected on read and MUST NOT be silently treated as zero or any other default value.
- **SEC-PTR-002:** The OTP offset MUST only advance forward. Any command or request to set an offset to a value less than or equal to its current verified value MUST be rejected and logged.
- **SEC-PTR-003:** The offset MUST be advanced and the update committed atomically before ciphertext is output. If the update cannot be verified, the operation MUST be aborted and no ciphertext output.

---

## 4. Key Distribution

- **SEC-DIST-001:** Keys MUST be distributed via physical transfer only. Electronic transmission of key material over any network is PROHIBITED.
- **SEC-DIST-002:** A Key SHOULD be shared between exactly one alice and one bob. Distributing to multiple bobs is possible but they MUST be treated as read-only recipients — multiple bobs share the same offset range and any bob encrypting from it would cause immediate key reuse and irrecoverable loss of secrecy for all recipients. In a multi-bob scenario, any bob can also impersonate alice by encrypting from alice's offset range, and other bobs have no way to detect this. More broadly, any party holding key material can misuse it in this way; limiting distribution limits exposure.
- **SEC-DIST-003:** Upon receiving a Key, the recipient SHOULD verify the Key ID matches the expected value before importing it into a session. Mismatches SHOULD be investigated before proceeding.
- **SEC-DIST-004:** Unintended duplication of a Key creates additional parties who can decrypt all messages encrypted under that Key. The system cannot prevent duplication; users are responsible for controlling how many copies of a Key exist.
- **SEC-DIST-005:** If a medium carrying a Key shows evidence of unexpected access or tampering, the user MUST be warned. The decision to proceed or discard is the user's.

---

## 5. Encryption and Decryption

### 5.1 Encryption Operation

- **SEC-ENC-001:** Encryption MUST be performed as `C[i] = P[i] XOR K[offset + i]` for each byte `i` of the plaintext, where `offset` is the current OTP offset for the session. The initial offset is role-dependent: alice starts at 0, bob starts at `key_length / 2`.
- **SEC-ENC-002:** The OTP offset MUST be advanced and committed before ciphertext is output (SEC-PTR-003).
- **SEC-ENC-003:** Plaintext MUST NOT be written to any persistent storage. Plaintext buffers in volatile memory MUST be cleared immediately after ciphertext is produced.
- **SEC-ENC-004:** The message header MUST include the OTP offset at which encryption began, so the receiver can locate the correct key bytes. The offset is not a secret. Whether to include a Key ID in the header is a protocol decision left to the implementation.

### 5.2 Decryption Operation

- **SEC-DEC-001:** Decryption MUST be performed as `P[i] = C[i] XOR K[offset + i]`, where `offset` is taken from the message header.
- **SEC-DEC-002:** If a Key ID is present in the message header, the receiver MUST verify it matches the session's Key before reading any key bytes. If no Key ID is present, session selection is the responsibility of the operator or higher-level protocol.
- **SEC-DEC-003:** Replay detection: the receiver MUST reject any message whose offset range overlaps a previously consumed range. Rejection MUST occur before any key bytes are read or output is produced.
- **SEC-DEC-004:** After successful decryption, the receiver's OTP offset MUST advance to `max(current_offset, message_offset + message_length)`.

### 5.3 Key Derivation Prohibition

- **SEC-KDF-001:** Key derivation functions, key stretching, or any algorithmic transformation of key material MUST NOT be used. Key bytes MUST be used directly as the key stream.

### 5.4 Session Isolation

- **SEC-ISO-001:** Key bytes from one session MUST NOT be accessible during an operation belonging to another session. The firmware MUST enforce session boundaries so that loading key bytes for session A never reads from the offset range of session B.
- **SEC-ISO-002:** It is PROHIBITED for two sessions on the same device to share the same Key ID. Importing a Key whose Key ID already exists in a session record MUST be rejected.

---

## 6. Transmission

- **SEC-TX-001:** Ciphertext MAY be transmitted over any channel. Channel confidentiality is not required.
- **SEC-TX-002:** The message header MUST carry the OTP offset (SEC-ENC-004). No plaintext, key material, or session state beyond what is required by the header MUST appear in transmitted data.

---

## 7. User Interface

- **SEC-UI-001:** The UI MUST display the remaining key capacity for each session. Remaining capacity is half the total key length minus bytes consumed, since each party (alice or bob) has access to only their half of the key. When remaining capacity falls below a configurable threshold (default: 20%), a persistent warning MUST be shown. When a session is fully exhausted, the UI MUST notify the user and mark the session inactive.
- **SEC-UI-002:** Plaintext MUST NOT be retained in any scrollback buffer, clipboard, or undo history after the user dismisses the message view.
- **SEC-UI-003:** The UI MUST require explicit user confirmation before any encryption operation that advances the OTP offset, to prevent accidental key consumption.
- **SEC-UI-004:** Quarantined sessions (SEC-META-003) MUST be visually distinguished from healthy sessions and MUST NOT be usable for encryption or decryption until the user explicitly resolves or deletes them.
- **SEC-UI-005:** OTP offset values and remaining key length MUST NOT appear in any log file or diagnostic output accessible to a remote party. Key IDs may appear in logs as they are not secret.

---

## 8. Hardware Design Requirements

- **SEC-HW-001:** All OTP operations (generation, encryption, decryption) MUST be performed on the dedicated Einszeit device. These operations MUST NOT be delegated to or performed on a host computer.
- **SEC-HW-002:** If removable media is used as key data storage during active sessions, its removal is equivalent to loss of key material for those sessions. The firmware MUST detect removal and MUST NOT continue an in-progress encryption or decryption operation after removal.
- **SEC-HW-003:** If key data storage and firmware storage share the same physical medium, they MUST occupy non-overlapping address regions. A firmware write or update operation MUST NOT be able to reach the key data region.

---

## 9. Firmware and Software Requirements

- **SEC-FW-001:** All firmware MUST be written in a memory-safe language, or all memory safety vulnerabilities MUST be identified and remediated by code review.
- **SEC-FW-002:** All variables holding plaintext or key bytes MUST be handled in a way that prevents compiler optimization from eliding clearing operations (e.g., `volatile`-qualified writes or explicit memory barrier calls in C).
- **SEC-FW-003:** Any memory region that held key bytes or plaintext MUST be cleared before it is reused for any other purpose.
- **SEC-FW-004:** The firmware MUST NOT expose a command, interface, or debug path that allows raw read access to key data storage. All key data access MUST go through the session management layer, which enforces offset advancement.

---

## 10. Testing Requirements

### 10.1 Entropy Testing

- **SEC-TEST-ENT-001:** TRNG output MUST pass the NIST SP 800-22 statistical test suite (all 15 tests) on a minimum sample of 10⁸ bits, performed on each hardware revision and after any modification to the entropy source.
- **SEC-TEST-ENT-002:** If online entropy monitoring is implemented (§2.3), it MUST be verified by injecting a known-bad (biased) byte stream and confirming it triggers halt within one rolling window.
- **SEC-TEST-ENT-003:** The AIS-31 (BSI) test suite MUST be applied to characterise the TRNG output on each hardware revision.

### 10.2 OTP Offset Tests

- **SEC-TEST-PTR-001:** A test harness MUST verify that offset advancement is monotonic under normal operation, simulated power loss at each stage of the metadata write sequence, and concurrent session access attempts.
- **SEC-TEST-PTR-002:** A test harness MUST verify that a corrupt session record (bit-flip injection into metadata storage) is detected on power-on and causes the session to be quarantined rather than silently used.
- **SEC-TEST-PTR-003:** A test harness MUST verify that offset rollback attempts (by command or simulated storage manipulation) are rejected.

### 10.3 Encryption Correctness Tests

- **SEC-TEST-ENC-001:** Known-answer tests (KATs) MUST be run on every firmware build: given a fixed key and plaintext, verify ciphertext byte-for-byte.
- **SEC-TEST-ENC-002:** A test MUST verify that encrypting the same plaintext at two different OTP offsets produces different ciphertexts.
- **SEC-TEST-ENC-003:** A test MUST verify that re-encrypting at the same offset is impossible because the offset has already advanced.

### 10.4 Session Isolation Tests

- **SEC-TEST-ISO-001:** A test MUST verify that importing a Key whose Key ID already exists in a session record is rejected (SEC-ISO-002).
- **SEC-TEST-ISO-002:** A test with two active sessions MUST verify that a read for session A never returns bytes from session B's offset range.

### 10.5 Replay Tests

- **SEC-TEST-REPLAY-001:** A test MUST verify that a message with a previously consumed offset range is rejected before any key bytes are read or output is produced.

### 10.6 Removable Media Tests

- **SEC-TEST-MEDIA-001:** A test MUST verify that removing key storage media during an in-progress operation causes the operation to be aborted cleanly, with no partial ciphertext output and no offset advancement recorded.

---

## 11. Requirements Traceability

Every implementation artifact (hardware schematic, firmware module, test case, user manual section) MUST reference the requirement IDs it satisfies. No requirement may be marked satisfied by documentation alone; each MUST be demonstrated by a passing test (§10) or a physical inspection record.

---

*End of EZ-SEC-001*
