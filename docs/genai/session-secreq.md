# Session Summary

## What Was Requested

You are developing **Einszeit**, an open-source OTP encryption device. Over the course of this session you asked for:

1. A **security requirements specification** (EZ-SEC-001) defining the constraints necessary for information-theoretic (perfect) secrecy with OTP encryption, covering all system levels: hardware, firmware, storage, protocol, transmission, and UI.

2. Iterative refinement of the security spec through multiple rounds of review — clarifying scope, removing hardware-specific references, correcting inconsistencies, and aligning requirements with actual threat model decisions (physical security out of scope, authentication out of scope, zeroization optional, etc.).

3. An **implementation specification** (EZ-IMPL-001) built from a V0 README and your V1 architecture notes, covering the concrete design of the system: storage layout, metadata format, session record, API commands, CLI, transports, forward secrecy feature, and hardware targets.

4. Ongoing cross-document consistency checks and refinements as both documents evolved together.

---

## What Was Produced

### EZ-SEC-001 — Security Requirements Specification

- Defines the three OTP invariants and all requirements that enforce them
- Covers: entropy and key generation, storage architecture, OTP offset integrity, key distribution, encryption/decryption, transmission, UI, hardware, and firmware
- Explicitly scopes out: physical security, host security, authentication, and zeroization
- Key design decisions documented: alice/bob role partitioning, optional Key ID, multi-bob trust surface warning, dual-slot atomic offset update, per-session forward secrecy

### EZ-IMPL-001 — Implementation Specification

- Hardware abstraction layer and core API architecture
- FatFS on both NOR flash and MicroSD for key storage
- F-RAM layout: 32-byte device record (with boot counter for intrusion detection) + 48-byte session slots (up to 41 sessions in 2KB)
- Session record: full field layout including Key ID, key length, role, drive index, dual offset slots, selector byte, label, feature flags, CRC
- Core API command set with codes, grouped by function (session, key, crypto, drive, test, device)
- Message format with magic bytes, Key ID, offset, length, ciphertext, CRC32
- CLI command table mapping subcommands to API codes
- Forward secrecy feature with block-aligned erase strategy and power-loss recovery
- Development TODO list in priority order
