# Einszeit Requirements Traceability Matrix — Production

**Document ID:** EZ-TRACE-001  
**Governing specs:** EZ-SEC-001 Rev 1.4, EZ-IMPL-001 Rev 5.2  
**Scope:** portable core, production firmware, host software. The bench firmware has its own matrix (`fw/test/docs/EZ-TEST-TRACEABILITY.md`).  
**Status:** Living document. The rows reflect the tree as of round 16, with the job, stack and spare-copy rows (IMPL-JOB-001..003, IMPL-AV-005) updated for round 23. Hardware results (TR-03 to TR-09) are recorded with their procedures in `fw/einszeit/README.md` and in `docs/genai/session-v1-core.md`.

EZ-SEC-001 §11 requires every requirement to be demonstrated by a passing test or a physical inspection record; documentation alone never counts.

**Status values:**
- **Verified**: demonstrated by the passing test(s) named. "Verified (core)" means the requirement is fully demonstrated for the portable core, and the hardware port inherits the obligation through its HAL contract; the port's own evidence is listed as planned.
- **Partial**: the named part is verified; the rest is planned for the phase shown.

**Phases** (the order the work was done in): **1** the portable core on simulated hardware; **2** the USB protocol and host software; **3** the RP2350 firmware on V1 hardware; **4** the device's terminal interface; **5** the human audit before release. Phases 1 to 4 are done; a "planned" entry for phase 2, 3 or 4 means that piece is still to be shown, not that the phase is open.
- **Planned**: not yet implemented.
- **User**: an obligation on the user, covered by a manual section; it cannot be verified by test.
- **See DEV-nn**: deviation, interpretation or limitation in `docs/einszeit-deviations.md`.

**Test references:** `suite/case` refers to `tests/unit/<suite>.c`, case `<case>`. Run `tests/run.sh`; each case prints the IDs it demonstrates.

**Inspection references:** `file:symbol`. These count as evidence only together with the human audit (phase 5).

**Mutation evidence:** `tests/README.md` lists 43 deliberate defects (M1–M8, E1–E35), each caught by the suite. Where a row cites a mutation, that defect would violate the requirement, and the named tests catch it.

---

## EZ-SEC-001

### §2 Entropy and key generation

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-ENTROPY-001 | Partial | Key bytes come only from `ez_hal_trng.read()`; on target `fw/einszeit/src/hal_trng.c` reads only the TRNG EHR | Key file equals TRNG output byte for byte: `test_keygen/generate`. Inspection of `hal_trng.c` (no other source, no fallback). Hardware: TR-03 |
| SEC-ENTROPY-002 | Partial; see DEV-01 | Acceptance tests (`ez_entropy.c`); rename to `.KEY` only after acceptance | `test_entropy/accept_good`, `accept_rejects_sources`, `accept_each_test`, `reject_threshold`; `test_keygen/acceptance_rejects`; mutations E8, E14. The 8 bits/byte figure: DEV-01. Threshold check on ent001 data: test request |
| SEC-ENTROPY-003 | Partial; see DEV-03 | No software conditioning; profile 1 never sets `TRNG_DEBUG_CONTROL` | `test_keygen/generate`; inspection of `hal_trng.c` (no bypass code exists). Hardware register read-back: TR-03 follow-up |
| SEC-ENTROPY-004 | Partial | Halt on HAL fault, monitor failure or Key ID exhaustion; fault logged; no fallback | `test_keygen/trng_fault`, `monitor_halts`, `key_id_draw`; mutation E9. Hardware fault detection and reset in the port: Phase 3 |
| SEC-GEN-001 | Verified | One block in `kbuf`, cleared after write; `vbuf` cleared after compare | `test_keygen/*` checks both buffers are zero after every step |
| SEC-GEN-002 | Verified | Per-block read-back compare | `test_keygen/readback_corruption`; mutation E13 |
| SEC-GEN-003 | Verified; see DEV-07 | `EZ_EV_KEY_OK` / `EZ_EV_KEY_REJECTED` with length and test results | `test_keygen/generate`, `readback_corruption`, `trng_fault`, `acceptance_rejects`; `test_meta/log_ring`, `log_time`; `test_meta_powercut/log_append` |

### §3 Storage architecture

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-STORE-001 | Partial | `ez_key_delete()`, `ez_drive_disable0()`, `ez_device_erase()` over HAL `zap`/`wipe`; FatFs port erases in place; drive 0 store uses NOR block erase before commit | `test_core/key_delete`, `drive0`, `device_erase`; over FatFs, raw-medium scans show no key bytes after erase: `test_keystore/conf_rename_zap_list`, `conf_wipe`, `fatfs_device_interop`, `fatfs_drive0`; drive 0 store: `test_store0/basics`, `powercut` (gone from the table means gone from flash), `device_drive0`. Flash and SD drivers: Phase 3 |
| SEC-STORE-002 | Verified | Key ID drawn from the TRNG before the key; non-zero | `test_keygen/generate` (ID bytes precede, and are absent from, the key), `key_id_draw`; `test_meta/key_params` |
| SEC-AVAIL-001 | Verified | Encryption and decryption only read key storage | `test_chaos/chaos`, `chaos_mirror`: the simulator's write counter is unchanged around every encryption and decryption (about 7,000 operations); `test_mirror/failover` |
| SEC-AVAIL-002 | Verified (CLI) | `ez` warns before every write to key storage | `tests/e2e/e2e.sh` (warning before session creation) |
| SEC-AVAIL-003 | Partial (built everywhere; hardware TR-07 pending) | Mirror layer, replication, failover, check, repair | `test_mirror/*`; `test_chaos/chaos_mirror` (true-key oracle holds with copies; refusals 1,329 → 561 on the same seeds); e2e mirror scenario. TR-05 measures the premise on cards |
| SEC-AVAIL-004 | Verified (core) | `write_copy` one copy at a time, after copy 0 is complete | `test_mirror/replicate` (copy 0 unchanged during replication), `replication_interrupted` (power lost at each of 51 points: copy 0 intact, partial copy removed at mount, repair completes) |
| SEC-TEST-AVAIL-001 | Built, not yet run | TR-05 (`fw/einszeit/src/tr05.c`) | TR-05 run |
| SEC-FW-005 | Verified (build) | `einszeit_hid` and `einszeit_dev`; `app.h` refuses mixed definitions; development mark (`ez_core_mark_development`) | `fw/einszeit/check_production.cmake` (shown to fail when `reset_usb_boot` is reachable); `test_proto/device_and_sessions` (mark set, survives reboot, cleared by erase) |
| SEC-TEST-FW-005 | Verified | `check_production.cmake` after every production link, in CI | — |
| SEC-STORE-004 | Verified | Tags (`ez_sum.c`); verify-then-use (`ez_unit_load()`, `key_xor()`); instance tag; `.SUM` erased and copied with the key | `test_engine/damaged_zero`, `damaged_ff_stream`, `damaged_rx`, `damaged_tag`, `other_key_same_id`, `no_sum`; `test_sum/*`; `test_core/delete_erases_key` (`.SUM` erased); `test_chaos/chaos`; mutations E21–E23, E28 |
| SEC-STORE-005 | Verified | Import job (`ez_import.c`): acceptance tests and duplicate check without `.SUM` | `test_core/import`, `import_rejects`; mutations E24, E25 (see DEV-16) |
| SEC-STORE-003 | Verified | `ez_meta_session_create()` | `test_meta/key_params`; `test_core/session_create` |
| SEC-META-001 | Verified | Session record (IMPL §3.4) | `test_meta/full`; `test_meta_bitflip/single_bit_exhaustive`; `test_meta_rollback/role_tamper` |
| SEC-META-002 | Verified | IMPL-META-003 | `test_meta_powercut/*` (every byte); mutations M2–M4, M6 |
| SEC-META-003 | Partial | `ez_meta_boot()`; key-file checks in `ez_core_media_event()` | Records: `test_meta_bitflip/*`, `test_meta/quarantine_volatile`. Key files: `test_core/boot_key_checks`. User notification: Phase 2 |
| SEC-META-004 | Verified | `ez_meta_check_alloc()` | `test_meta/alloc_check` |
| SEC-PTR-001 | Verified | Checked slots, IMPL-META-002 | `test_meta_bitflip/*`; `test_meta_rollback/damaged_selected_slot`, `garbage_selector`; mutation M1 |
| SEC-PTR-002 | Verified; see DEV-12 | `commit()` | `test_meta_rollback/by_command`; mutation M5 |
| SEC-PTR-004 | Verified (key and `.SUM`) | `ez_session_delete()`: quarantine, erase, remove; same order in `ez_key_delete()`, `ez_device_erase()`; override logged | `test_core/delete_erases_key`, `delete_powercut`, `delete_refused_and_override`, `delete_missing_key`, `interrupted_*`; `test_keystore/fatfs_delete_sweep`; mutations E15, E18–E20 |
| SEC-PTR-003 | Verified | Buffered: commit, then assemble output. Streaming: commit inside each update | `test_media/buffered_removal`, `buffered_swap`, `streaming_removal` (invariant checked at every output), `streaming_powercut`; mutations E1, E2 |

### §4 Key distribution

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-DIST-001 | Partial | No core function accepts or returns key bytes (IMPL-API-001) | Inspection: `core/include/ez_core.h`, `ez_engine.h`, `ez_keygen.h`. Protocol test: Phase 2 |
| SEC-DIST-002 | User | Manual | Phase 5 |
| SEC-DIST-003 | User | Key ID shown at import | Phase 2 CLI test; manual |
| SEC-DIST-004 | User | Manual; see OI-01 | Phase 5 |
| SEC-DIST-005 | Planned (2) | Warning on unexpected key-file state | Phase 2 |

### §5 Encryption and decryption

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-ENC-001 | Verified | `key_xor()` over the TX range, key bytes from verified units | `test_engine/kat` (vectors computed independently in Python), `interop`; `test_chaos/chaos` (every output byte against the true key); mutation E11 |
| SEC-ENC-002 | Verified | As SEC-PTR-003 | `test_media/*`; `test_engine/no_reencrypt_at_same_offset` |
| SEC-ENC-003 | Verified | XOR in place; `ez_release()` clears the stage | `test_engine/plaintext_cleared`; `test_media/buffered_removal` (stage zero after failure); mutation E7 |
| SEC-ENC-004 | Verified | Message format v1 | `test_engine/kat` (offset field), `test_codec/header_roundtrip` |
| SEC-DEC-001 | Verified | `dec_select()` range check | `test_engine/kat`, `interop`, `tx_rx_ranges`; mutation E5 |
| SEC-DEC-002 | Verified | `dec_select()` | `test_engine/key_id` (mismatch rejected with no key read) |
| SEC-DEC-003 | Verified | `dec_select()` high-water mark | `test_engine/replay` (no key read); mutation E4 |
| SEC-DEC-004 | Verified | RX commit after CRC; TX untouched | `test_engine/tx_rx_ranges`, `integrity`; `test_media/decrypt_removal`; `test_meta/tx_rx_independent`; mutation E3 |
| SEC-KDF-001 | Verified; see DEV-17 | Key bytes XORed directly; tags never enter the key stream | `test_engine/kat` (independent plain-XOR vectors); `test_chaos/chaos`; inspection `core/src/ez_engine.c:key_xor` |
| SEC-ISO-001 | Verified | Session-bounded and range-bounded reads; `key_xor()` re-checks bounds | `test_engine/session_isolation`, `tx_rx_ranges`; `test_meta_rollback/out_of_range` |
| SEC-ISO-002 | Verified | `ez_meta_session_create()` | `test_meta/duplicate_key_id`; `test_core/session_create`, `import` |

### §6 Transmission

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-TX-001 | User | — | Manual |
| SEC-TX-002 | Verified | Output is header, ciphertext and CRC only | `test_engine/kat` (exact bytes and length) |

### §7 User interface

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-UI-001 | Partial; see DEV-08 | Capacity helpers, derived exhaustion | `test_meta/exhaustion`; `test_engine/session_states`. Display: Phase 2 |
| SEC-UI-002 | Partial; see DEV-05 | Device side: decrypted plaintext cleared on release | `test_engine/plaintext_cleared`. Host and console: Phase 2/4 |
| SEC-UI-003 | Planned (2, 4) | IMPL-CLI-001; console `YES` | Phase 2 |
| SEC-UI-004 | Partial | Engine and metadata refuse quarantined sessions | `test_engine/session_states`; `test_meta/quarantine_persisted`. Visual distinction: Phase 2 |
| SEC-UI-005 | Partial; see DEV-06 | IMPL-LOG-001 | `test_meta_rollback/by_command`. `ez` logging: Phase 2 |

### §8 Hardware design

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-HW-001 | Planned (2, 3) | All OTP operations in the core on the device | Phase 2 inspection of `ez`; Phase 3 |
| SEC-HW-002 | Partial; card check confirmed on V1 (TR-03) | IMPL-ENG-010 | Simulated removal and swap at every HAL call: `test_media/*`, `test_keygen/removal`; at every block-device call over FatFs: `test_keystore/conf_removal`, `fatfs_removal_sweep`; mutation E1. Hardware: Phase 5 |
| SEC-HW-003 | Partial; see DEV-04 | Separate regions (partition table: firmware 8 KiB–1 MiB, keys 1 MiB–4084 KiB, Secure-only); image size checked against its partition; the firmware refuses drive 0 unless the boot ROM confirms the protection (IMPL-DRV-003) | `check_size.cmake` on every build; `test_core/drive0_guard`; table contents checked with picotool at build. Hardware: TR-06 |

### §9 Firmware and software

| ID | Status | Implementation | Evidence / plan |
|---|---|---|---|
| SEC-FW-001 | Partial | C11, no heap; `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`; ASan + UBSan on every run; `gcc -fanalyzer` and `clang --analyze` in CI | Clean with gcc 13 and clang; analysers report no findings on `core/` (round 2). Fuzzing: Phase 1c. Human review: Phase 5 |
| SEC-FW-002 | Partial | `ez_secure_zero()` at every key and plaintext site | `test_primitives/secure_zero`; inspection `core/src/ez_secure.c`. Audit: Phase 5 |
| SEC-FW-003 | Verified (core) | Scratch cleared per piece and per call; stage cleared on release and failure; monitor and acceptance state cleared | `DEV_KBUF_CLEAR` after every engine and keygen call; simulated storage counts reads into dirty buffers (zero in all suites); `test_entropy/acc_clears_state`; mutation E6. Port buffers: Phase 3 |
| SEC-FW-004 | Partial | No core function returns key bytes (IMPL-API-001) | Inspection of the public headers. Protocol: Phase 2; firmware: Phase 3; see DEV-04 |

### §10 Testing requirements

| ID | Status | Evidence / plan |
|---|---|---|
| SEC-TEST-ENT-001 | Planned; see DEV-02 | NIST `sts-2.1.2` record |
| SEC-TEST-ENT-002 | Verified | `test_entropy/monitor_halts_within_one_window`, `monitor_late_failure`; `test_keygen/monitor_halts` |
| SEC-TEST-ENT-003 | Verified for V1 hardware rev | Carried from `fw/test` (AIS-31 T0–T8 on ent001) |
| SEC-TEST-PTR-001 | Partial | Power loss, TX and RX: `test_meta_powercut/*`, `test_media/streaming_powercut`. Concurrent access: Phase 2 (IMPL-ARCH-004; `test_engine/stream_exclusive` covers the engine part) |
| SEC-TEST-PTR-002 | Verified | `test_meta_bitflip/*` |
| SEC-TEST-PTR-003 | Verified | `test_meta_rollback/*` (see DEV-11) |
| SEC-TEST-PTR-004 | Verified (cards and drive 0) | `test_core/delete_powercut` (F-RAM cut at every byte), `interrupted_session_delete` (erase cut half way), `delete_refused_and_override`; `test_keystore/fatfs_delete_sweep` (card lost before every block-device call, on FAT and exFAT) |
| SEC-TEST-ENC-001 | Verified | `test_engine/kat`, run on every push by `.github/workflows/host-tests.yml` |
| SEC-TEST-ENC-002 | Verified | `test_engine/kat` (KAT_ALICE_1 vs KAT_ALICE_2) |
| SEC-TEST-ENC-003 | Verified | `test_engine/no_reencrypt_at_same_offset` |
| SEC-TEST-ISO-001 | Verified | `test_meta/duplicate_key_id` |
| SEC-TEST-ISO-002 | Verified | `test_engine/session_isolation` |
| SEC-TEST-ISO-003 | Verified | `test_engine/tx_rx_ranges`; `test_meta/tx_rx_independent` |
| SEC-TEST-REPLAY-001 | Verified | `test_engine/replay` |
| SEC-TEST-MEDIA-001 | Partial | (a) `test_media/buffered_removal`, `buffered_swap`, and over FatFs `test_keystore/fatfs_removal_sweep`; (b) `streaming_removal`; (c) `decrypt_removal`. On hardware: Phase 5 |
| SEC-TEST-STORE-001 | Verified | `test_meta/key_params` |
| SEC-TEST-STORE-002 | Verified | `test_chaos/chaos`: four seeds × 3,000 steps of arbitrary card misbehaviour; true-key oracle on every output byte (≈4.3 million per run), reuse check on every key position, plaintext check on every successful decryption |
| SEC-TEST-STORE-003 | Verified | `test_core/import_with_sum` (transfer damage refused), `import_rejects` (statistics, zeroed region, duplicated block); mutations E24–E26 |

---

## EZ-IMPL-001

| ID | Status | Evidence / plan |
|---|---|---|
| IMPL-ARCH-001 | Partial | Core includes only `ez_*.h` and the C library (inspection of `core/`) |
| IMPL-ARCH-002 | Partial | C11, no heap, `-Wpedantic -Werror`; Zeitlos build later |
| IMPL-ARCH-003 | Partial | All key access in `core/`; transports: Phase 2 |
| IMPL-ARCH-004 | Partial | `test_engine/stream_exclusive`; dispatcher: Phase 2 |
| IMPL-DRV-001 | Verified (core) | `test_meta/format_defaults`; `test_core/session_create`, `drive0`; `test_keygen/params` |
| IMPL-DRV-002 | Partial | Refusal with sessions, erase before disabling: `test_core/drive0`. Confirmation: Phase 2 |
| IMPL-DRV-003 | Partial | `test_core/drive0_guard` (refusal, unusable when protection disappears, erasing still possible, guard kept across init); hardware: TR-06 |
| IMPL-DRV-004 | Partial | Both stdio reset interfaces disabled (`fw/einszeit/CMakeLists.txt`). The bring-up image has `fw update` under `EZ_BRINGUP` (DEV-19); production images must not define it, to be checked by a build test once they exist. Hardware confirmation (`picotool reboot` must fail): TR-03 follow-up |
| IMPL-KEY-001 | Verified | `test_core/key_name` |
| IMPL-KEY-002 | Verified | `test_keygen/params` |
| IMPL-KEY-003 | Verified | `test_keygen/key_id_draw` |
| IMPL-KEY-005 | Verified | `test_engine/other_key_same_id`; `test_keygen/generate`; `test_core/import_with_sum`; `test_chaos/chaos` (card substitution); mutation E22 |
| IMPL-SUM-001 … 003 | Verified | `test_keygen/generate` (tags from read-back pass), `test_sum/*`, `test_core/delete_erases_key`, `key_copy` |
| IMPL-KEY-004 | Verified | `test_core/import`; long UTF-8 names on FAT and exFAT: `test_keystore/conf_long_names`, `exfat_device` |
| IMPL-GEN-001 | Verified | `test_keygen/removal`, `power_loss`; `test_core/import` |
| IMPL-META-001 … 007, 002a | Verified | See round 1 rows: `test_meta*` suites; mutations M1–M8. Coded quarantine reason: `test_meta_bitflip/*` (an "erasing" session never becomes resolvable); mutation E17 |
| IMPL-LOG-001, 002 | Verified | `test_meta/log_ring`, `role_default`; `test_keygen/generate` |
| IMPL-API-001 | Partial | Core API inspection; protocol: Phase 2 |
| IMPL-MSG-001 | Verified | `test_engine/key_id` |
| IMPL-ENG-001 | Verified | `test_engine/tx_rx_ranges`, `session_states`, `replay` |
| IMPL-ENG-002 | Verified | Unit-buffer and dirty-read checks after every engine call (`DEV_KBUF_CLEAR`); mutation E6 (round 2 form) |
| IMPL-ENG-013 | Verified | `test_engine/damaged_*`; `test_chaos/chaos`; mutations E21, E23 |
| IMPL-ENG-014 | Verified | `test_engine/damaged_zero`, `damaged_ff_stream`; `test_chaos/chaos` (skips under random damage, no reuse); mutation E27 |
| IMPL-ENG-003 | Verified | `test_media/buffered_removal`, `buffered_swap`; mutation E7 |
| IMPL-ENG-004 | Verified | `test_media/streaming_removal`, `streaming_powercut`; mutation E2 |
| IMPL-ENG-005 | Verified | `test_media/streaming_removal` (spent equals output); `test_engine/stream_exclusive` |
| IMPL-ENG-006 | Verified | `test_engine/integrity`; `test_media/decrypt_removal`; mutations E3, E12 |
| IMPL-ENG-007 | Partial | Device side (buffered releases only after CRC): `test_engine/integrity`. `ez`: Phase 2 |
| IMPL-ENG-008, 009 | Verified | `test_engine/resend` |
| IMPL-ENG-010 | Verified (core) | `test_media/*` (removal and swap before every HAL call). SD port (CMD13 + CID): Phase 3 |
| IMPL-ENG-011 | Verified on V1 (TR-03) | SD_DET active-high with the internal pull-down; the card check stays authoritative |
| IMPL-JOB-001/002 | Verified (host and V1: TR-08, round 23) | `test_proto/deferred_jobs` (answered at once, BUSY until run, JOB_RESULT, RAM-only commands during a second-core job, the command's result during the sync after it), `test_proto/jobs_and_busy` (KEY_STATUS reports the generation during the sync after it), fuzz; e2e |
| IMPL-JOB-003 | Verified (inspection and V1, round 23) | `app.c` (`app_main_on_stack`, `core1_main`): 16 KB stacks, `MSPLIM` set; high-water marks from the development image's `info` on V1 (core 0 7.2 KB, core 1 3 KB) |
| IMPL-AV-008/009 | Verified (host); hardware TR-08 | `test_mirror/sync` (repairs, lost units, quarantine lifting, degraded cases, yield); e2e (self-repair, DEGRADED, --force, recovery) |
| IMPL-AV-005 | Verified (host) | `test_mirror/critical` (drive 0 copy, failover to it, lost card rebuilt and session resolved with offsets intact, deletion of every copy, reported when drive 0 is disabled); the spare copy on and off from the interface (`tests/ui`, section 15); e2e |
| IMPL-AV-006 | Verified (host) | e2e (staged on drive 0, on the card afterwards, gone from drive 0) |
| IMPL-AV-007 | Verified (host) | `test_core/drive_format` (refused with sessions, never drive 0, hook kept across init); e2e (refused, then erases both copies on a mirrored virtual device); hardware: TR-07 |
| IMPL-PROTO-001 | Verified | `test_proto/interrupted_requests`, `jobs_and_busy` (one response for a refused multi-frame request); `fuzz_dispatch` |
| IMPL-PROTO-002 | Verified | `test_proto/device_and_sessions`, `encrypt_decrypt` (Key ID mismatch refused, nothing spent) |
| IMPL-API-001 | Verified | `test_proto/random_frames`: no 16-byte window of the key in any response, over 129 KB of responses |
| IMPL-ARCH-004 | Verified | `test_proto/jobs_and_busy` |
| IMPL-CLI-001, 003, 005, 006 | Verified | `tests/e2e/e2e.sh` (no terminal and no `--yes`: refused with no key spent; no output file on failure; deletion and import warnings) |
| IMPL-S0-001 | Verified | `test_store0/basics`, `table_wear`, `device_drive0` |
| IMPL-S0-002 | Verified | `test_store0/powercut` (every flash operation of create/append/rename, erase and wipe, plus the F-RAM selector byte), `table_wear`; mutations E29, E31, E32 |
| IMPL-S0-003 | Verified | `test_store0/mount_faults` (damaged table, damaged selector, cross-linked chain with valid CRC); mutations E30, E33 |
| IMPL-INT-001 | Verified | `test_core/interrupted_*`, `delete_refused_and_override` (pending blocks others; resumes on insertion), `device_erase` (power cut at every 7th F-RAM byte: undone or completed); `test_keystore/fatfs_delete_sweep`; `test_store0/intent_drive0`; mutations E34, E35 |
| IMPL-ENG-012 | Verified | Retained as a further defence; mutation E16 (round 3) |
| IMPL-FS-001 | Verified (FatFs port) | `test_keystore/fatfs_drive0` (no erase block holds bytes of two keys) |
| IMPL-ENT-001 | Partial | Profile 1 in `hal_trng.c`, reported by `info` and recorded in events; hardware: TR-03 |
| IMPL-ENT-002 | Partial | Halt and log on HAL fault: `test_keygen/trng_fault`. Block reset and fatal autocorrelation handling: Phase 3 |
| IMPL-CLI-001 … 005 | Planned (2) | |

---

## Coverage summary

| Round | Verified | Partial | Planned | User |
|---|---|---|---|---|
| 1 (62 SEC IDs) | 12 | 15 | 31 | 4 |
| 2 (62 SEC IDs) | 36 | 17 | 5 | 4 |
| 3 (64 SEC IDs) | 38 | 17 | 5 | 4 |
| 5 (68 SEC IDs) | 42 | 17 | 5 | 4 |

---

*End of EZ-TRACE-001*
