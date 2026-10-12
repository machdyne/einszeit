# tests/ — Einszeit host test suite

Host-side tests for the portable core (`core/`), run against simulated
hardware (EZ-IMPL-001 §12). Each test case names the EZ-SEC-001 or
EZ-IMPL-001 requirement IDs it demonstrates; the runner prints them, so the
output can be cited directly in `docs/einszeit-traceability.md`.

## Running

```sh
tests/run.sh                 # build with ASan + UBSan and run everything
tests/run.sh -DEZ_SANITIZE=OFF
build/tests/test_meta_powercut commit_tx   # run one case
```

Requirements: a C11 compiler (gcc or clang) and CMake ≥ 3.13. No other
dependencies. After the unit suites, `run.sh` runs `tests/e2e/e2e.sh`: two virtual devices driven by `ez`, exchanging 64 KiB messages and checking replay refusal, terminal confirmation, the import checks, deletion, internal storage (drive 0), the card mirror's self-repair and degraded state, and spare copies (44 checks). Fuzzing is separate (`tests/fuzz`, clang only, 60 s per harness in CI). A full run takes about three minutes (the exFAT sweeps scan 16 MiB RAM disks; the chaos run checks about 4 million bytes).

Example output line:

```
[PASS] commit_tx          66 checks  (SEC-TEST-PTR-001, SEC-META-002, SEC-PTR-003)
```

## Layout

```
framework/   ez_test.h/.c   minimal runner (longjmp-based checks)
sim/         sim_fram       simulated SPI F-RAM with power-cut and bit-flip injection
             sim_keystore   simulated key storage: removal, swap, corruption, read log, stale-buffer detection
             sim_trng       TEST-ONLY deterministic entropy source with failure modes
             sim_blockdev   RAM disk under the FatFs port: removal, swap, raw-medium scans
             sim_flash      NOR flash: erase/program semantics, torn operations, erase counts
unit/        meta_fixture   shared setup for metadata tests
             core_fixture   a complete simulated device (two make a pair)
tools/       ez_entropy_check   run the device's entropy tests over a capture file
             derive_thresholds.py  reproduce the statistical constants
             test_*.c       the suites
```

## Suites

| Suite | Cases | Demonstrates |
|---|---|---|
| `test_primitives` | 4 | CRC check values, byte order, `ez_secure_zero` (SEC-FW-002) |
| `test_meta` | 19 | Functional metadata behaviour: ranges, Key ID/length rules (SEC-TEST-STORE-001), duplicate Key ID (SEC-TEST-ISO-001), allocation (SEC-META-004), TX/RX independence, exhaustion, quarantine, event log, device fault and repair |
| `test_meta_powercut` | 13 | SEC-TEST-PTR-001 / SEC-META-002: power cut after every byte of every metadata write sequence, then a full boot verification |
| `test_meta_bitflip` | 5 | SEC-TEST-PTR-002: every single bit of the F-RAM flipped in turn; 100,000 sampled 2-bit and 3-bit flips per suite |
| `test_meta_rollback` | 7 | SEC-TEST-PTR-003: rollback by command and by storage manipulation |
| `test_codec` | 5 | Message header (SEC-ENC-004, SEC-TX-002); base64 RFC 4648 vectors, incremental, malformed input |
| `test_entropy` | 8 | SEC-TEST-ENT-002 (monitor halts within one window); SEC-ENTROPY-002 acceptance tests on good, biased, correlated, counter and planted-defect data |
| `test_core` | 21 | Session create and import, key-file checks at boot (SEC-META-003), key delete and copy, drive 0 policy, device erase with power cuts |
| `test_keygen` | 9 | Generation pipeline: key equals TRNG output, read-back, TRNG fault, monitor halt, acceptance rejection, Key ID draw, removal, power loss |
| `test_engine` | 18 | SEC-TEST-ENC-001/002/003 (KATs computed independently in Python), SEC-TEST-ISO-002/003, SEC-TEST-REPLAY-001, Key ID selection, integrity, resend, clearing of plaintext |
| `test_keystore` | 10 | Key storage HAL conformance, run against three backends: the simulator, and the FatFs port (`ports/fatfs`) on FAT and on exFAT RAM disks; long UTF-8 names; raw-medium proof that erased keys leave no bytes; FatFs-backed device interop; removal and interrupted-deletion sweeps over FatFs; erase-block separation on drive 0 (IMPL-FS-001) |
| `test_sum` | 5 | SHA-256 (FIPS 180-4 vectors), unit geometry (units never cross the halves), tag binding to Key ID, length and position, incremental tagger, `.SUM` header |
| `test_chaos` | 2 | SEC-TEST-STORE-002: two devices, 4 seeds × 3,000 steps of arbitrary card misbehaviour; after every step a true-key oracle checks every ciphertext byte, every key position for reuse, and every successful decryption |
| `test_store0` | 6 | Drive 0 key store: basics, table wear, power cut at every flash operation of create/append/rename, erase and wipe (and at the F-RAM selector byte), mount-time table and chain validation, a complete device with drive 0 on the store (import from a card, generation, exchange, deletion, disable), interrupted deletion on drive 0 completed at boot |
| `test_proto` | 11 | USB protocol: frames, bounds-checked payloads, dispatcher and client end to end, including a 64 KiB round trip, RESEND/RELEASE, interrupted requests, BUSY during jobs, import, deferred jobs on a second core (with a background sync after them: status polling never holds it off, and the command's own result stays readable), streaming, and 200,000 random frames with every response scanned for key bytes |
| `test_mirror` | 11 | Keys kept as two copies: replication (copy 0 untouched), failover per unit, check and repair, deletion of every copy, a different key in a copy refused, power lost at every point of a replication |
| `test_sdcard` | 9 | **Hardware simulation** (`tests/hwsim`): the firmware's own SD driver, block layer and card module (`fw/einszeit/src/ez_sd.c`, `hal_sdblk.c`, `card.c`), compiled unchanged against a pico-sdk shim and an SD card emulated byte by byte in SPI mode. It reproduces V1's TR-07 failures (slow writes after a whole-card erase, a card unresponsive after a reset while busy, a volume B that was never formatted) and shows they are handled. `SDTRACE=1` prints every command |
| `test_xmodem` | 5 | XMODEM on its own (`xfer/`): every size boundary in 128-byte and 1K blocks, the checksum fallback, a noisy line, cancels both ways, an oversize file, timeouts. `tests/xfer/test_interop.py` runs XMODEM, ZMODEM and detection against lrzsz (64 combinations) |
| `test_zmodem` | 8 | ZMODEM on its own: window and subpacket boundaries with exact lengths, every byte value with and without ESCCTL, a noisy line (ZRPOS recovery, shrinking subpackets), oversize (ZSKIP), cancels, timeouts, ZCOMMAND refused, garbage |
| `test_xfer` | 3 | Protocol detection: the auto receiver against XMODEM (128 and 1K) and ZMODEM senders, the auto sender against both receivers, an XMODEM receiver already asking |
| `test_media` | 6 | SEC-TEST-MEDIA-001 (a), (b), (c): card removed or swapped before every HAL call; power cut at every byte of a streamed encryption |

## Fault model (F-RAM)

The simulator follows the `ez_hal_meta` contract: each byte write is
atomic, bytes are written in ascending address order, and nothing is cached.
`sim_fram_arm_cut(f, n)` lets the next `n` byte writes through, then drops
every later write and fails every access until `sim_fram_power_on()`.

The power-cut tests first measure how many bytes an operation writes, then
repeat it with the cut at every position from 0 to that count.

## Mutation check

To confirm the suites detect protocol defects rather than merely exercising
code, eight deliberate defects were injected into `core/src/ez_meta.c` one at
a time. Every one was detected.

| Mutation | Detected by |
|---|---|
| M1 Fall back to the other slot when the selected slot is corrupt | `damaged_selected_slot`, `out_of_range`, `reasons`, all bit-flip suites |
| M2 Drop the larger-of-two read rule | `selector_swap`, `commit_after_torn_commit`, `commit_after_repair_normalises`, `random_sequences`, bit-flip suites |
| M3 Drop commit-path normalisation | `commit_after_repair_normalises` |
| M4 Drop boot normalisation | `commit_after_torn_commit`, bit-flip suites |
| M5 Accept an equal offset as a commit | `by_command` |
| M6 Flip the selector before writing the slot | `commit_tx`, `commit_rx`, `random_sequences`, bit-flip suites and others |
| M7 Treat a corrupt record as valid (validate it) | `quarantine_volatile`, `damaged_selected_slot`, `role_tamper`, bit-flip suites and others |
| M8 Format writes the new header before clearing sessions | `format` |

Round 2 added fourteen more, in the engine, key generation and entropy code. All are detected.

| Mutation | Detected by |
|---|---|
| E1 Skip the card check before a buffered commit | `buffered_swap` |
| E2 Streaming commits only every other chunk | `streaming_powercut`, `streaming_removal`, `kat`, `interop`, `session_isolation` |
| E3 Streaming decryption commits RX before checking the CRC | `integrity`, `decrypt_removal`, `kat`, `interop` |
| E4 No replay check | `replay` |
| E5 No RX lower-bound check | `tx_rx_ranges` |
| E6 Key scratch not cleared per piece | eight engine and media cases (stale-buffer detection) |
| E7 Failed buffered encryption keeps the buffer | `buffered_removal`, `buffered_swap` |
| E8 Key generation ignores the acceptance verdict | `acceptance_rejects` |
| E9 Key generation ignores the online monitor | `monitor_halts` |
| E10 No capacity check before streaming | `tx_rx_ranges` |
| E11 Off-by-one key offset | `kat`, `interop` |
| E12 Buffered decryption reads key bytes before checking the CRC | `integrity` |
| E13 Key generation skips the read-back compare | `readback_corruption` |
| E14 Chi-square lower bound removed (counter accepted) | `accept_rejects_sources` |

Round 3 added six more, all detected:

| Mutation | Detected by |
|---|---|
| E15 Session record removed before the key is erased | `delete_erases_key`, `delete_powercut`, `delete_refused_and_override` |
| E16 Damaged-key run checked only at the end of each piece | `damaged_zero`, `damaged_ff_stream` |
| E17 Quarantine reason stored uncoded | `quarantine_persisted`, `quarantine_resolve`, `damaged_*` |
| E18 Session delete erases before quarantining | `interrupted_session_delete`, `delete_refused_and_override` |
| E19 Key delete quarantines after erasing | `interrupted_key_delete` |
| E20 Device erase skips quarantine | `interrupted_device_erase` |

Round 5 added eight more, for key integrity. All are detected:

| Mutation | Detected by |
|---|---|
| E21 Tag verification bypassed | `chaos`, `damaged_zero`, `damaged_ff_stream`, `damaged_rx`, `damaged_tag` |
| E22 Instance tag not compared | `chaos`, `other_key_same_id` |
| E23 Key bytes re-read from the card after verification | `chaos` (only the oracle sees this) |
| E24 Import ignores the acceptance verdict | `import_rejects` |
| E25 Import skips the duplicate check | `import_rejects` |
| E26 Import with `.SUM` ignores mismatches | `import_with_sum` |
| E27 Skip lands on the damaged unit instead of past it | `damaged_zero`, `damaged_ff_stream` |
| E28 `.SUM` not erased with the key | `delete_erases_key` |

Round 6 added seven more, for the drive 0 store and the intent record. All are detected:

| Mutation | Detected by |
|---|---|
| E29 Store flips the F-RAM selector before writing the new table | `powercut` |
| E30 Store mount falls back to the other table copy | `mount_faults` |
| E31 Store commits the table before erasing a file's data | `powercut` (bytes left in flash) |
| E32 Wipe erases the tables first | `powercut` |
| E33 Mount check for shared blocks removed | `mount_faults` |
| E34 No intent record for session delete | `interrupted_session_delete`, `delete_refused_and_override`, `fatfs_delete_sweep` |
| E35 No resume at the end of boot | `resume_without_drives` |

E33 and E35 first survived, and both showed gaps in the tests rather than in the code. The cross-link test's table had other defects too (a wrong length, an orphaned block), so other checks caught it before the sharing check was needed; it now isolates sharing. Resume also runs whenever a drive is mounted, which hid the boot-level call; a new test interrupts a device erase and boots with no usable drive.

E27 is not caught by the chaos oracle, and should not be. It costs availability (the next encryption is refused again), never secrecy, and the oracle checks secrecy.

Mutation runs work on a copy of the tree (`cp -r` to a scratch directory). In round 5 a run inside the working tree timed out and left a mutation in place.

The conformance suite also found a real divergence in the FatFs port before any firmware existed. FatFs's `FA_OPEN_APPEND` silently creates a missing file, whereas the HAL contract (and the simulator the other suites rely on) requires the append to fail.

E6 initially survived: the engine also clears the scratch buffer at the end of every call, which hid a missing per-piece clear from checks made between calls. The simulated key storage now counts any read into a buffer that still holds data, and all suites require that count to be zero.

## Adding tests

Each case is `{ "name", "REQUIREMENT-IDS", function }` in the suite's table.
Use `EZ_CHECK`, `EZ_CHECK_EQ` or `EZ_CHECK_MSG`; a failure aborts the case
and is reported with file and line. Add new suites to the `foreach` in
`CMakeLists.txt` and to `run.sh`.


## Screen tests

`tests/ui/test_ui.py <build dir>` drives the terminal interface (EZ-UI-001) through `ez-vdev --term` with the `pyte` VT100 emulator, and checks what a terminal would show (112 checks: the frame, Home, navigation, the CLI, the degraded state, the key manager, Send/Receive between two devices, background generation, cancel and spare copies with `ez-vdev --worker --trng-rate`, the terms on Home and Help, and XMODEM and ZMODEM through the interface against lrzsz). `tests/run.sh` runs them when `pyte` is installed (`pip install pyte`; CI installs `python3-pyte`). To look at the interface yourself: `ez-vdev DIR --term /tmp/t.sock` and `socat -,raw,echo=0 UNIX-CONNECT:/tmp/t.sock`.
