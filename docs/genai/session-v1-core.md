# Session Summary — V1 planning, specification update, metadata layer

## What Was Requested

A review of the V1 plan for the firmware refactor, the `ez` rewrite, the
on-device CDC console and the automated test suite, followed by
implementation. Constraints: conformance to EZ-SEC-001 with every deviation
documented; requirement IDs on every artifact; host testing against
simulated memory wherever possible; three UF2 images (HID, CDC, composite).

## Decisions Reached in Review

- Each party encrypts from its own half of the key and decrypts from the
  peer's half, with separate TX and RX offsets. Rev 1.0's single offset
  allowed decryption to move the encryption offset into the peer's half.
- Replay detection by RX high-water mark. A decryption commits only after
  its CRC verifies, so failures spend nothing.
- Encryption in two modes: buffered (up to 64 KB; nothing spent unless the
  single commit happens) and streaming (commit before each frame; a failure
  spends only the key behind output already sent). Committed ciphertext may
  be re-sent unchanged.
- Confirmation is a UI obligation (`--yes`, or typing `YES`); the hardware
  button is for the bootloader only.
- Drive 0 (NOR flash) disabled by default because the bootloader can read
  flash; no software path into BOOTSEL.
- Key ID 0 disallowed; 24 sessions; event log in F-RAM.
- Host-link encryption and Zeitlos deferred to later phases.

## What Was Produced

- EZ-SEC-001 Rev 1.1, with a revision history stating the security effect of
  each change.
- EZ-IMPL-001 Rev 2.0, with binding `IMPL-` IDs.
- New documents: EZ-DEV-001 (deviations), EZ-TRACE-001 (traceability),
  EZ-PLAN-001 (plan).
- `core/`: the metadata layer and its primitives.
- `tests/`: framework, F-RAM simulator, 48 test cases, CI workflow.

## Findings During Implementation

- Rev 1 of the session record put one CRC over the whole record, including
  the offsets. Every offset commit therefore rewrote the CRC, and a power cut
  between the two writes made a healthy session look corrupt. Rev 2 moves
  frequently written fields outside the static CRC.
- The bit-flip suite found that after a torn commit, the larger offset sat in
  a slot the read rule treats as expendable, so a later bit flip could
  silently revert it. The reversion was harmless in that case, but the design
  now persists the roll-forward at boot, so the protection no longer depends
  on that argument.
- Deleting a session and re-creating it for the same key file restarts the
  offsets (DEV-12 / OI-01). This is open and needs a decision.
- An off-by-one in format's final chunk was found by the first test run.

## Verification

All 48 cases pass under ASan and UBSan with gcc 13 and clang. `gcc -fanalyzer`
and `clang --analyze` report nothing on `core/`. Eight deliberate defects in
the commit protocol were each detected by the suite.

---

## Round 2 — Phase 1b

### Produced

- Keystore and TRNG HAL contracts; simulators for both. The TRNG simulator is test-only and deterministic.
- Core management (`ez_core.c`), the encryption engine (`ez_engine.c`), the key generation job (`ez_keygen.c`), entropy tests (`ez_entropy.c`), the message codec and base64.
- EZ-ENT-THR-001 with a reproducible derivation script, and `ez_entropy_check` for checking the thresholds against real captures.
- 96 host test cases; 22 deliberate defects in total, all caught.

### Findings

- Rejecting a key on any failed FIPS 140-2 block would reject about 4% of 1 MiB keys from a perfect source; ent001 itself shows one monobit failure in 5,040 blocks. Acceptance therefore counts failing blocks against a Poisson bound.
- The first mutation run showed that a missing per-piece clear of key scratch was invisible to checks made between calls. The simulated key storage now flags any read into a buffer that still holds data.
- Several media tests initially assumed a fixed number of storage calls per operation; the count depends on how the key range aligns to blocks. The sweeps now search for the completing fault position instead.
- Two test bugs (reusing a zeroed output length; decrypting the same message twice) were found by the engine's own checks: the replay check correctly refused the second decryption.

---

## Round 3 — session deletion and FatFs

### Decisions

- Deleting a session erases its key, after a warning. A user who must keep a key can copy it first.
- FatFs may be vendored; its licence is listed in the README.

### Produced

- EZ-SEC-001 Rev 1.2: SEC-PTR-004 and SEC-TEST-PTR-004.
- Core: deletion in three steps (quarantine, erase, remove record) with a logged override; key delete and device erase quarantine first; coded quarantine reasons; damaged-key detection in the engine.
- FatFs R0.16 patch 3 vendored unmodified, with provenance and checksums.
- FatFs key storage port, a block-device interface, and a RAM-disk simulator.
- Key storage conformance suite run against both backends.
- 114 host test cases; 28 deliberate defects caught in total.

### Findings

- Erasure on a real filesystem proceeds block by block. Erasing a key before making its session unusable would let an interruption leave a usable session over partly zeroed key bytes, and XOR with zero outputs the plaintext. The simulator's all-at-once erase had hidden this; considering FatFs exposed it. SEC-PTR-004 now requires quarantine before erasure.
- That made the quarantine reason byte security-relevant: a single bit flip could have turned "being erased" (not resolvable) into "missing" (resolvable). The bit-flip suite found it, and the byte is now coded like the status byte.
- The first damaged-key check missed a run of exactly 16 because it was tested only at the end of each piece; the new tests caught it.
- The conformance suite found that FatFs's append mode silently creates a missing file, contrary to the HAL contract.
- FatFs is not power-fail safe; the residual risk to key files is recorded as DEV-15 and open item OI-10.

---

## Round 4 — long file names and exFAT

- Long file names (UTF-8 API) and exFAT enabled after measuring the cost on Cortex-M33: about +7 KB flash and +1.1 KB RAM. `ffunicode.c` is 1.3 MB of source but compiles to one code page's tables.
- HAL names widened to 255 bytes and matched case-insensitively, as on FAT. Over-long names are refused rather than truncated, because a truncated name could address a different file.
- exFAT added as a third conformance backend; the removal and interrupted-deletion sweeps and a complete device test run on exFAT too. 116 host test cases.
- First size measurement was wrong: the mirror's template `ffconf.h` beside `ff.h` was picked up instead of the project's configuration. That is why the vendored copy deliberately omits it.
- Question answered: F-RAM cannot make FAT access atomic on V1 (2 KB, 96 bytes spare; a sector journal needs kilobytes), and a journal would not stop SD-internal corruption anyway. Proposed instead (OI-10): pin each key's extent and card identity in F-RAM and read key bytes through the extent; run drive 0 without a filesystem, with its allocation table in F-RAM.

---

## Round 5 — key integrity

### Decided

FatFs stays and is treated as an untrusted data store. The guarantee is that whatever happens to a card, the device either uses the true key bytes for a position or refuses. Broken parts of a key can be skipped for encryption, after the user confirms. A `.SUM` cannot be assumed to travel with a key. The cross-key duplicate check is not built.

### Produced

- EZ-SEC-001 Rev 1.3: verify before use (SEC-STORE-004), checks for keys arriving without integrity values (SEC-STORE-005), clarified SEC-KDF-001, and tags handled as key material.
- EZ-IMPL-001 Rev 3.0: the `.SUM` format, instance tags, the import job, verify-then-use, and skip.
- Code: SHA-256, the tag module, a verified-unit buffer in the engine, the skip command, `.SUM` generation and verified copies, and the import job (acceptance tests plus duplicate check when no `.SUM` is present).
- The chaos test: two devices, arbitrary card misbehaviour, and an oracle that checks every output byte against the true key and every key position for reuse.

### Findings

- A different card holding a different key under the same Key ID would carry a self-consistent `.SUM`. A random instance tag recorded with the session closes this.
- The first skip design looked only at the current position; the failing message's damage was in the next unit. Skip now acts on the damage the operation reported.
- The chaos run's coverage check showed skips almost never happened. Most persistent damage made every operation fail before any unit was read, which is correct but untested for skipping, so the corruption was redirected to the region about to be used.
- Process: a mutation run inside the working tree timed out and left a mutation (the disabled instance check) in place. It was found by inspection and restored, and mutation runs now use a separate copy of the tree.

---

## Round 6 — drive 0 store and intent record

### Produced

- **Drive 0 key store** (`ports/ezstore`): two flash copies of a 4 KiB allocation table, one selected by a coded F-RAM byte, so a commit is a single atomic byte. Appends are not committed; temporaries are finalised by rename, so a full-partition key costs two table writes. Files are erased before they leave the table, and mount fully validates the table and every chain.
- **Router** joining the store (drive 0) and FatFs (cards) into one key storage interface, so the core is unchanged.
- **Intent record:** confirmed destructive operations complete automatically after interruption, and others wait while one is pending.
- **NOR flash simulator** with torn erase and program.
- 133 host test cases; 7 more mutations.

### Findings

- The first wipe design erased the table copies first, so an interruption would have left the selector pointing at an erased table. It now erases data, commits an empty table to the inactive copy, then erases the old copy.
- A torn erase leaves part of a block erased. "Original or erased" holds per byte, not per block.
- Two mutations first survived because of weak tests, not weak code. A cross-link test with several defects at once, and a boot-level resume hidden by the per-drive resume. Both tests were sharpened.

---

## Round 7 — hardware bring-up image (Phase 3a)

- Reordered ahead of Phase 2, at the owner's delegation, to test hardware assumptions early.
- **Produced:**
  - drivers behind every HAL: F-RAM, the QSPI key partition via `flash_safe_execute`, the microSD with SEND_STATUS and CID re-check, and the TRNG at profile 1 with no bypass code;
  - a bring-up shell and an on-target KAT running the core over RAM HALs;
  - a post-build check that the image never reaches the key partition;
  - a CI firmware job.
- **Built with pico-sdk 2.1.1:** 116 KB flash, 124 KB static RAM.
- **Not yet run on hardware.** The procedure is TR-03.
- **Findings at build time:**
  - The SDK has a `reset_block` symbol that clashed with a local name.
  - Automatic reconfigures lost `PICO_SDK_PATH`; it is now cached.
  - The large job structures were moved off the stack. pico-sdk's `PICO_STACK_SIZE` does not set the real limit with this memory map.

### TR-03, first results

- F-RAM present, and the KAT passes on target.
- TRNG at 2,264 bit/s, with no health flags in 1,708 collections.
- Keys generated on drive 0 and on the card, with correct `.SUM` sizes.
- A session works: send counter correct, and `dec` of an own message is refused with RANGE.
- The card check detects removal. The first `sd watch` did not remount, a shell gap since fixed in 0.1.1.
- SD_DET is driven high with a card present and floats without one, so it needs the internal pull-down. The bench `board.h` assumed active-low with a pull-up, which read 1 in both states. Image 0.1.2 corrects this; OI-03 is closed.
- Step 9: pulling the card during key generation gave MEDIA_REMOVED. On reinsertion the card was remounted and the cleanup removed the leftover temporaries. Cosmetic fix in 0.1.4: the shell no longer shows 100% for a failed run, and names the failure bits.
- At the owner's request, `fw update` (reboot into the UF2 bootloader) was added to the bring-up image only, under `EZ_BRINGUP` (DEV-19).

---

## Round 8 — Phase 2 part 1

- **Produced:**
  - `proto/`: the frame and payload codec, the dispatcher and the client;
  - the virtual device and the new `ez` (buffered mode);
  - protocol tests, an end-to-end script with two virtual devices, and four libFuzzer harnesses in CI.
- **Found while building:**
  - A request refused at its first frame would have drawn one error per remaining frame, desynchronising the host. Fixed by the rule of exactly one response per request (IMPL-PROTO-001).
  - The client tracked frame position in an 8-bit counter, which broke responses over 256 frames (a 64 KiB message is 1,131).
  - The random-frame key scan first covered only 440 response bytes; valid read-only commands were added, bringing it to 129 KB.
  - A new device read as FAULT: the drive 0 store formats itself and writes its F-RAM selector before the core boots, and the core required all 2 KB to be blank. Blankness is now judged over the core's own regions only. This likely also explains the FAULT on the board's first bring-up boot.
  - The first fuzzing runs showed the store fuzzer stopped at the CRC check and the FatFs fuzzer slowed by a large image; both harnesses were improved. No crashes in about 3 million executions.

---

## Round 9 — USB

- The bring-up image is now a CDC + HID composite, driven through TinyUSB directly, with the console as a stdio driver over CDC.
- HID frames are queued in the USB callback and dispatched only while the shell is idle, so the shell and USB never use the core at once. The protocol works with no terminal open.
- Cards are mounted automatically on SD_DET.
- `ez` gained the hidapi transport, using upstream's vendored hidapi 0.15 amalgamation (Windows, macOS and Linux). It selects the interface by usage page, with `--device`, `device list` and a udev rule. Also fixed: `--help` works without a device, `ez` waits for a starting virtual device, and `DEVICE` now has an explanation.
- Known limitation, OI-13: long single-request commands block the USB task.
- Earlier in this round: the owner's two-device test with virtual devices tripped over two mistakes in my instructions. One was a race in starting the device; the other was `device erase` erasing the key just copied onto the virtual card, which is correct behaviour.
- TR-04 first results: `ez` over USB works (device info, log, sessions, key generation on the card and on drive 0). Card removal mid-generation over USB is handled. A 64 KiB key on the card works from the shell, so the first failed USB generation was not size-related; still unexplained, watching for a repeat.
- Fixes: CDC echo (no background flush in the new stdio driver), `ez` wording for failure bit 0x80, BUSY instead of silence while the console holds the core (`external_busy`, with a test), and 100% shown at job completion.
- Open question to the owner: `5B79EE11.KEY` (session `self`) is missing from the card. Either removed by hand, or lost to FAT damage from the interrupted writes (DEV-15, availability only).

---

## Round 10 — availability decisions, images, TR-05

### Discussion (owner's decisions)

- **Card:** storage only, behind a closed case. FatFs kept; mirrored FAT volumes, written one at a time.
- **Writes:** normal use never writes; a "do not unplug" warning only during maintenance.
- **No OTP.** Drive 0 stays disabled by default until OI-02 is proven.
- **Critical keys** are mirrored everywhere available.
- **Exchange:** a new card is handed over and kept by the receiver.
- **Default key size 256 KiB.** No "lasts about" estimates.
- **Firmware partition** up to 1 MiB.
- **SEC-HW-003:** the owner corrected my misquotation ("share no medium"); the actual text allows a shared medium with separated regions, which drive 0 can meet through the partition table.

### Produced

- SRS Rev 1.4 (SEC-AVAIL-001..004, SEC-FW-005, tests); EZ-IMPL-001 Rev 4.0.
- Production and development images. The production image passes a post-link check that rejects any reachable bootloader call; the check was shown to fail on such a call.
- The development mark in F-RAM, `ez` warnings and presets, and TR-05 (write protection, then power cuts with a tally).

### Found

- My first attempt at proving the production check passed vacuously: the injected call was unreachable, so the linker removed it. With the call made reachable, the build fails as intended.
- A duplicated §2.7 heading from round 6 broke a document edit, and was fixed.

---

## Round 11 — OI-02, drive 0's flash protection

- **Partition table** (`partitions.json`, checked with picotool at build): firmware 8 KiB–1 MiB; keys 1 MiB–4084 KiB with Secure-only access; the last 12 KiB left unpartitioned after picotool warned about the boot ROM's RP2350-E10 block.
- **Flash driver:** maps the key partition into XIP window 1 (ATRANS1), since with a partition table the boot ROM maps the firmware's partition at the start of window 0.
- **Guard:** the core's drive 0 guard is answered by the boot ROM's partition information. Drive 0 is refused, or unusable once enabled, unless the protection is verified; erasing it stays possible. Status `PROTECTION`, and the protection state in `DEVICE_INFO`. The guard survives core re-initialisation; a test checks this, after noticing `ez_core_init` clears the structure.
- **Not yet run on hardware.** The register and boot ROM details came from SDK headers, not from a running board. TR-06 proves it.
- The guard test showed that, without protection, a session on drive 0 could not be deleted, because erasing its key went through the guarded check. Erasing reveals nothing, so the destructive paths now use a separate check without the guard.

---

## Round 12 — the mirror core

- **Produced:**
  - the portable mirror layer and copy addressing in the storage interface (`EZ_COPY`);
  - replication at session creation, import and copy;
  - failover per unit, check and repair, with protocol commands and `ez` commands;
  - SEC-AVAIL-002 warnings, `ez-vdev --mirror`, a mirrored chaos run, mirror tests and an e2e scenario.
- **Found:** the mirrored chaos run's true-key oracle failed. Failover accepted a unit from copy 1 that belonged to a *different key under the same Key ID*: its own valid `.SUM` vouched for it, because unit tags do not include the instance. Fixed by requiring any `.SUM` that vouches for a unit to carry the expected instance. A deterministic regression test was added, and shown to fail with the condition removed (on the second attempt; the first mutation did not compile, so the old binary passed).
- **Measured:** on the same seeds, refusals fell from 1,329 to 561 with two copies, and encryptions completed rose from 3,564 to 4,244. Secrecy held in both.
- **Deferred to round 13:** the firmware's card format with two volumes.

---

## Round 13 — the card mirror in firmware

- **Card format** (IMPL-AV-007): an `EZM2` MBR with two FAT32 partitions (A: 4 MiB to half the card; B: half to the end). Formatting erases reachable files in place, issues SD ERASE over the card, then writes the MBR and both file systems.
- **Mounting** detects the format: a mirrored card gives two copies; any other card gives one.
- **Isolation:** every drive except 0 and the card answers "absent", so volume B cannot be reached directly.
- **Policy in the core, mechanics in the platform:** a format hook, refused while sessions use the drive. `ez drive format`, copies shown in `drive info`, a virtual-device hook, e2e 29 checks.
- **Not run on hardware:** the SD erase command sequence and MBR layout come from the SD and MBR specifications; TR-07 tests them.
- **Moved to round 14:** critical keys and drive-0 generation, both of which depend on TR-06.

---

## Round 14 — critical keys, generation on drive 0

- **Critical sessions** (a static flag) keep an extra copy on drive 0:
  - written after the card copies;
  - the last failover source;
  - checked and repaired;
  - the source for rebuilding a lost card (format, repair, resolve; the offsets survive in F-RAM);
  - erased with the session.
- **Staged generation:** `ez key generate` generates on drive 0 when it is usable, copies the key to the card in one burst, and erases it from drive 0.
- **Process slips this round:**
  - A Python edit script with a syntax error did nothing, while a compile check still passed on the unchanged files.
  - A run against a removed build directory showed only failures until it was reconfigured.
  - A positional initialiser missed the new `flags` field.
  All were caught before packaging.

### Owner's hardware results, after round 14

- **TR-06 passes on V1. OI-02 is closed.**
  - The table installs as designed.
  - The firmware verifies the protection through the boot ROM.
  - Drive 0 works through XIP window 1 at its new location.
  - picotool reads the firmware partition but gets "permission failure" on the key partition, for both reading and writing.
  - A drag-and-drop UF2 aimed at the key partition was refused by the boot ROM ("Access denied").
  - The drive 0 key still encrypts afterwards, with its offset continuing.
- **TR-07: `ez drive format 1` failed with MEDIA_REMOVED** with the card present. The format re-initialised the SD card up to three times. It now does so only if the card is not working, checks with SEND_STATUS after the ERASE commands, and the shell's `sd format` prints each step.
- **TR-07 diagnosis:**
  - The PC formats the card fine; the board fails on block writes, then the card wedges until power is cut.
  - Cause: the SD driver sent commands without waiting for the card to be ready, and capped the write busy time at 1 s.
  - Fixed: wait for ready before every command except the init CMD0; 3 s busy limit.
  - A failed read or write on a card that still answers now reports MEDIA, not MEDIA_REMOVED, and keeps the card marked present.
  - The driver records its last error for `sd format` and the new `sd test`.
  - Format no longer uses the port's whole-device zero-fill (hours on 32 GB); it zaps reachable key files, then uses SD ERASE.
- **TR-07, card unresponsive after format attempts until power-cycled** (formatting on Linux power-cycles it):
  - SD reset (CMD0) now waits for the card to finish, resynchronises with 80 clocks, and reselects for up to 50 attempts.
  - Presence is "any valid SEND_STATUS reply"; error flags are card errors (MEDIA), never "absent".
  - No command is sent for blocks beyond the card's end, since damaged FAT structures can point there.
  - Initialisation failures name their step in `sd test` and `sd format`.
- TR-07: write test OK, ERASE 7550/7550 OK, MBR OK; mkfs failed 'busy before CMD13' after the whole-card ERASE. Busy limits raised to 10 s, settle up to 30 s after ERASE; failed format leaves 'not mounted'.
- TR-07: after the whole-card ERASE, the card stayed busy across runs (the first ERASE of the next run failed; still busy after 30 s). Whole-card ERASE is now opt-in (`--erase`, `sd format 2 erase`), waiting up to 5 min for the card; default format = erase reachable key files, then MBR and file systems. Staged generation worked on hardware: the key was generated on drive 0 and kept there when the copy to the card failed.
- TR-07: volume B never mounted (its file system was never created by an interrupted format). Added IMPL-AV-004 volume repair (ez drive repair 1 / sd repair: recreate only unmountable copy volumes), periodic remount of copy volumes, per-volume state in info and in the format printout.

---

## Round 15 (part 1) — an SD card simulator

At the owner's suggestion, an SD card emulated byte by byte in SPI mode (`tests/hwsim`), with a pico-sdk shim and virtual time. The firmware's own `ez_sd.c`, `hal_sdblk.c` and `card.c` run unchanged on the host.

**The simulator's first bugs were its own:**
- the response to CMD24 was swallowed by data-receive mode;
- background erase time accumulated per chunk.

Both were found by tracing (`SDTRACE=1`).

**Reproduced TR-07:**
- the exact `write MBR … busy before CMD 0x0d` line;
- the reset-while-busy limit;
- a never-formatted volume B.

**Fixed and kept as tests:**
- a 5-minute write limit during format;
- volume repair;
- repair skipping unavailable copies.

The background-erase test was shown to fail with the old 10-second limit.

## Round 15 (part 2) — streaming over USB

- **Protocol:** six lockstep commands (`ENC_BEGIN/DATA/END`, `DEC_BEGIN/DATA/END`) over the core's existing stream API. Any other command, or a transport reset, aborts a stream; key already committed stays spent.
- **`ez`:** streams above 64 KiB (`--stream` forces it). Plaintext is written only after `DEC_END` succeeds.
- **Tests:** 300,000 bytes A to B over the protocol; tampering detected at the end; an interrupted stream leaves its key spent and refuses further data; e2e with `--stream`.
- **Two test-side mistakes:** a 1,000-byte chunk (the limit is 512), and an e2e message larger than its session's sending half.

### TR-07 rerun (0.3.6-dev): `sd repair` failed after 10 s, then the shell froze

- **Repair** now has format's patience: a 2-minute settle and a 5-minute write limit.
- **The periodic remount** blocked the main loop on a busy card. It now tries at most every 30 s, and never while the card is busy (a one-byte check).
- **Firmware** 0.3.7-dev.
- **Simulator tests:** the first versions passed even with the fixes removed, because the driver waits out busy periods inside a write. Two emulator controls (`sim_sd_make_busy`, `sim_sd_slow_next_writes`) make the tests fail with each fix removed and pass with it.
- **TR-07, `sd repair` silent for over a minute:**
  - I first blamed FatFs's cluster size; a test on a simulated V1-size card showed FatFs already uses 32 KiB clusters there, so I reverted that change.
  - Recreating a 15 GB volume is ~7,600 writes (~15 s at 1.5 ms per write in the simulator; over a minute on V1's card).
  - Fix: progress in MiB during format and repair, and an up-front "can take a few minutes" line. The USB console services USB while printing, so progress arrives live.
  - Multi-block writes (CMD25) could speed this up: round 16, with the simulator.
- **TR-07, volume B mounted after `sd repair` was restarted part-way:** not proof of a complete file system, since FatFs writes the boot sector first.
  - A volume's MBR entry is now type 0xDA (pending) while its file system is created, and 0x0C only once complete; pending volumes are never mounted.
  - `sd repair a|b` forces recreation of a volume that mounts (needed once for V1's card, whose B predates the marker).
  - Simulator test: repair cut 20 writes in; shown to fail without the marker. Firmware 0.3.9-dev.
- TR-07: sd repair b showed no progress (1 MiB granularity too coarse for V1's slow card). Progress every 64 KiB or 2 s with estimate and elapsed time; average ms per block reported at the end. Owner's direction: automate mirror sync in the background, show 'degraded', require --force; design proposed for round 16 (second core for card maintenance).
- **TR-07:** owner reports no output for several minutes after 'mark it pending' on 0.3.9; the slow-card theory is wrong. A liveness hook inside the SD driver's waits now prints 'card busy (...) for N s', to tell a stuck card, slow writes and a crash apart (0.3.11-dev).
- **Owner's decisions for round 16:**
  - while degraded, no writes to the card without --force;
  - --force in ez only;
  - CLI message 'system degraded; recommend waiting for nominal state';
  - automatic background sync.
- **Proposed exception:** deletion stays allowed while degraded.
- TR-07: repair wrote 1,564 blocks, then one CMD24 stayed busy for over 54 s, permanently (only a power cut recovers). Same pattern as earlier hangs after runs of writes: suspect card power, signal integrity, or card firmware in SPI mode. Added 'sd stress <blocks> <pause ms> <MHz>' to measure (0.3.12-dev).
- TR-07 stress: at 12 MHz, 4 MHz and with 5 ms pauses, the card stalls between blocks 1,000 and 1,500 (repair: 1,564). It follows the write count, not time: not power or clock; the card in SPI single-block mode. 0.3.13-dev: stress shows busy seconds, waits 10 min, reports every 100 blocks.

### TR-07 root cause: our SD driver, not the card

- **Reference tests (owner):** Linux wrote 3,000 synchronous single-block writes to the Transcend card at 2.7 ms each; another card passed `sd stress` with our driver. So the driver failed with this card.
- **Difference from Linux:** our driver polled a busy card continuously with CS low; Linux polls with status commands. The card's periodic internal work (every ~1,565 writes) never finished while clocked continuously.
- **Fix (0.3.14-dev):** poll continuously for 2 ms, then release the card between checks (deselect, 8 clocks, 1 ms, reselect).
- **Simulator mode:** a card whose internal work progresses only while released. With the old polling it stops at write 1,564 (the board stopped at 1,564 and 1,566); with the fix it passes 3,500 writes.
- **Lesson:** I blamed the card repeatedly; the owner's insistence that real cards don't stall for 70 s was right.

---

## Round 16 — jobs on the second core, the automatic mirror

**The owner's direction:** no freezes; all long work on the second core; the mirror maintains itself; degraded means no card writes without `--force` (`ez` only).

**Built:**
- **Jobs:** long commands are deferred and run as jobs; `JOB_RESULT` returns the reply. A core-1 worker on the device runs them, and `ez_dispatch_poll` runs them inline elsewhere.
- **Background sync:** quick (files, sizes, instances) every 5 minutes; full on events and failovers. It yields to commands.
- **Health:** shown in `DEVICE_INFO`, with `ez` warnings and the `--force` policy.
- **Device side:** the console's format and repair run as jobs; output from core 1 goes through a ring.

**Found while building:**
- A sync scheduled before the worker started lost an early yield request; the flag is now cleared when scheduled.
- My test damaged copy 0 and deleted copy 1 together; that unit is genuinely lost, and the sync was right to say degraded.
- External changes went unnoticed until the next event, hence the periodic quick sync.
- "Read-only" commands that touch the card or F-RAM are unsafe in parallel with a core-1 job; only RAM-only commands are answered during a job.

**Verified:** host tests, 43 e2e checks, 140k fuzz executions. Firmware 0.4.0-dev builds; not yet on hardware (TR-08).
- Owner: 'sd dir' shows one list (the mirror's combined view). Added 'sd dir a|b' per volume, and a mirror line in the console's info (health, last full and quick checks). 0.4.1-dev.

---

## Round 17 — the terminal interface

**Built:**
- **The UI module** (`ui/`, portable): the frame, Home with live status and warnings (the owner's logo), Keys (list and details), Device, Help, and the new CLI. Long commands are jobs.
- **Images:** `einszeit_hid`, `einszeit_cdc` and `einszeit_composite` (production checks on all three), plus `einszeit_dev`.
- **Drive 0 on by default** when protected.
- **`ez-vdev --term`,** with 28 screen tests using `pyte`.

**Found while building:**
- **The keys table was 81 columns wide** in the first rendering; caught by looking at the emulated screen.
- **Device erase listed only copy 0** of a mirrored card; it now reaches every copy.
- **My `#ifdef` for the stdio driver** closed at the wrong `#endif`; caught by the firmware build.
- **`pyte` doesn't implement the DEC line-drawing set,** so the line under the menu shows as `qqqq` in tests. Real terminals draw a line; TR-09 checks it.

## Round 18 — the key manager

**Owner's changes:** an ASCII separator, and a logo-only Home.

**Built:**
- **Dialogs and multi-step flows** in the UI.
- **Actions on the Keys screen:** N new (staged on drive 0), I import, X export to a transfer card (guided swap), D delete (type the label; force on failure), S skip, Q resolve.
- **Dispatcher:** `ez_dispatch_start_keygen` and `ez_dispatch_start_import`, shared by HID and UI.
- **Firmware:** card removal is noticed at once (SD_DET).

**Found by the screen tests:**
- Import's file name was blanked: `snprintf` copied a buffer onto itself. Fixed with `memmove`.
- A shorter dialog left a taller one's border behind.
- My test sent two backspaces where one was meant.
- My packaging step kept deleting the build directory; it no longer does.

**Result:** 54 screen checks, stable across runs.

## Round 19 — Send and Receive

**Built:**
- **Zetta,** vendored unmodified.
- **Send:** key pick, editor, a confirmation with the byte counts, encryption, an immediate wipe, the base64 view and copy view.
- **Receive:** paste capture with an early check of the message magic, staged once at full length, verified plaintext, plain-language errors, ready for the next paste.
- **Idle wipe** after 10 minutes.
- **Static UI scratch buffers** (stack frames measured on ARM), and a stack high-water mark in the dev image.

**Found by the screen tests:**
- `zetta_key(NULL, 0)` is undefined behaviour in its `memcpy`, which UBSan caught.
- Calling `ez_stage_message` per byte wiped the stage, and it refuses short lengths.
- A paste's trailing Enter closed the plaintext view.
- After an error, Receive wasn't ready for the next paste.
- My tampered test message was really a replay, so the test now tampers with a fresh message and checks the original still decrypts.
- Garbage was only recognised after 16 decoded bytes.

**Result:** 77 screen checks, stable across runs.

## Round 20 — polish from the owner's review

**The owner's points, all addressed:**
- size wording and a 64 KiB option;
- plain "where" choices;
- generation in the background with cancel;
- a backup on/off toggle;
- Ctrl-Y in the development image;
- clearing the terminal on connect.

**Backup toggle:** an atomic one-byte toggle bitmap in reserved F-RAM, rather than rewriting the static session record. The latter would risk an unreadable identity on power loss.

**Two races, found by the new background tests:**
- The shared `job_result` was overwritten by a background sync, so a cancel looked like success. Fixed with job tickets.
- Next steps couldn't start while a sync ran. Fixed with pending starts and yield.

**Vdev:** a worker thread and a TRNG rate limit, so background behaviour is testable. 90 screen checks.

## Round 21 — XMODEM

**The owner's direction:** a "security Swiss army knife" with XMODEM, YMODEM, ZMODEM and Kermit; no vendored code; each protocol isolated for testing. Reliable copy and paste matters greatly.

**Built:**
- `xfer/ez_xmodem`, written from the protocol description;
- isolated tests with a simulated line and time;
- interoperability with lrzsz (a test tool only): 25 of 25 on the first run;
- the interface: Send upload (Ctrl-O), view download (D), Receive upload (Ctrl-R);
- `ez decrypt` strips ^Z.

**Found by the tests:**
- An empty file's immediate EOT was ignored by the receiver.
- A strict-conversion warning in the CRC.
- `ez decrypt` rejected XMODEM-padded files.

**Result:** 99 screen checks, including a full round trip through the interface against lrzsz.

## Round 22 — ZMODEM

**Workspace:** the session's workspace was reset; it was restored from upstream (86791ef) plus the round 21 zip, and the toolchain was reinstalled.

**Built:**
- `xfer/ez_zmodem`, from Forsberg's description;
- `xfer/ez_xfer`, the protocol detection;
- the interface wired to it, with ZMODEM recognised on Receive;
- `fuzz_xfer`.

**Found against lrzsz,** none visible in the isolated tests:
- a hex header's CR LF read as data;
- `rz`'s double `ZRINIT`, which drew a second `ZFILE` and a rewinding `ZRPOS 0`;
- `sz` falling back to YMODEM on an early `C`;
- `sx` cancelled by repeated `ZRINIT` (the CAN in every header);
- prompt text reaching a terminal-started `sz`.

**Corrected test mistakes:**
- an assertion that block sizes never shrink under duplicated messages (wrong measure; replaced by an overhead bound);
- a test that duplicated every message, which no real line does (replaced by `rz`'s actual double `ZRINIT`); its mutation check showed our own receiver can't reproduce the `rz` bug, so the interop test is the regression check, and the test says so;
- an interop test that started the upload before the device asked, which a person can't do.

**Also found in round 22, by a clean-copy verification:**
- An end-to-end check ("the device returns to ok") waited a fixed 3 s, right on the edge of the virtual device's mirror-check timing (every 2 s after a quiet second), and had passed by luck.
- Replacing the sleep with 0.5 s polling exposed a real device problem: every request counted as activity, so a program polling the device's status more than once a second would hold off mirror maintenance indefinitely.
- Fix: status queries (`DEVICE_INFO`, `KEY_STATUS`, `JOB_RESULT`) are no longer activity. Tested in `test_proto/deferred_jobs`, including a mutation check, and the e2e checks now wait for the state instead of a fixed time.

## Round 23 — hardware testing, fixes and terms

**Tested by the owner on V1** (`einszeit_dev`, `einszeit_composite`; minicom with lrzsz on Linux): TR-09 (Home, navigation, Keys, Send, ZMODEM and XMODEM) and TR-08 (responsiveness during a job, self-repair of a deleted key file and of an overwritten card copy). The fixes below were sent back as new images and confirmed on the board, except the `JOB_RESULT` fix and the terms, which come after the last hardware run and are tested on the host only.

**Found on hardware and fixed:**
- The development image did not enumerate: `dev_early()` asked whether TR-05 was armed, which reads F-RAM, before F-RAM was initialised. F-RAM is now set up first.
- Device kept the arrow keys until Esc; Send did not open the editor after a key was picked if an information box had been shown earlier (its "end of flow" step outlived the flow). Both have screen tests that fail on the old code.
- Round 22's fix (status polls are not activity) let a background sync start the moment a job ended. `KEY_STATUS` then described the sync, so `ez key generate` printed no key ID; `JOB_RESULT` answered BUSY, so the copy to the card after a staged generation failed. Both now report the last command's job (`ujob`). Unit tests for each, mutation-checked.
- `ez device info` showed the last sync's 100% during a generation, and a card copy recreated by the sync showed 0% for several minutes. Real progress is now reported for both.
- The stack measurement counted core 1's stack; once corrected, it showed core 0 using all 6 KB before core 1's 2 KB stack. Each core now has a 16 KB stack in main RAM, with `MSPLIM` set (IMPL-JOB-003). Measured: core 0 7.2 KB (at boot), core 1 3 KB.

**Not explained:** one background sync stayed at 0% for about seven minutes, then finished normally. The likeliest causes are a card copy being recreated (which reported no progress then) or the stack overlap (fixed since); neither is confirmed.

**Terms, decided by the owner:** *internal storage* (drive 0) and *spare copy* (a critical key's drive 0 copy), with *card copy A/B* and *card mirror*; "backup" is no longer used. Applied to the interface (Home, Keys, dialogs, Help, which now explains them), the CLI (`ls internal`), `ez` (`session spare`, `--spare`; the old names still work) and the documents. EZ-IMPL-001 Rev 5.2 catches up rounds 18 to 23.

**Result:** host tests pass (screen 112, e2e 44, interop 64); all images build without warnings and the production check passes.
