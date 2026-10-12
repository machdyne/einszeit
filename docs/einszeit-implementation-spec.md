# Einszeit Implementation Specification

**Document ID:** EZ-IMPL-001  
**Status:** Informative, except where an `IMPL-` requirement ID is given; those are binding on the implementation and traced like EZ-SEC-001 requirements.  
**Revision:** 5.2 (see §14 Revision History)  
**Governing spec:** EZ-SEC-001 Rev 1.4  
**Scope:** Einszeit firmware, host software, and hardware interface design

---

## 0. Purpose

This document describes how the Einszeit system implements EZ-SEC-001. It covers architecture, storage layout, metadata format, the encryption engine, protocols, CLI design, and hardware targets.

Requirements specific to this implementation carry `IMPL-` IDs. Like SEC IDs, each must be demonstrated by a passing test or an inspection record and appears in the traceability matrix (`docs/einszeit-traceability.md`). Deviations from EZ-SEC-001 are recorded in `docs/einszeit-deviations.md`; open design questions and phase status are in `docs/einszeit-dev-plan.md`.

**Terms.** This specification uses the technical names: **drive 0** is the device's internal flash, **drive 1** the card, **copy volumes** the card's two copies, and a **critical** session one whose key also has a copy on drive 0. The interface and user documentation call these *internal storage*, *the card*, *card copy A and B* and a *spare copy* (EZ-UI-001, Terms); `ez` accepts both (`--spare` or `--critical`).

---

## 1. Architecture

### 1.1 Layers

```
 ez (host CLI)        on-device console (CDC)
       |                      |
   HID transport         shared CLI layer
       \                     /
        dispatcher (single operation at a time)
                 |
              core API          <- all security logic
                 |
   HAL: meta | keystore | trng | media | clock
                 |
   ports: rp2350 | host simulation | (zeitlos, later)
```

- **IMPL-ARCH-001:** The core MUST NOT reference hardware peripherals, register addresses, vendor SDKs or operating system services. All hardware access goes through the HAL interfaces in `core/include/ez_hal_*.h`.
- **IMPL-ARCH-002:** The core MUST be written in C11 with no dynamic memory allocation and no floating point, so the same sources build for RP2350, the host test suite, and later Zeitlos.
- **IMPL-ARCH-003:** The core is the only component permitted to access key data storage (EZ-SEC-001 SEC-FW-004). Transports and the CLI layers MUST NOT contain security logic; they translate requests into core API calls.
- **IMPL-ARCH-004:** The dispatcher MUST serialise operations: while one operation is in progress, a request arriving on any transport (HID or CDC in a composite build) receives `BUSY` and has no effect.

### 1.2 Repository layout

```
core/            portable core (include/, src/, core.cmake source list)
ports/fatfs/     key storage HAL over FatFs, for cards
ports/mirror/    the card mirror: copies A and B behind one key storage HAL
ports/ezstore/   drive 0 key store over NOR flash, and the router joining the drives into one HAL
proto/           the USB protocol: frames, payloads, the dispatcher and jobs, the host client
ui/              the terminal interface (EZ-UI-001)
xfer/            file transfer protocols: XMODEM, ZMODEM, detection
third_party/     vendored third-party code, code unmodified (fatfs/, zetta/)
fw/einszeit/     RP2350 firmware: drivers behind the HALs, the production and development images
fw/test/         bench validation firmware (existing; not a production artifact)
sw/ez/           host CLI, over USB HID (hidapi in sw/)
sw/vdev/         virtual device for tests (ez-vdev)
tests/           host tests: framework/, sim/ (simulated hardware), unit/, hwsim/ (SD card
                 emulator), e2e/, ui/ (screen tests), xfer/ (interop), fuzz/, tools/
docs/            specifications, user interface, deviations, traceability, entropy thresholds
```

### 1.3 HAL interfaces

| Interface | Purpose | Contract highlights |
|---|---|---|
| `ez_hal_meta` | Metadata storage (F-RAM) | Byte-addressed read/write; each byte write is atomic and bytes are written in ascending address order; no write caching. Backends that cannot meet this MUST provide an adapter that does, and MUST pass the metadata conformance tests (§12.2). |
| `ez_hal_keystore` | Key files on a drive | File-level: size, read at offset, create, append, rename, zap (zero then delete), list, wipe (drive 0), presence, and `check()` (same medium still mounted). No caching of file data; internal buffers cleared after each call. Full contract in `core/include/ez_hal_keystore.h`. Implemented in `ports/fatfs/` over FatFs R0.16 on an `ez_blockdev_t` per drive; the core does not depend on any filesystem. The port and the in-memory simulator pass the same conformance suite (`tests/unit/test_keystore.c`). |
| `ez_hal_trng` | Hardware entropy | Health-tested, hardware-debiased output only. MUST NOT be backed by any DRNG, PRNG or CSPRNG (SEC-ENTROPY-001). Returns `EZ_ERR_ENTROPY` after resetting the block on a health fault. Contract in `core/include/ez_hal_trng.h`. |
| `ez_hal_clock` | Uptime | Monotonic milliseconds since boot. The device has no real-time clock. |

---

## 2. Key Data Storage

### 2.1 Drives

| Index | Medium | Default |
|---|---|---|
| 0 | NOR flash key partition (2 MB), Einszeit store (§2.6) | **Disabled** |
| 1 | MicroSD | Enabled |
| 2 | MicroSD slot 2 (P1 only) | Enabled where fitted |

Drive 0 is disabled by default because the RP2350 USB bootloader (BOOTSEL mode, entered by holding the BOOT button while connecting) can read arbitrary flash with `picotool`. Key material on drive 0 is therefore exposed to anyone with brief physical access, unless the partition protection in IMPL-DRV-003 holds.

- **IMPL-DRV-001:** Drive 0 MUST be disabled after device initialisation. While disabled, every core operation addressing drive 0 MUST fail with `DRIVE_DISABLED`.
- **IMPL-DRV-002:** Enabling drive 0 requires an explicit command with user confirmation (SEC-UI-003 style) after the BOOTSEL readability warning has been shown. Disabling it MUST be refused while any session references drive 0, and MUST erase the whole key partition before the disabled state is recorded.
- **IMPL-DRV-003 (as built, round 11):** The flash carries a partition table (`fw/einszeit/partitions.json`, installed as `einszeit_pt.uf2`). Its key partition grants Secure read and write and denies Non-secure and bootloader access, so neither picotool nor a UF2 can read or write it (SEC-HW-003). At boot the firmware maps the key partition into XIP window 1 (QMI `ATRANS1`) and asks the boot ROM (`get_partition_table_info`) whether a partition table is present, and whether the partition covering the key region matches it exactly with those permissions. Only then does the core's drive 0 guard allow drive 0. Otherwise enabling it fails with `PROTECTION`, and an already-enabled drive 0 cannot be read or used (`PROTECTION`). Everything that only erases stays possible without the protection, since erasing reveals nothing: session delete, key delete, their resumption, drive 0 disable, device erase. A session on an unprotected drive 0 can therefore always be deleted normally, its key really erased. `DEVICE_INFO` reports the result (§9.4: one more byte: 0 not applicable, 1 missing, 2 verified). The hardware proof is TR-06.
- **IMPL-DRV-004:** Production firmware MUST NOT provide any software path into BOOTSEL mode: no vendor reset interface, no 1200-baud touch, no reboot-to-bootloader command. Firmware updates require the BOOT button at connection time.

### 2.2 Key files

A key file contains only raw TRNG bytes: no header, no metadata.

- **IMPL-KEY-001:** Key files are named `<KEYID>.KEY`, the Key ID in eight upper-case hexadecimal digits (e.g. `A73F2C01.KEY`). The Key ID MUST be non-zero (SEC-STORE-002).
- **IMPL-KEY-002:** Keys generated by the device MUST have a length that is a multiple of 512 bytes, from 8 KiB to 64 MiB. The lower limit gives the acceptance tests at least three FIPS blocks; the upper limit keeps the block-failure rule inside its precomputed table (§7.3). Keys from other sources MUST have a non-zero even length (SEC-STORE-003).
- **IMPL-KEY-003:** Key IDs are drawn from the TRNG before, and separately from, the key bytes (SEC-STORE-002). A Key ID that equals zero or collides with an existing session's Key ID or an existing file on the target drive is discarded and redrawn. Sixteen consecutive unusable draws are treated as an entropy fault (SEC-ENTROPY-004).
- **IMPL-KEY-004:** A key file without a `.SUM` beside it, or with any name other than `<KEYID>.KEY`, becomes usable only through the import job (§2.5). The user supplies the agreed non-zero Key ID; the file, which may have any long UTF-8 name, is renamed to `<KEYID>.KEY` once it has been accepted. Session creation directly from a file (`SESSION_CREATE`) requires a matching `.SUM`.
- **IMPL-KEY-005:** Each key has a random 16-bit *instance tag*, drawn from the TRNG separately from the key bytes when its `.SUM` is first written (at generation or import), stored in the `.SUM` header, and recorded in the session record (offset 18) when a session is created. Copies of a key carry the same `.SUM` and therefore the same tag. A different key under the same Key ID, for example on another card, has a different tag and is refused even though its own tags verify.

### 2.3 Key generation pipeline

1. Draw a Key ID (IMPL-KEY-003).
2. Draw the instance tag (IMPL-KEY-005). Create `<KEYID>.TMP`. Write the key one 512-byte block at a time from the TRNG, with online monitoring active (§7.2). After each block is written, read it back and compare (SEC-GEN-002), then clear the block buffer (SEC-GEN-001).
3. Create `<KEYID>.SUT` with the integrity-file header. Read the whole key back from storage, running the per-key acceptance tests (§7.3) over it and computing the integrity tags (§2.4) from the bytes *as stored*, appending them to the `.SUT`.
4. Write the generation event to the event log (§3.7) with the test results.
5. If the tests passed, rename `<KEYID>.SUT` to `<KEYID>.SUM`, then `<KEYID>.TMP` to `<KEYID>.KEY`. The second rename is the act of marking the key valid (SEC-ENTROPY-002). Otherwise both files are overwritten with zeros and deleted.

- **IMPL-GEN-001:** `.TMP` and `.SUT` files MUST never be accepted for session creation or import. On boot and on card insertion, stale `.TMP` and `.SUT` files, and any `.SUM` whose `.KEY` is absent, are overwritten with zeros and deleted.

### 2.4 Integrity tags (SEC-STORE-004)

The key file stays raw random bytes. Beside it, `<KEYID>.SUM` holds one tag per 4 KiB *unit*.

**Units** are counted separately within each half of the key, so a unit never straddles the alice/bob boundary; the last unit of each half may be shorter. With `n = ceil((L/2) / 4096)`, units `0 … n−1` cover the first half and `n … 2n−1` the second.

**Tag:** the first 8 bytes of SHA-256(`"EZ-UNIT1"` ‖ Key ID ‖ L ‖ unit index ‖ unit bytes), all integers little-endian. Binding the Key ID, length and position means a unit from another key, or from elsewhere in this key, cannot verify.

**File format:**

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | Magic `"EZSU"` |
| 4 | 1 | Version 1 |
| 5 | 1 | log2(unit size) = 12 |
| 6 | 1 | Tag length = 8 |
| 7 | 1 | Reserved (0) |
| 8 | 4 | Key ID |
| 12 | 4 | Key length L |
| 16 | 4 | Tag count (2n) |
| 20 | 2 | Instance tag (IMPL-KEY-005) |
| 22 | 6 | Reserved (0) |
| 28 | 4 | CRC-32 of bytes 0–27 |
| 32 | 8 × 2n | Tags, in unit order |

The overhead is 0.2% of the key's size.

- **IMPL-SUM-001:** Tags are computed only from key bytes as read back from storage: at generation from the read-back pass, at import from the file as received.
- **IMPL-SUM-002:** A `.SUM` is handled exactly like key material (SEC-STORE-004):
  - stored only beside its key;
  - never transmitted, logged or written to F-RAM;
  - erased whenever its key is erased (session delete, key delete, device erase);
  - copied only together with its key (`KEY_COPY`, which verifies every unit while copying).
- **IMPL-SUM-003:** SHA-256 is used for these tags only. It never touches the key stream (SEC-KDF-001). The portable implementation is in `core/src/ez_sha256.c`; the RP2350 port may substitute the hardware accelerator behind the same interface.

### 2.5 Importing keys (SEC-STORE-004, SEC-STORE-005)

Import is a stepwise job (`ez_import.h`) that ends with a session.

- **With a `.SUM`** whose header names the same Key ID and length: every unit is verified against its tag. Any mismatch refuses the import, reporting the number of damaged units and the first one; this catches damage in transfer before either party encrypts. A `.SUM` naming a different Key ID or length is refused (SEC-DIST-003), never overwritten.
- **Without a `.SUM`:** the key must be 8 KiB to 64 MiB and must pass two checks:
  - the per-key acceptance tests (§7.3);
  - a duplicate check: no two 4 KiB units are identical. Fingerprints of all units are held in the 64 KiB staging buffer, sorted, and every equal pair is compared exactly.

  Tags are then computed from the file as it is and written as `<KEYID>.SUM` with a new instance tag. The user is warned that the copy could not be checked against the original (IMPL-CLI-006).
- **On success:** the file is renamed to `<KEYID>.KEY` if needed (IMPL-KEY-004), the session is created, and an `EZ_EV_KEY_IMPORTED` event is logged (detail 1 = verified against its `.SUM`, 2 = checked and tagged).
- **On failure:** nothing is renamed and any `.SUT` is erased.

### 2.6 Drive 0 key store (`ports/ezstore`)

Drive 0 does not use FatFs. The internal flash belongs to the device alone, so it uses a simple store with its own atomic commit. The store implements the key storage HAL for drive 0. A router (`ez_ks_route`) joins it with the FatFs port for drives 1 and 2, so the core is unchanged: verify-then-use, `.SUM` files, quarantine and the intent record apply to drive 0 exactly as to cards.

- **IMPL-S0-001 (layout):** The partition (at most 4 MiB, separate from the firmware, SEC-HW-003) is divided into 4 KiB NOR erase blocks.
  - Blocks 0 and 1 hold two copies of a 4 KiB allocation table: header, 64 file entries (name up to 12 characters, first block, length), a block map (next block, end or free) and a CRC-32.
  - Blocks 2 onwards hold data. Each block belongs to at most one file (IMPL-FS-001).
  - Names are 8.3: drive 0 only ever holds key files and their temporaries, so it can hold up to 32 keys with their `.SUM` files.
- **IMPL-S0-002 (commit):** Create, rename, erase and wipe commit the in-RAM table:
  1. Write it to the copy not currently selected.
  2. Verify it by read-back.
  3. Write the copy's coded selector byte in F-RAM (`0x5A` = A, `0xA5` = B). This single atomic byte is the commit.

  Appends write data into newly erased blocks without committing, because the core only appends to temporary files, which a rename finalises. Generating a full-partition key therefore costs two table writes, not thousands. Erasing a file erases its blocks first and then commits the table without it, so a file missing from the table never leaves its bytes in flash. Wipe erases the data, commits an empty table to the inactive copy, then erases the old copy, so every interruption leaves a mountable store.
- **IMPL-S0-003 (mount):** The selected table is verified completely:
  - the CRC and header;
  - every file's block chain (in range, never shared, no cycles, length matching);
  - no block marked used that belongs to no file.

  A selector byte that is not a valid code, or a selected table that fails any check, makes drive 0 faulty until it is wiped. The store never falls back to the other copy, which could be older. A blank selector (new device, or after device erase) formats the store.

### 2.6a Intent record (IMPL-INT-001)

Destructive operations the user has confirmed are recorded in F-RAM before they start and cleared when complete:
- session delete;
- key delete;
- device erase;
- disabling drive 0.

The record holds the coded operation byte, drive, slot, Key ID and a CRC-16. At boot, and when the operation's drive is inserted, an interrupted operation is completed automatically. A torn record fails its CRC and is ignored, because the operation it describes had not started. While a record is pending, other destructive operations are refused (`BUSY`); a forced session delete of the same session clears it. Device erase's final metadata format clears the record.

With verify-then-use in place, this is a recovery feature, not a security one. It saves the user from completing interrupted deletions by hand.

### 2.8 Card storage for availability (SEC-AVAIL-001..004; core built in round 12, card format pending TR-05)

The card slot holds key storage only, behind a closed case. Writes happen only during maintenance (SEC-AVAIL-001), and `ez` warns before each one (SEC-AVAIL-002): "Do not disconnect the device or remove the card until this finishes."

- **IMPL-AV-001 (mirrored volumes):** The card holds N independent FAT32 volumes (default N = 2), far apart on the card, each with its own FATs and directory, and each holding *whole* keys (both halves) with their `.SUM`. N is a parameter, so it can be raised if TR-05 shows damage spreading across volumes.
- **IMPL-AV-002 (writing in sequence):** A maintenance write goes to one volume at a time: write, verify by read-back, and only then the next volume (SEC-AVAIL-004). An F-RAM record (the intent record of §2.6a, extended) names the volume being written, so that boot knows which one an interruption may have damaged.
- **IMPL-AV-003 (failover per unit):** Verify-before-use takes each 4 KiB unit from the first copy that verifies. A damaged copy costs nothing in normal use.
- **IMPL-AV-004 (repair):** A volume that fails to mount, or holds a copy that fails verification, is reported in `ez session info` with per-copy health. The user starts the repair, which is a maintenance write: reformat the volume and restore it from a healthy copy, never writing two copies at once.
- **IMPL-AV-005 (critical keys):** A session can be created *critical*. The bit sits in the session record's flags, under its static CRC, and is chosen at creation. A critical key is also mirrored to drive 0 when drive 0 is enabled and has room; otherwise the user is told how many copies it has.
- **IMPL-AV-006 (generating on drive 0):** With drive 0 enabled, keys are generated there (power-safe, §2.6) and then copied to the card in one burst. The card is then written for under a second for 256 KiB, instead of for the whole generation.

**As built (round 12):**
- **The mirror layer** (`ports/mirror`) presents a drive kept as N copies over N backing volumes. The storage interface gained `copies()`, and copy *k* of drive *d* is addressed as `EZ_COPY(d, k)` (bit 7 marks an explicit copy). It is used by the virtual device (`ez-vdev --mirror`: `drive1/` and `drive2/`) and the tests.
- **The firmware (round 13)** detects an Einszeit-formatted card and keeps it as two copies; any other FAT card is one copy, as before.
- **IMPL-AV-007 (card format):** `ez drive format 1 [--copies 1|2]` (`DRIVE_FORMAT`) is refused while any session uses the card.
  - **Two copies:** the card gets an MBR with disk signature `EZM2` and two FAT32 partitions (type `0x0C`, so a PC sees both). A runs from 4 MiB to half the card; B from half the card to the end. Both are aligned to 4 MiB, and each is a volume with its own two FATs and directory.
  - **Formatting order:**
    1. Erase every key file still reachable, in place.
    2. Only with `--erase`: SD ERASE over the whole card, in 4 MiB steps. Consumer cards may complete it in the background and stay busy for minutes (seen on V1 in TR-07), and how physically thorough it is depends on the card, so it is not the default.
    3. Write the MBR and both file systems, then mount.
  - **One copy:** a single partition from 4 MiB to the end.
  - **The format belongs to the platform, the policy to the core:** a hook (`ez_core_t.format`) supplies the mechanics. The core refuses while sessions use the drive, and clears the stage first.
  - **No direct access to a copy:** every drive number other than 0 and the card answers "absent", so volume B is never reachable directly, bypassing the mirror.
- **Replication** happens at session creation, at import and after `key copy` (`ez_replicate`), never at the end of generation, so a good key is never reported as failed because a copy could not be written.
- **Each copy is written by `write_copy`:** from units that verify (in any copy), with its `.SUM` rebuilt from those units so a damaged tag never spreads, read back unit by unit, under temporary names, renamed only when complete. One copy at a time.
- **Failover per unit** (`ez_unit_load`): a unit is accepted from any copy whose data matches a tag from a `.SUM` whose header carries the **expected instance** (the session's, else the primary copy's). The instance condition was added after the mirrored chaos run found a different key under the same ID being accepted from copy 1.
- **`SESSION_CHECK` and `SESSION_REPAIR`** (§9.4) report damaged units per copy, and units that verify in no copy ("lost"), and rewrite damaged copies. Repair never invents data: lost units are reported, and repair refuses.
- **Mount-time cleanup** of temporaries runs in every copy.
- **`ez`** prints the SEC-AVAIL-002 warning before every write to key storage, and reports a replication that could not complete.

**Volume repair (IMPL-AV-004, round 14):**
- **A volume being created is marked pending.** Its MBR partition type is `0xDA` until its file system is complete, then `0x0C`. A pending volume is never mounted: FatFs writes the boot sector first, so an interrupted creation would otherwise mount over incomplete FATs.
- `ez drive repair 1` (`DRIVE_REPAIR`; `sd repair [a|b]` in the development shell, where naming a volume forces it) recreates the file system only on copy volumes that do not mount, never touching a healthy one, after which `ez session repair` restores their keys.
- `session repair` skips copies whose volume is unavailable, and `ez` shows the check result with a hint.
- The firmware retries mounting copy volumes while idle.

**Jobs on the second core and the automatic mirror (round 16):**
- **IMPL-JOB-001 (no freezes).** Every long command runs as a job on core 1: session create, delete, check and repair; key copy and delete; drive enable, disable, format and repair; device erase; the entropy test; key generation and import; and the background sync. Core 0 keeps USB and the console. A long command is answered at once; the host polls `KEY_STATUS` (job, progress, deferred command) and fetches the reply with `JOB_RESULT`. Both describe the last job a command started: when a background sync starts the moment that job ends, `KEY_STATUS` reports the command's job as finished, and `JOB_RESULT` returns its reply (round 23). While a job runs, the device answers only `DEVICE_INFO`, `KEY_STATUS` and `JOB_RESULT`, which touch RAM only; everything else gets `BUSY`, and `ez` waits and says what the device is doing.
- **IMPL-JOB-003 (stacks).** Each core runs on a 16 KB stack in main RAM, with its stack-limit register (`MSPLIM`) set to the stack's bottom, so an overflow faults instead of overwriting memory. Core 0 moves to its stack first thing in `main()`. Measured on V1 (round 23): core 0 7.2 KB, core 1 3 KB at most; the development image's `info` reports both.
- **IMPL-JOB-002 (one owner).** Core 0 never touches the core, the card or F-RAM while a job runs. Drive 0 flash writes pause the other core via `flash_safe_execute()`, so both cores are lockout victims. Output from jobs goes through a ring that core 0 empties, because the USB stack is not safe across cores.
- **IMPL-AV-008 (automatic sync).** `ez_sync` brings every mirrored drive to a nominal state: it recreates unavailable volumes, rewrites damaged or missing copies (and critical keys' drive 0 copies), and lifts "key missing" quarantines whose key verifies again. Other quarantines stay for the user.
  - **A full sync** (every unit verified) runs at boot, on card insertion, after every job, and when a read had to fail over to another copy.
  - **A quick sync** (files, sizes and instance tags) runs every 5 minutes; a session failing it gets the full treatment.
  - **It yields** to any command at its next checkpoint, and resumes after a quiet second. Status queries (`DEVICE_INFO`, `KEY_STATUS`, `JOB_RESULT`) are not activity, so polling the status never holds maintenance off.
- **IMPL-AV-009 (health).** `DEVICE_INFO` reports `ok`, `syncing` or `degraded` (detail bits: a copy not repaired, a critical key without a drive 0 copy, data in no copy, a volume unavailable). `ez` warns on every command while not nominal, refuses writes to the card while degraded unless `--force` ("system degraded; recommend waiting for nominal state"), and never blocks deletion or erasure.

**Critical keys and generation on drive 0 (round 14):**
- **IMPL-AV-005 as built:** `ez session create … --critical` sets `EZ_SESS_CRITICAL` (session flags, static CRC).
  - **Creating:** after the card copies are written, the key is also written to drive 0 (`write_copy_to`, the same verified path), if drive 0 is usable. Otherwise the session is created anyway and `ez` reports why there is no drive 0 copy.
  - **Reading:** drive 0 is the last failover source, for units that fail in every card copy, with the same instance-bound check.
  - **`SESSION_CHECK`** reports the drive 0 copy, and **`SESSION_REPAIR`** rewrites it, or rebuilds the card's copies from it.
  - **A lost card:** insert a new card, format it, `ez session repair`, then `ez session resolve`. The offsets are in F-RAM and were never lost.
  - **Deletion** erases the drive 0 copy too. Disabling drive 0 wipes it, as with everything on drive 0. A critical session cannot itself be on drive 0.
  - **Turning it on or off later (round 20):** `SESSION_CRITICAL` (0x09, deferred). The effective flag is the record's creation-time flag XOR the session's bit in a toggle bitmap in reserved F-RAM (+2..+4); a toggle is one byte write, atomic in F-RAM, never a rewrite of the static record. Turning on writes and verifies the drive 0 copy, then sets the bit; turning off clears the bit, then erases the copy. `ez session spare <label> on|off`; P on the interface's Keys screen.
- **IMPL-AV-006 as built:** `ez key generate` (to a card) generates on drive 0 when drive 0 is enabled and not reported unprotected, then copies the finished key to the card (`KEY_COPY`, verified, then replicated) and erases it from drive 0. `--direct` generates straight onto the card. If the copy fails, the key stays on drive 0 and `ez` says so.

What this cannot survive: failure of the whole card, when its controller loses its mapping, for a key that is not critical. That is the residual risk the warning and the user manual describe.

### 2.9 Key exchange (SEC-DIST-001)

Keys move only on a card handed over in person. Public-key transfer through a computer would make the exchange only computationally secure, so it is excluded.
1. Alice buys a **new card**, inserts it, and generates the key onto it.
2. Her device copies the key to her own storage (drive 0, then her storage card if she keeps one) before the card leaves.
3. Bob keeps the card for good. He imports the key into his device's storage, and the card becomes his offline copy of this one key.

A storage card holding other keys is never handed over, because the receiving device could read them. On a one-slot device, drive 0 is needed to receive or hand over a key, which puts OI-02 on the critical path.

### 2.10 Key sizes

`ez key generate` takes a size (`128K`, `256K`, `512K`, `2M`, or bytes); **256 KiB is the default**. At the TRNG rate measured on V1 (2,264 bit/s), these take about 8, 15, 30 and 120 minutes. Each party sends from half the key: a 256 KiB key gives each side 128 KiB, about twelve years of one 150-byte note a week. Usage varies too much for predictions, so `ez` shows bytes left and warns at 20% (IMPL-CLI-004). Drive 0 (about 3 MiB with a firmware partition of up to 1 MiB) holds about 11 keys of 256 KiB.

### 2.7 Session label

At session creation the user provides a human-readable label (up to 15 bytes of UTF-8). It is the primary identifier in the UI and CLI and has no cryptographic significance. Labels are unique on a device.

---

## 3. Metadata Storage (F-RAM)

The V1 board carries an MB85RS16 (2 KB SPI F-RAM, 2-byte addressing). All multi-byte integers in metadata are little-endian.

### 3.1 Layout

| Address | Size | Region |
|---|---|---|
| 0 | 32 | Device record |
| 32 | 24 × 64 = 1,536 | Session slots 0–23 |
| 1,568 | 16 × 24 = 384 | Event log ring |
| 1,952 | 1 | Drive 0 store table selector (IMPL-S0-002) |
| 1,953 | 1 | Development mark (IMPL-MODE-002) |
| 1,954 | 30 | Reserved |
| 1,984 | 24 | Intent record (IMPL-INT-001) |
| 2,008 | 40 | TR-05 tally (development images only) |

### 3.2 Integrity model

Writes that happen often (offset commits, boot counter) and writes that change state (status, drive 0 state) are designed so that a power cut at any byte leaves either the old or the new state, without relying on a recovery step. Three techniques are used.

**Coded single bytes.** A single byte write is atomic. State bytes use codes with a Hamming distance of at least 4 from each other and from `0x00` and `0xFF`, so a corrupted byte is recognised as invalid instead of being read as a different valid state.

| Byte | Codes |
|---|---|
| Session status | `0x00`/`0xFF` EMPTY, `0x3C` VALID, `0xC3` QUARANTINED, `0x96` EXHAUSTED (reserved: exhaustion is derived from the TX offset, IMPL-META-005), `0x69` ZEROIZE_PENDING (reserved, §8) |
| Offset selector | `0x5A` slot A current, `0xA5` slot B current |
| Drive 0 state | `0xC3` disabled, `0x3C` enabled |
| Quarantine reason (persisted) | `0x33` key missing, `0x55` key size, `0xCC` key being erased, `0xAA` key damaged; any other value is read as "key being erased", the strictest |

**Checked slots.** A 6-byte value slot holds a 32-bit value and a CRC-16/CCITT-FALSE computed over a binding tag, the slot's identity and the value. The binding means a slot copied to another place fails its check.

**Static CRC.** Fields written only at creation are covered by one CRC-32 (IEEE 802.3).

### 3.3 Device record (32 bytes)

| Offset | Length | Field | Integrity |
|---|---|---|---|
| 0 | 2 | Magic `0x455A` ("EZ") | static CRC |
| 2 | 1 | Format version `0x02` | static CRC |
| 3 | 1 | Drive 0 state (coded) | coded byte |
| 4 | 4 | Device flags (reserved, 0) | static CRC |
| 8 | 8 | Reserved (0) | static CRC |
| 16 | 4 | CRC-32 over bytes 0–2 and 4–15 | |
| 20 | 6 | Boot counter slot A | checked slot |
| 26 | 6 | Boot counter slot B | checked slot |

The boot counter is the larger of the valid slots. Each power-on writes `counter + 1` into the slot holding the smaller or invalid value. An unexpected increase indicates the device was powered without the user's knowledge.

- **IMPL-META-001:** On power-on the device record is classified as **uninitialised** (the entire F-RAM reads uniformly `0x00` or `0xFF`), **valid**, or **faulty** (anything else, including the `fw/test` bench marker). An uninitialised device permits only initialisation. A faulty device still verifies and lists sessions but refuses all crypto, key and drive operations until the user runs `device repair` (rewrites the record with drive 0 disabled) or `device erase`.

### 3.4 Session record (64 bytes)

| Offset | Length | Field | Integrity |
|---|---|---|---|
| 0 | 2 | Magic `0x455A` | static CRC |
| 2 | 1 | Record version `0x01` | static CRC |
| 3 | 1 | Status (coded) | coded byte |
| 4 | 1 | Quarantine reason (coded) | coded byte |
| 5 | 1 | TX offset selector (coded) | coded byte |
| 6 | 1 | RX offset selector (coded) | coded byte |
| 7 | 1 | Role: `0x00` alice, `0x01` bob | static CRC |
| 8 | 4 | Key ID (non-zero) | static CRC |
| 12 | 4 | Key length in bytes (non-zero, even) | static CRC |
| 16 | 1 | Drive index | static CRC |
| 17 | 1 | Feature flags (bit 0: forward secrecy, reserved) | static CRC |
| 18 | 2 | Key instance tag (IMPL-KEY-005) | static CRC |
| 20 | 16 | Label, UTF-8, NUL-terminated | static CRC |
| 36 | 4 | CRC-32 over bytes 0–2 and 7–35 | |
| 40 | 6 | TX offset slot A | checked slot |
| 46 | 6 | TX offset slot B | checked slot |
| 52 | 6 | RX offset slot A | checked slot |
| 58 | 6 | RX offset slot B | checked slot |

Ranges for key length `L`: alice TX `[0, L/2)`, RX `[L/2, L)`; bob TX `[L/2, L)`, RX `[0, L/2)`. Offsets range over the closed interval `[start, end]`; an offset equal to `end` means that range is fully consumed.

Rev 1 of this specification had one offset pair and one CRC over the whole record including the offsets. Because an offset update then also rewrote the CRC, a power cut between the two writes made a healthy session look corrupt. Rev 2 keeps every frequently written field outside the static CRC.

### 3.5 Offset commit and read rules

- **IMPL-META-002 (read):** The effective offset is the larger of the two slots, provided the slot named by the selector is valid. If the selector is not a valid code, or the selected slot fails its check, the session is quarantined. An invalid non-selected slot is ignored. Any valid slot holding a value outside its range `[start, end]` quarantines the session.
- **IMPL-META-002a (boot normalisation):** On power-on of a valid device, if the non-selected slot is valid and larger than the selected one, the selector is pointed at it (one atomic byte write) before any session operation. At rest, the effective offset is therefore always in the selected slot.
- **IMPL-META-003 (commit):** To commit offset `n`:
  1. Reject unless `n` is strictly greater than the effective offset (SEC-PTR-002) and `n ≤ end` of the range (SEC-ISO-001). A rejected rollback is written to the event log.
  2. If the non-selected slot holds the effective (larger) value, first write the selector to point at it and verify ("normalise").
  3. Write `n` into the non-selected slot and verify by read-back.
  4. Write the selector to point at that slot and verify.

  If any verification fails, the commit is reported as failed and the operation MUST be aborted with no further output (SEC-PTR-003). If the selector read-back fails, the session is also quarantined until the next power-on re-checks it.

Why this is safe:

- A power cut during step 3 leaves the non-selected slot invalid. It is ignored, and the old offset stands (pre-update state).
- A power cut between steps 3 and 4 leaves a valid non-selected slot larger than the selected one. The larger-of-two rule reads the new value (post-update state). No ciphertext has been output for that range, so rolling forward wastes key at worst and never reuses it.
- Boot normalisation (IMPL-META-002a) persists that roll-forward. Without it, the larger value would sit in a slot the read rule treats as expendable, and a later bit flip there would silently return the offset to its pre-update value. The host test suite found this case (`test_meta_bitflip`); the reversion was harmless only because the interrupted commit never reported success.
- Step 2 ensures the slot about to be overwritten never holds the effective value. After boot normalisation it is needed only when a faulty device (which is never written at boot) is repaired and then used in the same power cycle; it is kept as defence in depth.
- A corrupted selected slot is detected by its check. Falling back to the other slot could roll the offset back, so the session is quarantined instead.
- A selector changed to the other valid code cannot roll the offset back either, because the larger of the two slots is used.

What this cannot defend against: someone with physical access writing a well-formed lower value with a correct check into the selected slot. Physical attacks are out of scope (EZ-SEC-001 §0); see deviation DEV-11.

- **IMPL-META-004 (status):** Status changes are single coded-byte writes. Session creation writes the full record with status EMPTY, verifies it, then writes status VALID. Deletion writes status EMPTY first, then zeroes the record. A power cut therefore leaves a slot either empty or complete.
- **IMPL-META-005 (exhaustion):** A session whose TX offset equals the end of its TX range is EXHAUSTED. The state is derived from the offset, so no separate write is needed and no write can be torn. An EXHAUSTED session refuses encryption but still decrypts, because its RX range is independent. The UI shows it as inactive for sending (SEC-UI-001).

### 3.6 Quarantine

| Reason | Code | Persisted | Resolution |
|---|---|---|---|
| Key file or its `.SUM` missing | `0x01` | yes | `session resolve` once both are accessible again (instance tag must match) |
| Key file size differs from record | `0x02` | yes | `session resolve` once corrected |
| Key erasure started (SEC-PTR-004) | `0x03` | yes | delete only |
| Key data damaged (IMPL-ENG-012) | `0x04` | yes | delete only |
| Record format or magic invalid | `0x81` | no (RAM) | delete only |
| Static CRC failure | `0x82` | no (RAM) | delete only |
| Status byte not a valid code | `0x83` | no (RAM) | delete only |
| Offset selector not a valid code | `0x84` | no (RAM) | delete only |
| Selected offset slot fails its check | `0x85` | no (RAM) | delete only |
| Offset outside its range | `0x86` | no (RAM) | delete only |
| Commit verification failed | `0x87` | no (RAM) | power cycle; re-checked at boot |

- **IMPL-META-006:** Quarantine for reasons `0x81` and above is held in RAM and re-established at every power-on. The record's checks are never rewritten to validate it (SEC-META-003).
- **IMPL-META-007:** While any non-empty slot has an unreadable identity (reasons `0x81` and `0x82`, where the Key ID cannot be trusted), session creation MUST be refused. That slot might belong to the key being imported, and creating a session for it would restart its offsets (SEC-ISO-002).

### 3.7 Event log (16 × 24 bytes)

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | Sequence number (newest = highest valid) |
| 4 | 4 | Boot counter at the time of the event |
| 8 | 4 | Time: uptime in seconds, or host-supplied Unix time (type bit 7 set; untrusted) |
| 12 | 4 | Key ID (0 if not applicable) |
| 16 | 4 | Argument (key length for generation events; otherwise event-specific, never an offset) |
| 20 | 1 | Type (bits 0–6) and host-time flag (bit 7) |
| 21 | 1 | Detail (test-failure bitmap, quarantine reason, or slot index) |
| 22 | 2 | CRC-16 over bytes 0–21 and the entry index |

Types: `0x01` key generated (valid), `0x02` key rejected, `0x03` offset rollback rejected, `0x04` session quarantined, `0x05` device initialised, `0x06` drive 0 enabled, `0x07` drive 0 disabled, `0x08` entropy fault (generation halted), `0x09` device record repaired, `0x0A` session deleted (key erased), `0x0B` session deleted by override (key not erased).

- **IMPL-LOG-001:** Entries never contain an OTP offset or remaining capacity (SEC-UI-005). A torn entry fails its CRC and is ignored; the next append overwrites the same position.
- **IMPL-LOG-002:** When no role is given at session creation, the role defaults to alice if the Key ID appears in a valid "key generated" entry and to bob otherwise. The log is a ring, so for keys generated long ago the user may need to give the role explicitly.

---

## 4. Core API

Each command has a canonical code used by all transports. The CLI maps subcommands to these codes. Commands that change state are marked ●.

| Code | Command | Description |
|---|---|---|
| `0x01` | `SESSION_LIST` | All session slots: label, Key ID, role, drive, status, quarantine reason, remaining TX and RX capacity |
| `0x02` | `SESSION_CREATE` ● | Create a session for an existing key file with a matching `.SUM` (Key ID, label, drive, optional role) |
| `0x03` | `SESSION_DELETE` ● | Quarantine the session, erase its key file, then remove the record (SEC-PTR-004). Refused if the key file cannot be erased, unless the request carries the override flag; overrides are logged |
| `0x04` | `SESSION_INFO` | Details for one session |
| `0x05` | `SESSION_RESOLVE` ● | Clear a persisted quarantine once its cause is fixed |
| `0x06` | `SESSION_SKIP` ● | Move the TX offset past a reported run of damaged units (IMPL-ENG-014) |
| `0x07` | `SESSION_CHECK` | Check every copy of a session's key (IMPL-AV-004) |
| `0x08` | `SESSION_REPAIR` ● | Rewrite damaged or missing copies from those that verify |
| `0x09` | `SESSION_CRITICAL` ● | Turn a session's drive 0 copy (spare copy) on or off |
| `0x0C` | `JOB_RESULT` | The reply of the last deferred command, once its job has finished |
| `0x10` | `KEY_GENERATE` ● | Generate a key file (default drive 1) |
| `0x11` | `KEY_COPY` ● | Copy a key file between drives |
| `0x12` | `KEY_DELETE` ● | Delete a key file; linked sessions are quarantined before the erase begins |
| `0x13` | `KEY_STATUS` | The last command's job: kind, running, progress, result; cancel a generation or import with the `ABORT` flag |
| `0x14` | `KEY_IMPORT` ● | Start the import job (§2.5) for a file on a drive, with Key ID, label and role |
| `0x20` | `ENCRYPT` ● | Encrypt (buffered or streaming, §6) |
| `0x21` | `DECRYPT` ● | Decrypt (buffered or streaming, §6) |
| `0x22` | `RESEND` | Re-send retained ciphertext (§6.4) |
| `0x23` | `RELEASE` | Acknowledge receipt; clears retained ciphertext |
| `0x30` | `DRIVE_LIST` | Key files on a drive |
| `0x31` | `DRIVE_INFO` | Type, capacity, free space, presence, enabled state |
| `0x32` | `DRIVE_ENABLE` ● | Enable drive 0 (IMPL-DRV-002) |
| `0x33` | `DRIVE_DISABLE` ● | Erase and disable drive 0 (IMPL-DRV-002) |
| `0x40` | `ENTROPY_TEST` | Run the acceptance tests on fresh TRNG output; returns pass/fail per test |
| `0x41` | `RANDOM` | N bytes of fresh TRNG output (never key material) |
| `0x50` | `DEVICE_INFO` | Firmware version, USB variant, hardware revision, TRNG profile, boot counter, drive status, device record state |
| `0x51` | `DEVICE_ERASE` ● | Initialise metadata and erase all key files on all enabled drives |
| `0x52` | `DEVICE_REPAIR` ● | Rewrite a faulty device record (IMPL-META-001) |
| `0x53` | `LOG_READ` | Event log, newest first |

- **IMPL-API-001:** No command returns key bytes, and none returns statistics computed over key bytes. `ENTROPY_TEST` operates on fresh TRNG output only. Key file contents can be checked only by the acceptance tests during generation (SEC-FW-004).

Status codes are defined in `core/include/ez_status.h` and are part of the protocol.

---

## 5. Message Format (version 1)

All integers little-endian. Messages are base64-encoded for text channels; the base64 step is not an OTP operation and may run on the host (SEC-HW-001).

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | Magic `0x455A` |
| 2 | 1 | Format version `0x01` |
| 3 | 1 | Flags (reserved, 0) |
| 4 | 4 | Key ID (non-zero) |
| 8 | 4 | OTP offset: absolute byte offset into the key where encryption began |
| 12 | 4 | Plaintext length N |
| 16 | N | Ciphertext |
| 16+N | 4 | CRC-32 over bytes 0 to 15+N |

Overhead is 20 bytes. The header length field precedes the data and the CRC is a trailer, so the format can be produced and consumed as a stream. The CRC detects accidental damage only and is not authentication (EZ-SEC-001 §0).

- **IMPL-MSG-001:** The receiver selects the session by Key ID when the user does not name one. If the user names a session, the header Key ID MUST match it (SEC-DEC-002).

---

## 6. Encryption and Decryption Engine

One engine serves both modes. For each key block it checks the range, reads the key block, XORs it, and clears the block buffer immediately. Commit happens before output. The modes differ only in staging and in how often they commit.

- **IMPL-ENG-001:** Before any key byte is read, the engine MUST check: session usable (VALID, or EXHAUSTED for decryption only); drive enabled and present; for encryption `tx_offset + N ≤ tx_end`; for decryption `[offset, offset + N) ⊆ [rx_offset, rx_end]` (SEC-ENC-001, SEC-DEC-001, SEC-DEC-003).
- **IMPL-ENG-002:** Key bytes are held only in the verified-unit buffer (IMPL-ENG-013), and only while an operation is using that unit. That is the whole call for buffered operations, and across the calls of one stream for streaming operations. The buffer is cleared when the operation moves to another unit, ends, fails or is aborted (SEC-FW-002, SEC-FW-003). The host suite checks the buffer after every call, and the simulated storage counts any read into a buffer that still holds data.
- **IMPL-ENG-013 (verify, then use):** To use any byte of a unit, the engine reads the whole unit (it never crosses a half, so never touches the peer's range), reads its tag, computes the tag over the bytes read, and only if they match uses bytes, taken from that same buffer. Nothing is read twice, so nothing can change between verification and use. A mismatch, a missing or malformed `.SUM`, or an instance-tag mismatch refuses the operation before any output or commit, with `KEY_DAMAGED`, and records which unit failed in `c->damage` for the user interface. The session is not quarantined, so that a damaged region can be skipped. A missing `.SUM` quarantines the session (reason `0x01`).
- **IMPL-ENG-014 (skip):** After an encryption is refused because a unit ahead in the TX range failed verification, `SESSION_SKIP` (after the user confirms) moves the TX offset to the start of the first unit after that run of damaged units that verifies, or to the end of the range. Moving forward wastes key; it never reuses it. The event log records the number of units skipped, never offsets. Damage on the receiving side cannot be skipped: messages covering it cannot be decrypted, and the user can see the damaged range to agree with the sender out of band.

### 6.1 Buffered mode (plaintext up to 65,536 bytes)

Sequence: receive the whole plaintext into RAM; XOR key blocks in place (the plaintext is overwritten as ciphertext is produced, SEC-ENC-003); confirm the card is still present and unchanged; commit the TX offset once; output.

- **IMPL-ENG-003:** Any failure before the commit, including media removal, cancellation, or a transport error while plaintext is being received, results in no ciphertext output and no offset change. The buffer is wiped and the client is told the key is unspent (SEC-TEST-MEDIA-001 (a)).

### 6.2 Streaming mode (any size)

The header, including total length N, is checked as in IMPL-ENG-001 before any output.

- **IMPL-ENG-004:** Each streaming update transforms one chunk in place and returns only after the TX offset has been committed past the end of that chunk. The caller (the transport) may hand the chunk on only after that. No byte is output before the commit covering it is verified (SEC-PTR-003). The commit unit is therefore the transport's chunk size, normally one frame.
- **IMPL-ENG-005:** On any failure, the engine stops output immediately and reports the number of key bytes spent: exactly the bytes already output, plus at most one commit unit (SEC-TEST-MEDIA-001 (b)). The partial message has no trailer, so receivers reject it; `ez` discards it.

At full-speed HID throughput (roughly 1,100 frames/s) per-frame commits are well within the MB85RS16's rated endurance of 10¹² writes per byte.

### 6.3 Decryption

- **IMPL-ENG-006:** The RX offset is committed only after the trailer CRC has been verified, immediately before success is reported (SEC-DEC-004). A decryption that fails or is interrupted commits nothing and may be retried.
- **IMPL-ENG-007:** In buffered mode, plaintext is released only after the CRC verifies. In streaming mode, plaintext frames are released as they are produced. The host (`ez`) MUST hold the output and discard it unless the device reports success.

### 6.4 Retained ciphertext and resend

- **IMPL-ENG-008:** After a buffered encryption commits, the ciphertext stays in RAM until `RELEASE`, a timeout, any other command, or power loss, so `RESEND` can recover a dropped transfer. In streaming mode only the most recent frame is retained.
- **IMPL-ENG-009:** The retained buffer is read-only. `RESEND` returns its bytes unchanged and performs no key access and no XOR. Any new input clears the buffer; a new encryption always requires a new range and a new commit. No key bytes are retained alongside it (IMPL-ENG-002).

### 6.5 Damaged key data

- **IMPL-ENG-012:** While using key bytes, the engine also tracks runs of identical `0x00` and `0xFF` bytes across the operation; a run of 16 refuses the operation with `KEY_DAMAGED` before the affected bytes are output or committed. Since IMPL-ENG-013 this is a third line of defence (after quarantine-before-erase and tag verification), relevant only if a key were tagged from already-blank data.

### 6.6 Removable media

- **IMPL-ENG-010:** The software card check (`ez_hal_keystore.check()`) is authoritative. Any failed storage access aborts the operation. The engine calls `check()` before the first key read, at least every 64 key reads, and immediately before every commit. The SD port implements it as SEND_STATUS (CMD13) plus a comparison of the card's CID with the CID recorded at mount, so a swapped card is detected as well as a removed one (SEC-HW-002).
- **IMPL-ENG-011 (SD_DET, measured):** On V1 the socket switch drives SD_DET to 3.3 V when a card is present and leaves it open otherwise; there is no external pull. The pin is therefore read with the internal pull-down, and high means a card is present (TR-03 step 7, OI-03 closed). It may trigger a mount or flag a likely removal faster than polling, but the card check (IMPL-ENG-010) stays authoritative.
- **IMPL-ENG-011 (original text):** `SD_DET` is an additional trigger. Until its polarity is verified on hardware (OI-03), it is advisory: a disagreement with the software check is logged and treated as removal.

---

## 7. Key Generation and Entropy Monitoring

### 7.1 TRNG operating profile

- **IMPL-ENT-001:** The TRNG configuration (`SAMPLE_CNT1`, inverter chain, health tests enabled, Von Neumann balancer enabled) is a build-time profile with a numeric ID. The profile ID is reported by `DEVICE_INFO` and recorded in every generation event. Hardware health tests (CRNGT, Von Neumann 32-identical-bits, autocorrelation) are never bypassed in production.
- **IMPL-ENT-002:** A collection on which the hardware raised a health flag (Von Neumann or continuous RNG test) is discarded, never used. An autocorrelation failure (fatal in hardware), a collection timeout, or more than 4 flagged collections within one `read()` resets the TRNG block, discards everything buffered, and returns `EZ_ERR_ENTROPY`. Generation then halts, discards the `.TMP` file and logs an entropy-fault event (SEC-ENTROPY-004). Implemented in `fw/einszeit/src/hal_trng.c`; see DEV-20 for why an isolated flag does not halt generation.

### 7.2 Online monitoring (EZ-SEC-001 §2.3)

Monobit, runs (count and longest run) and autocorrelation at lags 1–16, over consecutive 4,096-bit windows, halting on failure. Thresholds are derived from the ideal-source distribution: about 7.5 × 10⁻⁹ false alarms per window. Derivation and verification: `docs/einszeit-entropy-thresholds.md`. They are verified by SEC-TEST-ENT-002 with injected biased, stuck, periodic and correlated streams. Checking them against the ent001 capture with `ez_entropy_check` is the remaining part of this requirement (TR-01, in `docs/einszeit-entropy-thresholds.md`).

### 7.3 Per-key acceptance tests (SEC-ENTROPY-002)

Run over the complete key as read back from storage:
- FIPS 140-2 §4.9.1 tests (monobit, poker, runs, long run) on every complete 20,000-bit block. An ideal source fails each test in about one block in 10,000, so a key is rejected when its count of failing blocks for a test reaches a Poisson bound giving at most 10⁻⁹ false rejection.
- Whole-key monobit (7σ).
- Byte-frequency χ² (255 dof), bounded on both sides, so output that is too uniform (for example a counter) is rejected too.

About 4 × 10⁻⁹ false rejections per key. Derivation: `docs/einszeit-entropy-thresholds.md`.

The measured entropy of the V1 source does not yet demonstrably meet the 8 bits/byte of SEC-ENTROPY-002; see deviation DEV-01.

---

## 8. Forward Secrecy (deferred)

Forward secrecy (erasing consumed key bytes) is deferred until after the core has been audited. The record keeps the feature flag and the `ZEROIZE_PENDING` status code. Rev 1's "last erased block" pointer is dropped: erasure is idempotent, so recovery can recompute the work from the offsets. The block-alignment rules IMPL-FS-001 to IMPL-FS-003 from Rev 1 remain the intended design.

---

## 9. Transports

### 9.1 USB variants

| Image | Interfaces | `bcdDevice` |
|---|---|---|
| `einszeit_hid.uf2` | HID | `0x0101` |
| `einszeit_cdc.uf2` | CDC-ACM (console) | `0x0102` |
| `einszeit_composite.uf2` | HID + CDC-ACM (IAD) | `0x0103` |

The bring-up image is a composite of CDC (debug shell) and HID (protocol) with `bcdDevice` `0x0110`. All images use VID:PID `16d0:1475`. A different `bcdDevice` per variant keeps Windows from applying a cached configuration of one variant to another. Host software finds the HID interface by its usage page, not by interface number. Windows 10/11 bind CDC-ACM automatically through the built-in `usbser.sys`; confirming that the composite image works without a driver there is open item OI-05. The CDC-only image has no HID interface, so `ez` cannot use it; everything is done through the console.

### 9.2 USB HID

Vendor-defined usage page `0xFF00`, usage `0x01`, 64-byte input and output reports, no report IDs (the report ID byte seen in some host APIs is not part of the 64 bytes). A vendor page is required for WebHID, which blocks keyboard and FIDO pages.

Frame (64 bytes):

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | Command code (echoed in responses) |
| 1 | 1 | Flags: bit 0 FIRST, bit 1 LAST, bit 2 ABORT, bits 3–6 reserved (0), bit 7 reserved for host-link protection (0) |
| 2 | 1 | Frame sequence within a transaction, starting at 0, modulo 256 |
| 3 | 1 | Status (responses); 0 in requests |
| 4 | 2 | Payload length (0–58) |
| 6 | 58 | Payload |

A transaction is a FIRST…LAST run of request frames followed by a FIRST…LAST run of response frames. The request payload is the concatenation of the request frames' payloads; the response likewise. The sequence number wraps modulo 256; positions within a transaction do not. Payload encodings are in §9.4, and every decoder is fuzz-tested (`tests/fuzz`), closing `fw/test` gap G-03 for the production protocol.

- **IMPL-PROTO-001 (one response per request):** Every request (a FIRST frame), and every ABORT frame, receives exactly one response run. A request refused before its LAST frame, because it is malformed, out of sequence, too large, or BUSY, is answered at once, and its remaining frames are dropped silently. Continuation frames with no open request are ignored. A new FIRST frame abandons any request still being received, clearing its staged data (IMPL-ENG-003). The host therefore never sees a stale response; the client drains its input before each request.
- **IMPL-PROTO-002 (sessions named twice):** Commands that change a session (`SESSION_DELETE`, `SESSION_RESOLVE`, `SESSION_SKIP`, `ENCRYPT`) name it by slot and Key ID. A mismatch is `BAD_REQUEST`, so a stale host view can never act on the wrong session.

Frame bit 7 is reserved so that a host-link protection layer (encryption of the USB link, considered in the final phase) can be added without changing the core or dispatcher.

### 9.4 Payloads (protocol version 1)

All integers little-endian. A *string* is a 1-byte length followed by that many bytes, with no NUL. Decoding is bounds-checked: a short payload, trailing bytes, an over-long string or an embedded NUL is `BAD_REQUEST`. The status is in the response frame header, so payloads below are for `OK` responses only; error responses carry no payload.

| Command | Request | Response |
|---|---|---|
| `SESSION_LIST` | — | count u8, then count × *session* |
| `SESSION_INFO` | slot u8 | *session* |
| `SESSION_CREATE` | Key ID u32, drive u8, role u8 (0 alice, 1 bob, 0xFF default), label string, flags u8 (bit 0 critical) | slot u8, replication status u8, drive 0 copy status u8 |
| `SESSION_DELETE` | slot u8, Key ID u32, force u8 (0/1) | — |
| `SESSION_RESOLVE` | slot u8, Key ID u32 | — |
| `SESSION_SKIP` | slot u8, Key ID u32 | units skipped u32 |
| `ENC_BEGIN` (0x24) | slot u8, Key ID u32, length u32 | header (16) |
| `ENC_DATA` (0x25) | plaintext chunk (1..512) | ciphertext chunk (released after its key is committed) |
| `ENC_END` (0x26) | — | trailer (4) |
| `DEC_BEGIN` (0x27) | slot u8 (0xFF: by Key ID), header (16) | — |
| `DEC_DATA` (0x28) | ciphertext chunk (1..512) | plaintext chunk (the host holds it until `DEC_END` succeeds, IMPL-CLI-003) |
| `DEC_END` (0x29) | trailer (4) | — (`INTEGRITY` on a CRC mismatch) |
| `JOB_RESULT` (0x0C) | — | the last deferred command's reply, once its job has finished, also while a background sync runs after it (its status is the command's; `BUSY` while the job runs, `STATE` if no deferred command has run) |
| `SESSION_CHECK` (0x07) | slot u8, Key ID u32 | copies u8, units u32, lost u32, copies × (present u8, has key u8, bad units u32), failovers u32, critical u8, drive 0 copy u8 (0 not checked, 1 missing, 2 ok, 3 damaged), its bad units u32 |
| `SESSION_REPAIR` (0x08) | slot u8, Key ID u32 | copies rewritten u8, units lost u8 (0/1) |
| `SESSION_CRITICAL` (0x09) | slot u8, Key ID u32, on u8 (0/1) | — |
| `KEY_GENERATE` | length u32, drive u8 | — (job started) |
| `KEY_IMPORT` | drive u8, Key ID u32, role u8, label string, file string | have_sum u8 (job started) |
| `KEY_STATUS` | — (ABORT flag cancels the job) | *job* |
| `KEY_COPY` | Key ID u32, from u8, to u8 | replication status u8 |
| `KEY_DELETE` | Key ID u32, drive u8 | — |
| `ENCRYPT` (buffered) | slot u8, Key ID u32, length u32 (1–65,536), then the plaintext; the 9-byte header must be in the FIRST frame | the message (§5), retained for `RESEND` |
| `DECRYPT` (buffered) | slot u8 (0xFF: select by Key ID), length u32, then the message | the plaintext |
| `RESEND` | — | the retained message, unchanged |
| `RELEASE` | — | — |
| `DRIVE_LIST` | drive u8, start index u16 | count u8, count × (size u32, name string), more u8 |
| `DRIVE_INFO` | drive u8 | present u8, enabled u8, usable status u8, copies u8 |
| `DRIVE_ENABLE` / `DRIVE_DISABLE` | drive u8 (0) | — |
| `DRIVE_FORMAT` (0x34) | drive u8 (1), copies u8 (1 or 2; bit 7: also erase the whole card) | — |
| `DRIVE_REPAIR` (0x35) | drive u8 (1) | volumes recreated u8 |
| `ENTROPY_TEST` | bytes u32 (2,560–65,536, multiple of 512) | monitor bits u8, acceptance bits u8 |
| `RANDOM` | n u16 (1–1,024) | n bytes of fresh TRNG output |
| `DEVICE_INFO` | — | protocol version u8, firmware string, variant u8, hardware revision u8, TRNG profile u8, device state u8, boot count u32, drive 0 enabled u8, drives present bitmask u8, intent pending u8, job running u8, build u8 (0 production, 1 development, 2 virtual), development mark u8, drive 0 protection u8 (0 not applicable, 1 missing, 2 verified) |
| `DEVICE_ERASE` / `DEVICE_REPAIR` | — | — |
| `LOG_READ` | — | count u8, count × (seq u32, boot u32, time u32, type u8, detail u8, Key ID u32, arg u32, host-time u8) |

*session*: slot u8, state u8, quarantine reason u8, role u8, drive u8, flags u8 (bit 0 identity verified, bit 1 offsets verified, bit 2 send capacity below 20%), Key ID u32, key length u32, send bytes left u32, receive bytes left u32, send range u32, label string.

*job*: job u8 (0 none, 1 generation, 2 import), running u8, result u8 (status once finished), failure bits u8, have_sum u8, session slot u8 (import; 0xFF none), progress u16 (per mille), Key ID u32, units failing their tag u32, first such unit u32, duplicated blocks u32, replication status u8 (import).

Variant codes in `DEVICE_INFO`: 1 HID, 2 CDC, 3 composite, 0x10 bring-up, 0xEE virtual device. Streaming `ENCRYPT`/`DECRYPT` over USB (messages over 64 KiB) is specified with the HID images in the next round.

- **IMPL-ARCH-004 (as built):** While a generation or import job runs, only `KEY_STATUS`, `DEVICE_INFO`, `SESSION_LIST`, `SESSION_INFO`, `LOG_READ` and `DRIVE_INFO` are accepted; everything else is `BUSY`. The import job uses the staging buffer, which is never released underneath it.

### 9.6 Images (SEC-FW-005)

- **IMPL-MODE-001:** `fw/einszeit` builds two images.
  - **`einszeit_hid` (production):** HID only, `bcdDevice` `0x0101`, build code 0.
  - **`einszeit_dev` (development):** CDC debug shell plus HID, `bcdDevice` `0x0110`, build code 1, with `fw update`, the self-test, TR-05 and the plaintext-printing shell.

  `DEVICE_INFO` ends with the build code and the taint flag (§9.4). The production image is checked after linking: the build fails if it contains `rom_reset_usb_boot`, `reset_usb_boot`, TR-05 or the self-test (SEC-TEST-FW-005; the check has been shown to fail when such a call is reachable). Production devices are updated with the BOOT button only.
- **IMPL-MODE-002:** At every boot, a development image writes a mark (`0xD5`) into F-RAM byte 1,953, which only device erase clears. `ez` warns on every command to a development image or to a marked device, and `ez device info` explains the mark.

### 9.5 Virtual device

`sw/vdev` (`ez-vdev <state-dir>`) runs the core and the dispatcher on the host. The F-RAM and the drive 0 flash are files (`fram.bin`, `flash.bin`, with NOR semantics). Drives 1 and 2 are directories (`drive1/`, `drive2/`), with FatFs-like case-insensitive names and zero-before-delete. The device is reachable over a Unix socket that carries the same 64-byte frames as HID. Keys it generates come from the operating system's generator under TRNG profile `0xEE`, so the virtual device is for testing only (DEV-21). `ez --virtual <socket>` uses it; CI runs two of them end to end (`tests/e2e`).

### 9.3 USB CDC console

Interactive only. It runs the shared CLI layer, with `YES` typed for confirmation. Messages are composed in a zetta-based editor and output as base64. When a message view is dismissed the console clears the screen and sends the clear-scrollback sequence (`ESC[3J`). The terminal's scrollback is held by the host terminal emulator, so SEC-UI-002 can only be met on a best-effort basis there (DEV-05).

---

## 10. CLI

### 10.1 Host CLI (`ez`)

C, built with vendored hidapi (`sw/hidapi.c`, libusb/hidapi 0.15, BSD licence option): hidraw and libudev on Linux, IOKit on macOS, setupapi on Windows (the Windows build is still to come). `ez` opens the interface of `16d0:1475` whose usage page is `0xFF00`; with several devices connected, `--device <serial>` chooses one and `ez device list` lists them. `--virtual <socket>`, or `EZ_VIRTUAL`, selects a virtual device instead. On Linux, `sw/ez/99-einszeit.rules` gives the logged-in user access without root. It will share the command table and output formatting with the device console (`cli/`).

### 10.2 Commands

| Command | API |
|---|---|
| `ez session list` | `SESSION_LIST` |
| `ez session create <label> --key-id <id> [--drive <n>] [--role alice\|bob]` | `SESSION_CREATE` |
| `ez session import <label> <file> --key-id <id> [--drive <n>] [--role ...]` | `KEY_IMPORT`, `KEY_STATUS` |
| `ez session delete <label> [--yes] [--force]` | `SESSION_DELETE` |
| `ez session skip <label> [--yes]` | `SESSION_SKIP` |
| `ez session info <label>` | `SESSION_INFO` |
| `ez session resolve <label>` | `SESSION_RESOLVE` |
| `ez key generate <length> [--drive <n>]` | `KEY_GENERATE`, `KEY_STATUS` |
| `ez key copy <keyid> --from <n> --to <n>` | `KEY_COPY` |
| `ez key delete <keyid> --drive <n> [--yes]` | `KEY_DELETE` |
| `ez drive list [--drive <n>]` / `ez drive info [--drive <n>]` | `DRIVE_LIST` / `DRIVE_INFO` |
| `ez drive enable 0 [--yes]` / `ez drive disable 0 [--yes]` | `DRIVE_ENABLE` / `DRIVE_DISABLE` |
| `ez encrypt [<label>] [--yes] [--stream] [-i file] [-o file]` | `ENCRYPT` |
| `ez decrypt [<label>] [-i file] [-o file]` | `DECRYPT` |
| `ez device info` / `ez device erase [--yes]` / `ez device repair [--yes]` | `DEVICE_*` |
| `ez log` | `LOG_READ` |
| `ez test entropy` / `ez test random [N]` | `ENTROPY_TEST` / `RANDOM` |

- **IMPL-CLI-001:** `ez encrypt` without `--yes` shows the session label, the bytes to be consumed and the capacity remaining afterwards, then asks for confirmation on the controlling terminal (not standard input, which carries the plaintext). If no terminal is available it refuses (SEC-UI-003).
- **IMPL-CLI-002:** `ez encrypt` uses buffered mode for inputs up to 65,536 bytes and streaming mode above that, or when `--stream` is given. Before a streaming encryption it states that a failure spends the key behind whatever has already been sent.
- **IMPL-CLI-003:** `ez decrypt` writes plaintext only after the device reports success (IMPL-ENG-007).
- **IMPL-CLI-005:** Before `session delete`, the CLI and the console warn that the key file will be erased, and that a copy made before deletion must never be used to start a new session, because its first bytes have already been used. With `--force` (used only when the key cannot be erased) they additionally warn that the key file remains on its medium and must be destroyed by the user; the device logs the override (SEC-PTR-004).
- **IMPL-CLI-006:** Importing a key that arrived without its `.SUM` warns that the copy cannot be checked against the original, and that the generating device's `.SUM` should be copied with the key whenever possible. Before `session skip`, the CLI shows how many units are damaged and how much key will be skipped, and asks for confirmation.
- **IMPL-CLI-004:** A session whose remaining TX capacity is below 20% of its TX range (configurable) shows a persistent warning in `session list`, `session info` and before every encryption (SEC-UI-001).

The original `ez`'s single-binary flag interface (`-i`, `-c`, `-w`, `-r`, `-E`, `-R`) and fixed alice/bob identity model are superseded. Its key copy from the host (`-c`) is not carried forward: key material never travels over USB (SEC-DIST-001).

---

## 11. Hardware Targets

### 11.1 Einszeit V1

| Component | Part | Notes |
|---|---|---|
| MCU | RP2350A | Secure Arm build; TRNG behind ACCESSCTRL |
| NOR flash | W25Q32JV or ZD25Q32 (4 MB) | Partition table at 0 (8 KiB); firmware partition 8 KiB–1 MiB (the build fails if an image exceeds 1016 KiB); key partition (drive 0) 1 MiB–4084 KiB, 765 blocks, Secure-only; last 12 KiB unpartitioned (erratum RP2350-E10) |
| F-RAM | MB85RS16 (2 KB) | SPI0: SCK 18, MOSI 19, MISO 20, CS 21 |
| MicroSD | TF-018B socket | SPI1: SCK 26, MOSI 27, MISO 28, CS 29; SD_DET 25 (polarity unverified, OI-03) |
| LED | GPIO 12 | Activity and fault indication |
| BOOT button | QSPI_SS | Bootloader entry only; not used by firmware |

### 11.2 Einszeit P1 (planned)

Same core API and HAL as V1, with a second microSD slot (drive 2).

### 11.2a FatFs configuration

`ports/fatfs/ffconf.h`, derived from the R0.16 template:
- **Drive 0:** since round 6 drive 0 uses the Einszeit store (§2.6), not FatFs. The FatFs drive 0 configuration remains tested (`test_keystore/fatfs_drive0`) but is not used by the firmware.
- **Cards:** FAT12, FAT16, FAT32 and exFAT are all supported. Most microSDXC cards (over 32 GB) arrive formatted exFAT. The device never formats a card.
- **Names:** long file names, UTF-8 at the API (`FF_USE_LFN 1`, `FF_LFN_UNICODE 2`), up to 255 bytes. Key files created by the device stay 8.3 (IMPL-KEY-001). Long names exist so that keys received under any name can be imported (IMPL-KEY-004). Names that are too long are refused, never truncated. No RTC timestamps.
- **Cost:** long names and exFAT add about 7 KB of flash and 1.1 KB of RAM on Cortex-M33 (measured, `-Os`).

FatFs is not power-fail safe. Key files are written only during generation and copying, and as `.TMP` files that are destroyed if interrupted; erasure is protected by quarantine. See DEV-15 for the remaining risk.

### 11.3 Zeitlos (later)

The portable core and CLI layer are intended to run on Zeitlos. Constraints recorded for that port: the TRNG HAL must expose the debiased hardware stream and never `zrng`; metadata needs an F-RAM on PMOD or a flash adapter that passes the metadata conformance tests; SEC-HW-001 requires the machine to operate as a dedicated, offline Einszeit appliance.

---

## 12. Testing Architecture

### 12.1 Host test suite (`tests/`)

The core is built for the host together with simulated hardware and run under AddressSanitizer and UndefinedBehaviorSanitizer. Every test case names the requirement IDs it demonstrates, and the test runner prints them.

| Simulator | Fault injection |
|---|---|
| F-RAM (`tests/sim/sim_fram`) | Power cut after any number of byte writes; single and multiple bit flips; arbitrary storage manipulation |
| Key storage (`tests/sim/sim_keystore`) | Removal or card swap before any HAL call; corrupted append (read-back test); a log of every read (isolation and replay tests); detection of reads into buffers holding stale data |
| TRNG (`tests/sim/sim_trng`, test only) | Replay of supplied bytes; biased, stuck, correlated, periodic and counter streams; health fault after n bytes |
| NOR flash (`tests/sim/sim_flash`) | Erase to `0xFF`, program clears bits only, power cut tearing the next erase or program (and the F-RAM with it), per-block erase counts |
| Block device (`tests/sim/sim_blockdev`) | RAM disk under the FatFs port (512-byte card or 4 KiB-sector flash); removal or card swap before any call; raw-medium scan proving erased key bytes are gone |

### 12.2 Metadata conformance tests

The power-cut and bit-flip suites (SEC-TEST-PTR-001/002/003) run against the `ez_hal_meta` interface. Any future metadata backend, such as a Zeitlos flash adapter, must pass them unchanged.

### 12.3 Hardware tests

What simulation cannot cover is tested on V1 by procedure (TR-03 to TR-09 in `fw/einszeit/README.md`): real power removal, card removal and damage, USB enumeration of the images, partition protection, the terminal interface with real terminal programs, and the end-to-end entropy pipeline. Automating them (pytest over HID and CDC against a device) is planned.

---

## 13. Open Items

Design questions raised during development, by ID. The deviations register and the traceability matrix refer to them. Hardware test procedures (TR-03 to TR-09) are in `fw/einszeit/README.md`; TR-01 is in `docs/einszeit-entropy-thresholds.md`.

**Open:**

| ID | Item | Next step |
|---|---|---|
| OI-04 | Entropy: NIST SP 800-90B IID and non-IID tracks, `sts-2.1.2` at 10⁸ bits, the `SAMPLE_CNT1` choice (DEV-01, DEV-02). Blocks release. | Separate entropy assessment, with TR-01 |
| OI-05 | Do the CDC and composite images work without a driver on Windows 10 and 11 (`usbser.sys`)? | TR-09 step 9 |
| OI-06 | Rewording of SEC-ENTROPY-003 (DEV-03). | Specification decision |
| OI-11 | A duplicate check across keys at import (DEV-16). | Low priority; possibly not needed |
| OI-12 | TRNG health-flag policy (DEV-20): how often the Von Neumann and continuous tests flag at profile 1. TR-03 saw none in 1,708 collections. | More data from long generations |

**Still to run on hardware:** TR-05 (power loss during card writes, needs a spare card), TR-09 steps 5, 7 and 9 (export and import, two devices, Windows), and TR-01.

**Closed:**

| ID | Item | Resolution |
|---|---|---|
| OI-01 | Session delete followed by re-create restarted the offsets (DEV-12). | SEC-PTR-004: deletion quarantines the session, erases its key, then removes the record |
| OI-02 | Do the RP2350 partition permissions keep `picotool` and UF2 writes away from the key partition? | Yes: TR-06 passed on V1 (IMPL-DRV-003) |
| OI-03 | SD_DET polarity. | Active-high, with the internal pull-down (TR-03) |
| OI-07 | FatFs for the key storage port. | Vendored (`third_party/fatfs`): R0.16, identical to ChaN's official `ff16.zip` |
| OI-08 | Re-reading key blocks for every frame. | The verified 4 KiB unit is held for a whole stream (IMPL-ENG-002/013) |
| OI-09 | exFAT and long file names. | Enabled |
| OI-10 | Key files against filesystem and card corruption (DEV-15). | Verify before use (SEC-STORE-004) and the instance tag; drive 0 has its own store without a filesystem |
| OI-13 | Long commands blocked the USB task. | All long work runs as jobs on the second core (IMPL-JOB-001) |
| OI-14 | Key exchange with a closed case. | A new card is handed over and kept by the receiver (§2.9) |

---

## 14. Revision History

| Rev | Date | Changes |
|---|---|---|
| 1.0 | 2026-09 | Initial version. |
| 4.0 | 2026-10 | EZ-SEC-001 Rev 1.4: card storage for availability (§2.8, design pending TR-05), key exchange by a handed-over new card (§2.9), key sizes with a 256 KiB default (§2.10), production and development images with a binary check and a development mark (§9.6), F-RAM reserved layout. Fixed a duplicated §2.7 heading. |
| 5.2 | 2026-10-12 | Rounds 18 to 23: §13 now lists the open items (formerly in the development plan); `SESSION_CRITICAL` and its toggle bitmap (IMPL-AV-005); `KEY_STATUS` and `JOB_RESULT` report the last command's job even while a background sync follows it (IMPL-JOB-001); IMPL-JOB-003 stacks; the commands 0x07-0x09 and 0x0C in the command table; terms (§0). |
| 5.1 | 2026-10 | Round 17: images einszeit_hid / _cdc / _composite / _dev (bcdDevice 0x0101/0x0102/0x0103/0x0110); the terminal interface (EZ-UI-001); drive 0 on by default when protected; device erase reaches every copy volume. |
| 5.0 | 2026-10 | Round 16: long commands are jobs on the second core (IMPL-JOB-001/002), `JOB_RESULT`, health in `DEVICE_INFO` (health, detail, job, deferred command, progress), automatic sync (IMPL-AV-008) and health policy (IMPL-AV-009). |
| 4.6 | 2026-10 | Streaming over USB (`ENC_*`, `DEC_*`): lockstep 512-byte chunks; any other command or a transport reset aborts a stream (committed key stays spent); `ez` streams above 64 KiB or with `--stream`. |
| 4.5 | 2026-10 | TR-07 fixes: SD driver waits for ready before commands and resets, long write limit during format, whole-card erase opt-in, `DRIVE_REPAIR` (volume repair), presence vs card errors; hardware simulation of the SD path. |
| 4.4 | 2026-10 | IMPL-AV-005 critical keys and IMPL-AV-006 generation on drive 0, as built; session flags in the record; protocol fields. |
| 4.3 | 2026-10 | IMPL-AV-007 card format (`EZM2` MBR, two FAT32 volumes), firmware mirror over the card, `DRIVE_FORMAT`, copies in `DRIVE_INFO`. |
| 4.2 | 2026-10 | §2.8 core as built: mirror layer, copy addressing, replication, failover bound to the instance, check and repair, `SESSION_CHECK`/`SESSION_REPAIR`, `ez` maintenance warnings, `ez-vdev --mirror`. |
| 4.1 | 2026-10 | IMPL-DRV-003 as built: `partitions.json`/`einszeit_pt.uf2`, key partition 1 MiB–4084 KiB, mapped through XIP window 1, guard checked against the boot ROM's partition table, `PROTECTION` status, protection state in `DEVICE_INFO`. |
| 3.4 | 2026-10 | USB: bring-up composite (CDC + HID, `0x0110`), `ez` over hidapi with `--device` and `device list`, automatic card mount on SD_DET. |
| 3.3 | 2026-10 | Phase 2, part 1: payload encodings (§9.4), IMPL-PROTO-001/002, dispatcher rules as built (IMPL-ARCH-004), virtual device (§9.5). |
| 3.2 | 2026-10 | RP2350 drivers and bring-up image (Phase 3a); IMPL-ENT-002 made precise (flagged collections discarded, repeated flags halt). |
| 3.1 | 2026-10 | Drive 0 store specified as built (§2.6, IMPL-S0-001..003); intent record (§2.6a, IMPL-INT-001); F-RAM reserved region allocated; NOR flash simulator. |
| 3.0 | 2026-10 | EZ-SEC-001 Rev 1.3: integrity tags and `.SUM` format (§2.4), import job (§2.5), instance tag (IMPL-KEY-005), verify-then-use (IMPL-ENG-013) replacing piece-wise reads (IMPL-ENG-002 revised), skip (IMPL-ENG-014), `SESSION_SKIP` and `KEY_IMPORT` commands, session creation requires a `.SUM`, cleanup of `.SUT` and orphan `.SUM`; drive 0 store and intent record outlined (§2.6). |
| 2.3 | 2026-10 | Long file names (UTF-8) and exFAT enabled in the FatFs port; HAL names up to 255 bytes, case-insensitive, never truncated; exFAT 64-bit sizes guarded. |
| 2.2 | 2026-10 | EZ-SEC-001 Rev 1.2: session deletion quarantines, erases the key, then removes the record; the same order for key delete and device erase. Quarantine reasons 0x03 (key being erased) and 0x04 (key damaged), not resolvable; reason byte coded. IMPL-ENG-012 damaged-key detection. IMPL-CLI-005 deletion warnings. FatFs port and configuration (§11.2a); repository layout. |
| 2.1 | 2026-10 | Phase 1b. Keystore and TRNG HAL contracts specified; generated key size 8 KiB to 64 MiB; Key ID redraw limit; engine key-reading discipline (IMPL-ENG-002) and commit unit (IMPL-ENG-004) stated as implemented; card-check points (IMPL-ENG-010); monitor and acceptance thresholds defined with a reference to EZ-ENT-THR-001; simulator table updated. |
| 2.0 | 2026-10 | Aligned with EZ-SEC-001 Rev 1.1. Separate TX and RX offsets; session record redesigned (64 bytes, 24 sessions) so that offset commits no longer rewrite a whole-record CRC; coded state bytes; larger-of-two offset read rule; event log in F-RAM; Key ID 0 removed; drive 0 disabled by default with partition protection and no software BOOTSEL path; buffered and streaming encryption with per-frame commit and resend; decryption commits after CRC verification; new commands (`SESSION_RESOLVE`, `KEY_STATUS`, `RESEND`, `RELEASE`, `DRIVE_ENABLE`, `DRIVE_DISABLE`, `DEVICE_REPAIR`, `LOG_READ`); message format version byte; HID frame header; USB variants; hardware table corrected to MB85RS16; `IMPL-` requirement IDs introduced. |

---

*End of EZ-IMPL-001*
