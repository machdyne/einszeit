# Einszeit Deviations, Interpretations and Limitations — Production

**Document ID:** EZ-DEV-001  
**Governing spec:** EZ-SEC-001 Rev 1.3  
**Scope:** production firmware, host software and the portable core. The bench validation firmware has its own register (`fw/test/docs/EZ-TEST-DEVIATIONS.md`), and none of its deviations may be carried into a production build.  
**Status:** Living document, updated every development round.

Each entry has a type:

- **Deviation**: the implementation knowingly does not meet a requirement. It must be justified, contained, and either scheduled for remediation or accepted by the project owner.
- **Gap**: compliance is intended but not yet achieved.
- **Interpretation**: the requirement's wording needed a reading; the reading is recorded so it can be reviewed.
- **Limitation**: behaviour outside the requirement's scope, documented so users are not surprised.

Requirement IDs refer to EZ-SEC-001 unless prefixed `IMPL-` (EZ-IMPL-001).

---

## Summary

| ID | Type | Requirement | Blocks a compliant product? | Status |
|---|---|---|---|---|
| DEV-01 | Deviation | SEC-ENTROPY-002 | Yes | Open: entropy work continues separately |
| DEV-02 | Gap | SEC-TEST-ENT-001 | Yes | Open: NIST STS run pending |
| DEV-03 | Interpretation | SEC-ENTROPY-003 | No | Open spec question |
| DEV-04 | Deviation | SEC-FW-004, SEC-HW-003 | No (opt-in) | Drive 0 disabled by default; protection built and enforced by firmware (round 11); hardware proof pending (TR-06) |
| DEV-05 | Limitation | SEC-UI-002 | No | Accepted |
| DEV-06 | Interpretation | SEC-UI-005 | No | Proposed |
| DEV-07 | Interpretation | SEC-GEN-003 | No | Proposed |
| DEV-08 | Interpretation | SEC-UI-001 | No | Proposed |
| DEV-09 | Limitation | SEC-PTR-003 (streaming) | No | Accepted |
| DEV-10 | Limitation | IMPL-META-001 | No | Accepted |
| DEV-11 | Limitation | SEC-TEST-PTR-003 | No | Accepted (out of scope, §0) |
| DEV-12 | Gap | SEC-PTR-002, SEC-ISO-002 | No | **Closed** by EZ-SEC-001 Rev 1.2 (SEC-PTR-004) |
| DEV-13 | Interpretation | §2.3, SEC-ENTROPY-002 | No | Proposed |
| DEV-14 | Limitation | IMPL-ENG-012 | No | **Closed** by SEC-STORE-004 (round 5) |
| DEV-15 | Limitation | SEC-ISO-001, SEC-META-003 (FatFs) | No | **Closed** for secrecy by SEC-STORE-004 (round 5); availability residual remains |
| DEV-16 | Limitation | SEC-STORE-005 | No | Accepted; OI-11 open |
| DEV-17 | Interpretation | SEC-KDF-001, SEC-STORE-004 | No | Clarified in EZ-SEC-001 Rev 1.3 |
| DEV-18 | Limitation | IMPL-S0-001 | No | Accepted |
| DEV-19 | Deviation | SEC-UI-002, SEC-FW-004 (DEV-04), SEC-ENTROPY-002 | No (not a release image) | Bring-up image only |
| DEV-20 | Interpretation | SEC-ENTROPY-004 | No | Proposed; first TR-03 data: no flags in about 2,000 collections |
| DEV-21 | Deviation | SEC-ENTROPY-001, SEC-STORE-001 | No (not a device) | Virtual device is test-only |
| DEV-22 | Limitation | SEC-AVAIL-003 | No | Measured on V1; mitigation designed (IMPL §2.8), TR-05 pending |
| DEV-23 | Limitation | SEC-AVAIL-003 | No | Accepted for V1; card power switch recommended for the next revision |

---

## DEV-01 — Entropy per byte not yet demonstrated (SEC-ENTROPY-002)

**Type:** Deviation (open non-conformance)

**Requirement:** the TRNG must produce at least 8 bits of entropy per output byte.

**Finding:** the ent001-16384 characterisation (conditioned output, `SAMPLE_CNT1 = 16384`) gives an SP 800-90B non-IID min-entropy of 0.879 bit/bit, limited by the Compression estimator. That estimator is flagged "at ceiling": ideal random data scores 0.881 at that sample size, so it cannot certify a higher figure. The other nine estimators give between 0.93 and 0.999. The data is consistent with full entropy, but the requirement is not demonstrated by any test.

**Containment:**
- Per-key acceptance tests (EZ-IMPL-001 §7.3) and online monitoring (§7.2) are implemented regardless.
- The TRNG profile ID is recorded in every generation event (IMPL-ENT-001), so keys can be traced to the operating point that produced them.
- The device documentation will state the measured figure.

**Action:** entropy work (NIST IID and non-IID tracks, a possible increase of `SAMPLE_CNT1`) continues outside this development track. To whatever extent V1 falls short, that is documented here, and later hardware revisions address it.

## DEV-02 — SP 800-22 at 10⁸ bits not yet recorded (SEC-TEST-ENT-001)

**Type:** Gap. Carried from `fw/test` gap G-04.

**Action:** run NIST `sts-2.1.2` on the archived captures and cite the result here. The project's Python implementation is not the formal record.

## DEV-03 — Wording of SEC-ENTROPY-003

**Type:** Interpretation (spec question). Carried from `fw/test` D-02.

The hardware Von Neumann balancer is a debiaser whose purpose is to raise entropy density. SEC-ENTROPY-003 reads as though debiasing were a risk to be bounded.

**Reading applied:** the balancer, the continuous RNG test and the autocorrelation test stay enabled in production (IMPL-ENT-001), and no algorithmic conditioning is applied in software.

**Action:** consider rewording so that post-debiasing output must meet SEC-ENTROPY-002, with the raw-source min-entropy documented separately.

## DEV-04 — Drive 0 is readable through the bootloader when enabled (SEC-FW-004, SEC-HW-003)

**Type:** Deviation (user opt-in)

In BOOTSEL mode, entered with the BOOT button at connection, the RP2350 bootrom can read flash with `picotool`.

**Containment:**
- Drive 0 is disabled by default (IMPL-DRV-001); enabling it requires confirmation after a warning (IMPL-DRV-002).
- Disabling it erases the partition.
- No software path into BOOTSEL exists (IMPL-DRV-004).
- The partition table denies bootloader access to the key partition (IMPL-DRV-003).

The remaining exposure requires physical access, which is outside scope (EZ-SEC-001 §0).

**Action:** verify on hardware that the partition permissions block `picotool` reads and UF2 writes, including writes to the partition table itself (OI-02). If they do not, the warning shown when enabling drive 0 must say so explicitly.

## DEV-05 — Scrollback on the CDC console (SEC-UI-002)

**Type:** Limitation

The console clears the screen and sends the clear-scrollback sequence when a message view is dismissed. The scrollback buffer, however, belongs to the host terminal emulator, which the device cannot control. The user manual will say this.

## DEV-06 — "Remote party" in SEC-UI-005

**Type:** Interpretation

`ez session info`, `session list` and the console show offsets and remaining capacity to the locally connected host, as SEC-UI-001 requires.

**Reading:** the USB host is local, not a remote party. The device itself never writes offsets or remaining capacity to any log (IMPL-LOG-001; verified by `test_meta_rollback/by_command`). `ez` must not write them to log files either; this is to be verified in Phase 2.

## DEV-07 — Timestamps without a real-time clock (SEC-GEN-003)

**Type:** Interpretation

V1 has no RTC. Generation events are timestamped with the boot counter plus uptime in seconds, or with host-supplied Unix time marked as untrusted (EZ-IMPL-001 §3.7). Together with the event sequence number, this orders events reliably but does not give trusted wall-clock time.

## DEV-08 — "Mark the session inactive" on exhaustion (SEC-UI-001)

**Type:** Interpretation

Exhaustion of the TX range makes the session inactive for encryption. It still decrypts, because its RX range is independent and may hold unread messages from the peer (IMPL-META-005; verified by `test_meta/exhaustion`).

## DEV-09 — Streaming encryption spends key on failure

**Type:** Limitation (not a security deviation)

In streaming mode, an encryption that fails part-way has already spent the key behind every frame it output, plus at most one commit unit (IMPL-ENG-005). This follows from SEC-PTR-003, because the device cannot rely on the host to delete output. Buffered mode (up to 64 KB) spends nothing on failure before its commit. `ez` warns about this before a streaming encryption (IMPL-CLI-002).

## DEV-10 — Boot counter can appear to drop by one

**Type:** Limitation

The boot counter is advisory. Corruption of the slot holding the newer count exposes the older slot, which is one lower. The next boot continues from there. This is documented in `test_meta_bitflip/single_bit_exhaustive`.

## DEV-11 — Forged well-formed offsets

**Type:** Limitation (out of scope, EZ-SEC-001 §0)

Someone with physical access to the F-RAM can write a lower offset with a correct check value into the selected slot, and a lower value into the other slot, and the device cannot detect it. Every other manipulation is detected or has no effect, as verified by `test_meta_rollback`: a selector swap, a lower value in the inactive slot, a damaged selected slot, a corrupt selector, an out-of-range value, a slot copied from another session, or a changed role.

## DEV-12 — Deleting and re-creating a session restarts its offsets

**Type:** Gap. **Status: closed** (round 3) by EZ-SEC-001 Rev 1.2, SEC-PTR-004.

**Original problem:** deleting a session kept its key file, so a new session for the same file restarted the TX offset and reused every byte already consumed.

**Resolution:** session deletion now happens in three steps:
1. Quarantine the session.
2. Erase the key file.
3. Remove the record.

If the key cannot be erased, deletion is refused unless the user overrides, and the override is logged (`EZ_EV_SESSION_FORCE`). Verified by `test_core/delete_*`, `interrupted_*`, and `test_keystore/fatfs_delete_sweep`.

**Residual, by design:** a user who copies a key before deleting its session, or who overrides deletion of an inaccessible key, can still start a new session from the copy. The user chose to keep this possible so that a key can be recovered after a technical failure. The warnings (IMPL-CLI-005) say plainly that such a copy must never start a new session from the beginning, and SEC-DIST-004 assigns responsibility for copies to the user.

## DEV-13 — What the statistical tests can and cannot show (§2.3, SEC-ENTROPY-002)

**Type:** Interpretation

SEC-ENTROPY-002 requires post-generation statistical testing of every key, and that a key is not marked valid unless it passes.

**Reading applied:**
- The acceptance tests (EZ-ENT-THR-001 §2) are the "post-generation statistical testing". A key passes when its failure counts stay within bounds chosen for at most 10⁻⁹ false rejection per test. A small number of failing FIPS blocks is expected from a perfect source and does not reject the key.
- The "rolling window" of §2.3 is implemented as consecutive, non-overlapping 4,096-bit windows. A failure is therefore detected within one window of its onset, which is what SEC-TEST-ENT-002 asks for.
- Neither test can establish 8 bits of entropy per byte; that is DEV-01.

## DEV-14 — Limit of the damaged-key check (IMPL-ENG-012)

**Type:** Limitation. **Status: closed** (round 5). Since EZ-SEC-001 Rev 1.3 every key byte is verified against its unit's tag before use (SEC-STORE-004, IMPL-ENG-013), so a damaged region of any length is refused before a single byte of it is output. The run check below remains as a further line of defence. The original entry is kept for the record.

The engine refuses key data containing 16 identical `0x00` or `0xFF` bytes in a row. A short damaged region at the very start of the bytes an operation reads can still pass:
- With streaming, up to 15 such bytes can be output in earlier chunks before the run reaches 16.
- Fewer than 16 zero bytes are indistinguishable from random data.

XOR with zero outputs the plaintext unchanged, so those bytes would be exposed.

**Why it is acceptable:** this check is a second line. The first line is SEC-PTR-004: every session using a key is quarantined before any byte of the key is erased, so the normal cause of zeroed key data (interrupted erasure) never meets a usable session. The check exists for causes outside the device's control, such as card corruption, and catches any damage longer than 15 bytes.

## DEV-15 — FatFs and power loss

**Type:** Limitation. Open item OI-10, **closed for secrecy** (round 5).

**Resolution:** SEC-STORE-004 (verify before use) and the instance tag (IMPL-KEY-005). Whatever a power cut, a card fault or a PC does to a card, the device either uses the true key bytes for a position or refuses. This includes cross-linked clusters, a key's data moved elsewhere, corruption inside the card, and a different key under the same ID. The chaos test (SEC-TEST-STORE-002) checks exactly this against the true key after every operation. What remains is availability: a damaged card can make part of a key, or all of it, unusable. The original analysis is kept below.

FatFs (R0.16) is not power-fail safe. The key files themselves are protected:
- They are written only while generating or copying, as `.TMP` files that are destroyed on interruption (IMPL-GEN-001).
- A key file is never appended to after it is renamed to `.KEY`.
- Erasure is guarded by quarantine (SEC-PTR-004).

The remaining risk is filesystem corruption from a power cut during a write: a FAT sector (or, on exFAT, the allocation bitmap) updated while another key's file is being extended. In the worst case, one key file's cluster chain could point into another file's clusters. A session would then read the other key's bytes. The file size check at boot would not notice. The damaged-key check would notice only if the clusters were blank.

**Likelihood:** low. It needs a power cut during key generation or copying, on a card whose FAT sector write is not atomic, affecting a FAT sector shared with an existing key's chain.

SD cards add a risk no host software can remove: a power cut during a write can corrupt data inside the card beyond the sector being written, because of the card's internal flash management.

**Mitigation considered for OI-10, not needed:** pin each key's location at creation. Allocate the key contiguously, record its extent (start sector, length) and the card's identity with the session in F-RAM, and read key bytes through that extent rather than through the filesystem. Refuse any new allocation that overlaps a recorded extent. It was not adopted: verify before use (the resolution above) closes the secrecy risk without it.

## DEV-16 — What the import checks cannot see (SEC-STORE-005)

**Type:** Limitation. Open item OI-11.

A key that arrives *with* the generating device's `.SUM` is verified completely. A key that arrives *without* one is tagged as it is. Two checks catch damage that would matter for secrecy:
- the acceptance tests, which reject blank, patterned or biased regions;
- the duplicate check, which rejects any two identical 4 KiB units.

What they cannot catch:
- **Damage that looks random,** such as bit flips. This is harmless to secrecy: the two parties' copies differ, so some messages fail to decrypt, but nothing is reused.
- **A duplicate not aligned to the 4 KiB units,** possible only on cards with clusters smaller than 4 KiB (small FAT12/16 volumes).
- **A block copied from a *different* key,** for example after filesystem corruption on the sender's card. A cross-key check (OI-11) would compare against the keys already on the device. It has not been built, because the owner judged it unnecessary for now.

**Mitigation:** copy the `.SUM` with the key. The import warns when it is missing (IMPL-CLI-006).

## DEV-17 — Integrity tags and SEC-KDF-001

**Type:** Interpretation, adopted into EZ-SEC-001 Rev 1.3.

SEC-KDF-001 forbade "any algorithmic transformation of key material", which also covers hashing key units for verification. The clarified requirement keeps the intent: the key stream is the key bytes themselves. The tags are never used as, or mixed into, the key stream. Because the tags carry a little information about the key, they are handled exactly like key material: stored only beside it, never transmitted, never logged, erased with it.

## DEV-18 — Drive 0 store capacity and wear

**Type:** Limitation

- **Capacity.** The drive 0 store's table has 64 entries, so at most 32 keys with their `.SUM` files. The data blocks fill the partition: about 2 MB on V1.
- **Names.** Limited to 12 characters; drive 0 only holds key files.
- **Wear on the two table blocks.** Each create, rename or erase rewrites one of them, about four rewrites per key over its lifetime. At the NOR flash's typical 100,000 erase cycles, the table outlasts any realistic use.
- **Wear on data blocks.** Each data block is erased when allocated and again when its file is erased.

## DEV-19 — The development image is not a release image

**Type:** Deviation (bounded to `einszeit_dev.uf2`; SEC-FW-005 now requires separate images)

- The debug shell prints decrypted plaintext to the CDC terminal (SEC-UI-002).
- Drive 0 has no partition protection, so it can be read in BOOTSEL mode (DEV-04, OI-02).
- No HID interface.
- `fw update` reboots into the UF2 bootloader from the shell, at the owner's request for testing (IMPL-DRV-004). Anything able to type into the console, including malware on the host, can therefore put the device into BOOTSEL, then read drive 0 or load other firmware. The command is compiled only when `EZ_BRINGUP` is defined; production targets must never define it.

**Containment:**
- The image announces itself as bring-up.
- Its README and the test procedure say it must never hold real secrets.
- Production images are separate build targets.
- No command reads key bytes. The stdio reset interfaces stay disabled.

## DEV-20 — Isolated TRNG health flags do not halt generation (SEC-ENTROPY-004)

**Type:** Interpretation

The RP2350 TRNG's own health tests (Von Neumann 32-identical-bits, continuous RNG test) flag individual 192-bit collections, and the hardware itself discards such a collection.

**Reading:** a single flag is the health test working as designed, not evidence that the source is degraded. `hal_trng.c` therefore discards the flagged collection and continues. Generation halts with a logged fault on an autocorrelation failure, a timeout, or more than 4 flagged collections in one read. Generation also remains subject to the online monitor and the acceptance tests.

**Action:** TR-03 step 3 measures how often flags occur at profile 1. If they are frequent, the threshold or the profile will be revisited (OI-12).

## DEV-21 — The virtual device is for testing only

**Type:** Deviation (bounded to `sw/vdev`)

`ez-vdev` takes its key bytes from the operating system's random generator, not a hardware TRNG (SEC-ENTROPY-001). Its drives are ordinary files and directories: zero-before-delete is applied, but the host file system's handling of the underlying blocks is outside its control (SEC-STORE-001).

**Containment:**
- It identifies itself as variant `0xEE` with TRNG profile `0xEE`, and `ez device info` says it is virtual.
- Its banner and the specification say it must never be used for real secrets.
- It exists so that the CLI and protocol can be tested end to end without hardware, and so that a second party can be simulated while only one prototype exists.

## DEV-22 — SD cards can lose more than the data being written

**Type:** Limitation, measured.

During TR-03 and TR-04, the card was pulled twice during writes. Afterwards `fsck.fat` reported both FAT copies corrupt, and a key not being written at the time (`5B79EE11`) was lost. The session using it was quarantined (reason `0x01`), so secrecy held, but the key is gone.

**Why:** consumer cards never rewrite data in place. Their controllers relocate data internally, and in MLC/TLC flash the cells of different pages are paired, so a power cut can corrupt data far from the write. FAT keeps both FAT copies and the directory together near the start of the volume, making them a single point of failure.

**Mitigations:**
- **Designed** (EZ-IMPL-001 §2.8): no writes in normal use (SEC-AVAIL-001); a warning before every maintenance write (SEC-AVAIL-002); mirrored volumes written one at a time (SEC-AVAIL-003/004); generation on drive 0 so the card is written only in short bursts.
- **To be measured:** TR-05, before the design is implemented.

**Residual:** failure of the whole card. No layout survives it; the user manual must say so.

## DEV-23 — A card can need its power cut to recover

**Type:** Limitation, observed on V1 (TR-07) and reproduced in `tests/hwsim`.

Some SD cards stop responding if they are reset (CMD0) while still busy. Only removing their power brings them back. V1 cannot switch the card's power from firmware, so a software reboot or a firmware update does not clear it; removing the card, or unplugging the device, does.

**Mitigations:**
- The driver never sends a command to a busy card. It waits for the card before every command, and before a reset.
- It never resets a card that still answers. A failed read or write on a card that answers is a card error, not a removal.
- Formatting waits up to 5 minutes for writes that follow a whole-card erase.
- Whole-card erase is opt-in.

**Root cause found later (TR-07):** the driver polled a busy card continuously with CS low, and a Transcend card's periodic internal work never finished under that. The driver now releases the card between checks after 2 ms. The remaining residual is a card that stays busy longer than the driver waits (10 s for a write, plus the status check), which the simulator shows can still stop responding. **Next hardware revision:** a load switch on the card's supply, so firmware can power-cycle it.

---

*End of EZ-DEV-001*
