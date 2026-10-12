# fw/einszeit — Einszeit V1 firmware

The production core (`core/`) and the key storage ports (`ports/`) on the RP2350 drivers.

**Images** (EZ-IMPL-001 §9.6, SEC-FW-005; the terminal interface is EZ-UI-001):

| Image | Interfaces | `bcdDevice` | For |
|---|---|---|---|
| `einszeit_composite.uf2` | CDC + HID | `0x0103` | **Production.** The terminal interface over CDC, and `ez` over HID. |
| `einszeit_cdc.uf2` | CDC only | `0x0102` | **Production.** The terminal interface only; `ez` cannot connect. |
| `einszeit_hid.uf2` | HID only | `0x0101` | **Production.** `ez` only, no terminal. |
| `einszeit_dev.uf2` | CDC + HID | `0x0110` | **Development and hardware tests.** The terminal interface plus the development commands in its CLI (`info`, `fw update`, `sd …`, TR-05), and Ctrl-Y into the bootloader. Marks the device (IMPL-MODE-002). |
| `einszeit_pt.uf2` | — | — | **The flash partition table.** Install once, with the BOOT button, before the firmware (TR-06). Without it internal storage (drive 0) cannot be used. |

The production images have no software path into the bootloader (the build checks each binary); update them with the BOOT button.

> **The development image must never hold real secrets (DEV-19).**
> - Its shell prints plaintext.
> - Any program on the PC can type `fw update` and then load firmware that reads every key, including the card's.
> - After using it, flash `einszeit_hid` and run `ez device erase` before real use. `ez` warns until you do.

All long work runs on the second core, so USB and the terminal stay responsive; each core has a 16 KB stack with its stack limit set (IMPL-JOB-003). While a development command runs, HID requests are answered BUSY. A card inserted while the board runs is mounted automatically (SD_DET, active-high).

## Hardware tests

The procedures for testing the firmware on V1 hardware, TR-03 to TR-09, are at the end of this file. TR-01 (the entropy thresholds against real captures) is in `docs/einszeit-entropy-thresholds.md`.

## Build

```sh
mkdir build && cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake ../fw/einszeit -DCMAKE_BUILD_TYPE=Release
make -j
```

Requires pico-sdk 2.1.1 with `lib/tinyusb`, and `arm-none-eabi-gcc`. The build fails if the image would reach the drive 0 key partition at 2 MiB (SEC-HW-003). CI builds the UF2 on every push.

## Layout

| File | Purpose | Traceability |
|---|---|---|
| `src/hal_fram.c` | Metadata HAL over SPI0 for the MB85RS16 | SEC-META-002 |
| `src/hal_flash.c` | Flash HAL over the QSPI key partition (upper 2 MiB). Writes go through `flash_safe_execute`; reads use the uncached XIP alias | SEC-HW-003, SEC-FW-003 |
| `src/hal_sdblk.c` | Block device for the microSD. The card check (SEND_STATUS plus CID comparison) is authoritative; SD_DET is advisory only | SEC-HW-002, IMPL-ENG-010/011 |
| `src/ez_sd.c` | SD SPI driver, forked from `fw/test` and extended with CMD13 and a CID re-read | — |
| `src/hal_trng.c` | TRNG HAL, production profile 1: `SAMPLE_CNT1 = 16384`, health tests always on, no bypass code at all | SEC-ENTROPY-001/003/004, IMPL-ENT-001/002 |
| `src/selftest.c` | Known-answer test on the target CPU, using RAM-only HALs | SEC-TEST-ENC-001 |
| `src/usb.c` | TinyUSB device: descriptors per §9.1–9.2 (`16d0:1475`, vendor usage page `0xFF00`, 64-byte reports), console as a stdio driver over CDC, HID frame queue | IMPL-DRV-004 (no vendor reset interface) |
| `src/app.c` | Boot, the second core (jobs), both cores' stacks, HID service, card polling | IMPL-JOB-001/002/003 |
| `src/card.c` | The card: plain or mirrored (`EZM2`, copies A and B), format and volume repair | IMPL-AV-004/007 |
| `src/main_ui.c` | Main loop of the terminal images (cdc, composite, dev) | EZ-UI-001 |
| `src/main_prod.c` | Main loop of `einszeit_hid` | IMPL-DRV-004 |
| `src/shell.c` | The development commands (dev image only) | IMPL-DRV-004 (`fw update` only with `EZ_BRINGUP`, DEV-19) |
| `src/tr05.c` | The power-loss test mode (TR-05) | SEC-TEST-AVAIL-001 |

Firmware updates: in the development image, `fw update` in the CLI (or Ctrl-Y) reboots into the UF2 bootloader. For the production image, hold BOOT while connecting. Either way, copy the UF2 to the `RP2350` drive that appears.

## TR-03 — bring-up test procedure

This needs one V1 board, a microSD card formatted FAT32 or exFAT (empty, or holding nothing you need), and a serial terminal such as `picocom /dev/ttyACM0`, `screen`, or PuTTY on Windows. Steps 2–7 and 9 need only the card; steps 8 and 10 need a second board or a second SD card slot.

Please send the full terminal output, or the lines marked **report**.

1. **Flash.** Hold BOOT, connect, copy `einszeit_dev.uf2` to the `RP2350` drive. Open a terminal on the serial port, press **C** for the CLI and type `info`. **Report** its output.
   - A board last used with `fw/test` shows the metadata as FAULT, because of its test marker. That is expected.
2. **Basics.** **Report** the output of each:
   - `fram` should say `present`.
   - `kat` should say `PASS`.
   - `init`, then `YES`, then `info`. Metadata should now be valid, with drive 0 disabled.
3. **TRNG.** `trng 16384` takes about a minute. **Report** the whole output: rate, monitor and acceptance bits, and the health counters.
4. **Drive 0.**
   - `d0 on`, then `YES`.
   - `keygen 16384 0` takes about two minutes. ESC cancels.
   - `d0 dir`.
   - **Report** the keygen result line, the trng line and the directory (expect `<ID>.KEY` and `<ID>.SUM`).
5. **Card.**
   - `sd mount`, then `sd dir`.
   - `keygen 8192 1`, then `sd dir`.
   - **Report** the results.
6. **Session and persistence.**
   - `create <ID from step 4> 0 auto self`. The role should come out as `alice`, because this device generated the key.
   - `enc <slot> hello` prints a base64 message.
   - `ls`, then `reboot`; reconnect, then `ls` again. The `tx` value must be identical across the reboot.
   - `dec - <that base64>` should be refused with `RANGE`: a device cannot decrypt its own messages, because they use the other half of the key.
   - **Report** all of this.
7. **Card detect and card check** (closes OI-03).
   - With the card in: `sd det`. Remove the card, then `sd det` again. **Report** both lines. Each reads SD_DET once with the internal pull-up and once with the pull-down, which shows how the socket's switch is wired.
   - Then `sd watch`: remove the card, wait two seconds, reinsert it, wait two seconds, press a key. **Report** the lines. Expect `absent` and then `inserted, remounted`.
8. **Two boards, optional.**
   - On board A: `copy <ID> 0 1` puts the key and its `.SUM` on the card.
   - Move the card to board B. On B: `init`, `YES`, `sd mount`, `import 1 <ID>.KEY <ID> bob alice`. It should import, verified against the `.SUM`.
   - `enc` on A, `dec - <base64>` on B; then the other way round.
   - **Report** the results.
9. **Removal during an operation.**
   - `keygen 65536 1`. Pull the card about 20 seconds in. **Report** the result line.
   - Reinsert, then `sd mount` and `sd dir`. The leftover `.TMP` and `.SUT` files should be gone.
10. **Interrupted deletion, optional.**
    - `del <slot>`, `YES` for a session on drive 0, and unplug the board immediately.
    - Reconnect, then run `ls` and `info`. The session should be gone and no intent pending.
    - **Report** the result.

## TR-04 — `ez` over USB, and the first exchange with a TRNG key

This needs the board with this image, the microSD in a card reader for one step, and `ez` and `ez-vdev` built on the PC (`cmake -S sw -B build/sw && cmake --build build/sw`; on Linux this needs `libudev-dev`).

1. **Flash and connect.**
   - In the shell: `fw update`, then copy the new UF2. The shell is not needed after this; you may close the terminal.
   - Linux: install the udev rule once (`sudo cp sw/ez/99-einszeit.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules && sudo udevadm trigger`), then replug the board.
   - Run `ez device list`, `ez device info`, `ez session list`, `ez log`. **Report** the output. It should show variant `0x10`, TRNG profile 1, and your existing session `self`.
2. **A key from the real TRNG, generated over USB.**
   - `ez key generate 65536`. Progress is shown; it takes about 4 minutes.
   - `ez session create peer --key-id <ID>`. The role becomes alice, because this device generated the key.
   - **Report** the result.
3. **Hand the key to the second party (the virtual device).**
   - Pull the card, put it in the PC's reader, and copy `<ID>.KEY` and `<ID>.SUM`:
     ```
     build/sw/ez-vdev /tmp/ezP &
     P="build/sw/ez --virtual /tmp/ezP/ez.sock"
     $P device erase --yes
     cp /media/.../<ID>.KEY /media/.../<ID>.SUM /tmp/ezP/drive1/
     $P session import board <ID>.KEY --key-id <ID> --role bob
     ```
   - Eject the card from the PC and put it back in the board; the board remounts it by itself.
   - **Report** the import result. It should be verified against the `.SUM`, with no warning.
4. **Exchange.**
   ```
   echo "from the board" | ez encrypt peer --yes | $P decrypt
   echo "from the PC" | $P encrypt --yes | ez decrypt
   ez session list; $P session list
   ```
   **Report** the output. Both texts should come through, and each side should show its send and receive counts.
5. **Large message and replay.**
   ```
   head -c 60000 /dev/urandom > big; ez encrypt peer --yes -i big -o big.msg
   $P decrypt -i big.msg -o big.out && cmp big big.out && echo SAME
   $P decrypt -i big.msg        # must be refused: REPLAY
   ```
6. **Confirmation.** `echo x | ez encrypt peer` with no `--yes` should ask on the terminal and accept only `y`. **Report** whether the prompt appeared and declined correctly.

## TR-05 — power loss during writes (SEC-TEST-AVAIL-001)

Needs `einszeit_dev`, a **spare** microSD card of at least 1 GB whose contents may be destroyed, and patience: the more power cuts, the better the numbers.

**Part 1: write protection.**
- In the shell: `tr05 wp`, then `YES`.
- It writes to a sector near the end of the card, sets the card's temporary write-protect bit, tries to write again, then clears the bit.
- **Report** its lines. The last one says whether the card honours the bit.

**Part 2: do power cuts spare the other copy?**
1. `tr05 prep`, then `YES`. The board reboots into test mode, puts two independent FAT32 volumes on the card (A at 4 MiB, B at half the card), and writes eight 256 KiB reference files to each. This takes a few minutes.
2. Once the terminal shows `writing volume A in a loop`, cut the power: unplug the USB cable.
3. Plug it back in. The board checks both volumes file by file, counts any damage, repairs it, and starts writing again. No terminal is needed.
4. Repeat, ideally 100 times or more, waiting a random 5–60 seconds before each unplug.
5. Connect a terminal at any point to see the tally. Press `q` to stop: the board disarms and reboots normally. `tr05 status` shows the tally later.

**Report** the tally. The key line is **"B (idle): … damaged on N power-ups"**. Zero across many cuts supports mirrored volumes; any non-zero count means damage spreads beyond the area written, and the number of copies, or the card, has to change. The same test can then be repeated with other cards, including a candidate industrial card.

Afterwards, reformat the card on a PC.

## TR-06 — internal storage's flash protection (drive 0; OI-02, IMPL-DRV-003)

Proves on the hardware that nothing across USB can read or write drive 0. Needs a USB-enabled `picotool` on the PC (any recent release).

**Before you start:** drive 0 moves from 2 MiB to 1 MiB, so anything on it now is lost. Optionally run `ez drive disable 0 --yes` first.

1. **Install the partition table.**
   - Hold BOOT, connect, and copy `einszeit_pt.uf2` to the `RP2350` drive.
   - Hold BOOT again if needed, and copy `einszeit_dev.uf2`. It lands in the firmware partition.
   - Back in BOOTSEL: `picotool partition info`. **Report** it. Expect `keys` at `0x100000–0x3fd000` with `S(rw) NSBOOT(-) NS(-)`.
2. **The firmware sees the protection.**
   - With the development image running: `ez device info`. **Report** it. Expect `internal   drive 0, …; flash protection verified`.
   - Then `ez drive enable 0 --yes`, `ez key generate 128K --drive 0`, and `ez session create d0 --key-id <ID> --drive 0`.
   - Run `echo test | ez encrypt d0 --yes` once, as a baseline.
3. **picotool cannot read the key partition.**
   - In the shell: `fw update`. In BOOTSEL:
     - `picotool save -r 0x10002000 0x10003000 fw.bin` should **succeed** (the firmware partition is readable; this shows picotool works).
     - `picotool save -r 0x10100000 0x10101000 keys.bin` must **fail**.
     - `picotool save -a all.bin` should fail or stop at the key partition. If it produces a file, `cmp` it against... nothing: just **report** its size.
4. **Nothing can write the key partition.**
   - Still in BOOTSEL: `head -c 4096 /dev/zero > z.bin; picotool load -o 0x10100000 z.bin` must **fail**.
   - Drag-and-drop route: `picotool uf2 convert z.bin z.uf2 --family absolute -o 0x10100000`, then copy `z.uf2` to the drive.
   - Reboot (`picotool reboot`, or replug), then `echo test | ez encrypt d0 --yes`. It must still **work**: any change to the key would fail verification.
5. **Production image.**
   - Hold BOOT and copy `einszeit_hid.uf2`. Then `ez device info`: expect `production`, protection verified, and the development-mark warning.
   - `picotool reboot -f -u` must **fail**: the production image has no way into the bootloader.
   - `ez device erase` clears the mark. **Report** both outputs.

**Report** each "must" that does not hold. Any of them failing means drive 0 must stay disabled.

## TR-07 — the card mirror (SEC-AVAIL-003)

Needs `einszeit_dev` (or `einszeit_hid` plus `ez`), and a card whose contents may be erased. A PC with a card reader helps for step 3.

1. **Format the card for two copies.**
   - Delete any sessions on the card first. Then `ez drive format 1 --yes`; this takes a few minutes on a large card.
   - Then `ez drive info 1`, which should end with `2 copies of every key`.
   - On a PC the card shows two partitions. **Report** the outputs.
2. **A mirrored session.**
   - `ez key generate 128K`, then `ez session create test --key-id <ID>`.
   - `ez session check test` should show `copy 0: ok` and `copy 1: ok`.
   - **Report** it.
3. **Failover** (needs the PC).
   - Power the board off, put the card in the PC, and change one byte inside `<ID>.KEY` on the **first** partition only, for example with a hex editor at offset 100. Put the card back.
   - `echo hi | ez encrypt test --yes` must **work**.
   - `ez session check test` must show `copy 0: DAMAGED` (1 unit).
   - `ez session repair test --yes`, then `check` again: both copies `ok`.
   - **Report** the outputs.
4. **Power loss during replication.**
   - `ez key generate 2M`; it takes about 2 hours. Then `ez session create big --key-id <ID>`, and pull the USB cable while it runs: the 2 MiB copy takes a few seconds.
   - Reconnect: `ez session check big` (copy 1 may be missing), then `ez session repair big --yes`, then `check` again.
   - **Report** the outputs.

## TR-08 — the automatic card mirror (IMPL-AV-008/009)

**Status (2026-10-12):** passed on V1. Step 1 used a 32 KiB key (a 256 KiB generation is still to be watched). In step 3 the device recreated the overwritten copy before `DEGRADED` could be seen: `ez device info` showed `syncing`, then `ok`.

1. **During long work:** `ez` and the console stay responsive during a format, a key generation and a session repair. `ez device info` shows the job and its progress.
2. **Self-repair:** delete one copy's key file on a PC (the card's second partition is copy B), then reinsert the card. The device returns to `mirror ok` by itself within a minute, and the file is back.
3. **A damaged copy:** make copy B unreadable by overwriting its first sectors on a PC (`dd if=/dev/zero of=/dev/sdX2 bs=512 count=64`). The device recreates it and restores its keys by itself; `ez device info` shows `syncing`, then `ok`. While it is degraded (in the moment before, or if the repair fails), `ez key generate` is refused without `--force`; `ez drive repair 1` repairs it by hand.

## TR-09 — the terminal interface (EZ-UI-001)

**Status (2026-10-12):** steps 1 to 4 and 6 passed on V1 with minicom and lrzsz, as did step 8's stack reading (core 0 7.2 KB, core 1 3 KB, of 16 KB each). Still to do: step 5's export and import (a second card or device), step 7 (Receive on a second device), and step 9 (other images, Windows).

1. Flash `einszeit_composite.uf2` (or `einszeit_dev.uf2`). Connect with `screen /dev/ttyACM0` (or PuTTY: serial, 115200; the speed is ignored).
2. **Home:** the logo, the live panel, the status line. Check that the line under the menu bar is a solid line, not `qqqq`. The status line should update by itself: insert or remove the card, and run `ez key generate 32K` from another terminal.
3. **Navigation:** arrows, Enter, Esc, and the letters H S R K D C ?. Then Keys (list and details), Device and Help.
4. **CLI:** `help`, `keys`, `ls card`, `ls a`, `ls b`, `ls internal`, `status`, `key <label> check`, `mirror check`, and `erase` answered with "no".
5. **Keys (round 18):**
   - **N:** a 128 KiB key on the card. It is generated in internal storage and copied to the card.
   - **P:** turn its spare copy on, then off. The Where column shows `card+spare`, then `card`.
   - **X:** export it to a second, FAT-formatted card. Follow the swap prompts; the status line should show the card going and coming within about a second.
   - **I:** on a second device (or after a device erase), import the transfer card's key as bob.
   - **D:** delete a key, typing its label.
6. **ZMODEM and XMODEM (rounds 21-22):** try the terminal(s) you expect to use.
   - **Send:** Ctrl-O, then a ZMODEM upload (minicom: Ctrl-A S, zmodem; Tera Term: File > Transfer > ZMODEM > Send).
   - **Download:** in the view, D. Many terminals start their ZMODEM download by themselves.
   - **Receive:** start a ZMODEM upload of the message file without pressing anything: it should be recognised.
   - **XMODEM:** the same with XMODEM. It starts about 6 s after the device asks, since the device listens for ZMODEM first.
7. **Between two devices:** upload the downloaded message file to Receive on the device that shares the key (Ctrl-R, or a terminal-started ZMODEM upload). The plaintext appears, verified.
8. **Send and Receive (round 19):**
   - On device A, open Send, type a few lines, press Ctrl-E, then y. Press C and copy the base64 from the terminal.
   - On device B (sharing the key), open Receive and paste: the plaintext appears, marked verified.
   - Paste the same message again: "already received".
   - Change one character and paste: "Changed or damaged in transit".
   - With the development image, run `info` after using the editor and report the two stack lines.
9. **Images:** `einszeit_cdc` (terminal only: `ez` cannot connect) and `einszeit_hid` (`ez` only). Check that Windows needs no driver for each (OI-05).
