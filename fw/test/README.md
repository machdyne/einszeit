# fw/test — Einszeit V1 hardware validation

Bring-up firmware and analysis tooling for the Einszeit V1 board (RP2350A).
Validates the HRNG, FRAM, microSD, clocks and board wiring, transfers entropy
captures over USB CDC with XMODEM-1K, and produces a report covering entropy
quality and the standards the RP2350 TRNG is claimed to meet.

> **This is a bench instrument, not a production artifact.** It deliberately
> bypasses the TRNG hardware health tests and exposes storage test paths. Never
> flash it to a device holding key material, and never include it in a build
> that generates key material. See `docs/EZ-TEST-DEVIATIONS.md`.

## Compliance status against EZ-SEC-001

This artifact is **not fully compliant, by design**. Three requirements are
deliberately inverted because inverting them is the tool's function: you cannot
characterise a noise source whose health tests halt it, and you cannot assess
raw entropy that has already been debiased.

- `docs/EZ-TEST-TRACEABILITY.md` — every requirement ID, its disposition, and
  the evidence for each satisfied row, per EZ-SEC-001 §11. Includes the
  SEC-FW-001 code review record.
- `docs/EZ-TEST-DEVIATIONS.md` — five deviations (D-01 … D-05) and six gaps
  (G-01 … G-06), each with a containment measure or an action.

Three gaps block a compliant *product*, not this tool: **G-04** (SP 800-22 at
10⁸ bits), **G-05** (online monitoring and per-key acceptance testing) and
**G-06** (the §10.2–10.6 harnesses, which need the session layer to exist).

The main control added by the audit is `src/ez_guard.c`: the firmware refuses
every storage read, write and erase path unless the FRAM is demonstrably blank
or carries this tool's own marker. On V1 the FRAM is metadata storage, holding
the OTP offsets. A bench tool that can roll an offset backwards causes silent
key reuse — the one failure EZ-SEC-001 §0 calls irrecoverable.

```
ez> fram test
refused: fram test

This board's FRAM holds data that is neither blank nor this tool's own test
marker. On a provisioned Einszeit device the FRAM is metadata storage: it holds
the OTP offsets that record how much of each Key has been consumed.
...
```

On a genuinely bare board, `guard claim` writes the marker and storage tests
become available.

## Layout

```
CMakeLists.txt      standalone or add_subdirectory(test) from fw/
include/  src/      firmware
host/               Python analysis and report tooling
docs/               EZ-SEC-001 audit records
```

## Build

```bash
mkdir build && cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

Or from `fw/CMakeLists.txt`, after the parent has called `pico_sdk_init()`:

```cmake
add_subdirectory(test)
```

Builds clean under `-Wall -Wextra`, which is part of the SEC-FW-001 evidence.
`-DEZ_ENABLE_RAW_STORAGE_DUMP=ON` re-enables the raw dump paths and knowingly
violates SEC-FW-004 and SEC-UI-005; CMake warns when you do it.

### Firmware update mode

Three ways in, no button needed for the first two:

```bash
python3 ez_validate.py bootsel --port /dev/ttyACM0   # from the host
```
```
ez> reboot bootsel                                    # from the device shell
```
```bash
picotool reboot -f -u                                 # works even if the shell hangs
```

`picotool` works without any cooperation from the firmware because the build
sets `PICO_STDIO_USB_ENABLE_RESET_VIA_VENDOR_INTERFACE=1`, which exposes a
reset endpoint alongside the CDC interface.

The board then enumerates as RPI-RP2 mass storage; copy
`build/einszeit_hwtest.uf2` to it, or `picotool load -x build/einszeit_hwtest.uf2`.
The status LED on GPIO12 keeps blinking in the bootloader as an activity
indicator, so you can tell the board is alive rather than hung.

Holding the BOOTSEL button while plugging in still works as the fallback.

Note that the card-detect policy and the storage guard release are held in RAM
only, so both revert on reboot. Re-apply them after an update, or make them
permanent in `board.h`.

## Run

```bash
cd host && pip install -r requirements.txt
./ez_validate.py selftest                  # check the tooling first
./ez_validate.py ports
./ez_validate.py all --port /dev/ttyACM0 --out runs/board-01
```

Produces `runs/board-01/report.html` (self-contained), `report.json`, and the
raw `.bin` captures so the analysis can be re-run or handed to NIST's tools.
A first pass takes about 15 minutes, most of it waiting on the TRNG.
`--sweep` and `--restart` add hours.

## Commands

```
help                            command list with capture examples
info [--json]                   chip, board id, clocks, die temperature
pins [--json]                   external pull-up verification (no SD card fitted)
guard [claim] [--json]          storage access policy; claim marks a blank board
led on|off|blink

clock [--json]                  clock tree, configured against measured
clock aon [ms] [--json]         always-on timer source and drift

fram id [--json]                JEDEC ID, vendor/part decode, status register
fram size [--json]              density by address aliasing        [guarded]
fram test [bytes] [--full]      patterns and address uniqueness     [guarded]
fram bench [bytes]              throughput at seven SPI clocks      [guarded]
fram dump <addr> <len>          disabled by default (SEC-FW-004, SEC-UI-005)
fram write <addr> <hex>                                             [guarded]

sd det [--watch]                card-detect level and transitions
sd init | sd info [--json]      SPI bring-up, CID/CSD decode        [needs card]
sd read <lba>                   read and CRC-verify; contents withheld
sd bench [blocks]               throughput and CRC errors           [needs card]
sd write <lba> --yes            destructive block write             [guarded]

hrng info [--json]              every TRNG register, decoded
hrng cfg [rosc N] [sample N] [raw|cond]
hrng health [n] [--json]        throughput and health-test error counters
hrng cap <bytes> [raw|cond] [rosc N] [sample N]
hrng sweep [collections] [raw]  chain length x sample interval, CSV
hrng restart <rows> <bytes>     SP 800-90B restart matrix

buf [zero]                      buffer status; 'buf zero' wipes and verifies
dump [n]                        hex dump of the capture buffer
send                            transmit the buffer over XMODEM-1K
selftest [--json]               every subsystem in one pass
reboot [bootsel]
```

Every command ends with `[done rc=N]` so a host script can frame the output.
`--json` emits one `#JSON {...}` line. Long operations emit `# progress` lines
and abort on ESC. `[guarded]` commands require `ez_guard_permit_storage()`.

## Capture modes

`cond` leaves the Von Neumann balancer, continuous RNG test and autocorrelation
test enabled — the configuration production firmware would use.

`raw` sets all three bypass bits in `TRNG_DEBUG_CONTROL`, giving raw digitised
ring-oscillator samples. This is what SP 800-90B assesses, and is deviation
D-02 against SEC-ENTROPY-003.

Captures are framed in a 1024-byte header carrying the exact payload length, a
CRC-32, and JSON metadata including `"key_material": false`. The length matters
because XMODEM pads its last block with 0x1A and pad bytes must never reach an
entropy estimator.

## Reading the entropy number

The report leads with min-entropy per captured bit and what follows from it:
how many raw bits you need per bit of one-time-pad key. At 0.35 bit/bit, a byte
of key needs about 23 bits of raw capture through a min-entropy-preserving
conditioner.

Two things to expect:

- **The raw capture will look bad.** Bias and short-lag correlation are normal
  for a directly sampled ring oscillator. That is why the hardware has a Von
  Neumann balancer in front of it.
- **The compression estimator often reads lowest.** Its expected-value curve is
  nearly flat near maximum entropy, so the 99% confidence subtraction costs a
  lot at small sample sizes. It converges slowly. The report flags this when it
  is the limiting estimator.

`SAMPLE_CNT1` resets to 65535, giving roughly 2.3 kbit/s at 150 MHz — well below
the ~7.5 kbit/s in the project README. Production firmware will need a shorter
interval, and shorter sampling costs sample independence. `--sweep` measures
that trade across all four inverter chain lengths.

## If `fram id` reports nothing

Two causes, both handled since 1.1.1:

**RDID is not universal.** The original Fujitsu MB85RS64 family, including the
MB85RS64PNF on Blaustahl, has no Device ID command, so opcode 0x9F clocks out
all zeroes from a perfectly healthy part. `fram id` now probes by toggling the
write-enable latch (WREN/WRDI, read back through RDSR), which every SPI FRAM
supports, and reports `PRESENT` even when the ID is unavailable. Use
`fram size` to measure density directly.

**Running `pins` first used to break the bus.** The pin test switches each GPIO
to SIO to read it, and before 1.1.1 it did not restore the SPI function
afterwards, so every later FRAM transfer returned 0x00. Fixed; function,
direction and level are now saved and restored per pin.

## FRAM identification: RDID is not universal

`fram id` does **not** use the JEDEC Device ID command to decide whether the
part is present, because not every SPI FRAM has one. The original Fujitsu
MB85RS64 family (including the MB85RS64PNF used on Blaustahl) predates RDID
entirely: sending 0x9F clocks out nothing and the host reads all zeroes, which
looks identical to a dead bus.

Presence is established instead by toggling the write-enable latch: `WREN` must
set WEL in the status register and `WRDI` must clear it. Every SPI FRAM ever
made supports RDSR and WREN/WRDI, the test is non-destructive, and it proves
the bus works in both directions. RDID is still read and reported when the part
answers, but its absence is reported as a property of the part, not a fault.

On a part without RDID, density cannot be read from the ID either. Use
`fram size`, which measures it directly by address aliasing. An MB85RS64 should
report 8192 bytes with 2-byte addressing.

`fram bench` sweeps to 32 MHz. The MB85RS64 family is rated to 20 MHz and the
V/B/T generations to 25-33 MHz, so verification failures at the top of the
sweep are the datasheet limit, not a board fault.

## When commands return rc=3

rc=3 is a policy refusal, not a hardware failure. Two policies can produce it.

**The storage guard** refuses FRAM and SD writes unless the FRAM is blank or
carries this tool's test marker. A board that this tool wrote patterns to in an
earlier session scans as occupied and locks itself out. Release it:

```bash
python3 ez_validate.py guard --port /dev/ttyACM2 --release
# or during a run:
python3 ez_validate.py collect --port ... --out runs/rN --allow-storage
# or on the device:
ez> guard claim --force --no-key-material
```

**Card detect** refuses SD commands when no card is seen. Not every microSD
socket has a detect switch, and polarity varies. `sd det` now classifies the
net by reading it with the internal pull-up and then the pull-down:

```
SD_DET (GPIO25)   : 1 with internal pull-up, 0 with pull-down
net               : floating: nothing is driving it
policy            : active-low
card present      : no
```

Floating with a card inserted means no usable detect line on this board:

```bash
python3 ez_validate.py guard --port /dev/ttyACM2 --sd-detect ignore
# or during a run: collect --sd-detect ignore
# or on the device: sd det ignore
```

Reading 0 with both pulls means something holds the pin at ground: with a card
in, that is an active-low switch (`sd det low`); with no card in, a normally
closed one (`sd det high`). Once you know, set `SD_DET_ACTIVE_LOW` in
`board.h` to make it the default.

EZ-SEC-001 SEC-HW-002 wants media removal to abort an operation in progress, so
`ignore` is a bench setting only. It must not be the default in firmware that
handles key material.

## Throughput and the SAMPLE_CNT1 decision

Conditioned throughput is fully determined by two things:

```
raw sample rate   = clk_sys / (SAMPLE_CNT1 + 1)
conditioned rate  = raw / 4      (Von Neumann emits ~1 bit per 4 raw bits)
```

At the SAMPLE_CNT1 **reset value of 65535** and clk_sys = 150 MHz that is
2.3 kbit/s raw and about 572 bit/s conditioned. The reset value is a power-on
default, not a recommendation, and it is far too slow for bulk key generation:

| SAMPLE_CNT1 | raw | conditioned | 1 MB takes |
| --- | --- | --- | --- |
| 65535 (reset) | 2.3 kbit/s | 572 bit/s | 4.1 hours |
| 16384 | 9.2 kbit/s | 2.3 kbit/s | 61 min |
| 4096 | 36.6 kbit/s | 9.2 kbit/s | 15 min |
| 1000 | 150 kbit/s | 37 kbit/s | 3.7 min |
| 256 | 584 kbit/s | 146 kbit/s | 1 min |

The ~7.5 kbit/s figure in the project README corresponds to SAMPLE_CNT1 near
5000.

**Shorter sampling is not free.** The entropy in each bit comes from ring
oscillator phase noise accumulated between sample points, so sampling faster
means less accumulated jitter per sample and more correlation between adjacent
samples. The right value is the smallest one at which the *conditioned* output
still measures 8 bits of entropy per byte, which is what EZ-SEC-001
SEC-ENTROPY-002 requires. `hrng sweep` plus the SP 800-90B analysis is how you
find it. Do not pick it by arithmetic.

**Do not copy the SDK's settings.** Raspberry Pi's own `pico_rand` sets
`SAMPLE_CNT1 = 0` and `TRNG_DEBUG_CONTROL = -1u`, streaming raw ROSC samples
with every decorrelator bypassed. Their comment says why that is acceptable
*for them*: "More temporal resolution to measure ROSC phase noise is better,
if we use a high quality hash function instead of naive VN decorrelation."
They mix the raw samples through a software hash. Einszeit cannot: SEC-ENTROPY-001
forbids CSPRNG contributions to key material and SEC-KDF-001 forbids
algorithmic transformation of it. Einszeit has to get full entropy out of the
hardware path alone, which means the Von Neumann corrector stays on and
SAMPLE_CNT1 has to be long enough to earn it.

One idea worth borrowing: `pico_rand` modulates `TRNG_CONFIG` (the inverter
chain length) with random bits "to reduce chance of injection locking". That is
a cheap defence against an attacker pulling the ring oscillator to a nearby
frequency, and it belongs in production generation firmware.

### Continuous vs cycled sampling

From v1.2.0 the driver leaves the noise source running between EHR reads
(`continuous`, the default). Reading the last EHR word restarts collection
automatically, so stopping and restarting the source only adds latency —
about 9% at SAMPLE_CNT1 = 65535, and proportionally far more at short
intervals. `hrng cfg cycled` restores the old behaviour, which starts every
192-bit block from the same source state and is the more conservative choice
when comparing blocks across a sweep.

## Two things still guessed

**`SD_DET` polarity** is assumed active-low in `board.h`. Confirm with
`sd det --watch` and correct `SD_DET_ACTIVE_LOW`. Gap G-02 depends on this.

**The clock.** RP2350 has no RTC, only the POWMAN always-on timer, so
`clock aon` handles all three tick sources and reports which is live. When the
tick derives from the same crystal as the system timer, the measured error
characterises the divider, not the crystal. If V1 carries a discrete RTC or a
32.768 kHz crystal, name the part and it can get a driver.
