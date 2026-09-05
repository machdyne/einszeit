# Einszeit V1 entropy source characterisation data

## What this is

Raw and conditioned output from the RP2350 TRNG on an Einszeit V1 board,
captured for entropy source characterisation, together with the analysis
reports generated from it.

## What this is NOT

**This is not key material and must never be used as any.** Every capture is
tagged `"key_material": false` in its metadata. It was produced by bench
firmware that deliberately bypasses the TRNG hardware health tests, and it has
crossed a USB link to a host computer. EZ-SEC-001 SEC-ENTROPY-001 requires key
bytes to come exclusively from the TRNG on the device itself, and SEC-DIST-001
prohibits electronic transmission of key material.

The board these captures came from is a characterisation board. It has never
held key material and never will.

## Why it is published

The min-entropy figures in the reports were produced by an independent
reimplementation of the SP 800-90B estimators, not a validated one. Publishing
the underlying data is what makes those numbers checkable: anyone can run
NIST's own EntropyAssessment and sts-2.1.2 against these files and compare.

A claim about an entropy source that cannot be independently verified is not
worth much, particularly for a one-time-pad device whose entire security
argument rests on it.

## Files

`*.bin`      raw capture bytes, exactly as the device produced them
`*.json`     capture metadata: mode, SAMPLE_CNT1, inverter chain, health-test
             error counts, die temperature, board ID, throughput
`report.*`   generated analysis, HTML and machine-readable JSON
`SHA256SUMS` checksums tying the reports to the data they describe

`raw.bin` is the noise source with the Von Neumann balancer, the continuous RNG
test and the autocorrelation test all bypassed. It is expected to be biased;
that is what makes it the right input for an SP 800-90B assessment.
`conditioned.bin` is what production firmware would actually emit.

## Reproducing the analysis

```
git clone <this repo> && cd fw/test/host
pip install -r requirements.txt
python3 ez_validate.py analyze <this directory>/conditioned.bin --sequences 3
```

Or with NIST's validated tools:

```
ea_non_iid -i -a -v raw.bin 1        # SP 800-90B
assess 1000000 < conditioned.bin      # SP 800-22, sts-2.1.2
```

If your numbers disagree with the published reports, that is a finding worth
raising as an issue.

## Provenance

Captured from device UUID(s): `9bae095b4556f8f4`

This is the RP2350 OTP CHIPID, a 64-bit per-die identifier that the datasheet
describes as a public device ID. It is recorded so these captures can be tied to
the specific silicon that produced them.
