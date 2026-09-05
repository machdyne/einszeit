/*
 * ez_guard.c -- see include/ez_guard.h
 *
 * EZ-SEC-001 traceability: SEC-FW-004, SEC-STORE-001, SEC-PTR-002,
 * SEC-META-003, SEC-HW-002.
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"

#include "board.h"
#include "ez_fram.h"
#include "ez_guard.h"
#include "ez_sd.h"

/* How much of FRAM to inspect. Session records live at the start of the
 * device in every layout we can foresee, and scanning 4 KB costs under a
 * millisecond at 8 MHz. */
#define GUARD_SCAN_BYTES 4096

static ez_guard_status_t s_status = {
    .state = EZ_GUARD_OCCUPIED,     /* fail closed until proven otherwise */
    .storage_allowed = false,
};

const ez_guard_status_t *ez_guard_status(void) { return &s_status; }

const char *ez_guard_state_name(ez_guard_state_t s)
{
    switch (s) {
    case EZ_GUARD_BLANK:       return "blank";
    case EZ_GUARD_TEST_MARKED: return "test board";
    case EZ_GUARD_OCCUPIED:    return "occupied";
    default:                   return "no device";
    }
}

void ez_guard_evaluate(ez_guard_status_t *out)
{
    uint8_t buf[256];
    ez_guard_status_t st;
    memset(&st, 0, sizeof(st));

    /*
     * Presence must not be decided by RDID. The Fujitsu MB85RS64 family has no
     * Device ID command, so ez_fram_read_id() always fails on it and the guard
     * classified perfectly good hardware as "no device" and refused every
     * storage operation permanently -- including immediately after a
     * successful `guard claim --force`, which is how this was found.
     *
     * ez_fram_probe() uses the WREN/WRDI write-enable-latch toggle, which
     * every SPI FRAM supports and which proves the bus works both ways.
     */
    ez_fram_probe_t probe;
    if (!ez_fram_probe(&probe)) {
        st.state = EZ_GUARD_NO_DEVICE;
        st.storage_allowed = false;
        s_status = st;
        if (out) *out = st;
        return;
    }

    ez_fram_read(0, buf, EZ_TEST_MARKER_LEN);
    bool marked = (memcmp(buf, EZ_TEST_MARKER, EZ_TEST_MARKER_LEN) == 0);

    bool all_zero = true, all_ff = true;
    bool found_unexpected = false;

    for (uint32_t addr = 0; addr < GUARD_SCAN_BYTES; addr += sizeof(buf)) {
        ez_fram_read(addr, buf, sizeof(buf));
        st.bytes_scanned += sizeof(buf);

        for (uint32_t i = 0; i < sizeof(buf); i++) {
            /* Skip our own marker when judging blankness. */
            if (marked && addr == 0 && i < EZ_TEST_MARKER_LEN) continue;

            if (buf[i] != 0x00) all_zero = false;
            if (buf[i] != 0xff) all_ff = false;

            if (!found_unexpected && buf[i] != 0x00 && buf[i] != 0xff) {
                found_unexpected = true;
                st.first_unexpected_addr = addr + i;
                uint32_t n = sizeof(buf) - i;
                if (n > sizeof(st.first_unexpected)) n = sizeof(st.first_unexpected);
                memcpy(st.first_unexpected, &buf[i], n);
            }
        }
    }

    if (marked && !found_unexpected) {
        st.state = EZ_GUARD_TEST_MARKED;
        st.storage_allowed = true;
    } else if (!marked && (all_zero || all_ff)) {
        st.state = EZ_GUARD_BLANK;
        st.storage_allowed = true;
    } else {
        /*
         * Content we do not recognise. It may be session records holding OTP
         * offsets, in which case overwriting them destroys the only record of
         * how much of each Key has been consumed and invites key reuse
         * (SEC-PTR-002). Refuse rather than guess.
         */
        st.state = EZ_GUARD_OCCUPIED;
        st.storage_allowed = false;
    }

    s_status = st;
    if (out) *out = st;
}

bool ez_guard_permit_storage(const char *what)
{
    if (s_status.storage_allowed) return true;

    if (s_status.state == EZ_GUARD_NO_DEVICE) {
        printf("refused: %s -- the FRAM did not respond, so the device cannot\n"
               "be classified. Check the SPI bus with 'pins' first.\n", what);
        return false;
    }

    printf("refused: %s\n\n", what);
    printf("This board's FRAM holds data that is neither blank nor this\n"
           "tool's own test marker. On a provisioned Einszeit device the FRAM\n"
           "is metadata storage: it holds the OTP offsets that record how much\n"
           "of each Key has been consumed.\n\n");
    printf("Overwriting or rolling back an offset causes silent key reuse,\n"
           "which destroys secrecy irrecoverably and leaves no evidence\n"
           "(EZ-SEC-001 SEC-PTR-002). Reading it out over USB would expose\n"
           "offsets in diagnostic output (SEC-UI-005).\n\n");
    printf("First unrecognised byte at 0x%06x.\n", (unsigned)s_status.first_unexpected_addr);
    printf("If this really is a bare board, erase the FRAM with production\n"
           "firmware or a programmer, then re-run. This tool will not do it\n"
           "for you.\n");
    return false;
}

bool ez_guard_claim(void)
{
    if (s_status.state != EZ_GUARD_BLANK) return false;
    ez_fram_write(0, (const uint8_t *)EZ_TEST_MARKER, EZ_TEST_MARKER_LEN);
    ez_guard_evaluate(NULL);
    return s_status.state == EZ_GUARD_TEST_MARKED;
}

bool ez_guard_sd_present(const char *what)
{
    if (ez_sd_card_detected()) return true;
    printf("refused: %s -- no card detected on SD_DET (GPIO%u).\n",
           what, SD_DET_PIN);
    printf("EZ-SEC-001 SEC-HW-002 treats removal of key media during an\n"
           "operation as loss of key material; this tool aborts rather than\n"
           "continuing against a socket that may have been emptied.\n");
    printf("If a card is definitely inserted, the detect polarity may be\n"
           "wrong: run 'sd det --watch' and set SD_DET_ACTIVE_LOW in board.h.\n");
    return false;
}
