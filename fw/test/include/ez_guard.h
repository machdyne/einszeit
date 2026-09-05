/*
 * ez_guard.h -- refuses storage operations on a provisioned device
 *
 * EZ-SEC-001 traceability:
 *   SEC-FW-004   no command may give raw read access to key data storage
 *   SEC-STORE-001 firmware is solely responsible for erase policy
 *   SEC-PTR-002  the OTP offset must only ever advance
 *   SEC-META-003 a corrupt session record must be quarantined, not reset
 *   SEC-UI-005   OTP offsets must not appear in diagnostic output
 *   SEC-HW-002   removal of key media must abort the operation in progress
 *
 * The problem this solves
 * -----------------------
 * On Einszeit V1 the microSD is key data storage and the FRAM is metadata
 * storage, which is where OTP offsets live. A bench tool that can hexdump the
 * SD card is a raw key read path, and one that can write arbitrary bytes to
 * FRAM can roll an OTP offset backwards. Either would be catastrophic on a
 * device holding real key material: a rolled-back offset causes silent key
 * reuse, which destroys secrecy irrecoverably and leaves no trace.
 *
 * The tool needs those capabilities to do its job on a bare board. So rather
 * than removing them, this module makes them conditional on the device being
 * demonstrably unprovisioned, and makes the raw-dump paths a build option that
 * is off by default.
 *
 * Detection is deliberately conservative: anything that is not recognisably
 * blank or recognisably a previously tested board is assumed to hold live key
 * metadata, and storage access is refused.
 */
#ifndef EZ_GUARD_H
#define EZ_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/* Written to FRAM offset 0 the first time a destructive test runs, so the
 * board can be re-tested without tripping the guard on its own leftovers. */
#define EZ_TEST_MARKER      "EZ-TESTBOARD-001"
#define EZ_TEST_MARKER_LEN  16

typedef enum {
    EZ_GUARD_BLANK,        /* FRAM is uniformly 0x00 or 0xFF: virgin part    */
    EZ_GUARD_TEST_MARKED,  /* our own marker: this board has been tested     */
    EZ_GUARD_OCCUPIED,     /* unrecognised content: assume live session data */
    EZ_GUARD_NO_DEVICE,    /* FRAM did not respond at all                    */
} ez_guard_state_t;

typedef struct {
    ez_guard_state_t state;
    bool     storage_allowed;   /* destructive and raw storage ops permitted */
    uint32_t bytes_scanned;
    uint8_t  first_unexpected[16];
    uint32_t first_unexpected_addr;
} ez_guard_status_t;

/* Scans FRAM and classifies the device. Call once at boot and after any
 * command that may have changed FRAM contents. */
void ez_guard_evaluate(ez_guard_status_t *out);

const ez_guard_status_t *ez_guard_status(void);

/*
 * Gate for every command that reads, writes or erases either storage tier.
 * Returns true if the operation may proceed; otherwise prints the reason and
 * returns false. `what` names the operation for the refusal message.
 *
 * SEC-FW-004: this is the single choke point. New storage commands must call
 * it, and the traceability matrix records that they do.
 */
bool ez_guard_permit_storage(const char *what);

/* Claims the board for testing by writing EZ_TEST_MARKER to FRAM offset 0.
 * Only permitted from EZ_GUARD_BLANK. */
bool ez_guard_claim(void);

/* SEC-HW-002: refuses SD operations when no card is present, and is called
 * again after long operations so removal mid-test is caught. */
bool ez_guard_sd_present(const char *what);

const char *ez_guard_state_name(ez_guard_state_t s);

#endif /* EZ_GUARD_H */
