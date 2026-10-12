/*
 * ez_status.h -- Einszeit core status codes
 *
 * These values are part of the device protocol (EZ-IMPL-001 §4): they are
 * returned in the status byte of HID response frames and printed by the
 * CLI. Never renumber an existing code.
 *
 * EZ-SEC-001 traceability: none directly; shared vocabulary for all modules.
 */
#ifndef EZ_STATUS_H
#define EZ_STATUS_H

typedef enum {
	EZ_OK                = 0,
	EZ_ERR_BUSY          = 1,   /* another operation is in progress (IMPL-ARCH-004) */
	EZ_ERR_BAD_REQUEST   = 2,   /* malformed or out-of-range parameters */
	EZ_ERR_NO_SESSION    = 3,   /* slot empty or label/Key ID not found */
	EZ_ERR_QUARANTINED   = 4,   /* session quarantined (SEC-UI-004) */
	EZ_ERR_CAPACITY      = 5,   /* not enough key left in the range */
	EZ_ERR_RANGE         = 6,   /* offset outside TX/RX range (SEC-ISO-001) */
	EZ_ERR_REPLAY        = 7,   /* below RX offset (SEC-DEC-003) */
	EZ_ERR_KEY_ID        = 8,   /* header Key ID mismatch (SEC-DEC-002) */
	EZ_ERR_MEDIA_REMOVED = 9,   /* SEC-HW-002 */
	EZ_ERR_MEDIA         = 10,  /* storage I/O error */
	EZ_ERR_META          = 11,  /* metadata write or verify failed (SEC-PTR-003) */
	EZ_ERR_INTEGRITY     = 12,  /* message CRC mismatch */
	EZ_ERR_ENTROPY       = 13,  /* TRNG fault or acceptance test failure */
	EZ_ERR_DRIVE_DISABLED= 14,  /* IMPL-DRV-001 */
	EZ_ERR_EXISTS        = 15,  /* duplicate Key ID or label (SEC-ISO-002) */
	EZ_ERR_NOT_FOUND     = 16,
	EZ_ERR_ABORTED       = 17,
	EZ_ERR_DEVICE        = 18,  /* device record uninitialised or faulty */
	EZ_ERR_UNSUPPORTED   = 19,
	EZ_ERR_ROLLBACK      = 20,  /* offset not strictly increasing (SEC-PTR-002) */
	EZ_ERR_FULL          = 21,  /* no free session slot */
	EZ_ERR_UNRESOLVED    = 22,  /* a slot with unreadable identity blocks creation (IMPL-META-007) */
	EZ_ERR_STATE         = 23,  /* operation not valid in the session's state */
	EZ_ERR_KEY_PARAM     = 24,  /* Key ID 0 or bad key length (SEC-STORE-002/003) */
	EZ_PENDING           = 25,  /* not an error: a stepwise job has more work to do */
	EZ_ERR_KEY_DAMAGED   = 26,  /* key data failed verification (SEC-STORE-004, IMPL-ENG-012) */
	EZ_ERR_UNVERIFIED    = 27,  /* key has no integrity file: import it first (IMPL-KEY-004) */
	EZ_ERR_PROTECTION    = 28,  /* drive 0's flash protection is not in place (IMPL-DRV-003) */
} ez_status_t;

const char *ez_status_name(ez_status_t s);

#endif /* EZ_STATUS_H */
