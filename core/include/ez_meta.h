/*
 * ez_meta.h -- metadata storage: device record, session records, offset
 * commits, quarantine and event log (EZ-IMPL-001 §3)
 *
 * EZ-SEC-001 traceability:
 *   SEC-META-001  session record fields and integrity coverage (§3.4)
 *   SEC-META-002  atomic offset updates (IMPL-META-003)
 *   SEC-META-003  every record verified at power-on; corrupt records
 *                 quarantined without re-validation (IMPL-META-006)
 *   SEC-META-004  ez_meta_check_alloc()
 *   SEC-PTR-001   checked offset slots; corruption detected, never
 *                 defaulted (IMPL-META-002)
 *   SEC-PTR-002   commits strictly forward; rollback rejected and logged
 *   SEC-PTR-003   commit verified by read-back before success is returned
 *   SEC-STORE-002 Key ID non-zero; SEC-STORE-003 key length even
 *   SEC-ISO-001   commits bounded to the TX or RX range
 *   SEC-ISO-002   duplicate Key ID rejected; IMPL-META-007
 *   SEC-GEN-003   generation events recorded in the event log
 *   SEC-UI-004    quarantine state exposed for the UI
 *   SEC-UI-005    event log never contains offsets (IMPL-LOG-001)
 *   SEC-DEC-004   separate RX offset, never touched by TX commits
 */
#ifndef EZ_META_H
#define EZ_META_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_hal_meta.h"
#include "ez_status.h"

/* ---- Layout (EZ-IMPL-001 §3.1) --------------------------------------- */
#define EZ_META_SIZE            2048u
#define EZ_META_DEV_ADDR        0u
#define EZ_META_DEV_SIZE        32u
#define EZ_META_SESSIONS        24
#define EZ_META_SESSION_ADDR    32u
#define EZ_META_SESSION_SIZE    64u
#define EZ_META_LOG_ADDR        1568u
#define EZ_META_LOG_ENTRIES     16
#define EZ_META_LOG_ENTRY_SIZE  24u
#define EZ_META_RESERVED_ADDR   1952u
#define EZ_META_RESERVED_SIZE   96u

/* Reserved region use (EZ-IMPL-001 §3.1). */
#define EZ_META_STORE0_SEL      (EZ_META_RESERVED_ADDR + 0)    /* drive 0 table selector */
#define EZ_META_TAINT_ADDR      (EZ_META_RESERVED_ADDR + 1)    /* development firmware has run */
/* Critical toggles: 3 bytes, a bit per slot. The effective flag is the
 * session's creation-time flag XOR its bit; toggling is one byte write
 * (atomic in F-RAM), never a rewrite of the session's static record. */
#define EZ_META_CRIT_ADDR       (EZ_META_RESERVED_ADDR + 2)
#define EZ_META_TR05_ADDR       (EZ_META_RESERVED_ADDR + 56)   /* TR-05 tally (development images only) */
#define EZ_META_TR05_SIZE       40u
#define EZ_META_INTENT_ADDR     (EZ_META_RESERVED_ADDR + 32)   /* intent record */
#define EZ_META_INTENT_SIZE     24u

#define EZ_MAGIC                0x455Au
#define EZ_DEV_VERSION          0x02
#define EZ_SESSION_VERSION      0x01

/* Device record field offsets (§3.3) */
#define EZ_DEV_OFF_DRIVE0       3u
#define EZ_DEV_OFF_CRC          16u
#define EZ_DEV_OFF_BOOT_A       20u
#define EZ_DEV_OFF_BOOT_B       26u

/* Session record field offsets (§3.4) */
#define EZ_SR_OFF_STATUS        3u
#define EZ_SR_OFF_QREASON       4u
#define EZ_SR_OFF_TX_SEL        5u
#define EZ_SR_OFF_RX_SEL        6u
#define EZ_SR_OFF_ROLE          7u
#define EZ_SR_OFF_KEY_ID        8u
#define EZ_SR_OFF_KEY_LEN       12u
#define EZ_SR_OFF_DRIVE         16u
#define EZ_SR_OFF_FLAGS         17u
#define EZ_SR_OFF_INSTANCE      18u   /* key instance tag (IMPL-KEY-005), static CRC */
#define EZ_SR_OFF_LABEL         20u
#define EZ_SR_OFF_CRC           36u
#define EZ_SR_OFF_TX_A          40u
#define EZ_SR_OFF_TX_B          46u
#define EZ_SR_OFF_RX_A          52u
#define EZ_SR_OFF_RX_B          58u

#define EZ_SLOT_SIZE            6u
#define EZ_LABEL_MAX            15u   /* bytes, excluding NUL */

/* Coded state bytes (§3.2): Hamming distance >= 4 from each other and
 * from 0x00 / 0xFF. */
/* Stored quarantine-reason codes (persisted reasons only). Any other value
 * is read as EZ_Q_KEY_ERASING, the strictest (not resolvable). */
#define EZ_QC_KEY_MISSING       0x33
#define EZ_QC_KEY_SIZE          0x55
#define EZ_QC_KEY_ERASING       0xCC
#define EZ_QC_KEY_DAMAGED       0xAA
#define EZ_ST_EMPTY0            0x00
#define EZ_ST_EMPTY1            0xFF
#define EZ_ST_VALID             0x3C
#define EZ_ST_QUARANTINED       0xC3
#define EZ_ST_EXHAUSTED         0x96  /* reserved: exhaustion is derived from the TX offset */
#define EZ_ST_ZEROIZE           0x69  /* reserved for forward secrecy (§8) */
#define EZ_SEL_A                0x5A
#define EZ_SEL_B                0xA5
#define EZ_DRIVE0_DISABLED      0xC3
#define EZ_DRIVE0_ENABLED       0x3C

/* ---- Types ------------------------------------------------------------ */
typedef enum { EZ_ROLE_ALICE = 0, EZ_ROLE_BOB = 1, EZ_ROLE_DEFAULT = 0xFF } ez_role_t;

typedef enum {
	EZ_SS_EMPTY = 0,
	EZ_SS_VALID,
	EZ_SS_EXHAUSTED,     /* TX range fully consumed: decrypt only */
	EZ_SS_QUARANTINED,
} ez_sstate_t;

/* Quarantine reasons (§3.6). Codes below 0x80 are persisted and can be
 * resolved; codes 0x80 and above are held in RAM only. */
enum {
	EZ_Q_NONE           = 0x00,
	EZ_Q_KEY_MISSING    = 0x01,
	EZ_Q_KEY_SIZE       = 0x02,
	EZ_Q_KEY_ERASING    = 0x03,   /* key erasure started (SEC-PTR-004): delete only */
	EZ_Q_KEY_DAMAGED    = 0x04,   /* key data damaged (IMPL-ENG-012): delete only */
	EZ_Q_FORMAT         = 0x81,
	EZ_Q_STATIC_CRC     = 0x82,
	EZ_Q_STATUS_CODE    = 0x83,
	EZ_Q_SELECTOR       = 0x84,
	EZ_Q_SLOT_CHECK     = 0x85,
	EZ_Q_RANGE          = 0x86,
	EZ_Q_COMMIT_VERIFY  = 0x87,
};

typedef enum {
	EZ_DEV_UNINIT = 0,   /* F-RAM blank: only initialisation permitted */
	EZ_DEV_VALID,
	EZ_DEV_FAULT,        /* IMPL-META-001: repair or erase required */
} ez_devstate_t;

/* Event types (§3.7). */
enum {
	EZ_EV_KEY_OK        = 0x01,
	EZ_EV_KEY_REJECTED  = 0x02,
	EZ_EV_ROLLBACK      = 0x03,
	EZ_EV_QUARANTINE    = 0x04,
	EZ_EV_DEVICE_INIT   = 0x05,
	EZ_EV_DRIVE0_ON     = 0x06,
	EZ_EV_DRIVE0_OFF    = 0x07,
	EZ_EV_ENTROPY_FAULT = 0x08,
	EZ_EV_DEVICE_REPAIR = 0x09,
	EZ_EV_SESSION_DELETE = 0x0A,  /* key erased, record removed (SEC-PTR-004) */
	EZ_EV_SESSION_FORCE  = 0x0B,  /* record removed WITHOUT erasing the key (override) */
	EZ_EV_KEY_IMPORTED   = 0x0C,  /* detail: 1 = verified against its .SUM, 2 = checked and tagged */
	EZ_EV_SKIP           = 0x0D,  /* TX skipped damaged units; detail = units (capped at 255) */
};
#define EZ_EV_HOST_TIME     0x80

typedef struct {
	uint32_t seq;
	uint32_t boot;
	uint32_t time;       /* uptime seconds, or host Unix time if host_time */
	uint32_t key_id;
	uint32_t arg;        /* never an OTP offset (IMPL-LOG-001) */
	uint8_t  type;
	uint8_t  detail;
	bool     host_time;
} ez_event_t;

typedef struct {
	ez_sstate_t state;
	uint8_t  qreason;        /* EZ_Q_*; EZ_Q_NONE unless quarantined */
	bool     identity;       /* static part verified: fields below trustworthy */
	bool     offsets;        /* tx_off / rx_off verified */
	uint32_t key_id;
	uint32_t key_len;
	uint8_t  role;
	uint8_t  drive;
	uint8_t  flags;
	uint16_t instance;       /* key instance tag from the .SUM header */
	char     label[EZ_LABEL_MAX + 1];
	uint32_t tx_off;         /* effective TX offset */
	uint32_t rx_off;         /* effective RX offset */

	/* Internal mirror of storage, used by the commit protocol. */
	uint8_t  sel[2];         /* [0]=TX [1]=RX: slot named by the stored selector, 0=A 1=B */
	uint32_t slot_val[2][2]; /* [tx/rx][A/B] */
	bool     slot_ok[2][2];
} ez_session_t;

typedef struct {
	uint32_t key_id;
	uint32_t key_len;
	uint8_t  role;           /* EZ_ROLE_ALICE, EZ_ROLE_BOB or EZ_ROLE_DEFAULT (IMPL-LOG-002) */
	uint8_t  drive;
	const char *label;
	uint16_t instance;       /* from the key's .SUM header (0 in metadata-only tests) */
	uint8_t  flags;          /* EZ_SESS_* (static, chosen at creation) */
} ez_session_params_t;

#define EZ_SESS_CRITICAL  0x01u   /* IMPL-AV-005: also kept on drive 0 */

/* Optional time source for event timestamps. Returns seconds; sets
 * *host_time if the value is host-supplied Unix time. */
typedef uint32_t (*ez_time_fn)(void *ctx, bool *host_time);

typedef struct {
	const ez_hal_meta_t *hal;
	ez_time_fn time_fn;
	void      *time_ctx;

	ez_devstate_t dev;
	bool     drive0_enabled;
	bool     boot_count_fault;     /* neither boot counter slot valid */
	uint32_t boot_count;
	uint32_t boot_slot[2];
	bool     boot_ok[2];

	ez_session_t s[EZ_META_SESSIONS];
	uint32_t log_next_seq;
} ez_meta_t;

/* ---- Lifecycle -------------------------------------------------------- */

/* Power-on: read and verify everything (SEC-META-003), then increment the
 * boot counter if the device record is valid. Never writes to an
 * uninitialised or faulty device. */
ez_status_t ez_meta_boot(ez_meta_t *m, const ez_hal_meta_t *hal);

/* Initialise metadata (part of DEVICE_ERASE). Destroys all sessions. */
ez_status_t ez_meta_format(ez_meta_t *m);

/* Rewrite a faulty device record, keeping sessions and log (IMPL-META-001). */
ez_status_t ez_meta_repair(ez_meta_t *m);

/* ---- Sessions --------------------------------------------------------- */
ez_status_t ez_meta_session_create(ez_meta_t *m, const ez_session_params_t *p, int *slot_out);
ez_status_t ez_meta_session_delete(ez_meta_t *m, int slot);
/* Turn a session's critical flag on or off (EZ_META_CRIT_ADDR). */
ez_status_t ez_meta_set_critical(ez_meta_t *m, int slot, bool on);

/* Commit a new effective offset (IMPL-META-003). new_off must be strictly
 * greater than the current one and within the range. */
ez_status_t ez_meta_commit_tx(ez_meta_t *m, int slot, uint32_t new_off);
ez_status_t ez_meta_commit_rx(ez_meta_t *m, int slot, uint32_t new_off);

/* Persisted quarantine (reasons 0x01..0x04). */
ez_status_t ez_meta_quarantine(ez_meta_t *m, int slot, uint8_t reason);
/* Clear a persisted quarantine for a missing or wrongly sized key file.
 * The caller must have verified the cause is fixed. Erasing, damaged and
 * RAM-held quarantines cannot be resolved, only deleted. */
ez_status_t ez_meta_resolve(ez_meta_t *m, int slot);

/* SEC-META-004: verify slot's address range is inside the session region
 * and overlaps no other occupied slot. */
ez_status_t ez_meta_check_alloc(const ez_meta_t *m, int slot);

int  ez_meta_find_key_id(const ez_meta_t *m, uint32_t key_id);
int  ez_meta_find_label(const ez_meta_t *m, const char *label);
bool ez_meta_can_encrypt(const ez_meta_t *m, int slot);
bool ez_meta_can_decrypt(const ez_meta_t *m, int slot);

/* Ranges (EZ-SEC-001 Definitions). end is exclusive for key bytes; an
 * offset equal to end means the range is consumed. */
void ez_range_tx(uint32_t key_len, uint8_t role, uint32_t *start, uint32_t *end);
void ez_range_rx(uint32_t key_len, uint8_t role, uint32_t *start, uint32_t *end);
uint32_t ez_meta_tx_remaining(const ez_session_t *s);
uint32_t ez_meta_rx_remaining(const ez_session_t *s);
/* SEC-UI-001: true if remaining TX capacity is below pct% of the TX range. */
bool ez_meta_tx_low(const ez_session_t *s, unsigned pct);

/* ---- Device settings -------------------------------------------------- */
ez_status_t ez_meta_set_drive0(ez_meta_t *m, bool enabled);

/* ---- Reserved region (EZ-IMPL-001 §3.1) ------------------------------- */
/* Verified read/write inside the reserved region only. */
ez_status_t ez_meta_aux_read(ez_meta_t *m, uint32_t addr, void *buf, uint32_t len);
ez_status_t ez_meta_aux_write(ez_meta_t *m, uint32_t addr, const void *buf, uint32_t len);

/* ---- Event log -------------------------------------------------------- */
ez_status_t ez_meta_log_append(ez_meta_t *m, uint8_t type, uint8_t detail,
                               uint32_t key_id, uint32_t arg);
/* Newest first. Returns the number of valid entries written to out. */
int ez_meta_log_read(ez_meta_t *m, ez_event_t *out, int max);

#endif /* EZ_META_H */
