/*
 * ez_core.h -- the core API object and its management operations
 * (EZ-IMPL-001 §1.1, §2, §4)
 *
 * ez_core_t ties metadata storage, key storage and the TRNG together. It is
 * the only component that touches key data (IMPL-ARCH-003, SEC-FW-004).
 * Encryption and decryption are in ez_engine.h, key generation in
 * ez_keygen.h; both operate on an ez_core_t.
 *
 * Callers (the dispatcher, Phase 2) are responsible for user confirmation
 * (SEC-UI-003) and for serialising calls (IMPL-ARCH-004).
 *
 * EZ-SEC-001 traceability:
 *   SEC-STORE-001  key deletion and drive erasure under core control
 *   SEC-PTR-004    session deletion erases the key first
 *   SEC-STORE-002  key files named by non-zero Key ID (IMPL-KEY-001)
 *   SEC-META-003   key file checks at boot and media insertion
 *   SEC-ISO-002    via ez_meta_session_create()
 *   SEC-HW-002     drive presence checked before use
 *   SEC-FW-004     no function returns key bytes
 *   IMPL-DRV-001/002, IMPL-KEY-001/004, IMPL-GEN-001
 */
#ifndef EZ_CORE_H
#define EZ_CORE_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_hal_keystore.h"
#include "ez_hal_meta.h"
#include "ez_hal_trng.h"
#include "ez_meta.h"
#include "ez_msg.h"
#include "ez_status.h"
#include "ez_sum.h"

#define EZ_KEY_BLOCK            512u
#define EZ_BUFFERED_MAX         65536u                    /* IMPL §6.1 */
#define EZ_STAGE_SIZE           (EZ_BUFFERED_MAX + EZ_MSG_OVERHEAD)
#define EZ_CHECK_INTERVAL       8u       /* key units (32 KiB) between card checks (IMPL-ENG-010) */
#define EZ_KEYGEN_MIN_LEN       8192u
#define EZ_KEYGEN_MAX_LEN       (64u * 1024u * 1024u)    /* see ez_entropy.h */

typedef enum {
	EZ_STAGE_EMPTY = 0,
	EZ_STAGE_PLAIN_IN,      /* plaintext being staged for buffered encryption */
	EZ_STAGE_MSG_IN,        /* message being staged for buffered decryption */
	EZ_STAGE_CIPHERTEXT,    /* retained output of a committed encryption */
	EZ_STAGE_PLAINTEXT,     /* decrypted output awaiting release */
} ez_stage_state_t;

typedef struct ez_core {
	ez_meta_t meta;
	const ez_hal_keystore_t *ks;
	const ez_hal_trng_t *trng;

	/* Staging buffer for buffered mode, supplied by the port (static). */
	uint8_t *stage;
	uint32_t stage_cap;
	ez_stage_state_t stage_state;
	uint32_t stage_len;          /* bytes staged or retained */
	uint32_t out_off, out_len;   /* retained output region */

	bool     stream_active;

	/* Key-byte scratch for generation and copying. Zero whenever no core
	 * call is running (SEC-FW-003); tests check this. */
	uint8_t  kbuf[EZ_KEY_BLOCK];

	/* The verified unit (IMPL-ENG-013): key bytes are used only from here,
	 * after their tag has been checked. Held only while an operation is
	 * using that unit (across the calls of one stream); zero otherwise. */
	uint8_t  ubuf[EZ_UNIT_SIZE];
	bool     u_valid;
	uint8_t  u_drive;
	uint32_t u_key_id, u_index, u_start, u_len;
	uint32_t u_loads;

	bool     resuming;           /* inside ez_core_resume() */

	/* IMPL-DRV-003: set by ports whose drive 0 shares a medium with the
	 * firmware. Returns true only if the medium's protection is verified
	 * (on RP2350: the partition table denies bootloader and Non-secure
	 * access to the key partition). NULL: no such concern (virtual device). */
	bool   (*drive0_guard)(void *ctx);
	void    *drive0_guard_ctx;

	/* IMPL-AV-007: set by ports that can (re)format a card drive with a
	 * given number of copies. Kept across ez_core_init(). NULL: no format. */
	ez_status_t (*format)(void *ctx, uint8_t drive, uint8_t copies);
	void    *format_ctx;
	/* IMPL-AV-004: recreate the file system of copy volumes that cannot be
	 * mounted, leaving healthy ones untouched. Kept across ez_core_init(). */
	ez_status_t (*repair_volumes)(void *ctx, uint8_t drive, uint8_t *recreated);

	/* SEC-AVAIL-003: units served from another copy, and the result of the
	 * last replication (EZ_OK, or why a copy could not be written). */
	uint32_t    failovers;
	ez_status_t last_replicate;

	/* Round 16: progress of the current long operation (per mille), a
	 * flag that asks it to stop at its next checkpoint (EZ_ERR_BUSY), and
	 * the health found by the last sync. */
	volatile uint16_t progress;
	volatile bool    *yield;
	uint8_t     health;                      /* EZ_HEALTH_* */
	uint8_t     health_detail;               /* EZ_HD_* bits */
	ez_status_t last_critical;               /* IMPL-AV-005: the drive 0 copy */

	/* Last verification failure, for reporting (never an offset in logs). */
	struct { bool valid; uint32_t key_id; uint32_t unit; } damage;
} ez_core_t;

/* Boot: verify metadata (SEC-META-003), then key files on every usable
 * drive. stage must hold EZ_STAGE_SIZE bytes. */
ez_status_t ez_core_init(ez_core_t *c, const ez_hal_meta_t *meta,
                         const ez_hal_keystore_t *ks, const ez_hal_trng_t *trng,
                         uint8_t *stage, uint32_t stage_cap);

/* Call when a medium is inserted (or at boot): removes stale .TMP files
 * (IMPL-GEN-001) and checks every session on that drive for a missing or
 * wrongly sized key file (quarantine, persisted). */
ez_status_t ez_core_media_event(ez_core_t *c, uint8_t drive);

/* IMPL-INT-001: complete an interrupted destructive operation recorded in
 * the intent record (session delete, key delete, device erase, drive 0
 * disable). Called by ez_core_init() and ez_core_media_event(); a no-op if
 * nothing is pending or its drive is absent. */
ez_status_t ez_core_resume(ez_core_t *c);
/* True if an intent is pending (another destructive operation is refused
 * with EZ_ERR_BUSY until it completes or is overridden). */
bool ez_core_intent_pending(ez_core_t *c);

/* IMPL-MODE-002: development firmware marks the device. The mark stays
 * until device erase, so production firmware booting later can warn that
 * keys present may have been exposed while development firmware ran. */
void ez_core_mark_development(ez_core_t *c);
bool ez_core_dev_tainted(ez_core_t *c);

/* IMPL-AV-007: format a card drive with `copies` volumes (1 or 2; bit 7 also
 * erases the whole card first, which can keep a card busy for minutes). Refused
 * while any session uses the drive (EZ_ERR_STATE) or a record's drive is
 * unknown (EZ_ERR_UNRESOLVED). Destroys every key file on the drive. */
ez_status_t ez_drive_format(ez_core_t *c, uint8_t drive, uint8_t copies);

/* IMPL-AV-004: recreate unmountable copy volumes of a card drive. Their
 * keys are then restored by ez_session_repair() from the other copies. */
ez_status_t ez_drive_repair(ez_core_t *c, uint8_t drive, uint8_t *recreated);

/* -1: no guard (not applicable), 0: protection missing, 1: verified. */
int ez_core_drive0_protected(ez_core_t *c);

/* Drive usable for key access: index valid, enabled (drive 0), present. */
ez_status_t ez_core_drive_usable(const ez_core_t *c, uint8_t drive);

/* Load unit i of a key into c->ubuf and verify it against the key's .SUM
 * (SEC-STORE-004). On EZ_ERR_KEY_DAMAGED, c->damage names the unit. A unit
 * already loaded for the same key and drive is reused. */
ez_status_t ez_unit_load(ez_core_t *c, uint8_t drive, uint32_t key_id,
                         uint32_t key_len, uint32_t i);
void        ez_unit_drop(ez_core_t *c);
/* Read and check the .SUM header of a key: EZ_ERR_UNVERIFIED if there is
 * none, EZ_ERR_KEY_DAMAGED if it is malformed or for another key. */
ez_status_t ez_sum_check(ez_core_t *c, uint8_t drive, uint32_t key_id,
                         uint32_t key_len, uint16_t *instance);

/* ---- copies (SEC-AVAIL-003/004, EZ-IMPL-001 §2.8) ---------------------------
 * On a drive kept as several copies (ez_hal_keystore_t.copies), every key
 * in use is in every copy. Copies are written one at a time from units
 * that verify, read back, and renamed into place only when complete. */
ez_status_t ez_replicate(ez_core_t *c, uint8_t drive, uint32_t key_id);

typedef struct {
	uint8_t  copies;
	uint32_t units;                        /* units in the key */
	uint32_t lost;                         /* units that verify in no copy */
	struct { bool present, has_key; uint32_t bad; } copy[EZ_COPIES_MAX];
	uint8_t  critical;                     /* IMPL-AV-005 */
	uint8_t  d0_state;                     /* 0 not checked (drive 0 unusable), 1 missing, 2 ok, 3 damaged */
	uint32_t d0_bad;
} ez_check_t;
/* Read every unit of every copy (a read-only health check). */
ez_status_t ez_session_check(ez_core_t *c, int slot, ez_check_t *r);
/* Rewrite damaged or missing copies, one at a time, from units that
 * verify. EZ_ERR_KEY_DAMAGED if some unit verifies in no copy. */
ez_status_t ez_session_repair(ez_core_t *c, int slot, uint8_t *repaired);

/* ---- health and background sync (round 16) -------------------------------- */
enum { EZ_HEALTH_UNKNOWN = 0, EZ_HEALTH_OK = 1, EZ_HEALTH_SYNCING = 2, EZ_HEALTH_DEGRADED = 3 };
enum {
	EZ_HD_UNREPAIRED  = 0x01,   /* a copy is damaged or missing and could not be rewritten */
	EZ_HD_NO_CRITICAL = 0x02,   /* a critical key has no usable drive 0 copy */
	EZ_HD_LOST        = 0x04,   /* some key units verify in no copy */
	EZ_HD_VOLUME      = 0x08,   /* a copy volume is unavailable */
};
/* Bring every mirrored drive to a nominal state: recreate unavailable
 * volumes, rewrite damaged or missing copies (and critical keys' drive 0
 * copies), lift "key missing" quarantines whose key verifies again. Sets
 * c->health. Stops with EZ_ERR_BUSY at a checkpoint when *c->yield. */
ez_status_t ez_sync(ez_core_t *c);
/* Quick: volumes present and every key's files present with the right size
 * and instance; a session failing that gets the full treatment. */
ez_status_t ez_sync_quick(ez_core_t *c);

/* "<KEYID>.KEY" / ".TMP" / ".SUM" / ".SUT" (IMPL-KEY-001). */
void ez_key_name(uint32_t key_id, const char *ext, char out[EZ_FNAME_MAX]);

/* Sessions */
ez_status_t ez_session_create(ez_core_t *c, uint32_t key_id, uint8_t drive,
                              uint8_t role, const char *label, int *slot);
/* IMPL-AV-005: with EZ_SESS_CRITICAL the key is also copied to drive 0
 * (when drive 0 is usable; the result is in c->last_critical). */
/* Turn a session's critical copy on (writes drive 0's copy, then the flag)
 * or off (the flag, then erases the copy). Not for a key on drive 0. */
ez_status_t ez_session_set_critical(ez_core_t *c, int slot, bool on);
ez_status_t ez_session_create_flags(ez_core_t *c, uint32_t key_id, uint8_t drive,
                                    uint8_t role, const char *label, uint8_t flags, int *slot);
/* SEC-PTR-004: erase the session's key file, then remove the record. The
 * caller has shown the warning and obtained confirmation. Without
 * `force`, deletion is refused if the key file cannot be erased (medium
 * absent, drive disabled, record identity unverified). With `force`, the
 * record is removed without erasing the key and an EZ_EV_SESSION_FORCE
 * event is logged; the caller must have shown the override warning. */
ez_status_t ez_session_delete(ez_core_t *c, int slot, bool force);
ez_status_t ez_session_resolve(ez_core_t *c, int slot);

/* Keys */
ez_status_t ez_key_delete(ez_core_t *c, uint8_t drive, uint32_t key_id);
ez_status_t ez_key_copy(ez_core_t *c, uint32_t key_id, uint8_t from, uint8_t to);

/* Drives */
ez_status_t ez_drive_enable0(ez_core_t *c);
ez_status_t ez_drive_disable0(ez_core_t *c);
ez_status_t ez_drive_list(ez_core_t *c, uint8_t drive, uint32_t index,
                          char name[EZ_NAME_MAX], uint32_t *size);

/* Device */
ez_status_t ez_device_erase(ez_core_t *c);

#endif /* EZ_CORE_H */
