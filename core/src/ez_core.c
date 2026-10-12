/*
 * ez_core.c -- see ez_core.h for traceability.
 */
#include "ez_core.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"

void ez_key_name(uint32_t key_id, const char *ext, char out[EZ_FNAME_MAX])
{
	static const char hex[] = "0123456789ABCDEF";
	for (int i = 0; i < 8; i++)
		out[i] = hex[(key_id >> (28 - 4 * i)) & 0xF];
	out[8] = '.';
	out[9] = ext[0]; out[10] = ext[1]; out[11] = ext[2];
	out[12] = '\0';
}

static char up(char ch) { return (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch; }

/* Case-insensitive, as FAT name matching is: "abcd.key" is a key file too. */
static bool has_ext(const char *name, const char *ext)
{
	size_t n = strlen(name);
	return n >= 4 && name[n - 4] == '.' && up(name[n - 3]) == ext[0] &&
	       up(name[n - 2]) == ext[1] && up(name[n - 1]) == ext[2];
}

/* ---- intent record (IMPL-INT-001) ---------------------------------------
 * A destructive operation the user has confirmed is recorded in F-RAM
 * before it starts and cleared when it is complete, so an interruption
 * (power, card removal) is finished at the next boot or insertion instead
 * of leaving a quarantined session for the user to clean up. Layout:
 * [0] op (coded), [1] drive, [2] slot, [3] 0, [4..7] Key ID, [8..21] 0,
 * [22..23] CRC-16. A torn record fails its CRC and is ignored: the
 * operation it describes had not started. */
#define IN_NONE            0x00
#define IN_SESSION_DELETE  0x33
#define IN_KEY_DELETE      0x55
#define IN_DEVICE_ERASE    0xCC
#define IN_DRIVE0_DISABLE  0xAA

typedef struct { uint8_t op, drive, slot; uint32_t key_id; } intent_t;

static void intent_read(ez_core_t *c, intent_t *in)
{
	uint8_t b[EZ_META_INTENT_SIZE] = { 0 };
	memset(in, 0, sizeof *in);
	if (ez_meta_aux_read(&c->meta, EZ_META_INTENT_ADDR, b, sizeof b) != EZ_OK) return;
	uint8_t op = b[0];
	if ((op != IN_SESSION_DELETE && op != IN_KEY_DELETE && op != IN_DEVICE_ERASE &&
	     op != IN_DRIVE0_DISABLE) || ez_get_le16(b + 22) != ez_crc16(b, 22))
		return;
	in->op = op;
	in->drive = b[1];
	in->slot = b[2];
	in->key_id = ez_get_le32(b + 4);
}

bool ez_core_intent_pending(ez_core_t *c)
{
	intent_t in;
	intent_read(c, &in);
	return in.op != IN_NONE;
}

static ez_status_t intent_set(ez_core_t *c, uint8_t op, uint8_t drive, uint8_t slot, uint32_t key_id)
{
	intent_t in;
	intent_read(c, &in);
	if (in.op != IN_NONE) {
		/* The same operation again (a retry or the resume itself) is fine;
		 * anything else waits until the pending one completes. */
		if (in.op == op && in.drive == drive && in.slot == slot && in.key_id == key_id)
			return EZ_OK;
		return EZ_ERR_BUSY;
	}
	uint8_t b[EZ_META_INTENT_SIZE] = { 0 };
	b[0] = op; b[1] = drive; b[2] = slot;
	ez_put_le32(b + 4, key_id);
	ez_put_le16(b + 22, ez_crc16(b, 22));
	return ez_meta_aux_write(&c->meta, EZ_META_INTENT_ADDR, b, sizeof b);
}

static void intent_clear(ez_core_t *c)
{
	uint8_t z = IN_NONE;                         /* one atomic byte */
	ez_meta_aux_write(&c->meta, EZ_META_INTENT_ADDR, &z, 1);
}

/* SEC-PTR-004: before any byte of a key is erased, every session using it
 * is made unusable, so an interrupted erasure (block by block on a real
 * filesystem) can never leave a usable session over a partly zeroed key. */
static ez_status_t quarantine_users(ez_core_t *c, uint8_t drive, uint32_t key_id)
{
	for (int s = 0; s < EZ_META_SESSIONS; s++) {
		const ez_session_t *ss = &c->meta.s[s];
		if ((ss->state == EZ_SS_VALID || ss->state == EZ_SS_EXHAUSTED) &&
		    ss->identity && ss->key_id == key_id && ss->drive == drive) {
			ez_status_t st = ez_meta_quarantine(&c->meta, s, EZ_Q_KEY_ERASING);
			if (st != EZ_OK)
				return st;
		}
	}
	return EZ_OK;
}

/* For erasing only: like ez_core_drive_usable() but without the drive 0
 * protection guard. Erasing reveals nothing, and must stay possible when
 * the protection is missing (IMPL-DRV-003). */
static ez_status_t drive_erasable(const ez_core_t *c, uint8_t drive)
{
	if (drive >= EZ_DRIVES)
		return EZ_ERR_BAD_REQUEST;
	if (drive == 0 && !c->meta.drive0_enabled)
		return EZ_ERR_DRIVE_DISABLED;
	if (!c->ks->present(c->ks->ctx, drive))
		return EZ_ERR_MEDIA_REMOVED;
	return EZ_OK;
}

ez_status_t ez_core_drive_usable(const ez_core_t *c, uint8_t drive)
{
	if (drive >= EZ_DRIVES)
		return EZ_ERR_BAD_REQUEST;
	if (drive == 0 && !c->meta.drive0_enabled)
		return EZ_ERR_DRIVE_DISABLED;                   /* IMPL-DRV-001 */
	if (drive == 0 && c->drive0_guard && !c->drive0_guard(c->drive0_guard_ctx))
		return EZ_ERR_PROTECTION;                       /* IMPL-DRV-003 */
	if (!c->ks->present(c->ks->ctx, drive))
		return EZ_ERR_MEDIA_REMOVED;
	return EZ_OK;
}

/* ---- verified key units (SEC-STORE-004, IMPL-ENG-013) ------------------ */

void ez_unit_drop(ez_core_t *c)
{
	ez_secure_zero(c->ubuf, sizeof c->ubuf);
	c->u_valid = false;
}

static uint8_t ncopies(const ez_core_t *c, uint8_t drive)
{
	uint8_t n = c->ks->copies ? c->ks->copies(c->ks->ctx, drive) : 1;
	return n ? n : 1;
}

/* The .SUM header at one address (the logical drive or one copy). */
static ez_status_t sum_check_at(ez_core_t *c, uint8_t addr, uint32_t key_id,
                                uint32_t key_len, uint16_t *instance)
{
	char name[EZ_FNAME_MAX];
	uint8_t hb[EZ_SUM_HDR] = { 0 };
	uint32_t size;
	ez_sum_hdr_t h;
	ez_key_name(key_id, "SUM", name);
	ez_status_t st = c->ks->size(c->ks->ctx, addr, name, &size);
	if (st == EZ_ERR_NOT_FOUND)
		return EZ_ERR_UNVERIFIED;
	if (st != EZ_OK)
		return st;
	if (size != ez_sum_size(key_len))
		return EZ_ERR_KEY_DAMAGED;
	if ((st = c->ks->read(c->ks->ctx, addr, name, 0, hb, sizeof hb)) != EZ_OK)
		return st;
	if (ez_sum_hdr_decode(hb, &h) != EZ_OK || h.key_id != key_id || h.key_len != key_len)
		return EZ_ERR_KEY_DAMAGED;
	if (instance) *instance = h.instance;
	return EZ_OK;
}

/* SEC-AVAIL-003: a damaged header in one copy falls back to another. */
ez_status_t ez_sum_check(ez_core_t *c, uint8_t drive, uint32_t key_id,
                         uint32_t key_len, uint16_t *instance)
{
	ez_status_t st = sum_check_at(c, drive, key_id, key_len, instance);
	uint8_t n = ncopies(c, drive);
	for (uint8_t k = 0; st == EZ_ERR_KEY_DAMAGED && n > 1 && k < n; k++)
		st = sum_check_at(c, EZ_COPY(drive, k), key_id, key_len, instance);
	return st;
}

/* Read unit i at one address into ubuf and verify it against the tag in
 * that address's .SUM, or failing that in any copy's .SUM. A tag binds the
 * Key ID, length and position -- but not the instance (IMPL-KEY-005): a
 * different key under the same ID, with its own valid .SUM, would verify
 * against its own tags. So a .SUM may vouch for a unit only if its header
 * carries the expected instance. (Found by the mirrored chaos run.) */
static ez_status_t unit_at(ez_core_t *c, uint8_t addr, uint8_t drive, uint32_t key_id,
                           uint32_t key_len, uint32_t i, uint32_t start, uint32_t len,
                           uint16_t instance)
{
	char kname[EZ_FNAME_MAX], sname[EZ_FNAME_MAX];
	ez_key_name(key_id, "KEY", kname);
	ez_key_name(key_id, "SUM", sname);
	ez_secure_zero(c->ubuf, sizeof c->ubuf);
	ez_status_t st = c->ks->read(c->ks->ctx, addr, kname, start, c->ubuf, len);
	if (st != EZ_OK)
		return st;
	uint8_t want[EZ_TAG_LEN] = { 0 }, got[EZ_TAG_LEN];
	ez_unit_tag(key_id, key_len, i, c->ubuf, len, got);
	uint8_t n = ncopies(c, drive);
	bool ok = false;
	for (int j = -1; j < (n > 1 ? n : 0) && !ok; j++) {
		uint8_t sa = j < 0 ? addr : EZ_COPY(drive, j);
		if (j >= 0 && sa == addr) continue;
		uint16_t inst;
		if (sum_check_at(c, sa, key_id, key_len, &inst) != EZ_OK || inst != instance) continue;
		ez_secure_zero(want, sizeof want);
		if (c->ks->read(c->ks->ctx, sa, sname, EZ_SUM_HDR + EZ_TAG_LEN * i, want, EZ_TAG_LEN) == EZ_OK)
			ok = memcmp(want, got, EZ_TAG_LEN) == 0;
	}
	ez_secure_zero(want, sizeof want);
	ez_secure_zero(got, sizeof got);
	if (!ok) {
		ez_secure_zero(c->ubuf, sizeof c->ubuf);  /* never used (SEC-STORE-004) */
		return EZ_ERR_KEY_DAMAGED;
	}
	return EZ_OK;
}

ez_status_t ez_unit_load(ez_core_t *c, uint8_t drive, uint32_t key_id,
                         uint32_t key_len, uint32_t i)
{
	if (c->u_valid && c->u_drive == drive && c->u_key_id == key_id && c->u_index == i)
		return EZ_OK;
	ez_unit_drop(c);
	if (i >= ez_unit_count(key_len))
		return EZ_ERR_RANGE;
	uint32_t start, len;
	ez_unit_geom(key_len, i, &start, &len);
	ez_status_t st;
	if (c->u_loads++ % EZ_CHECK_INTERVAL == 0 &&
	    (st = c->ks->check(c->ks->ctx, drive)) != EZ_OK)
		return st;
	/* The instance a .SUM must carry to vouch for a unit: the session's,
	 * if a session uses this key here; otherwise the primary copy's. */
	uint16_t instance = 0;
	int slot = ez_meta_find_key_id(&c->meta, key_id);
	if (slot >= 0 && c->meta.s[slot].identity && c->meta.s[slot].drive == drive)
		instance = c->meta.s[slot].instance;
	else if ((st = ez_sum_check(c, drive, key_id, key_len, &instance)) != EZ_OK)
		return st == EZ_ERR_UNVERIFIED ? EZ_ERR_KEY_DAMAGED : st;
	st = unit_at(c, drive, drive, key_id, key_len, i, start, len, instance);
	/* IMPL-AV-003: failover, unit by unit, to the other copies. */
	uint8_t n = ncopies(c, drive);
	for (uint8_t k = 0; st != EZ_OK && st != EZ_ERR_MEDIA_REMOVED && n > 1 && k < n; k++) {
		st = unit_at(c, EZ_COPY(drive, k), drive, key_id, key_len, i, start, len, instance);
		if (st == EZ_OK) c->failovers++;
	}
	/* IMPL-AV-005: a critical key's last copy is on drive 0 -- used only
	 * when drive 0 is usable (enabled and, where it matters, protected). */
	if (st != EZ_OK && drive != 0 && slot >= 0 && (c->meta.s[slot].flags & EZ_SESS_CRITICAL) &&
	    ez_core_drive_usable(c, 0) == EZ_OK) {
		st = unit_at(c, 0, 0, key_id, key_len, i, start, len, instance);
		if (st == EZ_OK) c->failovers++;
	}
	if (st != EZ_OK) {
		ez_unit_drop(c);
		if (st == EZ_ERR_MEDIA_REMOVED || c->ks->check(c->ks->ctx, drive) != EZ_OK)
			return EZ_ERR_MEDIA_REMOVED;
		/* No copy verifies: never use these bytes (SEC-STORE-004). */
		c->damage.valid = true;
		c->damage.key_id = key_id;
		c->damage.unit = i;
		return EZ_ERR_KEY_DAMAGED;
	}
	c->u_valid = true;
	c->u_drive = drive;
	c->u_key_id = key_id;
	c->u_index = i;
	c->u_start = start;
	c->u_len = len;
	return EZ_OK;
}

/* ---- copies: replication, check, repair (SEC-AVAIL-003/004) ------------------ */

/* Write a complete copy of a key into copy k, from units that verify (in
 * any copy), with a .SUM rebuilt from those units -- so a damaged tag in
 * one copy never spreads. Written under temporary names, read back unit by
 * unit, renamed only when complete. */
static ez_status_t write_copy_to(ez_core_t *c, uint8_t drive, uint32_t key_id, uint32_t len,
                                 uint16_t instance, uint8_t a)
{
	char key[EZ_FNAME_MAX], sum[EZ_FNAME_MAX], tmp[EZ_FNAME_MAX], sut[EZ_FNAME_MAX];
	ez_key_name(key_id, "KEY", key);
	ez_key_name(key_id, "SUM", sum);
	ez_key_name(key_id, "TMP", tmp);
	ez_key_name(key_id, "SUT", sut);
	if (!c->ks->present(c->ks->ctx, a))
		return EZ_ERR_MEDIA_REMOVED;
	c->ks->zap(c->ks->ctx, a, tmp);
	c->ks->zap(c->ks->ctx, a, sut);
	uint8_t hb[EZ_SUM_HDR], tag[EZ_TAG_LEN];
	ez_sum_hdr_t h = { key_id, len, ez_unit_count(len), instance };
	ez_sum_hdr_encode(&h, hb);
	ez_status_t st = c->ks->create(c->ks->ctx, a, tmp);
	if (st == EZ_OK) st = c->ks->create(c->ks->ctx, a, sut);
	if (st == EZ_OK) st = c->ks->append(c->ks->ctx, a, sut, hb, sizeof hb);
	for (uint32_t i = 0; st == EZ_OK && i < ez_unit_count(len); i++) {
		c->progress = (uint16_t)((uint64_t)i * 1000u / ez_unit_count(len));
		if ((st = ez_unit_load(c, drive, key_id, len, i)) != EZ_OK) break;
		ez_unit_tag(key_id, len, i, c->ubuf, c->u_len, tag);
		st = c->ks->append(c->ks->ctx, a, tmp, c->ubuf, c->u_len);
		if (st == EZ_OK) st = c->ks->append(c->ks->ctx, a, sut, tag, sizeof tag);
		for (uint32_t o = 0; st == EZ_OK && o < c->u_len; o += EZ_KEY_BLOCK) {
			uint32_t m = c->u_len - o < EZ_KEY_BLOCK ? c->u_len - o : EZ_KEY_BLOCK;
			st = c->ks->read(c->ks->ctx, a, tmp, c->u_start + o, c->kbuf, m);
			if (st == EZ_OK && memcmp(c->kbuf, c->ubuf + o, m) != 0) st = EZ_ERR_MEDIA;
			ez_secure_zero(c->kbuf, sizeof c->kbuf);
		}
		ez_secure_zero(tag, sizeof tag);
		ez_unit_drop(c);
	}
	if (st == EZ_OK) {
		c->ks->zap(c->ks->ctx, a, key);              /* a damaged old copy, if any */
		c->ks->zap(c->ks->ctx, a, sum);
		st = c->ks->rename(c->ks->ctx, a, sut, sum);
		if (st == EZ_OK) st = c->ks->rename(c->ks->ctx, a, tmp, key);
	}
	if (st != EZ_OK) {
		c->ks->zap(c->ks->ctx, a, tmp);
		c->ks->zap(c->ks->ctx, a, sut);
	}
	ez_unit_drop(c);
	return st;
}

static ez_status_t write_copy(ez_core_t *c, uint8_t drive, uint32_t key_id, uint32_t len,
                              uint16_t instance, uint8_t k)
{
	return write_copy_to(c, drive, key_id, len, instance, EZ_COPY(drive, k));
}

/* Health of one copy: units that fail to verify there (or all of them,
 * if the copy or its files are missing). */
static uint32_t bad_units_at(ez_core_t *c, uint8_t a, uint8_t drive, uint32_t key_id,
                             uint32_t len, uint16_t instance, bool *present, bool *has_key);
static uint32_t copy_bad_units(ez_core_t *c, uint8_t drive, uint8_t k, uint32_t key_id,
                               uint32_t len, uint16_t instance, bool *present, bool *has_key)
{
	return bad_units_at(c, EZ_COPY(drive, k), drive, key_id, len, instance, present, has_key);
}

static uint32_t bad_units_at(ez_core_t *c, uint8_t a, uint8_t drive, uint32_t key_id,
                             uint32_t len, uint16_t instance, bool *present, bool *has_key)
{
	uint32_t n = ez_unit_count(len), bad = 0, size = 0;
	char key[EZ_FNAME_MAX];
	uint16_t inst = 0;
	ez_key_name(key_id, "KEY", key);
	*present = c->ks->present(c->ks->ctx, a);
	*has_key = *present && c->ks->size(c->ks->ctx, a, key, &size) == EZ_OK && size == len &&
	           sum_check_at(c, a, key_id, len, &inst) == EZ_OK && inst == instance;
	if (!*has_key) return n;
	for (uint32_t i = 0; i < n; i++) {
		uint32_t st, l;
		ez_unit_geom(len, i, &st, &l);
		if (unit_at(c, a, drive, key_id, len, i, st, l, instance) != EZ_OK) bad++;
		ez_secure_zero(c->ubuf, sizeof c->ubuf);
	}
	return bad;
}

ez_status_t ez_replicate(ez_core_t *c, uint8_t drive, uint32_t key_id)
{
	uint8_t n = ncopies(c, drive);
	if (n < 2) return EZ_OK;
	char key[EZ_FNAME_MAX];
	uint32_t len;
	uint16_t instance;
	ez_key_name(key_id, "KEY", key);
	ez_status_t st = c->ks->size(c->ks->ctx, drive, key, &len);
	if (st == EZ_OK) st = ez_sum_check(c, drive, key_id, len, &instance);
	if (st != EZ_OK) return st;
	ez_status_t first = EZ_OK;
	for (uint8_t k = 0; k < n; k++) {               /* one copy at a time (SEC-AVAIL-004) */
		bool present, has;
		if (copy_bad_units(c, drive, k, key_id, len, instance, &present, &has) == 0 && has) continue;
		st = write_copy(c, drive, key_id, len, instance, k);
		if (st != EZ_OK && first == EZ_OK) first = st;
	}
	return first;
}

ez_status_t ez_session_check(ez_core_t *c, int slot, ez_check_t *r)
{
	memset(r, 0, sizeof *r);
	if (slot < 0 || slot >= EZ_META_SESSIONS) return EZ_ERR_BAD_REQUEST;
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state == EZ_SS_EMPTY) return EZ_ERR_NO_SESSION;
	if (!s->identity) return EZ_ERR_UNRESOLVED;
	ez_status_t st = ez_core_drive_usable(c, s->drive);
	if (st != EZ_OK) return st;
	r->copies = ncopies(c, s->drive);
	r->units = ez_unit_count(s->key_len);
	for (uint8_t k = 0; k < r->copies; k++) {
		bool p, h;
		r->copy[k].bad = r->copies > 1
		    ? copy_bad_units(c, s->drive, k, s->key_id, s->key_len, s->instance, &p, &h) : 0;
		if (r->copies == 1) {
			p = true;
			uint32_t size;
			char key[EZ_FNAME_MAX];
			ez_key_name(s->key_id, "KEY", key);
			h = c->ks->size(c->ks->ctx, s->drive, key, &size) == EZ_OK && size == s->key_len;
		}
		r->copy[k].present = p;
		r->copy[k].has_key = h;
	}
	for (uint32_t i = 0; i < r->units; i++) {
		if (c->yield && *c->yield) { ez_unit_drop(c); return EZ_ERR_BUSY; }
		if (ez_unit_load(c, s->drive, s->key_id, s->key_len, i) != EZ_OK) r->lost++;
		ez_unit_drop(c);
		c->progress = (uint16_t)((uint64_t)(i + 1) * 1000u / r->units);
	}
	if (r->copies == 1) r->copy[0].bad = r->lost;
	if (s->flags & EZ_SESS_CRITICAL) {
		r->critical = 1;
		if (s->drive != 0 && ez_core_drive_usable(c, 0) == EZ_OK) {
			bool p, h;
			r->d0_bad = bad_units_at(c, 0, 0, s->key_id, s->key_len, s->instance, &p, &h);
			r->d0_state = !h ? 1 : r->d0_bad ? 3 : 2;
		}
	}
	c->damage.valid = false;
	return EZ_OK;
}

ez_status_t ez_session_repair(ez_core_t *c, int slot, uint8_t *repaired)
{
	*repaired = 0;
	ez_check_t r;
	ez_status_t st = ez_session_check(c, slot, &r);
	if (st != EZ_OK) return st;
	const ez_session_t *s = &c->meta.s[slot];
	if (r.lost) return EZ_ERR_KEY_DAMAGED;     /* some units verify in no copy */
	ez_status_t first = EZ_OK;
	for (uint8_t k = 0; k < r.copies; k++) {        /* one copy at a time (SEC-AVAIL-004) */
		if (r.copy[k].has_key && r.copy[k].bad == 0) continue;
		/* A copy whose volume is not available cannot be written: skip it
		 * (the check reports it; `ez drive repair` recreates the volume). */
		if (r.copies > 1 && !r.copy[k].present) continue;
		st = r.copies > 1 ? write_copy(c, s->drive, s->key_id, s->key_len, s->instance, k)
		                  : write_copy_to(c, s->drive, s->key_id, s->key_len, s->instance, s->drive);
		if (st == EZ_OK) (*repaired)++;
		else if (first == EZ_OK) first = st;
	}
	if (r.d0_state == 1 || r.d0_state == 3) {      /* the critical copy on drive 0 */
		st = write_copy_to(c, s->drive, s->key_id, s->key_len, s->instance, 0);
		if (st == EZ_OK) (*repaired)++;
		else if (first == EZ_OK) first = st;
	}
	return first;
}


static ez_status_t check_key_file(ez_core_t *c, int slot)
{
	const ez_session_t *s = &c->meta.s[slot];
	char name[EZ_FNAME_MAX];
	uint32_t size = 0;
	ez_key_name(s->key_id, "KEY", name);
	ez_status_t st = c->ks->size(c->ks->ctx, s->drive, name, &size);
	if (st == EZ_ERR_NOT_FOUND) {
		ez_meta_quarantine(&c->meta, slot, EZ_Q_KEY_MISSING);
		return EZ_ERR_QUARANTINED;
	}
	if (st != EZ_OK)
		return st;
	if (size != s->key_len) {
		ez_meta_quarantine(&c->meta, slot, EZ_Q_KEY_SIZE);
		return EZ_ERR_QUARANTINED;
	}
	/* A key in use must have its integrity file (SEC-STORE-004). */
	if (ez_sum_check(c, s->drive, s->key_id, s->key_len, NULL) == EZ_ERR_UNVERIFIED) {
		ez_meta_quarantine(&c->meta, slot, EZ_Q_KEY_MISSING);
		return EZ_ERR_QUARANTINED;
	}
	return EZ_OK;
}

ez_status_t ez_core_media_event(ez_core_t *c, uint8_t drive)
{
	ez_status_t st = ez_core_drive_usable(c, drive);
	if (st != EZ_OK)
		return st;
	/* IMPL-GEN-001: stale temporary files from an interrupted generation
	 * or copy are destroyed, never offered as keys. */
	char name[EZ_NAME_MAX];
	uint32_t size, i = 0;
	uint8_t ncp = ncopies(c, drive);
	for (uint8_t k = 0; k < ncp; k++) {            /* every copy (SEC-AVAIL-003) */
	uint8_t a = ncp > 1 ? EZ_COPY(drive, k) : drive;
	if (!c->ks->present(c->ks->ctx, a)) continue;
	i = 0;
	while (c->ks->list(c->ks->ctx, a, i, name, &size) == EZ_OK) {
		bool stale = has_ext(name, "TMP") || has_ext(name, "SUT");
		/* An integrity file without its key (an interrupted copy or erase)
		 * is key-derived data with no purpose: remove it too. */
		if (!stale && has_ext(name, "SUM")) {
			char key[EZ_NAME_MAX];
			uint32_t ks;
			size_t n = strlen(name);
			memcpy(key, name, n + 1);
			key[n - 3] = 'K'; key[n - 2] = 'E'; key[n - 1] = 'Y';
			stale = c->ks->size(c->ks->ctx, a, key, &ks) == EZ_ERR_NOT_FOUND;
		}
		if (stale && c->ks->zap(c->ks->ctx, a, name) == EZ_OK)
			continue;              /* listing shifted; same index again */
		i++;
	}
	}
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_OK;
	ez_core_resume(c);                           /* an operation waiting for this drive */
	for (int s = 0; s < EZ_META_SESSIONS; s++) {
		const ez_session_t *ss = &c->meta.s[s];
		if ((ss->state == EZ_SS_VALID || ss->state == EZ_SS_EXHAUSTED) &&
		    ss->drive == drive)
			check_key_file(c, s);
	}
	return EZ_OK;
}

#define TAINT_MARK 0xD5

void ez_core_mark_development(ez_core_t *c)
{
	uint8_t v = 0;
	if (ez_meta_aux_read(&c->meta, EZ_META_TAINT_ADDR, &v, 1) == EZ_OK && v == TAINT_MARK) return;
	v = TAINT_MARK;
	ez_meta_aux_write(&c->meta, EZ_META_TAINT_ADDR, &v, 1);
}

bool ez_core_dev_tainted(ez_core_t *c)
{
	uint8_t v = 0;
	return ez_meta_aux_read(&c->meta, EZ_META_TAINT_ADDR, &v, 1) == EZ_OK && v == TAINT_MARK;
}

ez_status_t ez_core_resume(ez_core_t *c)
{
	if (c->resuming || c->meta.dev == EZ_DEV_UNINIT)
		return EZ_OK;
	intent_t in;
	intent_read(c, &in);
	if (in.op == IN_NONE)
		return EZ_OK;
	c->resuming = true;
	ez_status_t st = EZ_OK;
	switch (in.op) {
	case IN_SESSION_DELETE:
		if (in.slot >= EZ_META_SESSIONS || c->meta.s[in.slot].state == EZ_SS_EMPTY) {
			intent_clear(c);                     /* already done */
		} else if (c->meta.s[in.slot].identity && c->meta.s[in.slot].key_id == in.key_id) {
			if (drive_erasable(c, in.drive) == EZ_OK)
				st = ez_session_delete(c, in.slot, false);
		} else {
			intent_clear(c);                     /* not ours: cannot be */
		}
		break;
	case IN_KEY_DELETE:
		if (drive_erasable(c, in.drive) == EZ_OK) {
			st = ez_key_delete(c, in.drive, in.key_id);
			if (st == EZ_ERR_NOT_FOUND) { intent_clear(c); st = EZ_OK; }
		}
		break;
	case IN_DEVICE_ERASE:
		st = ez_device_erase(c);
		break;
	case IN_DRIVE0_DISABLE:
		st = ez_drive_disable0(c);
		break;
	}
	c->resuming = false;
	return st;
}

ez_status_t ez_core_init(ez_core_t *c, const ez_hal_meta_t *meta,
                         const ez_hal_keystore_t *ks, const ez_hal_trng_t *trng,
                         uint8_t *stage, uint32_t stage_cap)
{
	/* Set by the port before init, kept across it: the clock and the
	 * drive 0 guard (IMPL-DRV-003). */
	ez_time_fn tf = c->meta.time_fn;
	void *tc = c->meta.time_ctx;
	bool (*guard)(void *) = c->drive0_guard;
	void *gctx = c->drive0_guard_ctx;
	ez_status_t (*fmt)(void *, uint8_t, uint8_t) = c->format;
	void *fctx = c->format_ctx;
	ez_status_t (*rv)(void *, uint8_t, uint8_t *) = c->repair_volumes;
	volatile bool *yl = c->yield;
	memset(c, 0, sizeof *c);
	c->meta.time_fn = tf;
	c->meta.time_ctx = tc;
	c->drive0_guard = guard;
	c->drive0_guard_ctx = gctx;
	c->format = fmt;
	c->format_ctx = fctx;
	c->repair_volumes = rv;
	c->yield = yl;
	c->ks = ks;
	c->trng = trng;
	c->stage = stage;
	c->stage_cap = stage_cap;
	if (!stage || stage_cap < EZ_STAGE_SIZE)
		return EZ_ERR_BAD_REQUEST;
	ez_secure_zero(stage, stage_cap);
	ez_status_t st = ez_meta_boot(&c->meta, meta);
	if (st != EZ_OK)
		return st;
	for (uint8_t d = 0; d < EZ_DRIVES; d++)
		ez_core_media_event(c, d);
	ez_core_resume(c);                           /* e.g. a device erase, needing no drive */
	return EZ_OK;
}

/* ---- sessions -------------------------------------------------------- */

ez_status_t ez_session_create(ez_core_t *c, uint32_t key_id, uint8_t drive,
                              uint8_t role, const char *label, int *slot)
{
	return ez_session_create_flags(c, key_id, drive, role, label, 0, slot);
}

ez_status_t ez_session_create_flags(ez_core_t *c, uint32_t key_id, uint8_t drive,
                              uint8_t role, const char *label, uint8_t flags, int *slot)
{
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (key_id == 0)
		return EZ_ERR_KEY_PARAM;                         /* SEC-STORE-002 */
	ez_status_t st = ez_core_drive_usable(c, drive);
	if (st != EZ_OK)
		return st;
	char name[EZ_FNAME_MAX];
	uint32_t size = 0;
	ez_key_name(key_id, "KEY", name);
	st = c->ks->size(c->ks->ctx, drive, name, &size);
	if (st != EZ_OK)
		return st;
	if (size == 0 || (size & 1u))
		return EZ_ERR_KEY_PARAM;                         /* SEC-STORE-003 */
	/* SEC-STORE-004: only keys with an integrity file. A key without one
	 * must go through the import job (ez_import.h), which checks it. */
	uint16_t instance = 0;
	if ((st = ez_sum_check(c, drive, key_id, size, &instance)) != EZ_OK)
		return st;
	if ((flags & EZ_SESS_CRITICAL) && drive == 0)
		return EZ_ERR_BAD_REQUEST;          /* drive 0 cannot also be its own extra copy */
	ez_session_params_t p = { key_id, size, role, drive, label, instance, flags };
	if ((st = ez_meta_session_create(&c->meta, &p, slot)) != EZ_OK)
		return st;
	/* SEC-AVAIL-003: a key in use is kept in every copy. Replication is
	 * reported separately; the session exists either way. */
	c->last_replicate = ez_replicate(c, drive, key_id);
	/* IMPL-AV-005: a critical key also goes to drive 0, after the card
	 * copies are complete (SEC-AVAIL-004). */
	c->last_critical = EZ_OK;
	if (flags & EZ_SESS_CRITICAL) {
		c->last_critical = ez_core_drive_usable(c, 0);
		if (c->last_critical == EZ_OK)
			c->last_critical = write_copy_to(c, drive, key_id, size, instance, 0);
	}
	return EZ_OK;
}

ez_status_t ez_session_delete(ez_core_t *c, int slot, bool force)
{
	if (slot < 0 || slot >= EZ_META_SESSIONS)
		return EZ_ERR_BAD_REQUEST;
	if (c->stream_active)
		return EZ_ERR_BUSY;
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state == EZ_SS_EMPTY)
		return EZ_ERR_NO_SESSION;
	uint32_t key_id = s->identity ? s->key_id : 0;

	if (force) {
		intent_t in;
		intent_read(c, &in);
		if (in.op == IN_SESSION_DELETE && in.slot == slot)
			intent_clear(c);                     /* the user gave up on the erase */
	} else {
		/* SEC-PTR-004, in this order:
		 *   1. make the session unusable (an interrupted erase must not
		 *      leave a usable session over a partly zeroed key);
		 *   2. erase the key (if the record went first, an interruption
		 *      would leave a key with no record of what was consumed);
		 *   3. remove the record. */
		if (!s->identity)
			return EZ_ERR_UNRESOLVED;          /* which file is unknown */
		ez_status_t st = drive_erasable(c, s->drive);
		if (st != EZ_OK)
			return st;
		if ((st = intent_set(c, IN_SESSION_DELETE, s->drive, (uint8_t)slot, s->key_id)) != EZ_OK)
			return st;
		if ((s->state == EZ_SS_VALID || s->state == EZ_SS_EXHAUSTED) &&
		    (st = ez_meta_quarantine(&c->meta, slot, EZ_Q_KEY_ERASING)) != EZ_OK)
			return st;
		char name[EZ_FNAME_MAX];
		ez_key_name(s->key_id, "KEY", name);
		st = c->ks->zap(c->ks->ctx, s->drive, name);
		if (st != EZ_OK && st != EZ_ERR_NOT_FOUND)   /* already gone is fine */
			return st;
		ez_key_name(s->key_id, "SUM", name);         /* tags go with the key */
		st = c->ks->zap(c->ks->ctx, s->drive, name);
		if (st != EZ_OK && st != EZ_ERR_NOT_FOUND)
			return st;
		/* IMPL-AV-005: a critical key's copy on drive 0 (if drive 0 is
		 * disabled, its contents were wiped when it was disabled). */
		if ((s->flags & EZ_SESS_CRITICAL) && s->drive != 0 && drive_erasable(c, 0) == EZ_OK) {
			const char *ext[2] = { "KEY", "SUM" };
			for (int e = 0; e < 2; e++) {
				ez_key_name(s->key_id, ext[e], name);
				st = c->ks->zap(c->ks->ctx, 0, name);
				if (st != EZ_OK && st != EZ_ERR_NOT_FOUND)
					return st;
			}
		}
	}
	ez_status_t st = ez_meta_session_delete(&c->meta, slot);
	if (st != EZ_OK)
		return st;
	if (!force)
		intent_clear(c);
	ez_meta_log_append(&c->meta, force ? EZ_EV_SESSION_FORCE : EZ_EV_SESSION_DELETE,
	                   (uint8_t)slot, key_id, 0);
	return EZ_OK;
}

ez_status_t ez_session_resolve(ez_core_t *c, int slot)
{
	if (slot < 0 || slot >= EZ_META_SESSIONS)
		return EZ_ERR_BAD_REQUEST;
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state != EZ_SS_QUARANTINED)
		return EZ_ERR_STATE;
	if (s->qreason >= 0x80)
		return EZ_ERR_QUARANTINED;                       /* IMPL-META-006 */
	ez_status_t st = ez_core_drive_usable(c, s->drive);
	if (st != EZ_OK)
		return st;
	char name[EZ_FNAME_MAX];
	uint32_t size = 0;
	ez_key_name(s->key_id, "KEY", name);
	st = c->ks->size(c->ks->ctx, s->drive, name, &size);
	if (st != EZ_OK)
		return st;
	if (size != s->key_len)
		return EZ_ERR_KEY_PARAM;
	uint16_t instance = 0;
	if ((st = ez_sum_check(c, s->drive, s->key_id, s->key_len, &instance)) != EZ_OK)
		return st;
	if (instance != s->instance)
		return EZ_ERR_KEY_DAMAGED;               /* a different key under this ID */
	return ez_meta_resolve(&c->meta, slot);
}

/* ---- keys ------------------------------------------------------------ */

ez_status_t ez_key_delete(ez_core_t *c, uint8_t drive, uint32_t key_id)
{
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	ez_status_t st = drive_erasable(c, drive);
	if (st != EZ_OK)
		return st;
	char name[EZ_FNAME_MAX];
	uint32_t size;
	ez_key_name(key_id, "KEY", name);
	if ((st = c->ks->size(c->ks->ctx, drive, name, &size)) != EZ_OK)
		return st;
	if ((st = intent_set(c, IN_KEY_DELETE, drive, 0, key_id)) != EZ_OK)
		return st;
	/* EZ-IMPL-001 §2.3: linked sessions are quarantined -- before the
	 * erase, not after (SEC-PTR-004). The caller has already shown the
	 * warning and obtained confirmation. */
	if ((st = quarantine_users(c, drive, key_id)) != EZ_OK)
		return st;
	if ((st = c->ks->zap(c->ks->ctx, drive, name)) != EZ_OK)   /* SEC-STORE-001 */
		return st;
	ez_key_name(key_id, "SUM", name);                    /* tags go with the key */
	st = c->ks->zap(c->ks->ctx, drive, name);
	if (st == EZ_ERR_NOT_FOUND) st = EZ_OK;
	if (st == EZ_OK) intent_clear(c);
	return st;
}

/* Copy a key and its integrity file. Every unit is verified against the
 * source .SUM before it is written, and read back after (SEC-STORE-004,
 * SEC-GEN-002 discipline). Written under temporary names and renamed only
 * when complete; an interrupted copy leaves temporary files that are
 * destroyed at the next mount (IMPL-GEN-001). */
ez_status_t ez_key_copy(ez_core_t *c, uint32_t key_id, uint8_t from, uint8_t to)
{
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (from == to || c->stream_active)
		return from == to ? EZ_ERR_BAD_REQUEST : EZ_ERR_BUSY;
	ez_status_t st = ez_core_drive_usable(c, from);
	if (st == EZ_OK) st = ez_core_drive_usable(c, to);
	if (st != EZ_OK)
		return st;
	char key[EZ_FNAME_MAX], sum[EZ_FNAME_MAX], tmp[EZ_FNAME_MAX], sut[EZ_FNAME_MAX];
	uint32_t size = 0, dummy;
	ez_key_name(key_id, "KEY", key);
	ez_key_name(key_id, "SUM", sum);
	ez_key_name(key_id, "TMP", tmp);
	ez_key_name(key_id, "SUT", sut);
	if ((st = c->ks->size(c->ks->ctx, from, key, &size)) != EZ_OK)
		return st;
	if ((st = ez_sum_check(c, from, key_id, size, NULL)) != EZ_OK)
		return st;
	if (c->ks->size(c->ks->ctx, to, key, &dummy) != EZ_ERR_NOT_FOUND ||
	    c->ks->size(c->ks->ctx, to, sum, &dummy) != EZ_ERR_NOT_FOUND)
		return EZ_ERR_EXISTS;
	if ((st = c->ks->create(c->ks->ctx, to, tmp)) != EZ_OK)
		return st;
	if ((st = c->ks->create(c->ks->ctx, to, sut)) != EZ_OK) {
		c->ks->zap(c->ks->ctx, to, tmp);
		return st;
	}
	uint32_t n = ez_unit_count(size);
	for (uint32_t i = 0; i < n && st == EZ_OK; i++) {
		if ((st = ez_unit_load(c, from, key_id, size, i)) != EZ_OK) break;
		if ((st = c->ks->append(c->ks->ctx, to, tmp, c->ubuf, c->u_len)) != EZ_OK) break;
		for (uint32_t o = 0; o < c->u_len && st == EZ_OK; o += EZ_KEY_BLOCK) {
			uint32_t m = c->u_len - o < EZ_KEY_BLOCK ? c->u_len - o : EZ_KEY_BLOCK;
			st = c->ks->read(c->ks->ctx, to, tmp, c->u_start + o, c->kbuf, m);
			if (st == EZ_OK && memcmp(c->kbuf, c->ubuf + o, m) != 0) st = EZ_ERR_MEDIA;
			ez_secure_zero(c->kbuf, sizeof c->kbuf);
		}
		ez_unit_drop(c);
	}
	/* The integrity file, byte for byte, verified by read-back. */
	uint32_t ssize = ez_sum_size(size);
	const uint32_t half = EZ_KEY_BLOCK / 2;
	for (uint32_t o = 0; o < ssize && st == EZ_OK; o += half) {
		uint32_t m = ssize - o < half ? ssize - o : half;
		if ((st = c->ks->read(c->ks->ctx, from, sum, o, c->kbuf, m)) != EZ_OK) break;
		if ((st = c->ks->append(c->ks->ctx, to, sut, c->kbuf, m)) != EZ_OK) break;
		if ((st = c->ks->read(c->ks->ctx, to, sut, o, c->kbuf + half, m)) != EZ_OK) break;
		if (memcmp(c->kbuf, c->kbuf + half, m) != 0) st = EZ_ERR_MEDIA;
		ez_secure_zero(c->kbuf, sizeof c->kbuf);
	}
	ez_secure_zero(c->kbuf, sizeof c->kbuf);
	ez_unit_drop(c);
	if (st == EZ_OK) st = c->ks->rename(c->ks->ctx, to, sut, sum);
	if (st == EZ_OK) st = c->ks->rename(c->ks->ctx, to, tmp, key);
	if (st == EZ_OK) c->last_replicate = ez_replicate(c, to, key_id);
	if (st != EZ_OK) {
		c->ks->zap(c->ks->ctx, to, tmp);
		c->ks->zap(c->ks->ctx, to, sut);
		/* a .SUM renamed into place without its key is also removed */
		uint32_t ks_;
		if (c->ks->size(c->ks->ctx, to, key, &ks_) == EZ_ERR_NOT_FOUND)
			c->ks->zap(c->ks->ctx, to, sum);
	}
	return st;
}

/* ---- drives ---------------------------------------------------------- */

ez_status_t ez_drive_format(ez_core_t *c, uint8_t drive, uint8_t copies)
{
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (drive == 0 || drive >= EZ_DRIVES || (copies & 0x7Fu) < 1 || (copies & 0x7Fu) > 2)
		return EZ_ERR_BAD_REQUEST;
	if (!c->format)
		return EZ_ERR_UNSUPPORTED;
	if (c->stream_active)
		return EZ_ERR_BUSY;
	for (int s = 0; s < EZ_META_SESSIONS; s++) {    /* no session's key may be on it */
		const ez_session_t *ss = &c->meta.s[s];
		if (ss->state == EZ_SS_EMPTY) continue;
		if (!ss->identity) return EZ_ERR_UNRESOLVED;
		if (ss->drive == drive) return EZ_ERR_STATE;
	}
	ez_secure_zero(c->stage, c->stage_cap);          /* nothing staged survives a format */
	c->stage_state = EZ_STAGE_EMPTY;
	ez_unit_drop(c);
	ez_status_t st = c->format(c->format_ctx, drive, copies);
	if (st == EZ_OK)
		ez_core_media_event(c, drive);
	return st;
}

ez_status_t ez_drive_repair(ez_core_t *c, uint8_t drive, uint8_t *recreated)
{
	*recreated = 0;
	if (c->meta.dev != EZ_DEV_VALID) return EZ_ERR_DEVICE;
	if (drive == 0 || drive >= EZ_DRIVES) return EZ_ERR_BAD_REQUEST;
	if (!c->repair_volumes) return EZ_ERR_UNSUPPORTED;
	if (c->stream_active) return EZ_ERR_BUSY;
	ez_unit_drop(c);
	ez_status_t st = c->repair_volumes(c->format_ctx, drive, recreated);
	if (st == EZ_OK) ez_core_media_event(c, drive);
	return st;
}

static ez_status_t sync_drives(ez_core_t *c, bool full);
ez_status_t ez_session_set_critical(ez_core_t *c, int slot, bool on)
{
	if (slot < 0 || slot >= EZ_META_SESSIONS) return EZ_ERR_BAD_REQUEST;
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state == EZ_SS_EMPTY) return EZ_ERR_NO_SESSION;
	if (!s->identity) return EZ_ERR_UNRESOLVED;
	if (s->drive == 0) return EZ_ERR_BAD_REQUEST;     /* drive 0 cannot also be its own copy */
	if (((s->flags & EZ_SESS_CRITICAL) != 0) == on) return EZ_OK;
	ez_status_t st;
	if (on) {
		/* The copy first, then the flag: interrupted, it is only a spare file. */
		if ((st = ez_core_drive_usable(c, 0)) != EZ_OK) return st;
		if ((st = write_copy_to(c, s->drive, s->key_id, s->key_len, s->instance, 0)) != EZ_OK) return st;
		return ez_meta_set_critical(&c->meta, slot, true);
	}
	/* The flag first, then the copy: interrupted, the next sync or a
	 * deletion finds no reference to it, and drive 0 cleanup removes it. */
	if ((st = ez_meta_set_critical(&c->meta, slot, false)) != EZ_OK) return st;
	if (drive_erasable(c, 0) == EZ_OK) {
		const char *ext[2] = { "KEY", "SUM" };
		for (int e = 0; e < 2; e++) {
			char name[EZ_FNAME_MAX];
			ez_key_name(s->key_id, ext[e], name);
			st = c->ks->zap(c->ks->ctx, 0, name);
			if (st != EZ_OK && st != EZ_ERR_NOT_FOUND) return st;
		}
	}
	return EZ_OK;
}

ez_status_t ez_sync(ez_core_t *c) { return sync_drives(c, true); }
ez_status_t ez_sync_quick(ez_core_t *c) { return sync_drives(c, false); }

/* The files of every copy (and a critical key's drive 0 copy) are there,
 * with the right size and instance -- without reading key units. */
static bool session_files_ok(ez_core_t *c, const ez_session_t *ss)
{
	char key[EZ_FNAME_MAX];
	ez_key_name(ss->key_id, "KEY", key);
	uint8_t n = ncopies(c, ss->drive);
	for (uint8_t k = 0; k < n; k++) {
		uint8_t a = n > 1 ? EZ_COPY(ss->drive, k) : ss->drive;
		uint32_t size;
		uint16_t inst;
		if (!c->ks->present(c->ks->ctx, a)) return false;
		if (c->ks->size(c->ks->ctx, a, key, &size) != EZ_OK || size != ss->key_len) return false;
		if (sum_check_at(c, a, ss->key_id, ss->key_len, &inst) != EZ_OK || inst != ss->instance) return false;
	}
	if ((ss->flags & EZ_SESS_CRITICAL) && ez_core_drive_usable(c, 0) == EZ_OK) {
		uint32_t size;
		uint16_t inst;
		if (c->ks->size(c->ks->ctx, 0, key, &size) != EZ_OK || size != ss->key_len) return false;
		if (sum_check_at(c, 0, ss->key_id, ss->key_len, &inst) != EZ_OK || inst != ss->instance) return false;
	}
	return true;
}

static ez_status_t sync_drives(ez_core_t *c, bool full)
{
	uint8_t detail = 0;
	if (c->meta.dev != EZ_DEV_VALID) { c->health = EZ_HEALTH_OK; c->health_detail = 0; return EZ_OK; }
	for (uint8_t drive = 1; drive < EZ_DRIVES; drive++) {
		uint8_t n = ncopies(c, drive);
		bool critical = false, any = false;
		for (int s = 0; s < EZ_META_SESSIONS; s++) {
			const ez_session_t *ss = &c->meta.s[s];
			if (ss->state == EZ_SS_EMPTY || !ss->identity || ss->drive != drive) continue;
			any = true;
			if (ss->flags & EZ_SESS_CRITICAL) critical = true;
		}
		if (n < 2 && !critical) continue;
		if (!c->ks->present(c->ks->ctx, drive) && !(n >= 2 && c->repair_volumes)) continue;
		if (n >= 2 && c->repair_volumes) {           /* volumes first */
			uint8_t rec = 0;
			if (c->repair_volumes(c->format_ctx, drive, &rec) != EZ_OK) detail |= EZ_HD_VOLUME;
			if (rec) ez_core_media_event(c, drive);
		}
		if (c->yield && *c->yield) return EZ_ERR_BUSY;
		if (!any) continue;
		for (int s = 0; s < EZ_META_SESSIONS; s++) {
			const ez_session_t *ss = &c->meta.s[s];
			if (ss->state == EZ_SS_EMPTY || !ss->identity || ss->drive != drive) continue;
			bool missing_q = ss->state == EZ_SS_QUARANTINED && ss->qreason == EZ_Q_KEY_MISSING;
			if (ss->state == EZ_SS_QUARANTINED && !missing_q) continue;   /* needs the user */
			if (!full && !missing_q && session_files_ok(c, ss)) {
				if ((ss->flags & EZ_SESS_CRITICAL) && ez_core_drive_usable(c, 0) != EZ_OK) detail |= EZ_HD_NO_CRITICAL;
				continue;
			}
			ez_check_t ck;
			ez_status_t st = ez_session_check(c, s, &ck);
			if (st == EZ_ERR_BUSY) return st;
			if (st != EZ_OK) { detail |= EZ_HD_VOLUME; continue; }
			if (ck.lost) { detail |= EZ_HD_LOST; continue; }
			bool need = false;
			for (int k = 0; k < ck.copies && ck.copies > 1; k++) {
				if (!ck.copy[k].present) detail |= EZ_HD_VOLUME;
				else if (!ck.copy[k].has_key || ck.copy[k].bad) need = true;
			}
			if (ck.critical && (ck.d0_state == 1 || ck.d0_state == 3)) need = true;
			if (ck.critical && ck.d0_state == 0) detail |= EZ_HD_NO_CRITICAL;
			if (need) {
				uint8_t rep_n;
				if (ez_session_repair(c, s, &rep_n) == EZ_ERR_BUSY) return EZ_ERR_BUSY;
				if (ez_session_check(c, s, &ck) == EZ_OK) {
					for (int k = 0; k < ck.copies && ck.copies > 1; k++)
						if (ck.copy[k].present && (!ck.copy[k].has_key || ck.copy[k].bad)) detail |= EZ_HD_UNREPAIRED;
					if (ck.critical && (ck.d0_state == 1 || ck.d0_state == 3)) detail |= EZ_HD_UNREPAIRED;
				}
			}
			if (missing_q) ez_session_resolve(c, s);      /* only succeeds if the key verifies */
			if (c->yield && *c->yield) return EZ_ERR_BUSY;
		}
	}
	c->health = detail ? EZ_HEALTH_DEGRADED : EZ_HEALTH_OK;
	c->health_detail = detail;
	return EZ_OK;
}

int ez_core_drive0_protected(ez_core_t *c)
{
	if (!c->drive0_guard) return -1;
	return c->drive0_guard(c->drive0_guard_ctx) ? 1 : 0;
}

ez_status_t ez_drive_enable0(ez_core_t *c)
{
	/* IMPL-DRV-003: never enable drive 0 without verified protection.
	 * (Erasing it -- disable, device erase -- needs no protection.) */
	if (c->drive0_guard && !c->drive0_guard(c->drive0_guard_ctx))
		return EZ_ERR_PROTECTION;
	ez_status_t st = ez_meta_set_drive0(&c->meta, true);  /* IMPL-DRV-002 */
	if (st == EZ_OK)
		ez_core_media_event(c, 0);
	return st;
}

ez_status_t ez_drive_disable0(ez_core_t *c)
{
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	for (int s = 0; s < EZ_META_SESSIONS; s++) {
		const ez_session_t *ss = &c->meta.s[s];
		if (ss->state == EZ_SS_EMPTY) continue;
		if (!ss->identity) return EZ_ERR_UNRESOLVED;   /* might be on drive 0 */
		if (ss->drive == 0) return EZ_ERR_STATE;       /* IMPL-DRV-002 */
	}
	/* Erase before recording the disabled state: an interruption leaves
	 * drive 0 enabled and partly erased, never disabled with keys left;
	 * the intent record finishes the job at the next boot. */
	ez_status_t st = intent_set(c, IN_DRIVE0_DISABLE, 0, 0, 0);
	if (st != EZ_OK)
		return st;
	if ((st = c->ks->wipe(c->ks->ctx, 0)) != EZ_OK)
		return st;
	if ((st = ez_meta_set_drive0(&c->meta, false)) == EZ_OK)
		intent_clear(c);
	return st;
}

ez_status_t ez_drive_list(ez_core_t *c, uint8_t drive, uint32_t index,
                          char name[EZ_NAME_MAX], uint32_t *size)
{
	ez_status_t st = ez_core_drive_usable(c, drive);
	if (st != EZ_OK)
		return st;
	return c->ks->list(c->ks->ctx, drive, index, name, size);
}

/* ---- device ---------------------------------------------------------- */

ez_status_t ez_device_erase(ez_core_t *c)
{
	if (c->stream_active)
		return EZ_ERR_BUSY;
	/* Sessions unusable first (SEC-PTR-004), then key files, then
	 * metadata: if interrupted, sessions remain quarantined and point at
	 * missing or partly erased keys. Erasing the metadata first could
	 * leave keys with no record of what was consumed. */
	ez_status_t st;
	/* Recorded first, so an interrupted erase is completed at the next
	 * boot; the metadata format at the end clears the record. */
	if ((st = intent_set(c, IN_DEVICE_ERASE, 0, 0, 0)) != EZ_OK)
		return st;
	if (c->meta.dev != EZ_DEV_UNINIT) {
		for (int i = 0; i < EZ_META_SESSIONS; i++) {
			const ez_session_t *ss = &c->meta.s[i];
			if ((ss->state == EZ_SS_VALID || ss->state == EZ_SS_EXHAUSTED) &&
			    (st = ez_meta_quarantine(&c->meta, i, EZ_Q_KEY_ERASING)) != EZ_OK)
				return st;
		}
	}
	st = c->ks->wipe(c->ks->ctx, 0);                     /* always, enabled or not */
	if (st != EZ_OK)
		return st;
	for (uint8_t d = 1; d < EZ_DRIVES; d++) {
		/* Every copy volume, not just the logical view: a file can exist in
		 * one copy only (an interrupted replication). */
		uint8_t n = ncopies(c, d);
		for (uint8_t k = 0; k < n; k++) {
			uint8_t a = n > 1 ? EZ_COPY(d, k) : d;
			if (!c->ks->present(c->ks->ctx, a))
				continue;
			char name[EZ_NAME_MAX];
			uint32_t size, i = 0;
			while (c->ks->list(c->ks->ctx, a, i, name, &size) == EZ_OK) {
				if (has_ext(name, "KEY") || has_ext(name, "TMP") ||
				    has_ext(name, "SUM") || has_ext(name, "SUT")) {
					if ((st = c->ks->zap(c->ks->ctx, a, name)) != EZ_OK)
						return st;
					continue;
				}
				i++;
			}
		}
	}
	ez_secure_zero(c->stage, c->stage_cap);
	c->stage_state = EZ_STAGE_EMPTY;
	ez_unit_drop(c);
	st = ez_meta_format(&c->meta);
	/* EZ-UI-001 §13: drive 0 is on by default -- when its protection is
	 * verified (TR-06). Without the partition table it stays off. */
	if (st == EZ_OK && c->drive0_guard && c->drive0_guard(c->drive0_guard_ctx))
		(void)ez_drive_enable0(c);
	return st;
}
