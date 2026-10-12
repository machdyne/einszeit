/*
 * ez_meta.c -- metadata storage (EZ-IMPL-001 §3). See ez_meta.h for the
 * EZ-SEC-001 traceability list; requirement IDs are repeated at the code
 * that implements them.
 */
#include "ez_meta.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"

_Static_assert(EZ_META_DEV_SIZE + EZ_META_SESSIONS * EZ_META_SESSION_SIZE
               == EZ_META_LOG_ADDR, "session region");
_Static_assert(EZ_META_LOG_ADDR + EZ_META_LOG_ENTRIES * EZ_META_LOG_ENTRY_SIZE
               == EZ_META_RESERVED_ADDR, "log region");
_Static_assert(EZ_META_RESERVED_ADDR + EZ_META_RESERVED_SIZE == EZ_META_SIZE,
               "layout fills the F-RAM exactly");

#define TAG_TX  'T'
#define TAG_RX  'R'
#define TAG_BOOT 'C'
#define DEV_SLOT_ID 0xFF

/* ===================================================================== */
/* Storage access                                                        */
/* ===================================================================== */

static ez_status_t rd(const ez_meta_t *m, uint32_t addr, void *buf, uint32_t len)
{
	return m->hal->read(m->hal->ctx, addr, buf, len);
}

/* Write and verify by read-back (SEC-PTR-003: a commit is only reported
 * once verified). */
static ez_status_t wr(const ez_meta_t *m, uint32_t addr, const void *buf, uint32_t len)
{
	uint8_t chk[64];
	if (m->hal->write(m->hal->ctx, addr, buf, len) != EZ_OK)
		return EZ_ERR_META;
	const uint8_t *p = (const uint8_t *)buf;
	while (len) {
		uint32_t n = len > sizeof chk ? (uint32_t)sizeof chk : len;
		if (rd(m, addr, chk, n) != EZ_OK || memcmp(chk, p, n) != 0)
			return EZ_ERR_META;
		addr += n; p += n; len -= n;
	}
	return EZ_OK;
}

static ez_status_t wr_byte(const ez_meta_t *m, uint32_t addr, uint8_t v)
{
	return wr(m, addr, &v, 1);
}

static uint32_t sess_addr(int idx)
{
	return EZ_META_SESSION_ADDR + (uint32_t)idx * EZ_META_SESSION_SIZE;
}

static uint32_t log_addr(int idx)
{
	return EZ_META_LOG_ADDR + (uint32_t)idx * EZ_META_LOG_ENTRY_SIZE;
}

/* ===================================================================== */
/* Checked slots (§3.2)                                                  */
/* ===================================================================== */

static uint16_t slot_crc(uint8_t tag, uint8_t id, uint8_t ab, uint32_t v)
{
	uint8_t b[7] = { tag, id, ab };
	ez_put_le32(&b[3], v);
	return ez_crc16(b, sizeof b);
}

static void slot_encode(uint8_t out[EZ_SLOT_SIZE], uint8_t tag, uint8_t id,
                        uint8_t ab, uint32_t v)
{
	ez_put_le32(out, v);
	ez_put_le16(out + 4, slot_crc(tag, id, ab, v));
}

static bool slot_decode(const uint8_t in[EZ_SLOT_SIZE], uint8_t tag, uint8_t id,
                        uint8_t ab, uint32_t *v)
{
	*v = ez_get_le32(in);
	return ez_get_le16(in + 4) == slot_crc(tag, id, ab, *v);
}

/* ===================================================================== */
/* Ranges                                                                */
/* ===================================================================== */

void ez_range_tx(uint32_t key_len, uint8_t role, uint32_t *start, uint32_t *end)
{
	uint32_t h = key_len / 2;
	if (role == EZ_ROLE_ALICE) { *start = 0; *end = h; }
	else                       { *start = h; *end = key_len; }
}

void ez_range_rx(uint32_t key_len, uint8_t role, uint32_t *start, uint32_t *end)
{
	/* The RX range is always the peer's TX range. */
	ez_range_tx(key_len, role == EZ_ROLE_ALICE ? EZ_ROLE_BOB : EZ_ROLE_ALICE,
	            start, end);
}

static void range_of(const ez_session_t *s, int which, uint32_t *st, uint32_t *en)
{
	if (which == 0) ez_range_tx(s->key_len, s->role, st, en);
	else            ez_range_rx(s->key_len, s->role, st, en);
}

uint32_t ez_meta_tx_remaining(const ez_session_t *s)
{
	uint32_t st, en;
	ez_range_tx(s->key_len, s->role, &st, &en);
	return s->offsets ? en - s->tx_off : 0;
}

uint32_t ez_meta_rx_remaining(const ez_session_t *s)
{
	uint32_t st, en;
	ez_range_rx(s->key_len, s->role, &st, &en);
	return s->offsets ? en - s->rx_off : 0;
}

bool ez_meta_tx_low(const ez_session_t *s, unsigned pct)
{
	uint32_t half = s->key_len / 2;
	/* remaining / half < pct / 100, without overflow */
	return (uint64_t)ez_meta_tx_remaining(s) * 100u < (uint64_t)half * pct;
}

/* ===================================================================== */
/* Session record encode / parse (§3.4)                                  */
/* ===================================================================== */

static uint32_t session_static_crc(const uint8_t r[EZ_META_SESSION_SIZE])
{
	uint32_t c = ez_crc32_update(EZ_CRC32_INIT, r, 3);              /* 0..2  */
	c = ez_crc32_update(c, r + EZ_SR_OFF_ROLE, EZ_SR_OFF_CRC - EZ_SR_OFF_ROLE); /* 7..35 */
	return ez_crc32_final(c);
}

static bool label_valid(const char *l, size_t *len_out)
{
	size_t n = 0;
	if (!l) return false;
	while (n <= EZ_LABEL_MAX && l[n]) n++;
	if (n == 0 || n > EZ_LABEL_MAX) return false;
	if (len_out) *len_out = n;
	return true;
}

static void quarantine_ram(ez_session_t *s, uint8_t reason)
{
	/* SEC-META-003 / IMPL-META-006: never written back to storage. */
	s->state = EZ_SS_QUARANTINED;
	if (s->qreason == EZ_Q_NONE || s->qreason < 0x80)
		s->qreason = reason;
}

static void derive_state(ez_session_t *s)
{
	uint32_t st, en;
	ez_range_tx(s->key_len, s->role, &st, &en);
	s->state = (s->tx_off >= en) ? EZ_SS_EXHAUSTED : EZ_SS_VALID;
}

static void parse_session(int idx, const uint8_t r[EZ_META_SESSION_SIZE], ez_session_t *s)
{
	memset(s, 0, sizeof *s);
	uint8_t status = r[EZ_SR_OFF_STATUS];

	if (status == EZ_ST_EMPTY0 || status == EZ_ST_EMPTY1) {
		s->state = EZ_SS_EMPTY;
		return;
	}

	/* Identity: format, static CRC, field validity (SEC-META-001). */
	if (ez_get_le16(r) != EZ_MAGIC || r[2] != EZ_SESSION_VERSION) {
		quarantine_ram(s, EZ_Q_FORMAT);
		return;
	}
	if (ez_get_le32(r + EZ_SR_OFF_CRC) != session_static_crc(r)) {
		quarantine_ram(s, EZ_Q_STATIC_CRC);
		return;
	}
	s->role    = r[EZ_SR_OFF_ROLE];
	s->key_id  = ez_get_le32(r + EZ_SR_OFF_KEY_ID);
	s->key_len = ez_get_le32(r + EZ_SR_OFF_KEY_LEN);
	s->drive   = r[EZ_SR_OFF_DRIVE];
	s->flags   = r[EZ_SR_OFF_FLAGS];
	s->instance = ez_get_le16(r + EZ_SR_OFF_INSTANCE);
	memcpy(s->label, r + EZ_SR_OFF_LABEL, EZ_LABEL_MAX + 1);
	if (s->role > EZ_ROLE_BOB || s->key_id == 0 || s->key_len == 0 ||
	    (s->key_len & 1u) || s->drive > 2 ||
	    s->label[EZ_LABEL_MAX] != '\0' || !label_valid(s->label, NULL)) {
		quarantine_ram(s, EZ_Q_FORMAT);
		return;
	}
	s->identity = true;

	if (status != EZ_ST_VALID && status != EZ_ST_QUARANTINED &&
	    status != EZ_ST_EXHAUSTED) {
		/* Includes EZ_ST_ZEROIZE, unsupported in this version. */
		quarantine_ram(s, EZ_Q_STATUS_CODE);
		return;
	}

	/* Offsets (IMPL-META-002, SEC-PTR-001). */
	static const uint8_t tags[2] = { TAG_TX, TAG_RX };
	static const uint8_t sel_off[2] = { EZ_SR_OFF_TX_SEL, EZ_SR_OFF_RX_SEL };
	static const uint8_t slot_off[2][2] = {
		{ EZ_SR_OFF_TX_A, EZ_SR_OFF_TX_B }, { EZ_SR_OFF_RX_A, EZ_SR_OFF_RX_B } };
	uint32_t eff[2];
	for (int w = 0; w < 2; w++) {
		uint8_t sc = r[sel_off[w]];
		if (sc != EZ_SEL_A && sc != EZ_SEL_B) {
			quarantine_ram(s, EZ_Q_SELECTOR);
			return;
		}
		s->sel[w] = (sc == EZ_SEL_A) ? 0 : 1;
		for (int ab = 0; ab < 2; ab++)
			s->slot_ok[w][ab] = slot_decode(r + slot_off[w][ab], tags[w],
			                                (uint8_t)idx, (uint8_t)ab,
			                                &s->slot_val[w][ab]);
		int cur = s->sel[w], oth = 1 - cur;
		if (!s->slot_ok[w][cur]) {
			/* Never fall back to the other slot: it may be older. */
			quarantine_ram(s, EZ_Q_SLOT_CHECK);
			return;
		}
		eff[w] = s->slot_val[w][cur];
		if (s->slot_ok[w][oth] && s->slot_val[w][oth] > eff[w])
			eff[w] = s->slot_val[w][oth];     /* larger-of-two rule */
		/* Every valid slot must lie in the range; legitimate states never
		 * hold anything else. */
		uint32_t st, en;
		range_of(s, w, &st, &en);
		for (int ab = 0; ab < 2; ab++) {
			if (s->slot_ok[w][ab] &&
			    (s->slot_val[w][ab] < st || s->slot_val[w][ab] > en)) {
				quarantine_ram(s, EZ_Q_RANGE);
				return;
			}
		}
	}
	s->tx_off = eff[0];
	s->rx_off = eff[1];
	s->offsets = true;

	if (status == EZ_ST_QUARANTINED) {
		s->state = EZ_SS_QUARANTINED;
		uint8_t q = r[EZ_SR_OFF_QREASON];
		/* Coded byte: an unknown or damaged code is read as the strictest
		 * persisted reason, which cannot be resolved. */
		s->qreason = q == EZ_QC_KEY_MISSING ? EZ_Q_KEY_MISSING :
		             q == EZ_QC_KEY_SIZE    ? EZ_Q_KEY_SIZE :
		             q == EZ_QC_KEY_DAMAGED ? EZ_Q_KEY_DAMAGED : EZ_Q_KEY_ERASING;
	} else {
		derive_state(s);
	}
}

static void encode_new_session(int idx, const ez_session_params_t *p, uint8_t role,
                               uint8_t r[EZ_META_SESSION_SIZE])
{
	memset(r, 0, EZ_META_SESSION_SIZE);
	ez_put_le16(r, EZ_MAGIC);
	r[2] = EZ_SESSION_VERSION;
	r[EZ_SR_OFF_STATUS] = EZ_ST_EMPTY0;    /* flipped to VALID afterwards */
	r[EZ_SR_OFF_TX_SEL] = EZ_SEL_A;
	r[EZ_SR_OFF_RX_SEL] = EZ_SEL_A;
	r[EZ_SR_OFF_ROLE] = role;
	ez_put_le32(r + EZ_SR_OFF_KEY_ID, p->key_id);
	ez_put_le32(r + EZ_SR_OFF_KEY_LEN, p->key_len);
	r[EZ_SR_OFF_DRIVE] = p->drive;
	ez_put_le16(r + EZ_SR_OFF_INSTANCE, p->instance);
	r[EZ_SR_OFF_FLAGS] = p->flags;
	size_t n = 0;
	label_valid(p->label, &n);
	memcpy(r + EZ_SR_OFF_LABEL, p->label, n);
	ez_put_le32(r + EZ_SR_OFF_CRC, session_static_crc(r));

	uint32_t txs, txe, rxs, rxe;
	ez_range_tx(p->key_len, role, &txs, &txe);
	ez_range_rx(p->key_len, role, &rxs, &rxe);
	slot_encode(r + EZ_SR_OFF_TX_A, TAG_TX, (uint8_t)idx, 0, txs);
	slot_encode(r + EZ_SR_OFF_TX_B, TAG_TX, (uint8_t)idx, 1, txs);
	slot_encode(r + EZ_SR_OFF_RX_A, TAG_RX, (uint8_t)idx, 0, rxs);
	slot_encode(r + EZ_SR_OFF_RX_B, TAG_RX, (uint8_t)idx, 1, rxs);
}

/* ===================================================================== */
/* Device record (§3.3)                                                  */
/* ===================================================================== */

static uint32_t dev_static_crc(const uint8_t d[EZ_META_DEV_SIZE])
{
	uint32_t c = ez_crc32_update(EZ_CRC32_INIT, d, 3);
	c = ez_crc32_update(c, d + 4, EZ_DEV_OFF_CRC - 4);
	return ez_crc32_final(c);
}

static void encode_dev(uint8_t d[EZ_META_DEV_SIZE], uint32_t boot)
{
	memset(d, 0, EZ_META_DEV_SIZE);
	ez_put_le16(d, EZ_MAGIC);
	d[2] = EZ_DEV_VERSION;
	d[EZ_DEV_OFF_DRIVE0] = EZ_DRIVE0_DISABLED;   /* IMPL-DRV-001 */
	ez_put_le32(d + EZ_DEV_OFF_CRC, dev_static_crc(d));
	slot_encode(d + EZ_DEV_OFF_BOOT_A, TAG_BOOT, DEV_SLOT_ID, 0, boot);
	slot_encode(d + EZ_DEV_OFF_BOOT_B, TAG_BOOT, DEV_SLOT_ID, 1, boot);
}

static void parse_dev(ez_meta_t *m, const uint8_t d[EZ_META_DEV_SIZE])
{
	m->dev = EZ_DEV_VALID;
	m->drive0_enabled = false;
	if (ez_get_le16(d) != EZ_MAGIC || d[2] != EZ_DEV_VERSION ||
	    ez_get_le32(d + EZ_DEV_OFF_CRC) != dev_static_crc(d)) {
		m->dev = EZ_DEV_FAULT;
	}
	uint8_t c = d[EZ_DEV_OFF_DRIVE0];
	if (c == EZ_DRIVE0_ENABLED)       m->drive0_enabled = (m->dev == EZ_DEV_VALID);
	else if (c != EZ_DRIVE0_DISABLED) m->dev = EZ_DEV_FAULT;

	m->boot_ok[0] = slot_decode(d + EZ_DEV_OFF_BOOT_A, TAG_BOOT, DEV_SLOT_ID, 0, &m->boot_slot[0]);
	m->boot_ok[1] = slot_decode(d + EZ_DEV_OFF_BOOT_B, TAG_BOOT, DEV_SLOT_ID, 1, &m->boot_slot[1]);
	m->boot_count = 0;
	m->boot_count_fault = !m->boot_ok[0] && !m->boot_ok[1];
	for (int i = 0; i < 2; i++)
		if (m->boot_ok[i] && m->boot_slot[i] > m->boot_count)
			m->boot_count = m->boot_slot[i];
}

/* Write count+1 into the boot counter slot holding the smaller or invalid
 * value; the larger valid slot is never overwritten. */
static ez_status_t boot_increment(ez_meta_t *m)
{
	int tgt;
	if (!m->boot_ok[0])      tgt = 0;
	else if (!m->boot_ok[1]) tgt = 1;
	else tgt = (m->boot_slot[0] <= m->boot_slot[1]) ? 0 : 1;
	uint32_t v = m->boot_count == UINT32_MAX ? UINT32_MAX : m->boot_count + 1;
	uint8_t b[EZ_SLOT_SIZE];
	slot_encode(b, TAG_BOOT, DEV_SLOT_ID, (uint8_t)tgt, v);
	ez_status_t st = wr(m, EZ_META_DEV_ADDR + (tgt ? EZ_DEV_OFF_BOOT_B : EZ_DEV_OFF_BOOT_A),
	                    b, EZ_SLOT_SIZE);
	if (st != EZ_OK) {
		m->boot_ok[tgt] = false;
		return st;
	}
	m->boot_slot[tgt] = v;
	m->boot_ok[tgt] = true;
	m->boot_count = v;
	m->boot_count_fault = false;
	return EZ_OK;
}

/* ===================================================================== */
/* Event log (§3.7)                                                      */
/* ===================================================================== */

static uint16_t log_crc(int idx, const uint8_t e[EZ_META_LOG_ENTRY_SIZE])
{
	uint16_t c = ez_crc16_update(EZ_CRC16_INIT, e, 22);
	uint8_t i = (uint8_t)idx;
	return ez_crc16_update(c, &i, 1);
}

static bool log_decode(int idx, const uint8_t e[EZ_META_LOG_ENTRY_SIZE], ez_event_t *ev)
{
	if (ez_get_le16(e + 22) != log_crc(idx, e))
		return false;
	ev->seq    = ez_get_le32(e);
	ev->boot   = ez_get_le32(e + 4);
	ev->time   = ez_get_le32(e + 8);
	ev->key_id = ez_get_le32(e + 12);
	ev->arg    = ez_get_le32(e + 16);
	ev->type   = e[20] & 0x7F;
	ev->host_time = (e[20] & EZ_EV_HOST_TIME) != 0;
	ev->detail = e[21];
	/* An all-zero entry has a valid-looking structure only if its CRC
	 * matches, which for zeros it does not; still, type 0 is not an event. */
	return ev->type != 0 && (uint32_t)(ev->seq % EZ_META_LOG_ENTRIES) == (uint32_t)idx;
}

static void scan_log(ez_meta_t *m)
{
	bool any = false;
	uint32_t max = 0;
	for (int i = 0; i < EZ_META_LOG_ENTRIES; i++) {
		uint8_t e[EZ_META_LOG_ENTRY_SIZE];
		ez_event_t ev;
		if (rd(m, log_addr(i), e, sizeof e) != EZ_OK) continue;
		if (log_decode(i, e, &ev) && (!any || ev.seq > max)) {
			max = ev.seq;
			any = true;
		}
	}
	m->log_next_seq = any ? max + 1 : 0;
}

ez_status_t ez_meta_log_append(ez_meta_t *m, uint8_t type, uint8_t detail,
                               uint32_t key_id, uint32_t arg)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	bool host = false;
	uint32_t t = m->time_fn ? m->time_fn(m->time_ctx, &host) : 0;
	uint32_t seq = m->log_next_seq;
	int idx = (int)(seq % EZ_META_LOG_ENTRIES);
	uint8_t e[EZ_META_LOG_ENTRY_SIZE];
	ez_put_le32(e, seq);
	ez_put_le32(e + 4, m->boot_count);
	ez_put_le32(e + 8, t);
	ez_put_le32(e + 12, key_id);
	ez_put_le32(e + 16, arg);
	e[20] = (uint8_t)((type & 0x7F) | (host ? EZ_EV_HOST_TIME : 0));
	e[21] = detail;
	ez_put_le16(e + 22, log_crc(idx, e));
	/* Advance first: a torn entry is ignored on the next scan and the
	 * same position is reused, but in this boot we never reuse a seq. */
	m->log_next_seq = seq + 1;
	return wr(m, log_addr(idx), e, sizeof e);
}

int ez_meta_log_read(ez_meta_t *m, ez_event_t *out, int max)
{
	ez_event_t all[EZ_META_LOG_ENTRIES];
	int n = 0;
	for (int i = 0; i < EZ_META_LOG_ENTRIES; i++) {
		uint8_t e[EZ_META_LOG_ENTRY_SIZE];
		if (rd(m, log_addr(i), e, sizeof e) == EZ_OK && log_decode(i, e, &all[n]))
			n++;
	}
	/* Insertion sort, newest first. */
	for (int i = 1; i < n; i++) {
		ez_event_t t = all[i];
		int j = i - 1;
		while (j >= 0 && all[j].seq < t.seq) { all[j + 1] = all[j]; j--; }
		all[j + 1] = t;
	}
	int k = n < max ? n : max;
	for (int i = 0; i < k; i++) out[i] = all[i];
	return k;
}

static bool log_has_generated(ez_meta_t *m, uint32_t key_id)
{
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(m, ev, EZ_META_LOG_ENTRIES);
	for (int i = 0; i < n; i++)
		if (ev[i].type == EZ_EV_KEY_OK && ev[i].key_id == key_id)
			return true;
	return false;
}

/* ===================================================================== */
/* Lifecycle                                                             */
/* ===================================================================== */

/* A new device: the core's own regions (device record, sessions, event
 * log) are uniformly blank. The reserved region is not considered: its
 * owners (the drive 0 store's selector, the intent record) may write there
 * before the core first boots -- the store formats itself on a blank
 * selector -- and without a device record the device is uninitialised
 * whatever they hold. */
static bool region_blank(const ez_meta_t *m)
{
	uint8_t b[32], first = 0;
	bool have_first = false;
	for (uint32_t a = 0; a < EZ_META_RESERVED_ADDR; a += sizeof b) {
		if (rd(m, a, b, sizeof b) != EZ_OK) return false;
		for (size_t i = 0; i < sizeof b; i++) {
			if (!have_first) { first = b[i]; have_first = true; }
			if (b[i] != first) return false;
		}
	}
	return first == 0x00 || first == 0xFF;
}

/* IMPL-META-003 (boot): a power cut between writing a new offset and
 * flipping the selector leaves the larger value in the non-selected slot.
 * Persist the roll-forward by pointing the selector at it, so that at rest
 * the effective offset is always in the selected slot -- whose corruption
 * quarantines -- and never in a slot the read rule may ignore. */
static void normalise_session(ez_meta_t *m, int idx)
{
	ez_session_t *s = &m->s[idx];
	if (!s->offsets || (s->state == EZ_SS_QUARANTINED && s->qreason >= 0x80))
		return;
	for (int w = 0; w < 2; w++) {
		int sel = s->sel[w], oth = 1 - sel;
		if (!(s->slot_ok[w][oth] && s->slot_val[w][oth] > s->slot_val[w][sel]))
			continue;
		uint32_t a = sess_addr(idx) + (w == 0 ? EZ_SR_OFF_TX_SEL : EZ_SR_OFF_RX_SEL);
		if (wr_byte(m, a, oth == 0 ? EZ_SEL_A : EZ_SEL_B) != EZ_OK) {
			quarantine_ram(s, EZ_Q_COMMIT_VERIFY);
			return;
		}
		s->sel[w] = (uint8_t)oth;
	}
}

static uint8_t crit_byte(const ez_meta_t *m, int slot)
{
	uint8_t b = 0;
	if (rd(m, EZ_META_CRIT_ADDR + (uint32_t)slot / 8u, &b, 1) != EZ_OK) b = 0;
	return b;
}

/* Clear a slot's toggle (a new or deleted session starts from its record). */
static ez_status_t crit_clear(const ez_meta_t *m, int slot)
{
	uint8_t b = crit_byte(m, slot), bit = (uint8_t)(1u << (slot % 8));
	if (!(b & bit)) return EZ_OK;
	return wr_byte(m, EZ_META_CRIT_ADDR + (uint32_t)slot / 8u, (uint8_t)(b & ~bit));
}

static void load_sessions(ez_meta_t *m)
{
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		uint8_t r[EZ_META_SESSION_SIZE];
		if (rd(m, sess_addr(i), r, sizeof r) != EZ_OK) {
			memset(&m->s[i], 0, sizeof m->s[i]);
			quarantine_ram(&m->s[i], EZ_Q_FORMAT);
			continue;
		}
		parse_session(i, r, &m->s[i]);
		if (m->s[i].state != EZ_SS_EMPTY && (crit_byte(m, i) & (1u << (i % 8))))
			m->s[i].flags ^= EZ_SESS_CRITICAL;
	}
}

ez_status_t ez_meta_boot(ez_meta_t *m, const ez_hal_meta_t *hal)
{
	ez_time_fn tf = m->time_fn;
	void *tc = m->time_ctx;
	memset(m, 0, sizeof *m);
	m->hal = hal;
	m->time_fn = tf;
	m->time_ctx = tc;

	if (!hal || hal->size < EZ_META_SIZE) {
		m->dev = EZ_DEV_FAULT;
		return EZ_ERR_DEVICE;
	}
	if (region_blank(m)) {
		m->dev = EZ_DEV_UNINIT;   /* all sessions EMPTY by memset */
		return EZ_OK;
	}

	uint8_t d[EZ_META_DEV_SIZE];
	if (rd(m, EZ_META_DEV_ADDR, d, sizeof d) != EZ_OK) {
		m->dev = EZ_DEV_FAULT;
		return EZ_ERR_META;
	}
	parse_dev(m, d);
	load_sessions(m);          /* SEC-META-003: before any session operation */
	scan_log(m);

	if (m->dev == EZ_DEV_VALID) {
		for (int i = 0; i < EZ_META_SESSIONS; i++)
			normalise_session(m, i);
		if (boot_increment(m) != EZ_OK) {
			m->dev = EZ_DEV_FAULT;
			return EZ_ERR_META;
		}
	}
	return EZ_OK;
}

ez_status_t ez_meta_format(ez_meta_t *m)
{
	if (!m->hal) return EZ_ERR_DEVICE;
	/* 1. Invalidate the device record first, so an interrupted format
	 *    leaves a FAULT device rather than one that looks initialised
	 *    with some old sessions still present. */
	uint8_t z[64];
	memset(z, 0, sizeof z);
	ez_status_t st = wr(m, EZ_META_DEV_ADDR, z, 2);
	/* 2. Clear sessions, log and reserved region. */
	for (uint32_t a = EZ_META_DEV_SIZE; st == EZ_OK && a < EZ_META_SIZE; a += sizeof z) {
		uint32_t n = EZ_META_SIZE - a < sizeof z ? EZ_META_SIZE - a : (uint32_t)sizeof z;
		st = wr(m, a, z, n);
	}
	/* The critical toggles start clear (they are outside the area above). */
	if (st == EZ_OK) {
		static const uint8_t z3[3];
		st = wr(m, EZ_META_CRIT_ADDR, z3, sizeof z3);
	}
	/* 3. Write the new device record last. */
	uint8_t d[EZ_META_DEV_SIZE];
	encode_dev(d, 0);
	if (st == EZ_OK)
		st = wr(m, EZ_META_DEV_ADDR, d, sizeof d);
	if (st != EZ_OK) {
		m->dev = EZ_DEV_FAULT;
		return st;
	}
	parse_dev(m, d);
	load_sessions(m);
	m->log_next_seq = 0;
	ez_meta_log_append(m, EZ_EV_DEVICE_INIT, 0, 0, 0);
	return EZ_OK;
}

ez_status_t ez_meta_repair(ez_meta_t *m)
{
	if (m->dev != EZ_DEV_FAULT)
		return EZ_ERR_STATE;
	/* Continue the boot counter from the larger valid slot (if any). */
	uint32_t next = m->boot_count == UINT32_MAX ? UINT32_MAX : m->boot_count + 1;
	uint8_t d[EZ_META_DEV_SIZE];
	encode_dev(d, next);
	ez_status_t st = wr(m, EZ_META_DEV_ADDR, d, sizeof d);
	if (st != EZ_OK)
		return st;
	parse_dev(m, d);
	ez_meta_log_append(m, EZ_EV_DEVICE_REPAIR, 0, 0, 0);
	return EZ_OK;
}

/* ===================================================================== */
/* Sessions                                                              */
/* ===================================================================== */

static bool slot_index_ok(int i) { return i >= 0 && i < EZ_META_SESSIONS; }

ez_status_t ez_meta_check_alloc(const ez_meta_t *m, int slot)
{
	if (!slot_index_ok(slot))
		return EZ_ERR_BAD_REQUEST;
	uint32_t a = sess_addr(slot), e = a + EZ_META_SESSION_SIZE;
	if (a < EZ_META_SESSION_ADDR || e > EZ_META_LOG_ADDR)
		return EZ_ERR_META;
	if (m->s[slot].state != EZ_SS_EMPTY)
		return EZ_ERR_EXISTS;
	for (int j = 0; j < EZ_META_SESSIONS; j++) {
		if (j == slot || m->s[j].state == EZ_SS_EMPTY) continue;
		uint32_t b = sess_addr(j), f = b + EZ_META_SESSION_SIZE;
		if (a < f && b < e)
			return EZ_ERR_EXISTS;
	}
	return EZ_OK;
}

int ez_meta_find_key_id(const ez_meta_t *m, uint32_t key_id)
{
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		if (m->s[i].state != EZ_SS_EMPTY && m->s[i].identity && m->s[i].key_id == key_id)
			return i;
	return -1;
}

int ez_meta_find_label(const ez_meta_t *m, const char *label)
{
	if (!label) return -1;
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		if (m->s[i].state != EZ_SS_EMPTY && m->s[i].identity &&
		    strncmp(m->s[i].label, label, EZ_LABEL_MAX + 1) == 0)
			return i;
	return -1;
}

ez_status_t ez_meta_session_create(ez_meta_t *m, const ez_session_params_t *p, int *slot_out)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	/* SEC-STORE-002, SEC-STORE-003 */
	if (p->key_id == 0 || p->key_len == 0 || (p->key_len & 1u))
		return EZ_ERR_KEY_PARAM;
	if ((p->role != EZ_ROLE_ALICE && p->role != EZ_ROLE_BOB && p->role != EZ_ROLE_DEFAULT) ||
	    p->drive > 2 || !label_valid(p->label, NULL))
		return EZ_ERR_BAD_REQUEST;

	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &m->s[i];
		if (s->state == EZ_SS_EMPTY) continue;
		if (!s->identity)
			return EZ_ERR_UNRESOLVED;          /* IMPL-META-007 */
		if (s->key_id == p->key_id)
			return EZ_ERR_EXISTS;              /* SEC-ISO-002 */
		if (strncmp(s->label, p->label, EZ_LABEL_MAX + 1) == 0)
			return EZ_ERR_EXISTS;
	}

	int slot = -1;
	for (int i = 0; i < EZ_META_SESSIONS; i++)
		if (m->s[i].state == EZ_SS_EMPTY) { slot = i; break; }
	if (slot < 0)
		return EZ_ERR_FULL;
	ez_status_t st = ez_meta_check_alloc(m, slot);   /* SEC-META-004 */
	if (st != EZ_OK)
		return st;

	uint8_t role = p->role;
	if (role == EZ_ROLE_DEFAULT)                       /* IMPL-LOG-002 */
		role = log_has_generated(m, p->key_id) ? EZ_ROLE_ALICE : EZ_ROLE_BOB;

	if ((st = crit_clear(m, slot)) != EZ_OK)
		return st;
	uint8_t r[EZ_META_SESSION_SIZE];
	encode_new_session(slot, p, role, r);
	/* IMPL-META-004: full record with status EMPTY, then the status byte. */
	st = wr(m, sess_addr(slot), r, sizeof r);
	if (st == EZ_OK)
		st = wr_byte(m, sess_addr(slot) + EZ_SR_OFF_STATUS, EZ_ST_VALID);
	if (st != EZ_OK)
		return st;
	r[EZ_SR_OFF_STATUS] = EZ_ST_VALID;
	parse_session(slot, r, &m->s[slot]);
	if (slot_out) *slot_out = slot;
	return EZ_OK;
}

ez_status_t ez_meta_session_delete(ez_meta_t *m, int slot)
{
	if (m->dev == EZ_DEV_UNINIT)
		return EZ_ERR_DEVICE;
	if (!slot_index_ok(slot))
		return EZ_ERR_BAD_REQUEST;
	if (m->s[slot].state == EZ_SS_EMPTY)
		return EZ_ERR_NO_SESSION;
	/* IMPL-META-004: status first, then clear the record. */
	ez_status_t st = wr_byte(m, sess_addr(slot) + EZ_SR_OFF_STATUS, EZ_ST_EMPTY0);
	if (st != EZ_OK)
		return st;
	ez_secure_zero(&m->s[slot], sizeof m->s[slot]);
	m->s[slot].state = EZ_SS_EMPTY;
	uint8_t z[EZ_META_SESSION_SIZE];
	memset(z, 0, sizeof z);
	st = wr(m, sess_addr(slot), z, sizeof z);
	if (st == EZ_OK) st = crit_clear(m, slot);
	return st;
}

ez_status_t ez_meta_set_critical(ez_meta_t *m, int slot, bool on)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (!slot_index_ok(slot) || m->s[slot].state == EZ_SS_EMPTY || !m->s[slot].identity)
		return EZ_ERR_BAD_REQUEST;
	ez_session_t *s = &m->s[slot];
	if (((s->flags & EZ_SESS_CRITICAL) != 0) == on)
		return EZ_OK;
	uint8_t b = crit_byte(m, slot) ^ (uint8_t)(1u << (slot % 8));
	ez_status_t st = wr_byte(m, EZ_META_CRIT_ADDR + (uint32_t)slot / 8u, b);   /* one byte: atomic */
	if (st != EZ_OK)
		return st;
	s->flags ^= EZ_SESS_CRITICAL;
	return EZ_OK;
}

static ez_status_t commit(ez_meta_t *m, int slot, int w, uint32_t n)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (!slot_index_ok(slot))
		return EZ_ERR_BAD_REQUEST;
	ez_session_t *s = &m->s[slot];
	switch (s->state) {
	case EZ_SS_EMPTY:       return EZ_ERR_NO_SESSION;
	case EZ_SS_QUARANTINED: return EZ_ERR_QUARANTINED;      /* SEC-UI-004 */
	case EZ_SS_EXHAUSTED:   if (w == 0) return EZ_ERR_CAPACITY; break;
	case EZ_SS_VALID:       break;
	}

	uint32_t cur = w == 0 ? s->tx_off : s->rx_off, rs, re;
	range_of(s, w, &rs, &re);
	if (n <= cur) {
		/* SEC-PTR-002: rejected and logged (the log never holds offsets:
		 * arg is 0 for TX, 1 for RX; detail is the slot). */
		ez_meta_log_append(m, EZ_EV_ROLLBACK, (uint8_t)slot, s->key_id, (uint32_t)w);
		return EZ_ERR_ROLLBACK;
	}
	if (n > re)
		return EZ_ERR_RANGE;                                  /* SEC-ISO-001 */

	static const uint8_t tags[2] = { TAG_TX, TAG_RX };
	uint32_t base = sess_addr(slot);
	uint32_t sel_addr = base + (w == 0 ? EZ_SR_OFF_TX_SEL : EZ_SR_OFF_RX_SEL);
	uint32_t slot_addr[2] = {
		base + (w == 0 ? EZ_SR_OFF_TX_A : EZ_SR_OFF_RX_A),
		base + (w == 0 ? EZ_SR_OFF_TX_B : EZ_SR_OFF_RX_B) };
	int sel = s->sel[w], oth = 1 - sel;

	/* Step 2: normalise, so the slot about to be overwritten never holds
	 * the effective value. */
	if (s->slot_ok[w][oth] && s->slot_val[w][oth] > s->slot_val[w][sel]) {
		if (wr_byte(m, sel_addr, oth == 0 ? EZ_SEL_A : EZ_SEL_B) != EZ_OK) {
			quarantine_ram(s, EZ_Q_COMMIT_VERIFY);
			return EZ_ERR_META;
		}
		s->sel[w] = (uint8_t)oth;
		sel = oth; oth = 1 - sel;
	}

	/* Step 3: write the new value into the non-selected slot. */
	uint8_t b[EZ_SLOT_SIZE];
	slot_encode(b, tags[w], (uint8_t)slot, (uint8_t)oth, n);
	if (wr(m, slot_addr[oth], b, sizeof b) != EZ_OK) {
		s->slot_ok[w][oth] = false;     /* contents unknown; ignored on read */
		return EZ_ERR_META;
	}
	s->slot_val[w][oth] = n;
	s->slot_ok[w][oth] = true;

	/* Step 4: flip the selector (single atomic byte). */
	if (wr_byte(m, sel_addr, oth == 0 ? EZ_SEL_A : EZ_SEL_B) != EZ_OK) {
		quarantine_ram(s, EZ_Q_COMMIT_VERIFY);
		return EZ_ERR_META;
	}
	s->sel[w] = (uint8_t)oth;
	if (w == 0) s->tx_off = n; else s->rx_off = n;
	if (w == 0) derive_state(s);                              /* IMPL-META-005 */
	return EZ_OK;
}

ez_status_t ez_meta_commit_tx(ez_meta_t *m, int slot, uint32_t new_off)
{
	return commit(m, slot, 0, new_off);
}

ez_status_t ez_meta_commit_rx(ez_meta_t *m, int slot, uint32_t new_off)
{
	return commit(m, slot, 1, new_off);
}

ez_status_t ez_meta_quarantine(ez_meta_t *m, int slot, uint8_t reason)
{
	/* Quarantining only ever makes a session less usable, so it is also
	 * permitted on a faulty device (needed by device erase, SEC-PTR-004). */
	if (m->dev != EZ_DEV_VALID && m->dev != EZ_DEV_FAULT)
		return EZ_ERR_DEVICE;
	if (!slot_index_ok(slot) || reason < EZ_Q_KEY_MISSING || reason > EZ_Q_KEY_DAMAGED)
		return EZ_ERR_BAD_REQUEST;
	ez_session_t *s = &m->s[slot];
	if (s->state != EZ_SS_VALID && s->state != EZ_SS_EXHAUSTED)
		return EZ_ERR_STATE;
	uint32_t base = sess_addr(slot);
	static const uint8_t code[5] = { 0, EZ_QC_KEY_MISSING, EZ_QC_KEY_SIZE,
	                                 EZ_QC_KEY_ERASING, EZ_QC_KEY_DAMAGED };
	ez_status_t st = wr_byte(m, base + EZ_SR_OFF_QREASON, code[reason]);
	if (st == EZ_OK)
		st = wr_byte(m, base + EZ_SR_OFF_STATUS, EZ_ST_QUARANTINED);
	if (st != EZ_OK) {
		quarantine_ram(s, EZ_Q_COMMIT_VERIFY);
		return st;
	}
	s->state = EZ_SS_QUARANTINED;
	s->qreason = reason;
	ez_meta_log_append(m, EZ_EV_QUARANTINE, reason, s->key_id, (uint32_t)slot);
	return EZ_OK;
}

ez_status_t ez_meta_resolve(ez_meta_t *m, int slot)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (!slot_index_ok(slot))
		return EZ_ERR_BAD_REQUEST;
	ez_session_t *s = &m->s[slot];
	if (s->state != EZ_SS_QUARANTINED)
		return EZ_ERR_STATE;
	if (s->qreason >= 0x80 || s->qreason == EZ_Q_KEY_ERASING ||
	    s->qreason == EZ_Q_KEY_DAMAGED || !s->identity || !s->offsets)
		return EZ_ERR_QUARANTINED;   /* delete only (IMPL-META-006) */
	ez_status_t st = wr_byte(m, sess_addr(slot) + EZ_SR_OFF_STATUS, EZ_ST_VALID);
	if (st != EZ_OK)
		return st;
	s->qreason = EZ_Q_NONE;
	derive_state(s);
	return EZ_OK;
}

bool ez_meta_can_encrypt(const ez_meta_t *m, int slot)
{
	return m->dev == EZ_DEV_VALID && slot_index_ok(slot) &&
	       m->s[slot].state == EZ_SS_VALID;
}

bool ez_meta_can_decrypt(const ez_meta_t *m, int slot)
{
	return m->dev == EZ_DEV_VALID && slot_index_ok(slot) &&
	       (m->s[slot].state == EZ_SS_VALID || m->s[slot].state == EZ_SS_EXHAUSTED);
}

/* ===================================================================== */
/* Device settings                                                       */
/* ===================================================================== */

ez_status_t ez_meta_set_drive0(ez_meta_t *m, bool enabled)
{
	if (m->dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	ez_status_t st = wr_byte(m, EZ_META_DEV_ADDR + EZ_DEV_OFF_DRIVE0,
	                         enabled ? EZ_DRIVE0_ENABLED : EZ_DRIVE0_DISABLED);
	if (st != EZ_OK) {
		m->dev = EZ_DEV_FAULT;
		m->drive0_enabled = false;
		return st;
	}
	m->drive0_enabled = enabled;
	ez_meta_log_append(m, enabled ? EZ_EV_DRIVE0_ON : EZ_EV_DRIVE0_OFF, 0, 0, 0);
	return EZ_OK;
}

/* ===================================================================== */
/* Reserved region                                                       */
/* ===================================================================== */

static bool aux_ok(uint32_t addr, uint32_t len)
{
	return addr >= EZ_META_RESERVED_ADDR && len <= EZ_META_SIZE - addr;
}

ez_status_t ez_meta_aux_read(ez_meta_t *m, uint32_t addr, void *buf, uint32_t len)
{
	if (!m->hal || !aux_ok(addr, len)) return EZ_ERR_BAD_REQUEST;
	return rd(m, addr, buf, len);
}

ez_status_t ez_meta_aux_write(ez_meta_t *m, uint32_t addr, const void *buf, uint32_t len)
{
	if (!m->hal || !aux_ok(addr, len)) return EZ_ERR_BAD_REQUEST;
	return wr(m, addr, buf, len);
}
