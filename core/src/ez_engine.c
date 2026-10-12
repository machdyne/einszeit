/*
 * ez_engine.c -- see ez_engine.h for the API contract and traceability.
 */
#include "ez_engine.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"

/* ===================================================================== */
/* Shared helpers                                                        */
/* ===================================================================== */

/* IMPL-ENG-001, part 1 (no storage access): the session exists, is usable
 * for this direction, and the device is valid. */
static ez_status_t session_check(ez_core_t *c, int slot, int dir)
{
	if (slot < 0 || slot >= EZ_META_SESSIONS)
		return EZ_ERR_BAD_REQUEST;
	const ez_session_t *s = &c->meta.s[slot];
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	switch (s->state) {
	case EZ_SS_EMPTY:       return EZ_ERR_NO_SESSION;
	case EZ_SS_QUARANTINED: return EZ_ERR_QUARANTINED;     /* SEC-UI-004 */
	case EZ_SS_EXHAUSTED:   if (dir == 0) return EZ_ERR_CAPACITY; break;
	case EZ_SS_VALID:       break;
	}
	return EZ_OK;
}

/* IMPL-ENG-001, part 2: the key file and its integrity file are present,
 * match the record, and the medium is the one mounted. */
static ez_status_t session_open(ez_core_t *c, int slot)
{
	const ez_session_t *s = &c->meta.s[slot];
	ez_status_t st = ez_core_drive_usable(c, s->drive);
	if (st != EZ_OK)
		return st;
	char name[EZ_FNAME_MAX];
	ez_key_name(s->key_id, "KEY", name);
	uint32_t size = 0;
	st = c->ks->size(c->ks->ctx, s->drive, name, &size);
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
	uint16_t instance = 0;
	st = ez_sum_check(c, s->drive, s->key_id, s->key_len, &instance);
	if (st == EZ_ERR_UNVERIFIED) {
		ez_meta_quarantine(&c->meta, slot, EZ_Q_KEY_MISSING);
		return EZ_ERR_QUARANTINED;
	}
	if (st != EZ_OK)
		return st;
	/* IMPL-KEY-005: a different key under the same Key ID (another card)
	 * carries a different instance tag. */
	if (instance != s->instance) {
		c->damage.valid = true;
		c->damage.key_id = s->key_id;
		c->damage.unit = UINT32_MAX;
		return EZ_ERR_KEY_DAMAGED;
	}
	return c->ks->check(c->ks->ctx, s->drive);              /* IMPL-ENG-010 */
}

/* IMPL-ENG-012: a run of this many identical 0x00 or 0xFF key bytes means
 * erased or damaged key data (zeroed file, erased flash, unwritten
 * sectors). For TRNG output the probability anywhere in a 64 MiB key is
 * below 2^-100. Defence in depth: the primary protection against using a
 * partly erased key is SEC-PTR-004's quarantine-before-erase. */
#define EZ_DAMAGE_RUN 16u

typedef struct { uint32_t *run0, *runff; } key_track_t;

/* XOR n key bytes starting at absolute offset abs into buf, using only
 * [lo, hi). Key bytes come only from the verified unit buffer
 * (IMPL-ENG-013, SEC-STORE-004): a unit is read whole, its tag checked,
 * and only then are its bytes used -- no second read, so nothing can
 * change between verification and use. */
static ez_status_t key_xor(ez_core_t *c, const ez_session_t *s,
                           uint32_t abs, uint8_t *buf, uint32_t n,
                           uint32_t lo, uint32_t hi, key_track_t t)
{
	/* SEC-ISO-001: defence in depth; callers have already checked. */
	if (abs < lo || (uint64_t)abs + n > hi)
		return EZ_ERR_RANGE;
	ez_status_t st = EZ_OK;
	while (n && st == EZ_OK) {
		st = ez_unit_load(c, s->drive, s->key_id, s->key_len, ez_unit_index(s->key_len, abs));
		if (st != EZ_OK)
			break;
		uint32_t off = abs - c->u_start;
		uint32_t piece = c->u_len - off < n ? c->u_len - off : n;
		for (uint32_t i = 0; i < piece; i++) {      /* SEC-ENC-001, SEC-KDF-001 */
			uint8_t k = c->ubuf[off + i];
			*t.run0  = (k == 0x00) ? *t.run0 + 1 : 0;
			*t.runff = (k == 0xFF) ? *t.runff + 1 : 0;
			if (*t.run0 >= EZ_DAMAGE_RUN || *t.runff >= EZ_DAMAGE_RUN)
				st = EZ_ERR_KEY_DAMAGED;  /* callers clear buf and never output it */
			buf[i] ^= k;
		}
		abs += piece; buf += piece; n -= piece;
	}
	return st;
}

static uint32_t crc_hdr(const uint8_t hdr[EZ_MSG_HDR])
{
	return ez_crc32_update(EZ_CRC32_INIT, hdr, EZ_MSG_HDR);
}

/* Session selection and range checks for decryption, all before any key
 * byte is read (SEC-DEC-001/002/003, IMPL-MSG-001). */
static ez_status_t dec_select(ez_core_t *c, int slot, const ez_msg_hdr_t *h, int *out)
{
	if (slot < 0) {
		slot = ez_meta_find_key_id(&c->meta, h->key_id);
		if (slot < 0)
			return EZ_ERR_NO_SESSION;
	} else if (slot >= EZ_META_SESSIONS) {
		return EZ_ERR_BAD_REQUEST;
	} else if (!c->meta.s[slot].identity || c->meta.s[slot].key_id != h->key_id) {
		return c->meta.s[slot].state == EZ_SS_EMPTY ? EZ_ERR_NO_SESSION : EZ_ERR_KEY_ID;
	}
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state == EZ_SS_QUARANTINED)
		return EZ_ERR_QUARANTINED;
	if (!s->offsets)
		return EZ_ERR_QUARANTINED;
	uint32_t rs, re;
	ez_range_rx(s->key_len, s->role, &rs, &re);
	if (h->length == 0)
		return EZ_ERR_BAD_REQUEST;
	if (h->offset < rs || (uint64_t)h->offset + h->length > re)
		return EZ_ERR_RANGE;                               /* SEC-DEC-001 */
	if (h->offset < s->rx_off)
		return EZ_ERR_REPLAY;                              /* SEC-DEC-003 */
	*out = slot;
	return EZ_OK;
}

/* ===================================================================== */
/* Buffered mode                                                         */
/* ===================================================================== */

void ez_release(ez_core_t *c)
{
	if (c->stage)
		ez_secure_zero(c->stage, c->stage_cap);           /* SEC-ENC-003, SEC-FW-003 */
	c->stage_state = EZ_STAGE_EMPTY;
	c->stage_len = c->out_off = c->out_len = 0;
	if (!c->stream_active)
		ez_unit_drop(c);
}

uint8_t *ez_stage_plaintext(ez_core_t *c, uint32_t len)
{
	ez_release(c);                                        /* IMPL-ENG-009 */
	if (len == 0 || len > EZ_BUFFERED_MAX || c->stream_active)
		return NULL;
	c->stage_state = EZ_STAGE_PLAIN_IN;
	c->stage_len = len;
	return c->stage + EZ_MSG_HDR;
}

uint8_t *ez_stage_message(ez_core_t *c, uint32_t len)
{
	ez_release(c);
	if (len <= EZ_MSG_OVERHEAD || len > EZ_STAGE_SIZE || c->stream_active)
		return NULL;
	c->stage_state = EZ_STAGE_MSG_IN;
	c->stage_len = len;
	return c->stage;
}

const uint8_t *ez_retained(const ez_core_t *c, uint32_t *len)
{
	if (c->stage_state != EZ_STAGE_CIPHERTEXT && c->stage_state != EZ_STAGE_PLAINTEXT) {
		*len = 0;
		return NULL;
	}
	*len = c->out_len;
	return c->stage + c->out_off;
}

ez_status_t ez_encrypt_buffered(ez_core_t *c, int slot, uint32_t len,
                                const uint8_t **out, uint32_t *out_len)
{
	*out = NULL; *out_len = 0;
	if (c->stage_state != EZ_STAGE_PLAIN_IN || c->stage_len != len)
		return EZ_ERR_BAD_REQUEST;
	ez_status_t st = session_check(c, slot, 0);
	const ez_session_t *s = &c->meta.s[slot >= 0 && slot < EZ_META_SESSIONS ? slot : 0];
	if (st == EZ_OK && len > ez_meta_tx_remaining(s))
		st = EZ_ERR_CAPACITY;                              /* before any key read */
	if (st == EZ_OK)
		st = session_open(c, slot);
	if (st != EZ_OK) {
		ez_release(c);                                     /* nothing spent */
		return st;
	}
	uint32_t ts, te, base = s->tx_off, r0 = 0, rf = 0;
	ez_range_tx(s->key_len, s->role, &ts, &te);
	uint8_t *pt = c->stage + EZ_MSG_HDR;

	/* XOR in place: the plaintext is overwritten as ciphertext is made. */
	st = key_xor(c, s, base, pt, len, base, te, (key_track_t){ &r0, &rf });
	ez_unit_drop(c);
	/* Card still present and unchanged immediately before the commit. */
	if (st == EZ_OK)
		st = c->ks->check(c->ks->ctx, s->drive);
	if (st == EZ_OK)
		st = ez_meta_commit_tx(&c->meta, slot, base + len); /* SEC-PTR-003 */
	if (st != EZ_OK) {
		ez_release(c);                       /* SEC-TEST-MEDIA-001 (a): no output */
		return st;
	}
	/* Committed: assemble the message around the ciphertext. */
	ez_msg_hdr_t h = { s->key_id, base, len };
	ez_msg_hdr_encode(&h, c->stage);
	uint32_t crc = ez_crc32(c->stage, EZ_MSG_HDR + len);
	ez_put_le32(c->stage + EZ_MSG_HDR + len, crc);
	c->stage_state = EZ_STAGE_CIPHERTEXT;
	c->out_off = 0;
	c->out_len = EZ_MSG_OVERHEAD + len;
	*out = c->stage;
	*out_len = c->out_len;
	return EZ_OK;
}

ez_status_t ez_decrypt_buffered(ez_core_t *c, int slot, uint32_t msg_len,
                                const uint8_t **pt, uint32_t *pt_len)
{
	*pt = NULL; *pt_len = 0;
	if (c->stage_state != EZ_STAGE_MSG_IN || c->stage_len != msg_len)
		return EZ_ERR_BAD_REQUEST;
	ez_msg_hdr_t h;
	ez_status_t st = ez_msg_hdr_decode(c->stage, &h);
	if (st == EZ_OK && (uint64_t)h.length + EZ_MSG_OVERHEAD != msg_len)
		st = EZ_ERR_BAD_REQUEST;
	if (st == EZ_OK)
		st = dec_select(c, slot, &h, &slot);
	/* Integrity first: a damaged message is rejected before any key byte
	 * is read. */
	if (st == EZ_OK &&
	    ez_crc32(c->stage, EZ_MSG_HDR + h.length) != ez_get_le32(c->stage + EZ_MSG_HDR + h.length))
		st = EZ_ERR_INTEGRITY;
	if (st == EZ_OK)
		st = session_check(c, slot, 1);
	if (st == EZ_OK)
		st = session_open(c, slot);
	if (st != EZ_OK) {
		ez_release(c);
		return st;
	}
	const ez_session_t *s = &c->meta.s[slot];
	uint32_t r0 = 0, rf = 0;
	uint8_t *buf = c->stage + EZ_MSG_HDR;
	st = key_xor(c, s, h.offset, buf, h.length, h.offset, h.offset + h.length,
	             (key_track_t){ &r0, &rf });
	ez_unit_drop(c);
	if (st == EZ_OK)
		st = c->ks->check(c->ks->ctx, s->drive);
	if (st == EZ_OK)
		st = ez_meta_commit_rx(&c->meta, slot, h.offset + h.length);  /* SEC-DEC-004 */
	if (st != EZ_OK) {
		ez_release(c);                     /* clears partial plaintext */
		return st;
	}
	c->stage_state = EZ_STAGE_PLAINTEXT;
	c->out_off = EZ_MSG_HDR;
	c->out_len = h.length;
	*pt = buf;
	*pt_len = h.length;
	return EZ_OK;
}

/* ===================================================================== */
/* Streaming mode                                                        */
/* ===================================================================== */

uint32_t ez_stream_spent(const ez_stream_t *st) { return st->committed; }

void ez_stream_abort(ez_core_t *c, ez_stream_t *st)
{
	st->active = 0;
	c->stream_active = false;
	ez_unit_drop(c);
}

static ez_status_t stream_fail(ez_core_t *c, ez_stream_t *st, uint8_t *buf,
                               uint32_t n, ez_status_t err)
{
	if (buf) ez_secure_zero(buf, n);
	ez_stream_abort(c, st);
	return err;
}

ez_status_t ez_enc_stream_begin(ez_core_t *c, ez_stream_t *st, int slot,
                                uint32_t len, uint8_t hdr[EZ_MSG_HDR])
{
	memset(st, 0, sizeof *st);
	if (c->stream_active)
		return EZ_ERR_BUSY;
	if (len == 0)
		return EZ_ERR_BAD_REQUEST;
	ez_release(c);
	ez_status_t r = session_check(c, slot, 0);
	if (r != EZ_OK)
		return r;
	const ez_session_t *s = &c->meta.s[slot];
	if (len > ez_meta_tx_remaining(s))
		return EZ_ERR_CAPACITY;                            /* before any storage access */
	if ((r = session_open(c, slot)) != EZ_OK)
		return r;
	st->slot = slot; st->dir = 0; st->drive = s->drive; st->key_id = s->key_id;
	st->base = s->tx_off; st->len = len;
	ez_msg_hdr_t h = { s->key_id, st->base, len };
	ez_msg_hdr_encode(&h, hdr);
	st->crc = crc_hdr(hdr);
	st->active = 1;
	c->stream_active = true;
	/* The header carries no ciphertext; outputting it spends nothing. */
	return EZ_OK;
}

ez_status_t ez_enc_stream_update(ez_core_t *c, ez_stream_t *st, uint8_t *buf, uint32_t n)
{
	if (!st->active || st->dir != 0)
		return stream_fail(c, st, buf, n, EZ_ERR_STATE);
	if (n == 0 || (uint64_t)st->done + n > st->len)
		return stream_fail(c, st, buf, n, EZ_ERR_BAD_REQUEST);
	const ez_session_t *s = &c->meta.s[st->slot];
	uint32_t abs = st->base + st->done;
	/* The engine's view of the session must still match the stream. */
	if (s->state != EZ_SS_VALID || s->tx_off != abs)
		return stream_fail(c, st, buf, n, EZ_ERR_STATE);
	ez_status_t r = key_xor(c, s, abs, buf, n, st->base, st->base + st->len,
	                        (key_track_t){ &st->run0, &st->runff });
	if (r == EZ_OK)
		r = c->ks->check(c->ks->ctx, st->drive);          /* before the commit */
	if (r == EZ_OK)
		r = ez_meta_commit_tx(&c->meta, st->slot, abs + n);  /* IMPL-ENG-004 */
	if (r != EZ_OK)
		return stream_fail(c, st, buf, n, r);     /* no output for this chunk */
	st->committed += n;
	st->done += n;
	st->crc = ez_crc32_update(st->crc, buf, n);
	return EZ_OK;
}

ez_status_t ez_enc_stream_end(ez_core_t *c, ez_stream_t *st, uint8_t trl[EZ_MSG_TRL])
{
	if (!st->active || st->dir != 0 || st->done != st->len)
		return stream_fail(c, st, NULL, 0, EZ_ERR_STATE);
	ez_put_le32(trl, ez_crc32_final(st->crc));
	ez_stream_abort(c, st);       /* normal completion: same cleanup */
	return EZ_OK;
}

ez_status_t ez_dec_stream_begin(ez_core_t *c, ez_stream_t *st, int slot,
                                const uint8_t hdr[EZ_MSG_HDR])
{
	memset(st, 0, sizeof *st);
	if (c->stream_active)
		return EZ_ERR_BUSY;
	ez_release(c);
	ez_msg_hdr_t h;
	ez_status_t r = ez_msg_hdr_decode(hdr, &h);
	if (r == EZ_OK)
		r = dec_select(c, slot, &h, &slot);
	if (r == EZ_OK)
		r = session_check(c, slot, 1);
	if (r == EZ_OK)
		r = session_open(c, slot);
	if (r != EZ_OK)
		return r;
	st->slot = slot; st->dir = 1; st->drive = c->meta.s[slot].drive;
	st->key_id = h.key_id; st->base = h.offset; st->len = h.length;
	st->crc = crc_hdr(hdr);
	st->active = 1;
	c->stream_active = true;
	return EZ_OK;
}

ez_status_t ez_dec_stream_update(ez_core_t *c, ez_stream_t *st, uint8_t *buf, uint32_t n)
{
	if (!st->active || st->dir != 1)
		return stream_fail(c, st, buf, n, EZ_ERR_STATE);
	if (n == 0 || (uint64_t)st->done + n > st->len)
		return stream_fail(c, st, buf, n, EZ_ERR_BAD_REQUEST);
	st->crc = ez_crc32_update(st->crc, buf, n);          /* CRC is over ciphertext */
	ez_status_t r = key_xor(c, &c->meta.s[st->slot], st->base + st->done, buf, n,
	                        st->base, st->base + st->len, (key_track_t){ &st->run0, &st->runff });
	if (r != EZ_OK)
		return stream_fail(c, st, buf, n, r);
	st->done += n;
	return EZ_OK;
}

ez_status_t ez_dec_stream_end(ez_core_t *c, ez_stream_t *st, const uint8_t trl[EZ_MSG_TRL])
{
	if (!st->active || st->dir != 1 || st->done != st->len)
		return stream_fail(c, st, NULL, 0, EZ_ERR_STATE);
	ez_status_t r = EZ_OK;
	if (ez_crc32_final(st->crc) != ez_get_le32(trl))
		r = EZ_ERR_INTEGRITY;                              /* IMPL-ENG-006 */
	if (r == EZ_OK)
		r = c->ks->check(c->ks->ctx, st->drive);
	/* The RX offset may have moved while the stream ran (it cannot: the
	 * dispatcher serialises), but re-check rather than assume. */
	if (r == EZ_OK && c->meta.s[st->slot].rx_off > st->base)
		r = EZ_ERR_REPLAY;
	if (r == EZ_OK)
		r = ez_meta_commit_rx(&c->meta, st->slot, st->base + st->len);
	ez_stream_abort(c, st);
	return r;
}

/* ===================================================================== */
/* Skipping damaged key units (IMPL-ENG-014)                             */
/* ===================================================================== */

ez_status_t ez_session_skip(ez_core_t *c, int slot, uint32_t *units)
{
	*units = 0;
	if (c->stream_active)
		return EZ_ERR_BUSY;
	ez_status_t st = session_check(c, slot, 0);
	if (st == EZ_OK)
		st = session_open(c, slot);
	if (st != EZ_OK)
		return st;
	const ez_session_t *s = &c->meta.s[slot];
	uint32_t ts, te;
	ez_range_tx(s->key_len, s->role, &ts, &te);
	uint32_t first = ez_unit_index(s->key_len, s->tx_off);
	uint32_t last = ez_unit_index(s->key_len, te - 1);
	/* Skip only damage that an operation actually reported, ahead in the
	 * TX range, and that is still there. */
	if (!c->damage.valid || c->damage.key_id != s->key_id ||
	    c->damage.unit < first || c->damage.unit > last)
		return EZ_ERR_STATE;
	uint32_t i = c->damage.unit;
	st = ez_unit_load(c, s->drive, s->key_id, s->key_len, i);
	ez_unit_drop(c);
	if (st == EZ_OK) {
		c->damage.valid = false;
		return EZ_ERR_STATE;                   /* no longer damaged */
	}
	if (st != EZ_ERR_KEY_DAMAGED)
		return st;
	/* Advance over consecutive damaged units to the first that verifies.
	 * Skipping only moves forward: it wastes key, never reuses it. */
	uint32_t n = 1, next = te;
	for (uint32_t j = i + 1; j <= last; j++) {
		st = ez_unit_load(c, s->drive, s->key_id, s->key_len, j);
		ez_unit_drop(c);
		if (st == EZ_OK) {
			uint32_t len;
			ez_unit_geom(s->key_len, j, &next, &len);
			break;
		}
		if (st != EZ_ERR_KEY_DAMAGED)
			return st;
		n++;
	}
	if ((st = ez_meta_commit_tx(&c->meta, slot, next)) != EZ_OK)
		return st;
	c->damage.valid = false;
	ez_meta_log_append(&c->meta, EZ_EV_SKIP, (uint8_t)(n > 255 ? 255 : n), s->key_id, 0);
	*units = n;
	return EZ_OK;
}
