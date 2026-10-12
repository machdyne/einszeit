/*
 * ez_import.c -- see ez_import.h for the procedure and traceability.
 */
#include "ez_import.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_engine.h"
#include "ez_secure.h"

#define DUP_MAX_UNITS 16384u          /* fills the staging buffer exactly */
#define DUP_IDX_BITS  14u

static char up(char ch) { return (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch; }

static bool has_ext(const char *name, const char *ext)
{
	size_t n = strlen(name);
	return n >= 4 && name[n - 4] == '.' && up(name[n - 3]) == ext[0] &&
	       up(name[n - 2]) == ext[1] && up(name[n - 1]) == ext[2];
}

static void clear_job(ez_core_t *c, ez_import_t *im)
{
	ez_secure_zero(&im->acc, sizeof im->acc);
	ez_secure_zero(im->tags, sizeof im->tags);
	im->ntags = 0;
	ez_unit_drop(c);
	ez_secure_zero(c->kbuf, sizeof c->kbuf);
	if (!im->have_sum) {
		ez_secure_zero(c->stage, c->stage_cap);   /* block fingerprints */
		c->stage_state = EZ_STAGE_EMPTY;
	}
}

static ez_status_t fail(ez_core_t *c, ez_import_t *im, ez_status_t st)
{
	char sut[EZ_FNAME_MAX];
	clear_job(c, im);
	if (!im->have_sum) {
		ez_key_name(im->key_id, "SUT", sut);
		c->ks->zap(c->ks->ctx, im->drive, sut);
	}
	im->state = EZ_IM_DONE;
	im->result = st;
	return st;
}

ez_status_t ez_import_start(ez_core_t *c, ez_import_t *im, uint8_t drive, const char *file,
                            uint32_t key_id, uint8_t role, const char *label)
{
	memset(im, 0, sizeof *im);
	im->slot = -1;
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (c->stream_active)
		return EZ_ERR_BUSY;
	if (key_id == 0)
		return EZ_ERR_KEY_PARAM;
	if (!file || strlen(file) >= EZ_NAME_MAX || has_ext(file, "TMP") ||
	    has_ext(file, "SUT") || has_ext(file, "SUM") ||
	    !label || strlen(label) == 0 || strlen(label) > EZ_LABEL_MAX)
		return EZ_ERR_BAD_REQUEST;
	ez_status_t st = ez_core_drive_usable(c, drive);
	if (st != EZ_OK)
		return st;
	/* Refuse up front what session creation would refuse (SEC-ISO-002). */
	if (ez_meta_find_key_id(&c->meta, key_id) >= 0 || ez_meta_find_label(&c->meta, label) >= 0)
		return EZ_ERR_EXISTS;
	uint32_t size, dummy;
	if ((st = c->ks->size(c->ks->ctx, drive, file, &size)) != EZ_OK)
		return st;
	if (size == 0 || (size & 1u))
		return EZ_ERR_KEY_PARAM;                         /* SEC-STORE-003 */
	char key[EZ_FNAME_MAX];
	ez_key_name(key_id, "KEY", key);
	bool same = strlen(file) == strlen(key);
	for (size_t i = 0; same && file[i]; i++) same = up(file[i]) == key[i];
	if (!same && c->ks->size(c->ks->ctx, drive, key, &dummy) != EZ_ERR_NOT_FOUND)
		return EZ_ERR_EXISTS;

	memcpy(im->src, file, strlen(file) + 1);
	memcpy(im->label, label, strlen(label) + 1);
	im->drive = drive;
	im->role = role;
	im->key_id = key_id;
	im->key_len = size;
	im->units = ez_unit_count(size);

	/* The source file is opened as <ID>.KEY for unit loading only after
	 * the rename; until then units are read from the source name. */
	st = ez_sum_check(c, drive, key_id, size, &im->instance);
	if (st == EZ_OK) {
		im->have_sum = true;
	} else if (st == EZ_ERR_KEY_DAMAGED) {
		/* An integrity file exists but is for another Key ID or length,
		 * or is damaged: never overwrite it silently (SEC-DIST-003). */
		return EZ_ERR_KEY_ID;
	} else if (st == EZ_ERR_UNVERIFIED) {
		if (size < EZ_KEYGEN_MIN_LEN || im->units > DUP_MAX_UNITS)
			return EZ_ERR_KEY_PARAM;
		if (c->stage_cap < DUP_MAX_UNITS * 4u)
			return EZ_ERR_BAD_REQUEST;
		ez_release(c);
		uint8_t ib[2];
		if (c->trng->read(c->trng->ctx, ib, 2) != EZ_OK)
			return EZ_ERR_ENTROPY;
		im->instance = (uint16_t)(ib[0] | (ib[1] << 8));
		char sut[EZ_FNAME_MAX];
		uint8_t hb[EZ_SUM_HDR];
		ez_sum_hdr_t h = { key_id, size, im->units, im->instance };
		ez_sum_hdr_encode(&h, hb);
		ez_key_name(key_id, "SUT", sut);
		c->ks->zap(c->ks->ctx, drive, sut);              /* a stale one */
		if ((st = c->ks->create(c->ks->ctx, drive, sut)) != EZ_OK)
			return st;
		if ((st = c->ks->append(c->ks->ctx, drive, sut, hb, sizeof hb)) != EZ_OK) {
			c->ks->zap(c->ks->ctx, drive, sut);
			return st;
		}
		ez_acc_init(&im->acc);
	} else {
		return st;
	}
	im->state = EZ_IM_SCAN;
	im->result = EZ_PENDING;
	return EZ_PENDING;
}

/* Read unit i of the source file into ubuf (unverified: this is the check). */
static ez_status_t read_unit(ez_core_t *c, ez_import_t *im, uint32_t i, uint32_t *start, uint32_t *len)
{
	ez_unit_drop(c);
	ez_unit_geom(im->key_len, i, start, len);
	ez_status_t st = c->ks->read(c->ks->ctx, im->drive, im->src, *start, c->ubuf, *len);
	if (st != EZ_OK && c->ks->check(c->ks->ctx, im->drive) != EZ_OK)
		st = EZ_ERR_MEDIA_REMOVED;
	return st;
}

static ez_status_t scan_unit(ez_core_t *c, ez_import_t *im)
{
	uint32_t i = im->unit, start, len;
	ez_status_t st;
	if (i % EZ_CHECK_INTERVAL == 0 && (st = c->ks->check(c->ks->ctx, im->drive)) != EZ_OK)
		return st;
	if ((st = read_unit(c, im, i, &start, &len)) != EZ_OK)
		return st;
	uint8_t tag[EZ_TAG_LEN];
	ez_unit_tag(im->key_id, im->key_len, i, c->ubuf, len, tag);
	if (im->have_sum) {
		uint8_t want[EZ_TAG_LEN] = { 0 };
		char sum[EZ_FNAME_MAX];
		ez_key_name(im->key_id, "SUM", sum);
		st = c->ks->read(c->ks->ctx, im->drive, sum, EZ_SUM_HDR + EZ_TAG_LEN * i, want, EZ_TAG_LEN);
		if (st == EZ_OK && memcmp(want, tag, EZ_TAG_LEN) != 0) {
			if (im->bad++ == 0) im->first_bad = i;
		}
		ez_secure_zero(want, sizeof want);
	} else {
		ez_acc_feed(&im->acc, c->ubuf, len);
		/* Block fingerprint for the duplicate check: CRC-32 high bits
		 * and the block index, so equal fingerprints can be compared
		 * exactly afterwards. */
		uint32_t fp = (ez_crc32(c->ubuf, len) & ~((1u << DUP_IDX_BITS) - 1u)) | i;
		ez_put_le32(c->stage + 4u * i, fp);
		memcpy(im->tags + im->ntags * EZ_TAG_LEN, tag, EZ_TAG_LEN);
		if (++im->ntags == 8) {
			char sut[EZ_FNAME_MAX];
			ez_key_name(im->key_id, "SUT", sut);
			st = c->ks->append(c->ks->ctx, im->drive, sut, im->tags, sizeof im->tags);
			ez_secure_zero(im->tags, sizeof im->tags);
			im->ntags = 0;
		}
	}
	ez_secure_zero(tag, sizeof tag);
	ez_unit_drop(c);
	im->unit++;
	return st;
}

static void sift(uint8_t *a, uint32_t n, uint32_t i)
{
	for (;;) {
		uint32_t l = 2 * i + 1, r = l + 1, m = i;
		if (l < n && ez_get_le32(a + 4 * l) > ez_get_le32(a + 4 * m)) m = l;
		if (r < n && ez_get_le32(a + 4 * r) > ez_get_le32(a + 4 * m)) m = r;
		if (m == i) return;
		uint32_t t = ez_get_le32(a + 4 * i);
		ez_put_le32(a + 4 * i, ez_get_le32(a + 4 * m));
		ez_put_le32(a + 4 * m, t);
		i = m;
	}
}

/* Are blocks a and b of the source identical? (exact comparison) */
static ez_status_t same_blocks(ez_core_t *c, ez_import_t *im, uint32_t a, uint32_t b, bool *same)
{
	uint32_t sa, la, sb, lb;
	*same = false;
	ez_unit_geom(im->key_len, b, &sb, &lb);
	ez_status_t st = read_unit(c, im, a, &sa, &la);
	if (st != EZ_OK || la != lb) { ez_unit_drop(c); return st; }
	bool eq = true;
	for (uint32_t o = 0; o < la && eq && st == EZ_OK; o += EZ_KEY_BLOCK) {
		uint32_t m = la - o < EZ_KEY_BLOCK ? la - o : EZ_KEY_BLOCK;
		st = c->ks->read(c->ks->ctx, im->drive, im->src, sb + o, c->kbuf, m);
		if (st == EZ_OK) eq = memcmp(c->kbuf, c->ubuf + o, m) == 0;
		ez_secure_zero(c->kbuf, sizeof c->kbuf);
	}
	ez_unit_drop(c);
	*same = st == EZ_OK && eq;
	return st;
}

static ez_status_t duplicate_check(ez_core_t *c, ez_import_t *im)
{
	uint8_t *a = c->stage;
	uint32_t n = im->units;
	for (uint32_t i = n / 2; i-- > 0;) sift(a, n, i);         /* heapsort */
	for (uint32_t e = n; e-- > 1;) {
		uint32_t t = ez_get_le32(a);
		ez_put_le32(a, ez_get_le32(a + 4 * e));
		ez_put_le32(a + 4 * e, t);
		sift(a, e, 0);
	}
	const uint32_t mask = ~((1u << DUP_IDX_BITS) - 1u);
	for (uint32_t i = 0; i + 1 < n; i++) {
		uint32_t x = ez_get_le32(a + 4 * i);
		for (uint32_t j = i + 1; j < n; j++) {
			uint32_t y = ez_get_le32(a + 4 * j);
			if ((x & mask) != (y & mask)) break;
			bool same;
			ez_status_t st = same_blocks(c, im, x & ~mask, y & ~mask, &same);
			if (st != EZ_OK) return st;
			if (same) im->dups++;
		}
	}
	return EZ_OK;
}

ez_status_t ez_import_step(ez_core_t *c, ez_import_t *im, uint32_t max_units)
{
	if (im->state != EZ_IM_SCAN)
		return im->state == EZ_IM_DONE ? im->result : EZ_ERR_STATE;
	ez_status_t st = EZ_OK;
	for (uint32_t k = 0; k < max_units && im->unit < im->units && st == EZ_OK; k++)
		st = scan_unit(c, im);
	if (st != EZ_OK)
		return fail(c, im, st);
	if (im->unit < im->units)
		return EZ_PENDING;

	char key[EZ_FNAME_MAX], sut[EZ_FNAME_MAX], sum[EZ_FNAME_MAX];
	ez_key_name(im->key_id, "KEY", key);
	ez_key_name(im->key_id, "SUT", sut);
	ez_key_name(im->key_id, "SUM", sum);
	if (im->have_sum) {
		if (im->bad)
			return fail(c, im, EZ_ERR_KEY_DAMAGED);      /* damaged in transfer */
	} else {
		im->fail = ez_acc_finish(&im->acc);                /* SEC-STORE-005 */
		if (im->fail)
			return fail(c, im, EZ_ERR_ENTROPY);
		if ((st = duplicate_check(c, im)) != EZ_OK)
			return fail(c, im, st);
		if (im->dups)
			return fail(c, im, EZ_ERR_KEY_DAMAGED);
		if (im->ntags) {
			st = c->ks->append(c->ks->ctx, im->drive, sut, im->tags, im->ntags * EZ_TAG_LEN);
			if (st != EZ_OK) return fail(c, im, st);
		}
		if ((st = c->ks->rename(c->ks->ctx, im->drive, sut, sum)) != EZ_OK)
			return fail(c, im, st);
	}
	clear_job(c, im);
	/* IMPL-KEY-004: under its Key ID name. */
	bool same = strlen(im->src) == strlen(key);
	for (size_t i = 0; same && im->src[i]; i++) same = up(im->src[i]) == key[i];
	if (!same && (st = c->ks->rename(c->ks->ctx, im->drive, im->src, key)) != EZ_OK) {
		if (!im->have_sum) c->ks->zap(c->ks->ctx, im->drive, sum);
		im->state = EZ_IM_DONE;
		return im->result = st;
	}
	ez_session_params_t p = { im->key_id, im->key_len, im->role, im->drive, im->label, im->instance, 0 };
	st = ez_meta_session_create(&c->meta, &p, &im->slot);
	if (st == EZ_OK)
		c->last_replicate = ez_replicate(c, im->drive, im->key_id);   /* SEC-AVAIL-003 */
	if (st == EZ_OK)
		ez_meta_log_append(&c->meta, EZ_EV_KEY_IMPORTED, im->have_sum ? 1 : 2, im->key_id, im->key_len);
	im->state = EZ_IM_DONE;
	return im->result = st;
}

void ez_import_cancel(ez_core_t *c, ez_import_t *im)
{
	if (im->state == EZ_IM_SCAN)
		fail(c, im, EZ_ERR_ABORTED);
}
