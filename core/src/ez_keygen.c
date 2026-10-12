/*
 * ez_keygen.c -- see ez_keygen.h for the pipeline and traceability.
 */
#include "ez_keygen.h"

#include <string.h>

#include "ez_secure.h"

#define KEYID_ATTEMPTS 16

static void names(const ez_keygen_t *kg, char tmp[EZ_FNAME_MAX], char key[EZ_FNAME_MAX])
{
	ez_key_name(kg->key_id, "TMP", tmp);
	ez_key_name(kg->key_id, "KEY", key);
}

static ez_status_t flush_tags(ez_core_t *c, ez_keygen_t *kg)
{
	if (kg->ntags == 0) return EZ_OK;
	char sut[EZ_FNAME_MAX];
	ez_key_name(kg->key_id, "SUT", sut);
	ez_status_t st = c->ks->append(c->ks->ctx, kg->drive, sut, kg->tags, kg->ntags * EZ_TAG_LEN);
	ez_secure_zero(kg->tags, sizeof kg->tags);
	kg->ntags = 0;
	return st;
}

static void wipe_buffers(ez_core_t *c, ez_keygen_t *kg)
{
	ez_secure_zero(c->kbuf, sizeof c->kbuf);              /* SEC-GEN-001 */
	ez_secure_zero(kg->vbuf, sizeof kg->vbuf);
}

/* Halt: log, destroy the temporary file, clear all state. */
static ez_status_t finish_fail(ez_core_t *c, ez_keygen_t *kg, uint8_t bits, ez_status_t result)
{
	char tmp[EZ_FNAME_MAX], key[EZ_FNAME_MAX], sut[EZ_FNAME_MAX];
	names(kg, tmp, key);
	ez_key_name(kg->key_id, "SUT", sut);
	wipe_buffers(c, kg);
	ez_mon_clear(&kg->mon);
	ez_secure_zero(&kg->acc, sizeof kg->acc);
	ez_tagger_clear(&kg->tagger);
	ez_secure_zero(kg->tags, sizeof kg->tags);
	kg->ntags = 0;
	kg->fail = bits;
	if (result == EZ_ERR_ENTROPY && (bits & (EZ_EF_MON_MONOBIT | EZ_EF_MON_RUNS |
	                                         EZ_EF_MON_AUTOCORR | EZ_EF_OTHER)))
		ez_meta_log_append(&c->meta, EZ_EV_ENTROPY_FAULT, bits, kg->key_id, kg->len);
	ez_meta_log_append(&c->meta, EZ_EV_KEY_REJECTED, bits, kg->key_id, kg->len); /* SEC-GEN-003 */
	c->ks->zap(c->ks->ctx, kg->drive, tmp);
	c->ks->zap(c->ks->ctx, kg->drive, sut);
	kg->state = EZ_KG_DONE;
	kg->result = result;
	return result;
}

ez_status_t ez_keygen_start(ez_core_t *c, ez_keygen_t *kg, uint8_t drive, uint32_t len)
{
	memset(kg, 0, sizeof *kg);
	if (c->meta.dev != EZ_DEV_VALID)
		return EZ_ERR_DEVICE;
	if (len < EZ_KEYGEN_MIN_LEN || len > EZ_KEYGEN_MAX_LEN || len % EZ_KEY_BLOCK)
		return EZ_ERR_KEY_PARAM;                           /* IMPL-KEY-002 */
	ez_status_t st = ez_core_drive_usable(c, drive);
	if (st != EZ_OK)
		return st;

	/* IMPL-KEY-003 / SEC-STORE-002: the Key ID is drawn from the TRNG
	 * before, and separately from, the key bytes. */
	uint32_t id = 0;
	char tmp[EZ_FNAME_MAX], key[EZ_FNAME_MAX];
	int tries = 0;
	for (; tries < KEYID_ATTEMPTS; tries++) {
		uint8_t b[4];
		if (c->trng->read(c->trng->ctx, b, 4) != EZ_OK) {
			ez_meta_log_append(&c->meta, EZ_EV_ENTROPY_FAULT, EZ_EF_OTHER, 0, len);
			return EZ_ERR_ENTROPY;
		}
		id = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
		uint32_t sz;
		ez_key_name(id, "TMP", tmp);
		ez_key_name(id, "KEY", key);
		if (id != 0 && ez_meta_find_key_id(&c->meta, id) < 0 &&
		    c->ks->size(c->ks->ctx, drive, key, &sz) == EZ_ERR_NOT_FOUND &&
		    c->ks->size(c->ks->ctx, drive, tmp, &sz) == EZ_ERR_NOT_FOUND)
			break;
	}
	if (tries == KEYID_ATTEMPTS) {
		/* Sixteen collisions in a 32-bit space means the source is not
		 * producing entropy (SEC-ENTROPY-004). */
		ez_meta_log_append(&c->meta, EZ_EV_ENTROPY_FAULT, EZ_EF_OTHER, 0, len);
		return EZ_ERR_ENTROPY;
	}
	/* IMPL-KEY-005: the instance tag, also from the TRNG and separate from
	 * the key bytes. Not secret; distinguishes keys that share an ID. */
	uint8_t ib[2];
	if (c->trng->read(c->trng->ctx, ib, 2) != EZ_OK) {
		ez_meta_log_append(&c->meta, EZ_EV_ENTROPY_FAULT, EZ_EF_OTHER, 0, len);
		return EZ_ERR_ENTROPY;
	}
	if ((st = c->ks->create(c->ks->ctx, drive, tmp)) != EZ_OK)
		return st;
	kg->instance = (uint16_t)(ib[0] | (ib[1] << 8));
	kg->key_id = id;
	kg->drive = drive;
	kg->len = len;
	kg->state = EZ_KG_GENERATE;
	kg->result = EZ_PENDING;
	ez_mon_init(&kg->mon);
	return EZ_PENDING;
}

static ez_status_t step_generate(ez_core_t *c, ez_keygen_t *kg, const char *tmp)
{
	if (kg->since_check++ % EZ_CHECK_INTERVAL == 0 &&
	    c->ks->check(c->ks->ctx, kg->drive) != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA_REMOVED);
	/* One block from the TRNG into the single block buffer (SEC-GEN-001). */
	if (c->trng->read(c->trng->ctx, c->kbuf, EZ_KEY_BLOCK) != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_ENTROPY);   /* IMPL-ENT-002 */
	uint8_t mf = ez_mon_feed(&kg->mon, c->kbuf, EZ_KEY_BLOCK);
	if (mf)
		return finish_fail(c, kg, mf, EZ_ERR_ENTROPY);           /* §2.3: halt */
	ez_status_t st = c->ks->append(c->ks->ctx, kg->drive, tmp, c->kbuf, EZ_KEY_BLOCK);
	if (st == EZ_OK)                                              /* SEC-GEN-002 */
		st = c->ks->read(c->ks->ctx, kg->drive, tmp, kg->done, kg->vbuf, EZ_KEY_BLOCK);
	if (st == EZ_OK && memcmp(c->kbuf, kg->vbuf, EZ_KEY_BLOCK) != 0)
		st = EZ_ERR_MEDIA;
	wipe_buffers(c, kg);
	if (st != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER,
		                   c->ks->check(c->ks->ctx, kg->drive) != EZ_OK ?
		                   EZ_ERR_MEDIA_REMOVED : EZ_ERR_MEDIA);
	kg->done += EZ_KEY_BLOCK;
	if (kg->done == kg->len) {
		ez_mon_clear(&kg->mon);
		ez_acc_init(&kg->acc);
		ez_tagger_init(&kg->tagger, kg->key_id, kg->len);
		kg->done = 0;
		kg->since_check = 0;
		kg->state = EZ_KG_VERIFY;
		/* The integrity file, under a temporary name until accepted. */
		char sut[EZ_FNAME_MAX];
		uint8_t hb[EZ_SUM_HDR];
		ez_sum_hdr_t h = { kg->key_id, kg->len, ez_unit_count(kg->len), kg->instance };
		ez_key_name(kg->key_id, "SUT", sut);
		ez_sum_hdr_encode(&h, hb);
		ez_status_t s2 = c->ks->create(c->ks->ctx, kg->drive, sut);
		if (s2 == EZ_OK) s2 = c->ks->append(c->ks->ctx, kg->drive, sut, hb, sizeof hb);
		if (s2 != EZ_OK)
			return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA);
	}
	return EZ_PENDING;
}

static ez_status_t step_verify(ez_core_t *c, ez_keygen_t *kg, const char *tmp, const char *key)
{
	if (kg->since_check++ % EZ_CHECK_INTERVAL == 0 &&
	    c->ks->check(c->ks->ctx, kg->drive) != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA_REMOVED);
	/* Acceptance runs over the key as stored, not as generated. */
	ez_status_t st = c->ks->read(c->ks->ctx, kg->drive, tmp, kg->done, c->kbuf, EZ_KEY_BLOCK);
	if (st != EZ_OK) {
		wipe_buffers(c, kg);
		return finish_fail(c, kg, EZ_EF_OTHER,
		                   c->ks->check(c->ks->ctx, kg->drive) != EZ_OK ?
		                   EZ_ERR_MEDIA_REMOVED : EZ_ERR_MEDIA);
	}
	ez_acc_feed(&kg->acc, c->kbuf, EZ_KEY_BLOCK);
	/* SEC-STORE-004: tags are computed from the key as stored. */
	for (uint32_t o = 0; o < EZ_KEY_BLOCK && st == EZ_OK; ) {
		bool done;
		uint32_t idx;
		o += ez_tagger_feed(&kg->tagger, c->kbuf + o, EZ_KEY_BLOCK - o, &done, &idx,
		                    kg->tags + kg->ntags * EZ_TAG_LEN);
		if (done && ++kg->ntags == 8)
			st = flush_tags(c, kg);
	}
	wipe_buffers(c, kg);
	if (st != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA);
	kg->done += EZ_KEY_BLOCK;
	if (kg->done < kg->len)
		return EZ_PENDING;
	if (flush_tags(c, kg) != EZ_OK)
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA);
	ez_tagger_clear(&kg->tagger);

	uint8_t f = ez_acc_finish(&kg->acc);                   /* SEC-ENTROPY-002 */
	if (f)
		return finish_fail(c, kg, f, EZ_ERR_ENTROPY);
	/* Log first, then mark valid by renaming (EZ-IMPL-001 §2.3 steps 4-5). */
	ez_meta_log_append(&c->meta, EZ_EV_KEY_OK, 0, kg->key_id, kg->len);
	char sut[EZ_FNAME_MAX], sum[EZ_FNAME_MAX];
	ez_key_name(kg->key_id, "SUT", sut);
	ez_key_name(kg->key_id, "SUM", sum);
	st = c->ks->rename(c->ks->ctx, kg->drive, sut, sum);
	if (st == EZ_OK)
		st = c->ks->rename(c->ks->ctx, kg->drive, tmp, key);
	if (st != EZ_OK) {
		c->ks->zap(c->ks->ctx, kg->drive, sum);
		return finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_MEDIA);
	}
	kg->state = EZ_KG_DONE;
	kg->result = EZ_OK;
	return EZ_OK;
}

ez_status_t ez_keygen_step(ez_core_t *c, ez_keygen_t *kg, uint32_t max_blocks)
{
	char tmp[EZ_FNAME_MAX], key[EZ_FNAME_MAX];
	names(kg, tmp, key);
	ez_status_t st = kg->result;
	for (uint32_t i = 0; i < max_blocks; i++) {
		if (kg->state == EZ_KG_GENERATE)      st = step_generate(c, kg, tmp);
		else if (kg->state == EZ_KG_VERIFY)   st = step_verify(c, kg, tmp, key);
		else return kg->state == EZ_KG_DONE ? kg->result : EZ_ERR_STATE;
		if (st != EZ_PENDING)
			return st;
	}
	return st;
}

void ez_keygen_cancel(ez_core_t *c, ez_keygen_t *kg)
{
	if (kg->state == EZ_KG_GENERATE || kg->state == EZ_KG_VERIFY)
		finish_fail(c, kg, EZ_EF_OTHER, EZ_ERR_ABORTED);
}

uint32_t ez_keygen_progress(const ez_keygen_t *kg)
{
	if (kg->len == 0) return 0;
	uint64_t p = (uint64_t)kg->done * 500u / kg->len;
	if (kg->state == EZ_KG_VERIFY) p += 500;
	if (kg->state == EZ_KG_DONE) p = 1000;
	return (uint32_t)p;
}
