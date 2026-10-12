/* ez_sum.c -- see ez_sum.h. SEC-STORE-004. */
#include "ez_sum.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"

static const uint8_t DOMAIN[8] = { 'E', 'Z', '-', 'U', 'N', 'I', 'T', '1' };

void ez_sum_hdr_encode(const ez_sum_hdr_t *h, uint8_t o[EZ_SUM_HDR])
{
	memset(o, 0, EZ_SUM_HDR);
	o[0] = 'E'; o[1] = 'Z'; o[2] = 'S'; o[3] = 'U';
	o[4] = 1; o[5] = 12; o[6] = EZ_TAG_LEN;
	ez_put_le32(o + 8, h->key_id);
	ez_put_le32(o + 12, h->key_len);
	ez_put_le32(o + 16, h->tags);
	ez_put_le16(o + 20, h->instance);
	ez_put_le32(o + 28, ez_crc32(o, 28));
}

ez_status_t ez_sum_hdr_decode(const uint8_t in[EZ_SUM_HDR], ez_sum_hdr_t *h)
{
	memset(h, 0, sizeof *h);
	if (memcmp(in, "EZSU", 4) != 0 || in[4] != 1 || in[5] != 12 || in[6] != EZ_TAG_LEN ||
	    ez_get_le32(in + 28) != ez_crc32(in, 28))
		return EZ_ERR_KEY_DAMAGED;
	h->key_id = ez_get_le32(in + 8);
	h->key_len = ez_get_le32(in + 12);
	h->tags = ez_get_le32(in + 16);
	h->instance = ez_get_le16(in + 20);
	if (h->key_len == 0 || (h->key_len & 1u) || h->tags != ez_unit_count(h->key_len))
		return EZ_ERR_KEY_DAMAGED;
	return EZ_OK;
}

uint32_t ez_units_per_half(uint32_t key_len)
{
	uint32_t half = key_len / 2;
	return half / EZ_UNIT_SIZE + (half % EZ_UNIT_SIZE ? 1u : 0u);
}

uint32_t ez_unit_count(uint32_t key_len) { return 2u * ez_units_per_half(key_len); }

uint32_t ez_sum_size(uint32_t key_len) { return EZ_SUM_HDR + EZ_TAG_LEN * ez_unit_count(key_len); }

void ez_unit_geom(uint32_t key_len, uint32_t i, uint32_t *start, uint32_t *len)
{
	uint32_t n = ez_units_per_half(key_len), half = key_len / 2;
	uint32_t base = i < n ? 0 : half, j = i < n ? i : i - n;
	*start = base + j * EZ_UNIT_SIZE;
	uint32_t end = base + half;
	*len = end - *start < EZ_UNIT_SIZE ? end - *start : EZ_UNIT_SIZE;
}

uint32_t ez_unit_index(uint32_t key_len, uint32_t abs)
{
	uint32_t half = key_len / 2, n = ez_units_per_half(key_len);
	return abs < half ? abs / EZ_UNIT_SIZE : n + (abs - half) / EZ_UNIT_SIZE;
}

static void tag_begin(ez_sha256_t *s, uint32_t key_id, uint32_t key_len, uint32_t i)
{
	uint8_t b[12];
	ez_put_le32(b, key_id);
	ez_put_le32(b + 4, key_len);
	ez_put_le32(b + 8, i);
	ez_sha256_init(s);
	ez_sha256_update(s, DOMAIN, sizeof DOMAIN);
	ez_sha256_update(s, b, sizeof b);
}

static void tag_end(ez_sha256_t *s, uint8_t tag[EZ_TAG_LEN])
{
	uint8_t d[32];
	ez_sha256_final(s, d);
	memcpy(tag, d, EZ_TAG_LEN);
	ez_secure_zero(d, sizeof d);
}

void ez_unit_tag(uint32_t key_id, uint32_t key_len, uint32_t i,
                 const uint8_t *data, uint32_t len, uint8_t tag[EZ_TAG_LEN])
{
	ez_sha256_t s;
	tag_begin(&s, key_id, key_len, i);
	ez_sha256_update(&s, data, len);
	tag_end(&s, tag);
}

void ez_tagger_init(ez_tagger_t *t, uint32_t key_id, uint32_t key_len)
{
	memset(t, 0, sizeof *t);
	t->key_id = key_id;
	t->key_len = key_len;
	ez_unit_geom(key_len, 0, &t->start, &t->len);
	tag_begin(&t->sha, key_id, key_len, 0);
}

uint32_t ez_tagger_feed(ez_tagger_t *t, const uint8_t *p, uint32_t n,
                        bool *done, uint32_t *index, uint8_t tag[EZ_TAG_LEN])
{
	*done = false;
	uint32_t left = t->start + t->len - t->pos;
	uint32_t take = n < left ? n : left;
	ez_sha256_update(&t->sha, p, take);
	t->pos += take;
	if (t->pos == t->start + t->len) {
		*done = true;
		*index = t->index;
		tag_end(&t->sha, tag);
		if (++t->index < ez_unit_count(t->key_len)) {
			ez_unit_geom(t->key_len, t->index, &t->start, &t->len);
			tag_begin(&t->sha, t->key_id, t->key_len, t->index);
		}
	}
	return take;
}

void ez_tagger_clear(ez_tagger_t *t) { ez_secure_zero(t, sizeof *t); }
