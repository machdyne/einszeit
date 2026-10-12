#include "core_fixture.h"

#include <stdlib.h>
#include <string.h>

#include "ez_secure.h"

ezdev_t *dev_new(uint64_t seed)
{
	ezdev_t *d = calloc(1, sizeof *d);
	EZ_CHECK(d != NULL);
	sim_fram_init(&d->fram, 0xFF);
	sim_ks_init(&d->ks);
	sim_trng_init(&d->trng, seed);
	EZ_CHECK_EQ(ez_core_init(&d->c, &d->fram.hal, &d->ks.hal, &d->trng.hal,
	                         d->stage, sizeof d->stage), EZ_OK);
	EZ_CHECK_EQ(d->c.meta.dev, EZ_DEV_UNINIT);
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	dev_reboot(d);
	EZ_CHECK_EQ(d->c.meta.dev, EZ_DEV_VALID);
	return d;
}

void dev_free(ezdev_t *d)
{
	if (!d) return;
	EZ_CHECK_MSG(d->ks.dirty_reads == 0, "key read into a buffer holding stale data");
	sim_ks_free(&d->ks);
	free(d);
}

void dev_reboot(ezdev_t *d)
{
	sim_fram_power_on(&d->fram);
	sim_ks_clear_faults(&d->ks);
	ez_core_init(&d->c, &d->fram.hal, &d->ks.hal, &d->trng.hal, d->stage, sizeof d->stage);
}

void put_sum(sim_ks_t *ks, uint8_t drive, uint32_t key_id, const uint8_t *key,
             uint32_t len, uint16_t instance)
{
	uint32_t n = ez_unit_count(len), size = ez_sum_size(len);
	uint8_t *s = malloc(size);
	EZ_CHECK(s != NULL);
	ez_sum_hdr_t h = { key_id, len, n, instance };
	ez_sum_hdr_encode(&h, s);
	for (uint32_t i = 0; i < n; i++) {
		uint32_t st, l;
		ez_unit_geom(len, i, &st, &l);
		ez_unit_tag(key_id, len, i, key + st, l, s + EZ_SUM_HDR + EZ_TAG_LEN * i);
	}
	char name[EZ_FNAME_MAX];
	ez_key_name(key_id, "SUM", name);
	sim_ks_put(ks, drive, name, s, size);
	free(s);
}

void dev_put_key(ezdev_t *d, uint8_t drive, uint32_t key_id, uint32_t len, uint64_t seed)
{
	uint8_t *b = malloc(len ? len : 1);
	EZ_CHECK(b != NULL);
	sim_fill(b, len, seed);
	char name[EZ_FNAME_MAX];
	ez_key_name(key_id, "KEY", name);
	sim_ks_put(&d->ks, drive, name, b, len);
	if (len && !(len & 1u))
		put_sum(&d->ks, drive, key_id, b, len, (uint16_t)(seed * 2654435761u >> 7));
	free(b);
}

void dev_copy_key(ezdev_t *from, ezdev_t *to, uint8_t drive, uint32_t key_id)
{
	char name[EZ_FNAME_MAX];
	ez_key_name(key_id, "KEY", name);
	sim_file_t *f = sim_ks_get(&from->ks, drive, name);
	EZ_CHECK(f != NULL);
	sim_ks_put(&to->ks, drive, name, f->data, f->len);
	ez_key_name(key_id, "SUM", name);
	if ((f = sim_ks_get(&from->ks, drive, name)) != NULL)
		sim_ks_put(&to->ks, drive, name, f->data, f->len);
}

int dev_session(ezdev_t *d, uint32_t key_id, uint8_t drive, uint8_t role, const char *label)
{
	int slot = -1;
	EZ_CHECK_EQ(ez_session_create(&d->c, key_id, drive, role, label, &slot), EZ_OK);
	return slot;
}

ez_status_t dev_encrypt(ezdev_t *d, int slot, const uint8_t *pt, uint32_t len,
                        uint8_t *out, uint32_t *out_len)
{
	uint8_t *p = ez_stage_plaintext(&d->c, len);
	if (!p) return EZ_ERR_BAD_REQUEST;
	memcpy(p, pt, len);
	const uint8_t *o; uint32_t n;
	ez_status_t st = ez_encrypt_buffered(&d->c, slot, len, &o, &n);
	if (st == EZ_OK) { memcpy(out, o, n); *out_len = n; }
	ez_release(&d->c);
	return st;
}

ez_status_t dev_decrypt(ezdev_t *d, int slot, const uint8_t *msg, uint32_t len,
                        uint8_t *out, uint32_t *out_len)
{
	uint8_t *p = ez_stage_message(&d->c, len);
	if (!p) return EZ_ERR_BAD_REQUEST;
	memcpy(p, msg, len);
	const uint8_t *o; uint32_t n;
	ez_status_t st = ez_decrypt_buffered(&d->c, slot, len, &o, &n);
	if (st == EZ_OK) { memcpy(out, o, n); *out_len = n; }
	ez_release(&d->c);
	return st;
}

ez_status_t dev_encrypt_stream(ezdev_t *d, int slot, const uint8_t *pt, uint32_t len,
                               uint32_t chunk, uint8_t *out, uint32_t *out_len)
{
	ez_stream_t s;
	*out_len = 0;
	ez_status_t st = ez_enc_stream_begin(&d->c, &s, slot, len, out);
	if (st != EZ_OK) return st;
	uint32_t o = EZ_MSG_HDR;
	for (uint32_t i = 0; i < len; i += chunk) {
		uint32_t n = len - i < chunk ? len - i : chunk;
		memcpy(out + o, pt + i, n);
		st = ez_enc_stream_update(&d->c, &s, out + o, n);
		if (st != EZ_OK) { *out_len = o; return st; }
		o += n;
	}
	st = ez_enc_stream_end(&d->c, &s, out + o);
	*out_len = o + EZ_MSG_TRL;
	return st;
}

ez_status_t dev_decrypt_stream(ezdev_t *d, int slot, const uint8_t *msg, uint32_t len,
                               uint32_t chunk, uint8_t *out, uint32_t *out_len)
{
	ez_stream_t s;
	*out_len = 0;
	if (len < EZ_MSG_OVERHEAD) return EZ_ERR_BAD_REQUEST;
	ez_status_t st = ez_dec_stream_begin(&d->c, &s, slot, msg);
	if (st != EZ_OK) return st;
	uint32_t n_ct = len - EZ_MSG_OVERHEAD;
	for (uint32_t i = 0; i < n_ct; i += chunk) {
		uint32_t n = n_ct - i < chunk ? n_ct - i : chunk;
		memcpy(out + i, msg + EZ_MSG_HDR + i, n);
		st = ez_dec_stream_update(&d->c, &s, out + i, n);
		if (st != EZ_OK) return st;
	}
	st = ez_dec_stream_end(&d->c, &s, msg + len - EZ_MSG_TRL);
	*out_len = n_ct;
	return st;
}
