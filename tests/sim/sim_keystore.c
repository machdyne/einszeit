/* sim_keystore.c -- see sim_keystore.h */
#include "sim_keystore.h"

#include <stdlib.h>
#include <string.h>

#include <strings.h>

/* Case-insensitive, as on FAT (ez_hal_keystore.h). */
static sim_file_t *find(sim_drive_t *d, const char *name)
{
	for (int i = 0; i < SIM_KS_FILES; i++)
		if (d->f[i].used && strcasecmp(d->f[i].name, name) == 0)
			return &d->f[i];
	return NULL;
}

static bool name_ok(const char *name) { return name && strlen(name) < EZ_NAME_MAX; }

static void free_file(sim_file_t *f)
{
	if (f->data) memset(f->data, 0, f->cap);
	free(f->data);
	memset(f, 0, sizeof *f);
}

/* Every HAL call on a drive passes through here: fault counters tick. */
static sim_drive_t *access_drive(sim_ks_t *k, uint8_t drive)
{
	if (drive >= EZ_DRIVES) return NULL;
	sim_drive_t *d = &k->d[drive];
	d->calls++;
	if (d->remove_after == 0) { d->present = false; d->remove_after = -1; }
	else if (d->remove_after > 0) d->remove_after--;
	if (d->swap_after == 0) { d->card_id++; d->swap_after = -1; }
	else if (d->swap_after > 0) d->swap_after--;
	return d->present ? d : NULL;
}

static bool present(void *ctx, uint8_t drive)
{
	sim_ks_t *k = ctx;
	return drive < EZ_DRIVES && k->d[drive].present;
}

static ez_status_t check(void *ctx, uint8_t drive)
{
	sim_drive_t *d = access_drive(ctx, drive);
	if (!d || d->card_id != d->mounted_id) return EZ_ERR_MEDIA_REMOVED;
	return EZ_OK;
}

static ez_status_t size(void *ctx, uint8_t drive, const char *name, uint32_t *sz)
{
	sim_drive_t *d = access_drive(ctx, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	sim_file_t *f = find(d, name);
	if (!f) return EZ_ERR_NOT_FOUND;
	*sz = f->len;
	return EZ_OK;
}

static ez_status_t rd(void *ctx, uint8_t drive, const char *name, uint32_t off,
                      void *buf, uint32_t len)
{
	sim_ks_t *k = ctx;
	sim_drive_t *d = access_drive(k, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	sim_file_t *f = find(d, name);
	if (!f) return EZ_ERR_NOT_FOUND;
	if ((uint64_t)off + len > f->len) return EZ_ERR_RANGE;
	const uint8_t *chk = buf;
	for (uint32_t i = 0; i < len; i++)
		if (chk[i]) { k->dirty_reads++; break; }
	memcpy(buf, f->data + off, len);
	if (k->corrupt_reads > 0 && len) {           /* transient: the medium is unchanged */
		((uint8_t *)buf)[(off * 7u + len) % len] ^= (uint8_t)(1u << (k->reads % 8));
		k->corrupt_reads--;
	}
	k->reads++;
	if (k->logging && k->nlog < SIM_KS_LOGMAX) {
		sim_read_t *r = &k->log[k->nlog++];
		r->drive = drive;
		strncpy(r->name, name, EZ_NAME_MAX - 1);
		r->off = off;
		r->len = len;
	}
	return EZ_OK;
}

static ez_status_t create(void *ctx, uint8_t drive, const char *name)
{
	((sim_ks_t *)ctx)->mutations++;
	sim_drive_t *d = access_drive(ctx, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(name)) return EZ_ERR_BAD_REQUEST;
	if (find(d, name)) return EZ_ERR_EXISTS;
	for (int i = 0; i < SIM_KS_FILES; i++) {
		if (!d->f[i].used) {
			d->f[i].used = true;
			strncpy(d->f[i].name, name, EZ_NAME_MAX - 1);
			return EZ_OK;
		}
	}
	return EZ_ERR_FULL;
}

static ez_status_t append(void *ctx, uint8_t drive, const char *name,
                          const void *buf, uint32_t len)
{
	((sim_ks_t *)ctx)->mutations++;
	sim_ks_t *k = ctx;
	sim_drive_t *d = access_drive(k, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	sim_file_t *f = find(d, name);
	if (!f) return EZ_ERR_NOT_FOUND;
	if (f->len + len > f->cap) {
		uint32_t nc = f->cap ? f->cap : 4096;
		while (nc < f->len + len) nc *= 2;
		uint8_t *nd = calloc(nc, 1);
		if (!nd) return EZ_ERR_MEDIA;
		if (f->data) { memcpy(nd, f->data, f->len); memset(f->data, 0, f->cap); free(f->data); }
		f->data = nd;
		f->cap = nc;
	}
	memcpy(f->data + f->len, buf, len);
	k->appends++;
	if (k->corrupt_append == 0 && len) f->data[f->len + len / 2] ^= 0x01;
	if (k->corrupt_append >= 0) k->corrupt_append--;
	f->len += len;
	return EZ_OK;
}

static ez_status_t ren(void *ctx, uint8_t drive, const char *from, const char *to)
{
	((sim_ks_t *)ctx)->mutations++;
	sim_drive_t *d = access_drive(ctx, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(from) || !name_ok(to)) return EZ_ERR_BAD_REQUEST;
	sim_file_t *f = find(d, from);
	if (!f) return EZ_ERR_NOT_FOUND;
	if (find(d, to) && find(d, to) != f) return EZ_ERR_EXISTS;
	memset(f->name, 0, sizeof f->name);
	strncpy(f->name, to, EZ_NAME_MAX - 1);
	return EZ_OK;
}

static ez_status_t zap(void *ctx, uint8_t drive, const char *name)
{
	((sim_ks_t *)ctx)->mutations++;
	sim_ks_t *k = ctx;
	sim_drive_t *d = access_drive(k, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	sim_file_t *f = find(d, name);
	if (!f) return EZ_ERR_NOT_FOUND;
	if (k->zap_interrupt) {
		k->zap_interrupt = false;
		memset(f->data, 0, f->len / 2);
		d->present = false;
		return EZ_ERR_MEDIA_REMOVED;
	}
	free_file(f);        /* zeros, then delete */
	return EZ_OK;
}

static ez_status_t list(void *ctx, uint8_t drive, uint32_t index,
                        char name[EZ_NAME_MAX], uint32_t *sz)
{
	sim_drive_t *d = access_drive(ctx, drive);
	if (!d) return EZ_ERR_MEDIA_REMOVED;
	uint32_t n = 0;
	for (int i = 0; i < SIM_KS_FILES; i++) {
		if (!d->f[i].used) continue;
		if (n++ == index) {
			memcpy(name, d->f[i].name, EZ_NAME_MAX);
			*sz = d->f[i].len;
			return EZ_OK;
		}
	}
	return EZ_ERR_NOT_FOUND;
}

static ez_status_t wipe(void *ctx, uint8_t drive)
{
	((sim_ks_t *)ctx)->mutations++;
	sim_drive_t *d = access_drive(ctx, drive);
	if (drive >= EZ_DRIVES) return EZ_ERR_BAD_REQUEST;
	if (!d) {
		/* Drive 0 is internal flash: always reachable for wiping, even
		 * when disabled. */
		if (drive != 0) return EZ_ERR_MEDIA_REMOVED;
		d = &((sim_ks_t *)ctx)->d[0];
	}
	for (int i = 0; i < SIM_KS_FILES; i++)
		if (d->f[i].used) free_file(&d->f[i]);
	d->wipes++;
	return EZ_OK;
}

void sim_ks_init(sim_ks_t *k)
{
	memset(k, 0, sizeof *k);
	for (int i = 0; i < EZ_DRIVES; i++) {
		k->d[i].present = true;
		k->d[i].card_id = k->d[i].mounted_id = 100u + (uint32_t)i;
		k->d[i].remove_after = k->d[i].swap_after = -1;
	}
	k->corrupt_append = -1;
	k->hal = (ez_hal_keystore_t){ k, present, check, size, rd, create, append,
	                              ren, zap, list, wipe, NULL };
}

void sim_ks_free(sim_ks_t *k)
{
	for (int d = 0; d < EZ_DRIVES; d++)
		for (int i = 0; i < SIM_KS_FILES; i++)
			if (k->d[d].f[i].used) free_file(&k->d[d].f[i]);
}

void sim_ks_insert(sim_ks_t *k, uint8_t drive)
{
	k->d[drive].present = true;
	k->d[drive].mounted_id = k->d[drive].card_id;
}

void sim_ks_remove(sim_ks_t *k, uint8_t drive) { k->d[drive].present = false; }
void sim_ks_remove_after(sim_ks_t *k, uint8_t drive, long n) { k->d[drive].remove_after = n; }
void sim_ks_swap_after(sim_ks_t *k, uint8_t drive, long n) { k->d[drive].swap_after = n; }
void sim_ks_corrupt_append(sim_ks_t *k, long n) { k->corrupt_append = n; }
void sim_ks_interrupt_zap(sim_ks_t *k) { k->zap_interrupt = true; }
void sim_ks_corrupt_reads(sim_ks_t *k, long n) { k->corrupt_reads = n; }

void sim_ks_clear_faults(sim_ks_t *k)
{
	for (int i = 0; i < EZ_DRIVES; i++)
		k->d[i].remove_after = k->d[i].swap_after = -1;
	k->corrupt_append = -1;
	k->zap_interrupt = false;
	k->corrupt_reads = 0;
}

void sim_ks_put(sim_ks_t *k, uint8_t drive, const char *name, const uint8_t *data, uint32_t len)
{
	sim_drive_t *d = &k->d[drive];
	sim_file_t *f = find(d, name);
	if (f) free_file(f);
	for (int i = 0; i < SIM_KS_FILES; i++) {
		if (!d->f[i].used) {
			f = &d->f[i];
			f->used = true;
			strncpy(f->name, name, EZ_NAME_MAX - 1);
			f->cap = len ? len : 1;
			f->data = calloc(f->cap, 1);
			if (len) memcpy(f->data, data, len);
			f->len = len;
			return;
		}
	}
}

sim_file_t *sim_ks_get(sim_ks_t *k, uint8_t drive, const char *name)
{
	return find(&k->d[drive], name);
}

void sim_ks_log_reset(sim_ks_t *k, bool on)
{
	k->nlog = 0;
	k->logging = on;
}
