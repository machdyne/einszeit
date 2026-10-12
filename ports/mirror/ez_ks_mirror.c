/* ez_ks_mirror.c -- see ez_ks_mirror.h */
#include "ez_ks_mirror.h"

#define M(ctx) ((ez_ks_mirror_t *)(ctx))
#define V(m, k) ((m)->vol[k].hal)
#define VD(m, k) ((m)->vol[k].drive)

static bool mine(ez_ks_mirror_t *m, uint8_t x) { return EZ_COPY_DRIVE(x) == m->drive; }
static bool vpresent(ez_ks_mirror_t *m, int k) { return V(m, k)->present(V(m, k)->ctx, VD(m, k)); }

/* The copy an explicit address refers to, or -1. */
static int copy_of(ez_ks_mirror_t *m, uint8_t x)
{
	int k = EZ_COPY_INDEX(x);
	return k < m->n ? k : -1;
}

/* For reads on the logical drive: copy 0 if it has the file, else the
 * first present copy that does. */
static int reader(ez_ks_mirror_t *m, const char *name)
{
	for (int k = 0; k < m->n; k++) {
		uint32_t s;
		if (vpresent(m, k) && V(m, k)->size(V(m, k)->ctx, VD(m, k), name, &s) == EZ_OK) return k;
	}
	return -1;
}

static bool p_present(void *c, uint8_t x)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return EZ_IS_COPY(x) ? false : m->base->present(m->base->ctx, x);
	if (EZ_IS_COPY(x)) { int k = copy_of(m, x); return k >= 0 && vpresent(m, k); }
	for (int k = 0; k < m->n; k++) if (vpresent(m, k)) return true;
	return false;
}

static ez_status_t p_check(void *c, uint8_t x)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->check(m->base->ctx, x);
	if (EZ_IS_COPY(x)) { int k = copy_of(m, x); return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->check(V(m, k)->ctx, VD(m, k)); }
	for (int k = 0; k < m->n; k++) if (vpresent(m, k)) return V(m, k)->check(V(m, k)->ctx, VD(m, k));
	return EZ_ERR_MEDIA_REMOVED;
}

static ez_status_t p_size(void *c, uint8_t x, const char *n, uint32_t *s)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->size(m->base->ctx, x, n, s);
	int k = EZ_IS_COPY(x) ? copy_of(m, x) : reader(m, n);
	if (k < 0) return EZ_IS_COPY(x) ? EZ_ERR_BAD_REQUEST : (p_present(c, x) ? EZ_ERR_NOT_FOUND : EZ_ERR_MEDIA_REMOVED);
	return V(m, k)->size(V(m, k)->ctx, VD(m, k), n, s);
}

static ez_status_t p_read(void *c, uint8_t x, const char *n, uint32_t o, void *b, uint32_t l)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->read(m->base->ctx, x, n, o, b, l);
	int k = EZ_IS_COPY(x) ? copy_of(m, x) : reader(m, n);
	if (k < 0) return EZ_IS_COPY(x) ? EZ_ERR_BAD_REQUEST : (p_present(c, x) ? EZ_ERR_NOT_FOUND : EZ_ERR_MEDIA_REMOVED);
	return V(m, k)->read(V(m, k)->ctx, VD(m, k), n, o, b, l);
}

/* Writes on the logical drive go to copy 0 only. */
static int writer(ez_ks_mirror_t *m, uint8_t x)
{
	if (EZ_IS_COPY(x)) return copy_of(m, x);
	return 0;
}

static ez_status_t p_create(void *c, uint8_t x, const char *n)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->create(m->base->ctx, x, n);
	int k = writer(m, x);
	return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->create(V(m, k)->ctx, VD(m, k), n);
}

static ez_status_t p_append(void *c, uint8_t x, const char *n, const void *b, uint32_t l)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->append(m->base->ctx, x, n, b, l);
	int k = writer(m, x);
	return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->append(V(m, k)->ctx, VD(m, k), n, b, l);
}

static ez_status_t p_rename(void *c, uint8_t x, const char *a, const char *b)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->rename(m->base->ctx, x, a, b);
	int k = writer(m, x);
	return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->rename(V(m, k)->ctx, VD(m, k), a, b);
}

/* Every copy, in turn; NOT_FOUND only if no copy had the file. A copy
 * that is absent cannot be erased: that is an error, never a skip. */
static ez_status_t p_zap(void *c, uint8_t x, const char *n)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->zap(m->base->ctx, x, n);
	if (EZ_IS_COPY(x)) { int k = copy_of(m, x); return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->zap(V(m, k)->ctx, VD(m, k), n); }
	ez_status_t first_err = EZ_OK;
	bool found = false;
	for (int k = 0; k < m->n; k++) {
		ez_status_t st = vpresent(m, k) ? V(m, k)->zap(V(m, k)->ctx, VD(m, k), n) : EZ_ERR_MEDIA_REMOVED;
		if (st == EZ_OK) found = true;
		else if (st != EZ_ERR_NOT_FOUND && first_err == EZ_OK) first_err = st;
	}
	if (first_err != EZ_OK) return first_err;
	return found ? EZ_OK : EZ_ERR_NOT_FOUND;
}

static ez_status_t p_list(void *c, uint8_t x, uint32_t i, char n[EZ_NAME_MAX], uint32_t *s)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->list(m->base->ctx, x, i, n, s);
	int k = EZ_IS_COPY(x) ? copy_of(m, x) : -1;
	if (!EZ_IS_COPY(x)) for (int j = 0; j < m->n && k < 0; j++) if (vpresent(m, j)) k = j;
	if (k < 0) return EZ_IS_COPY(x) ? EZ_ERR_BAD_REQUEST : EZ_ERR_MEDIA_REMOVED;
	return V(m, k)->list(V(m, k)->ctx, VD(m, k), i, n, s);
}

static ez_status_t p_wipe(void *c, uint8_t x)
{
	ez_ks_mirror_t *m = M(c);
	if (!mine(m, x)) return m->base->wipe(m->base->ctx, x);
	if (EZ_IS_COPY(x)) { int k = copy_of(m, x); return k < 0 ? EZ_ERR_BAD_REQUEST : V(m, k)->wipe(V(m, k)->ctx, VD(m, k)); }
	ez_status_t first_err = EZ_OK;
	for (int k = 0; k < m->n; k++) {
		ez_status_t st = vpresent(m, k) ? V(m, k)->wipe(V(m, k)->ctx, VD(m, k)) : EZ_ERR_MEDIA_REMOVED;
		if (st != EZ_OK && first_err == EZ_OK) first_err = st;
	}
	return first_err;
}

static uint8_t p_copies(void *c, uint8_t d)
{
	ez_ks_mirror_t *m = M(c);
	if (EZ_COPY_DRIVE(d) == m->drive) return m->n;
	return m->base->copies ? m->base->copies(m->base->ctx, d) : 1;
}

void ez_ks_mirror_init(ez_ks_mirror_t *m, const ez_hal_keystore_t *base, uint8_t drive,
                       const ez_mirror_vol_t *vols, uint8_t n)
{
	m->base = base;
	m->drive = drive;
	m->n = n > EZ_COPIES_MAX ? EZ_COPIES_MAX : (n ? n : 1);
	for (int k = 0; k < m->n; k++) m->vol[k] = vols[k];
	m->hal = (ez_hal_keystore_t){ m, p_present, p_check, p_size, p_read, p_create, p_append,
	                              p_rename, p_zap, p_list, p_wipe, p_copies };
}
