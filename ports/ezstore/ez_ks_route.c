/* ez_ks_route.c -- see ez_ks_route.h */
#include "ez_ks_route.h"

/* Route on the drive number; explicit copy addresses (EZ_COPY) keep their drive. */
#define R(ctx, d) ((EZ_COPY_DRIVE(d) == 0) ? ((ez_ks_route_t *)(ctx))->d0 : ((ez_ks_route_t *)(ctx))->cards)

static bool present(void *c, uint8_t d) { const ez_hal_keystore_t *h = R(c, d); return h->present(h->ctx, d); }
static ez_status_t check(void *c, uint8_t d) { const ez_hal_keystore_t *h = R(c, d); return h->check(h->ctx, d); }
static ez_status_t size(void *c, uint8_t d, const char *n, uint32_t *s)
{ const ez_hal_keystore_t *h = R(c, d); return h->size(h->ctx, d, n, s); }
static ez_status_t rd(void *c, uint8_t d, const char *n, uint32_t o, void *b, uint32_t l)
{ const ez_hal_keystore_t *h = R(c, d); return h->read(h->ctx, d, n, o, b, l); }
static ez_status_t create(void *c, uint8_t d, const char *n)
{ const ez_hal_keystore_t *h = R(c, d); return h->create(h->ctx, d, n); }
static ez_status_t append(void *c, uint8_t d, const char *n, const void *b, uint32_t l)
{ const ez_hal_keystore_t *h = R(c, d); return h->append(h->ctx, d, n, b, l); }
static ez_status_t ren(void *c, uint8_t d, const char *a, const char *b)
{ const ez_hal_keystore_t *h = R(c, d); return h->rename(h->ctx, d, a, b); }
static ez_status_t zap(void *c, uint8_t d, const char *n)
{ const ez_hal_keystore_t *h = R(c, d); return h->zap(h->ctx, d, n); }
static ez_status_t list(void *c, uint8_t d, uint32_t i, char n[EZ_NAME_MAX], uint32_t *s)
{ const ez_hal_keystore_t *h = R(c, d); return h->list(h->ctx, d, i, n, s); }
static ez_status_t wipe(void *c, uint8_t d) { const ez_hal_keystore_t *h = R(c, d); return h->wipe(h->ctx, d); }
static uint8_t copies(void *c, uint8_t d) { const ez_hal_keystore_t *h = R(c, d); return h->copies ? h->copies(h->ctx, d) : 1; }

void ez_ks_route_init(ez_ks_route_t *r, const ez_hal_keystore_t *drive0,
                      const ez_hal_keystore_t *cards)
{
	r->d0 = drive0;
	r->cards = cards;
	r->hal = (ez_hal_keystore_t){ r, present, check, size, rd, create, append, ren, zap, list, wipe, copies };
}
