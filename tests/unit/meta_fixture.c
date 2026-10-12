#include "meta_fixture.h"

void fx_init(fx_t *fx)
{
	memset(fx, 0, sizeof *fx);
	sim_fram_init(&fx->fram, 0xFF);
	EZ_CHECK_EQ(ez_meta_boot(&fx->m, &fx->fram.hal), EZ_OK);
	EZ_CHECK_EQ(fx->m.dev, EZ_DEV_UNINIT);
	EZ_CHECK_EQ(ez_meta_format(&fx->m), EZ_OK);
	fx_reboot(fx);
	EZ_CHECK_EQ(fx->m.dev, EZ_DEV_VALID);
}

void fx_reboot(fx_t *fx)
{
	sim_fram_power_on(&fx->fram);
	ez_meta_boot(&fx->m, &fx->fram.hal);
}

int fx_create(fx_t *fx, uint32_t key_id, uint32_t key_len, uint8_t role, const char *label)
{
	ez_session_params_t p = { key_id, key_len, role, 1, label };
	int slot = -1;
	EZ_CHECK_EQ(ez_meta_session_create(&fx->m, &p, &slot), EZ_OK);
	return slot;
}

int fx_session_same(const ez_session_t *a, const ez_session_t *b)
{
	return a->state == b->state && a->qreason == b->qreason &&
	       a->identity == b->identity && a->offsets == b->offsets &&
	       a->key_id == b->key_id && a->key_len == b->key_len &&
	       a->role == b->role && a->drive == b->drive &&
	       strcmp(a->label, b->label) == 0 &&
	       a->tx_off == b->tx_off && a->rx_off == b->rx_off;
}
