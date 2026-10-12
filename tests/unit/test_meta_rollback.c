/*
 * test_meta_rollback.c -- offset rollback attempts.
 *
 * EZ-SEC-001:
 *   SEC-TEST-PTR-003  rollback attempts by command or by simulated storage
 *                     manipulation are rejected
 *   SEC-PTR-002       non-increasing offsets rejected and logged
 *
 * Out of scope (EZ-SEC-001 §0, deviation DEV-11): a physical attacker who
 * writes a well-formed lower value, with a correct check, into the
 * selected slot. That is not tested as "rejected" because it cannot be.
 */
#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "meta_fixture.h"

static fx_t fx;

static uint8_t *rec(int slot)
{
	return fx.fram.mem + EZ_META_SESSION_ADDR + (uint32_t)slot * EZ_META_SESSION_SIZE;
}

/* Same encoding as ez_meta.c (§3.2), so tests can forge well-formed slots. */
static void forge_slot(uint8_t *out, char tag, int slot, int ab, uint32_t v)
{
	uint8_t b[7] = { (uint8_t)tag, (uint8_t)slot, (uint8_t)ab };
	ez_put_le32(&b[3], v);
	ez_put_le32(out, v);
	ez_put_le16(out + 4, ez_crc16(b, sizeof b));
}

static void t_by_command(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 600), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_ERR_ROLLBACK);   /* equal */
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 99), EZ_ERR_ROLLBACK);    /* lower */
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 0), EZ_ERR_ROLLBACK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 600), EZ_ERR_ROLLBACK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 500), EZ_ERR_ROLLBACK);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 100);
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 600);
	/* Logged (SEC-PTR-002) without the offsets (SEC-UI-005). */
	ez_event_t ev[16];
	int n = ez_meta_log_read(&fx.m, ev, 16), rb = 0;
	for (int i = 0; i < n; i++) {
		if (ev[i].type != EZ_EV_ROLLBACK) continue;
		rb++;
		EZ_CHECK_EQ(ev[i].key_id, 0xAB);
		EZ_CHECK_EQ(ev[i].detail, a);
		EZ_CHECK(ev[i].arg == 0 || ev[i].arg == 1);
	}
	EZ_CHECK_EQ(rb, 5);
}

static void t_selector_swap(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 100), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 200), EZ_OK);
	EZ_CHECK_EQ(ez_meta_commit_rx(&fx.m, a, 700), EZ_OK);
	/* Point both selectors at the other (older) slot. */
	uint8_t *r = rec(a);
	r[EZ_SR_OFF_TX_SEL] = r[EZ_SR_OFF_TX_SEL] == EZ_SEL_A ? EZ_SEL_B : EZ_SEL_A;
	r[EZ_SR_OFF_RX_SEL] = r[EZ_SR_OFF_RX_SEL] == EZ_SEL_A ? EZ_SEL_B : EZ_SEL_A;
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);
	EZ_CHECK_MSG(fx.m.s[a].tx_off == 200, "larger-of-two rule defeats a selector swap");
	EZ_CHECK_EQ(fx.m.s[a].rx_off, 700);
	/* And the next commit still cannot go backwards or lose the value. */
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 150), EZ_ERR_ROLLBACK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 250), EZ_OK);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 250);
}

static void t_lower_value_in_inactive_slot(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 300), EZ_OK);
	int oth = 1 - fx.m.s[a].sel[0];
	forge_slot(rec(a) + (oth ? EZ_SR_OFF_TX_B : EZ_SR_OFF_TX_A), 'T', a, oth, 0);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_VALID);
	EZ_CHECK_EQ(fx.m.s[a].tx_off, 300);
}

static void t_damaged_selected_slot(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 300), EZ_OK);
	int sel = fx.m.s[a].sel[0];
	/* Overwrite the selected slot with an invalid encoding of a low value:
	 * must quarantine, never fall back to the other slot. */
	uint8_t *p = rec(a) + (sel ? EZ_SR_OFF_TX_B : EZ_SR_OFF_TX_A);
	ez_put_le32(p, 1);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_SLOT_CHECK);
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 400), EZ_ERR_QUARANTINED);
	EZ_CHECK_EQ(ez_meta_resolve(&fx.m, a), EZ_ERR_QUARANTINED);
}

static void t_garbage_selector(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	EZ_CHECK_EQ(ez_meta_commit_tx(&fx.m, a, 300), EZ_OK);
	for (int v = 0; v < 256; v++) {
		if (v == EZ_SEL_A || v == EZ_SEL_B) continue;
		rec(a)[EZ_SR_OFF_TX_SEL] = (uint8_t)v;
		fx_reboot(&fx);
		EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_QUARANTINED);
		EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_SELECTOR);
	}
}

static void t_out_of_range(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_BOB, "a");   /* TX [500,1000] */
	int sel = fx.m.s[a].sel[0], oth = 1 - sel;
	uint8_t *p = rec(a) + (sel ? EZ_SR_OFF_TX_B : EZ_SR_OFF_TX_A);
	uint8_t *q = rec(a) + (oth ? EZ_SR_OFF_TX_B : EZ_SR_OFF_TX_A);
	forge_slot(p, 'T', a, sel, 499);      /* below TX start: the peer's half */
	fx_reboot(&fx);
	EZ_CHECK_MSG(fx.m.s[a].qreason == EZ_Q_RANGE, "any valid slot out of range quarantines");
	forge_slot(p, 'T', a, sel, 600);
	forge_slot(q, 'T', a, oth, 1001);     /* beyond the key, in the other slot */
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_RANGE);
	forge_slot(q, 'T', a, oth, 500);
	/* A slot copied from another session fails its binding check. */
	uint8_t copy[EZ_SLOT_SIZE];
	forge_slot(copy, 'T', a + 1, sel, 700);
	memcpy(p, copy, EZ_SLOT_SIZE);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_SLOT_CHECK);
	/* An RX slot copied into the TX position fails too. */
	forge_slot(copy, 'R', a, sel, 700);
	memcpy(p, copy, EZ_SLOT_SIZE);
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_SLOT_CHECK);
}

/* Changing the role byte would swap TX and RX ranges: caught by the CRC. */
static void t_role_tamper(void)
{
	fx_init(&fx);
	int a = fx_create(&fx, 0xAB, 1000, EZ_ROLE_ALICE, "a");
	rec(a)[EZ_SR_OFF_ROLE] = EZ_ROLE_BOB;
	fx_reboot(&fx);
	EZ_CHECK_EQ(fx.m.s[a].state, EZ_SS_QUARANTINED);
	EZ_CHECK_EQ(fx.m.s[a].qreason, EZ_Q_STATIC_CRC);
}

static const ez_test_case_t cases[] = {
	{ "by_command",                 "SEC-TEST-PTR-003, SEC-PTR-002, SEC-UI-005", t_by_command },
	{ "selector_swap",              "SEC-TEST-PTR-003, IMPL-META-002", t_selector_swap },
	{ "lower_value_in_inactive_slot","SEC-TEST-PTR-003, IMPL-META-002", t_lower_value_in_inactive_slot },
	{ "damaged_selected_slot",      "SEC-TEST-PTR-003, SEC-PTR-001, IMPL-META-006", t_damaged_selected_slot },
	{ "garbage_selector",           "SEC-TEST-PTR-003, SEC-PTR-001", t_garbage_selector },
	{ "out_of_range",               "SEC-TEST-PTR-003, SEC-ISO-001", t_out_of_range },
	{ "role_tamper",                "SEC-TEST-PTR-003, SEC-META-001", t_role_tamper },
};
EZ_TEST_MAIN(cases)
