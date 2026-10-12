/*
 * meta_fixture.h -- shared setup for metadata tests: a simulated F-RAM,
 * a booted ez_meta_t, and helpers to snapshot, reboot and compare.
 */
#ifndef META_FIXTURE_H
#define META_FIXTURE_H

#include <string.h>

#include "ez_meta.h"
#include "ez_test.h"
#include "sim_fram.h"

typedef struct {
	sim_fram_t fram;
	ez_meta_t  m;
} fx_t;

/* Blank F-RAM, boot, format, reboot: a freshly initialised device. */
void fx_init(fx_t *fx);
/* Power cycle: restore power and run the full boot verification. */
void fx_reboot(fx_t *fx);
/* Create a session or fail the test. Returns the slot. */
int  fx_create(fx_t *fx, uint32_t key_id, uint32_t key_len, uint8_t role, const char *label);

/* Field-wise equality of the security-relevant parts of two sessions. */
int  fx_session_same(const ez_session_t *a, const ez_session_t *b);

#endif
