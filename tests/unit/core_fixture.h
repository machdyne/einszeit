/*
 * core_fixture.h -- a complete simulated device: F-RAM, key storage, TRNG
 * and an initialised ez_core_t. Two fixtures model two devices sharing a
 * key (alice and bob).
 */
#ifndef CORE_FIXTURE_H
#define CORE_FIXTURE_H

#include "ez_core.h"
#include "ez_engine.h"
#include "ez_keygen.h"
#include "ez_secure.h"
#include "ez_test.h"
#include "sim_fram.h"
#include "sim_keystore.h"
#include "sim_trng.h"

typedef struct {
	sim_fram_t fram;
	sim_ks_t   ks;
	sim_trng_t trng;
	ez_core_t  c;
	uint8_t    stage[EZ_STAGE_SIZE];
} ezdev_t;

/* Fresh device: formatted metadata, empty drives 0..2 present, drive 0
 * disabled, TRNG in GOOD mode with the given seed. Heap-allocated (the
 * key store's file log is large). */
ezdev_t *dev_new(uint64_t seed);
void   dev_free(ezdev_t *d);
/* Power cycle (F-RAM and key storage persist). */
void   dev_reboot(ezdev_t *d);
/* Put a key file <ID>.KEY with deterministic content (seed) on a drive,
 * with its integrity file <ID>.SUM (instance tag derived from the seed). */
void   dev_put_key(ezdev_t *d, uint8_t drive, uint32_t key_id, uint32_t len, uint64_t seed);
/* Write <ID>.SUM for given key bytes (as the generating device would). */
void   put_sum(sim_ks_t *ks, uint8_t drive, uint32_t key_id, const uint8_t *key,
               uint32_t len, uint16_t instance);
/* Copy a key file and its .SUM from one device to another (physical transfer). */
void   dev_copy_key(ezdev_t *from, ezdev_t *to, uint8_t drive, uint32_t key_id);
int    dev_session(ezdev_t *d, uint32_t key_id, uint8_t drive, uint8_t role, const char *label);

/* Buffered round trips. out must hold len + EZ_MSG_OVERHEAD bytes. */
ez_status_t dev_encrypt(ezdev_t *d, int slot, const uint8_t *pt, uint32_t len,
                        uint8_t *out, uint32_t *out_len);
ez_status_t dev_decrypt(ezdev_t *d, int slot, const uint8_t *msg, uint32_t len,
                        uint8_t *out, uint32_t *out_len);
/* Streaming with a given chunk size. */
ez_status_t dev_encrypt_stream(ezdev_t *d, int slot, const uint8_t *pt, uint32_t len,
                               uint32_t chunk, uint8_t *out, uint32_t *out_len);
ez_status_t dev_decrypt_stream(ezdev_t *d, int slot, const uint8_t *msg, uint32_t len,
                               uint32_t chunk, uint8_t *out, uint32_t *out_len);

/* Key scratch is clear between calls (SEC-FW-003, IMPL-ENG-002). */
#define DEV_KBUF_CLEAR(d) do { \
	EZ_CHECK_MSG(ez_is_zero((d)->c.kbuf, sizeof (d)->c.kbuf), "key scratch buffer not cleared"); \
	if (!(d)->c.stream_active) \
		EZ_CHECK_MSG(!(d)->c.u_valid && ez_is_zero((d)->c.ubuf, sizeof (d)->c.ubuf), \
		             "verified key unit not cleared"); \
	EZ_CHECK_MSG((d)->ks.dirty_reads == 0, "key read into a buffer holding stale data"); } while (0)

#endif
