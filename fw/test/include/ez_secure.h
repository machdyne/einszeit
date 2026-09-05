/*
 * ez_secure.h -- memory hygiene helpers
 *
 * EZ-SEC-001 traceability:
 *   SEC-FW-002  clearing operations must survive compiler optimisation
 *   SEC-FW-003  memory that held key bytes or plaintext must be cleared
 *               before reuse
 *
 * This test firmware never handles Key material or plaintext, so neither
 * requirement is load-bearing here. Both are implemented and used anyway for
 * two reasons: the shared capture buffer is reused as scratch by the FRAM and
 * SD tests, and stale contents leaking from one test into another produces
 * confusing results; and production firmware needs a reviewed implementation
 * of exactly this, which this file is intended to become.
 */
#ifndef EZ_SECURE_H
#define EZ_SECURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Overwrite `len` bytes at `p` with zero in a way the compiler may not remove.
 *
 * memset() to a buffer that is never read again is dead-store-eliminated by
 * every optimising compiler, which is the classic way this requirement is
 * violated without anyone noticing. The volatile pointer forces each store to
 * be emitted, and the barrier stops the compiler reordering later reads of the
 * same object ahead of the clear.
 */
void ez_secure_zero(void *p, size_t len);

/* Zero then verify. Returns false if any byte survived, which would mean the
 * region is not writable RAM and the caller must treat it as still dirty. */
bool ez_secure_zero_verify(void *p, size_t len);

#endif /* EZ_SECURE_H */
