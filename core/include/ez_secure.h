/*
 * ez_secure.h -- clearing of sensitive buffers
 *
 * EZ-SEC-001 traceability:
 *   SEC-FW-002  clears cannot be elided: volatile stores plus a compiler
 *               barrier.
 *   SEC-FW-003  every buffer that held key bytes or plaintext is cleared
 *               with ez_secure_zero() before reuse.
 *   SEC-GEN-001, SEC-ENC-003  callers clear block and plaintext buffers
 *               with this function.
 */
#ifndef EZ_SECURE_H
#define EZ_SECURE_H

#include <stdbool.h>
#include <stddef.h>

void ez_secure_zero(void *p, size_t n);

/* Returns true if all n bytes are zero. Used by tests and verified wipes. */
bool ez_is_zero(const void *p, size_t n);

#endif /* EZ_SECURE_H */
