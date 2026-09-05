/*
 * ez_secure.c -- see include/ez_secure.h
 *
 * EZ-SEC-001 traceability: SEC-FW-002, SEC-FW-003.
 */
#include <string.h>

#include "ez_secure.h"

void ez_secure_zero(void *p, size_t len)
{
    if (p == NULL || len == 0) return;

    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;

    /*
     * SEC-FW-002: the volatile stores above are guaranteed to be emitted, but
     * a compiler may still hoist a later read of the same object above them
     * unless it is told the memory changed.
     */
    __asm__ __volatile__("" ::: "memory");
}

bool ez_secure_zero_verify(void *p, size_t len)
{
    ez_secure_zero(p, len);

    const volatile uint8_t *v = (const volatile uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        if (v[i] != 0) return false;
    }
    return true;
}
