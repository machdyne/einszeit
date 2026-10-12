/*
 * ez_secure.c -- see ez_secure.h. SEC-FW-002, SEC-FW-003.
 */
#include "ez_secure.h"

#include <stdint.h>

void ez_secure_zero(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;
	while (n--)
		*v++ = 0;
	/* Prevent the compiler from treating the stores as dead. */
	__asm__ __volatile__("" : : "r"(p) : "memory");
}

bool ez_is_zero(const void *p, size_t n)
{
	const volatile uint8_t *v = (const volatile uint8_t *)p;
	uint8_t acc = 0;
	while (n--)
		acc |= *v++;
	return acc == 0;
}
