/* sim_trng.c -- see sim_trng.h. TEST ONLY. */
#include "sim_trng.h"

#include <string.h>

static uint64_t splitmix(uint64_t *s)
{
	uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
	return z ^ (z >> 31);
}

void sim_fill(uint8_t *out, size_t n, uint64_t seed)
{
	uint64_t s = seed;
	for (size_t i = 0; i < n; i += 8) {
		uint64_t v = splitmix(&s);
		for (size_t j = 0; j < 8 && i + j < n; j++) out[i + j] = (uint8_t)(v >> (8 * j));
	}
}

static uint8_t next_byte(sim_trng_t *t)
{
	switch (t->mode) {
	case SIM_TRNG_STUCK:       return (uint8_t)t->param;
	case SIM_TRNG_ALTERNATING: return 0x55;
	case SIM_TRNG_COUNTER:     return t->ctr++;
	case SIM_TRNG_BIASED: {
		uint8_t b = 0;
		for (int i = 0; i < 8; i++)
			b = (uint8_t)((b << 1) | ((splitmix(&t->s) & 0xFF) < t->param));
		return b;
	}
	case SIM_TRNG_CORRELATED: {
		uint8_t b = 0;
		for (int i = 0; i < 8; i++) {
			uint8_t bit = (splitmix(&t->s) & 0xFF) < t->param ? t->last
			                                                : (uint8_t)(splitmix(&t->s) & 1);
			t->last = bit;
			b = (uint8_t)((b << 1) | bit);
		}
		return b;
	}
	case SIM_TRNG_BUFFER:
		if (t->pos < t->buflen) return t->buf[t->pos++];
		/* fall through */
	case SIM_TRNG_GOOD:
	default:
		return (uint8_t)splitmix(&t->s);
	}
}

static ez_status_t rd(void *ctx, void *buf, uint32_t len)
{
	sim_trng_t *t = ctx;
	uint8_t *p = buf;
	for (uint32_t i = 0; i < len; i++) {
		if (t->fault_after == 0) return EZ_ERR_ENTROPY;
		if (t->fault_after > 0) t->fault_after--;
		p[i] = next_byte(t);
		t->bytes++;
	}
	return EZ_OK;
}

void sim_trng_init(sim_trng_t *t, uint64_t seed)
{
	memset(t, 0, sizeof *t);
	t->s = seed;
	t->fault_after = -1;
	t->hal.ctx = t;
	t->hal.profile = 0xF0;      /* simulator profile ID */
	t->hal.read = rd;
}

void sim_trng_mode(sim_trng_t *t, sim_trng_mode_t mode, uint32_t param)
{
	t->mode = mode;
	t->param = param;
}

void sim_trng_fault_after(sim_trng_t *t, long n) { t->fault_after = n; }
