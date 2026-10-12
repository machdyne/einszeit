/* ez_base64.c -- see ez_base64.h */
#include "ez_base64.h"

static const char ALPHA[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void enc3(const uint8_t *in, char *out)
{
	uint32_t v = ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | in[2];
	out[0] = ALPHA[(v >> 18) & 63]; out[1] = ALPHA[(v >> 12) & 63];
	out[2] = ALPHA[(v >> 6) & 63];  out[3] = ALPHA[v & 63];
}

static size_t enc_tail(const uint8_t *in, size_t n, char *out)
{
	if (n == 0) return 0;
	uint8_t t[3] = { in[0], n > 1 ? in[1] : 0, 0 };
	enc3(t, out);
	out[3] = '=';
	if (n == 1) out[2] = '=';
	return 4;
}

size_t ez_b64_encode(const uint8_t *in, size_t n, char *out)
{
	size_t o = 0, i = 0;
	for (; i + 3 <= n; i += 3, o += 4) enc3(in + i, out + o);
	return o + enc_tail(in + i, n - i, out + o);
}

void ez_b64_enc_init(ez_b64_enc_t *e) { e->npend = 0; }

size_t ez_b64_enc_update(ez_b64_enc_t *e, const uint8_t *in, size_t n, char *out)
{
	size_t o = 0;
	while (n && e->npend) {
		uint8_t t[3] = { e->pend[0], e->pend[1], 0 };
		t[e->npend++] = *in++; n--;
		if (e->npend == 3) { enc3(t, out); o += 4; e->npend = 0; }
		else { e->pend[0] = t[0]; e->pend[1] = t[1]; }
	}
	for (; n >= 3; n -= 3, in += 3, o += 4) enc3(in, out + o);
	while (n--) e->pend[e->npend++] = *in++;
	return o;
}

size_t ez_b64_enc_final(ez_b64_enc_t *e, char *out)
{
	size_t o = enc_tail(e->pend, e->npend, out);
	e->npend = 0;
	e->pend[0] = e->pend[1] = 0;
	return o;
}

static int val(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

void ez_b64_dec_init(ez_b64_dec_t *d)
{
	d->acc = 0; d->nacc = 0; d->npad = 0; d->done = 0; d->err = 0;
}

ez_status_t ez_b64_dec_update(ez_b64_dec_t *d, const char *in, size_t n,
                              uint8_t *out, size_t *out_n)
{
	size_t o = 0;
	for (size_t i = 0; i < n && !d->err; i++) {
		char c = in[i];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
		if (d->done) { d->err = 1; break; }
		if (c == '=') {
			/* padding only in positions 3 or 4 of a quantum */
			if (d->nacc + d->npad < 2) { d->err = 1; break; }
			d->npad++;
			if (d->nacc + d->npad == 4) {
				if (d->npad == 1) {          /* xx x= : 2 bytes */
					if (d->acc & 0x3u) { d->err = 1; break; }
					out[o++] = (uint8_t)(d->acc >> 10);
					out[o++] = (uint8_t)(d->acc >> 2);
				} else {                     /* xx== : 1 byte */
					if (d->acc & 0xFu) { d->err = 1; break; }
					out[o++] = (uint8_t)(d->acc >> 4);
				}
				d->done = 1;
			}
			continue;
		}
		int v = val(c);
		if (v < 0 || d->npad) { d->err = 1; break; }
		d->acc = (d->acc << 6) | (uint32_t)v;
		if (++d->nacc == 4) {
			out[o++] = (uint8_t)(d->acc >> 16);
			out[o++] = (uint8_t)(d->acc >> 8);
			out[o++] = (uint8_t)d->acc;
			d->acc = 0; d->nacc = 0;
		}
	}
	*out_n = o;
	return d->err ? EZ_ERR_BAD_REQUEST : EZ_OK;
}

ez_status_t ez_b64_dec_final(ez_b64_dec_t *d)
{
	if (d->err || (d->nacc != 0 && !d->done) || (d->npad && !d->done))
		return EZ_ERR_BAD_REQUEST;
	return EZ_OK;
}
