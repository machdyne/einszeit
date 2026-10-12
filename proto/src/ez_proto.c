/* ez_proto.c -- see ez_proto.h */
#include "ez_proto.h"

#include <string.h>

#include "ez_bytes.h"

void ez_frame_encode(const ez_frame_t *f, uint8_t o[EZ_FRAME_SIZE])
{
	memset(o, 0, EZ_FRAME_SIZE);
	o[0] = f->cmd; o[1] = f->flags; o[2] = f->seq; o[3] = f->status;
	uint16_t n = f->len > EZ_FRAME_PAYLOAD ? EZ_FRAME_PAYLOAD : f->len;
	ez_put_le16(o + 4, n);
	memcpy(o + 6, f->data, n);
}

ez_status_t ez_frame_decode(const uint8_t in[EZ_FRAME_SIZE], ez_frame_t *f)
{
	memset(f, 0, sizeof *f);
	f->cmd = in[0]; f->flags = in[1]; f->seq = in[2]; f->status = in[3];
	f->len = ez_get_le16(in + 4);
	if (f->len > EZ_FRAME_PAYLOAD || (f->flags & EZ_FF_RESERVED)) {
		f->len = 0;
		return EZ_ERR_BAD_REQUEST;
	}
	memcpy(f->data, in + 6, f->len);
	return EZ_OK;
}

void ez_rd_init(ez_rd_t *r, const uint8_t *p, size_t n) { r->p = p; r->n = n; r->i = 0; r->err = false; }

static const uint8_t *take(ez_rd_t *r, size_t k)
{
	if (r->err || r->n - r->i < k) { r->err = true; return NULL; }
	const uint8_t *q = r->p + r->i;
	r->i += k;
	return q;
}

uint8_t  ez_rd_u8(ez_rd_t *r)  { const uint8_t *q = take(r, 1); return q ? q[0] : 0; }
uint16_t ez_rd_u16(ez_rd_t *r) { const uint8_t *q = take(r, 2); return q ? ez_get_le16(q) : 0; }
uint32_t ez_rd_u32(ez_rd_t *r) { const uint8_t *q = take(r, 4); return q ? ez_get_le32(q) : 0; }

void ez_rd_str(ez_rd_t *r, char *out, size_t cap)
{
	out[0] = 0;
	uint8_t n = ez_rd_u8(r);
	const uint8_t *q = take(r, n);
	if (!q || (size_t)n + 1 > cap || memchr(q, 0, n)) { r->err = true; return; }
	memcpy(out, q, n);
	out[n] = 0;
}

bool ez_rd_done(const ez_rd_t *r) { return !r->err && r->i == r->n; }

void ez_wr_init(ez_wr_t *w, uint8_t *p, size_t cap) { w->p = p; w->cap = cap; w->n = 0; w->err = false; }

static uint8_t *put(ez_wr_t *w, size_t k)
{
	if (w->err || w->cap - w->n < k) { w->err = true; return NULL; }
	uint8_t *q = w->p + w->n;
	w->n += k;
	return q;
}

void ez_wr_u8(ez_wr_t *w, uint8_t v)   { uint8_t *q = put(w, 1); if (q) q[0] = v; }
void ez_wr_u16(ez_wr_t *w, uint16_t v) { uint8_t *q = put(w, 2); if (q) ez_put_le16(q, v); }
void ez_wr_u32(ez_wr_t *w, uint32_t v) { uint8_t *q = put(w, 4); if (q) ez_put_le32(q, v); }
void ez_wr_bytes(ez_wr_t *w, const void *b, size_t n) { uint8_t *q = put(w, n); if (q && n) memcpy(q, b, n); }

void ez_wr_str(ez_wr_t *w, const char *s)
{
	size_t n = strlen(s);
	if (n > 255) { w->err = true; return; }
	ez_wr_u8(w, (uint8_t)n);
	ez_wr_bytes(w, s, n);
}

void ez_wsession_write(ez_wr_t *w, const ez_wsession_t *s)
{
	ez_wr_u8(w, s->slot); ez_wr_u8(w, s->state); ez_wr_u8(w, s->qreason);
	ez_wr_u8(w, s->role); ez_wr_u8(w, s->drive); ez_wr_u8(w, s->flags);
	ez_wr_u32(w, s->key_id); ez_wr_u32(w, s->key_len);
	ez_wr_u32(w, s->tx_left); ez_wr_u32(w, s->rx_left); ez_wr_u32(w, s->tx_range);
	ez_wr_str(w, s->label);
}

void ez_wsession_read(ez_rd_t *r, ez_wsession_t *s)
{
	s->slot = ez_rd_u8(r); s->state = ez_rd_u8(r); s->qreason = ez_rd_u8(r);
	s->role = ez_rd_u8(r); s->drive = ez_rd_u8(r); s->flags = ez_rd_u8(r);
	s->key_id = ez_rd_u32(r); s->key_len = ez_rd_u32(r);
	s->tx_left = ez_rd_u32(r); s->rx_left = ez_rd_u32(r); s->tx_range = ez_rd_u32(r);
	ez_rd_str(r, s->label, sizeof s->label);
}

void ez_wjob_write(ez_wr_t *w, const ez_wjob_t *j)
{
	ez_wr_u8(w, j->job); ez_wr_u8(w, j->running); ez_wr_u8(w, j->result); ez_wr_u8(w, j->fail);
	ez_wr_u8(w, j->have_sum); ez_wr_u8(w, j->slot); ez_wr_u16(w, j->permille);
	ez_wr_u32(w, j->key_id); ez_wr_u32(w, j->bad); ez_wr_u32(w, j->first_bad); ez_wr_u32(w, j->dups);
	ez_wr_u8(w, j->replicate);
	ez_wr_u8(w, j->cmd);
}

void ez_wjob_read(ez_rd_t *r, ez_wjob_t *j)
{
	j->job = ez_rd_u8(r); j->running = ez_rd_u8(r); j->result = ez_rd_u8(r); j->fail = ez_rd_u8(r);
	j->have_sum = ez_rd_u8(r); j->slot = ez_rd_u8(r); j->permille = ez_rd_u16(r);
	j->key_id = ez_rd_u32(r); j->bad = ez_rd_u32(r); j->first_bad = ez_rd_u32(r); j->dups = ez_rd_u32(r);
	j->replicate = ez_rd_u8(r);
	j->cmd = ez_rd_u8(r);
}
