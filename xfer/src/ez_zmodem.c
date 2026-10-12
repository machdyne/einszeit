/* ez_zmodem.c -- see ez_zmodem.h */
#include "ez_zmodem.h"

#include <stdio.h>
#include <string.h>

/* ---- the protocol's constants (Forsberg 1988) ------------------------------- */
#define ZPAD   0x2A          /* '*' */
#define ZDLE   0x18          /* also CAN */
#define ZBIN   'A'
#define ZHEX   'B'
#define ZBIN32 'C'
#define XON    0x11

enum {
	ZRQINIT = 0, ZRINIT = 1, ZSINIT = 2, ZACK = 3, ZFILE = 4, ZSKIP = 5, ZNAK = 6,
	ZABORT = 7, ZFIN = 8, ZRPOS = 9, ZDATA = 10, ZEOF = 11, ZFERR = 12, ZCRC = 13,
	ZCHALLENGE = 14, ZCOMPL = 15, ZCAN = 16, ZFREECNT = 17, ZCOMMAND = 18, ZSTDERR = 19
};
#define ZCRCE 'h'            /* frame ends, a header follows */
#define ZCRCG 'i'            /* frame continues */
#define ZCRCQ 'j'            /* frame continues, ZACK expected */
#define ZCRCW 'k'            /* frame ends, ZACK expected */
#define ZRUB0 'l'            /* an escaped 0x7F */
#define ZRUB1 'm'            /* an escaped 0xFF */

/* ZRINIT flags (ZF0) */
#define CANFDX  0x01
#define CANOVIO 0x02
#define CANFC32 0x20
#define ESCCTL  0x40

/* ---- timing ---- */
#define RX_INIT_MS   3000u   /* receiver: ZRINIT every 3 s while nothing comes */
#define RX_INIT_MAX  10
#define WAIT_MS      10000u  /* no answer / no data */
#define RETRIES      10
#define TX_START_MS  5000u   /* sender: ZRQINIT every 5 s, for a minute */
#define TX_START_MAX 12
#define SUBPKT       1024u
#define WINDOW       4096u

/* ---- CRCs ------------------------------------------------------------------- */

uint16_t ez_zm_crc16(uint16_t c, const uint8_t *p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		c = (uint16_t)(c ^ (uint16_t)(p[i] << 8));
		for (int b = 0; b < 8; b++) c = (uint16_t)((c & 0x8000u) ? ((unsigned)c << 1) ^ 0x1021u : (unsigned)c << 1);
	}
	return c;
}

uint32_t ez_zm_crc32(uint32_t c, const uint8_t *p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		c ^= p[i];
		for (int b = 0; b < 8; b++) c = (c & 1u) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
	}
	return c;
}

const char *ez_zm_error(ez_zm_err_t e)
{
	switch (e) {
	case EZ_ZM_OK:            return "ok";
	case EZ_ZM_ERR_TIMEOUT:   return "no answer from the other side";
	case EZ_ZM_ERR_CANCELLED: return "cancelled";
	case EZ_ZM_ERR_REMOTE:    return "cancelled by the other side";
	case EZ_ZM_ERR_RETRIES:   return "too many errors on the line";
	case EZ_ZM_ERR_SINK:      return "the file is too large";
	case EZ_ZM_ERR_SKIPPED:   return "the other side did not take the file";
	case EZ_ZM_ERR_PROTOCOL:  return "the other side broke the protocol";
	}
	return "?";
}

/* ---- output ----------------------------------------------------------------- */

/* Output is gathered here and handed to out() a frame at a time. */
static uint8_t ob[2 * (SUBPKT + 8) + 32];
static uint32_t on;

static void flush(ez_zm_t *z) { if (on) z->out(z->ctx, ob, on); on = 0; }
static void put(ez_zm_t *z, uint8_t b) { if (on == sizeof ob) flush(z); ob[on++] = b; }

/* ZDLE-escape one byte (binary headers and data). */
static void put_esc(ez_zm_t *z, uint8_t b)
{
	bool esc;
	switch (b) {
	case ZDLE: case 0x10: case 0x90: case 0x11: case 0x91: case 0x13: case 0x93:
		esc = true;
		break;
	case 0x0D: case 0x8D:
		esc = z->escctl || z->last_at;           /* "@\r" upsets some networks */
		break;
	default:
		esc = z->escctl && (b & 0x60) == 0;      /* 0x00-0x1F, 0x80-0x9F */
		break;
	}
	if (esc) { put(z, ZDLE); put(z, (uint8_t)(b ^ 0x40)); }
	else put(z, b);
	z->last_at = (b & 0x7F) == '@';
}

static void put_hex(ez_zm_t *z, uint8_t b)
{
	static const char h[] = "0123456789abcdef";
	put(z, (uint8_t)h[b >> 4]);
	put(z, (uint8_t)h[b & 15]);
}

/* The header's 4 bytes: a position (little-endian), or flags ZF3..ZF0. */
static void hdr_bytes(uint8_t type, uint32_t arg, uint8_t h[5])
{
	h[0] = type;
	h[1] = (uint8_t)arg; h[2] = (uint8_t)(arg >> 8); h[3] = (uint8_t)(arg >> 16); h[4] = (uint8_t)(arg >> 24);
}

static void send_hex(ez_zm_t *z, uint8_t type, uint32_t arg)
{
	uint8_t h[5];
	hdr_bytes(type, arg, h);
	uint16_t c = ez_zm_crc16(0, h, 5);
	put(z, ZPAD); put(z, ZPAD); put(z, ZDLE); put(z, ZHEX);
	for (int i = 0; i < 5; i++) put_hex(z, h[i]);
	put_hex(z, (uint8_t)(c >> 8)); put_hex(z, (uint8_t)c);
	put(z, '\r'); put(z, 0x8A);
	if (type != ZACK && type != ZFIN) put(z, XON);
	flush(z);
}

static void send_bin(ez_zm_t *z, uint8_t type, uint32_t arg)
{
	uint8_t h[5];
	hdr_bytes(type, arg, h);
	put(z, ZPAD); put(z, ZDLE); put(z, z->crc32 ? ZBIN32 : ZBIN);
	for (int i = 0; i < 5; i++) put_esc(z, h[i]);
	if (z->crc32) {
		uint32_t c = ~ez_zm_crc32(0xFFFFFFFFu, h, 5);
		for (int i = 0; i < 4; i++) put_esc(z, (uint8_t)(c >> (8 * i)));
	} else {
		uint16_t c = ez_zm_crc16(0, h, 5);
		put_esc(z, (uint8_t)(c >> 8)); put_esc(z, (uint8_t)c);
	}
	flush(z);
}

static void send_sub(ez_zm_t *z, const uint8_t *d, uint32_t n, uint8_t end)
{
	for (uint32_t i = 0; i < n; i++) put_esc(z, d[i]);
	put(z, ZDLE); put(z, end);
	if (z->crc32) {
		uint32_t c = ez_zm_crc32(0xFFFFFFFFu, d, n);
		c = ~ez_zm_crc32(c, &end, 1);
		for (int i = 0; i < 4; i++) put_esc(z, (uint8_t)(c >> (8 * i)));
	} else {
		uint16_t c = ez_zm_crc16(ez_zm_crc16(0, d, n), &end, 1);
		put_esc(z, (uint8_t)(c >> 8)); put_esc(z, (uint8_t)c);
	}
	flush(z);
}

static ez_zm_result_t fail(ez_zm_t *z, ez_zm_err_t e, bool send_can)
{
	if (send_can) {
		static const uint8_t can[18] = { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
		                                 8, 8, 8, 8, 8, 8, 8, 8, 8, 8 };
		z->out(z->ctx, can, sizeof can);
	}
	z->result = EZ_ZM_FAILED;
	z->err = e;
	return z->result;
}

void ez_zm_cancel(ez_zm_t *z) { if (z->result == EZ_ZM_RUNNING) fail(z, EZ_ZM_ERR_CANCELLED, true); }

/* ---- the line parser: headers and data subpackets ------------------------------ */

enum { HP_IDLE, HP_PAD, HP_FMT, HP_BODY };

static int unhex(uint8_t c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decoded header: type and argument; false if damaged. */
static bool hdr_done(ez_zm_t *z, uint8_t *type, uint32_t *arg)
{
	const uint8_t *h = z->hbuf;
	bool ok;
	if (z->hfmt == ZBIN32) {
		uint32_t c = ~ez_zm_crc32(0xFFFFFFFFu, h, 5);
		ok = (uint32_t)h[5] == (c & 0xFF) && h[6] == (uint8_t)(c >> 8) && h[7] == (uint8_t)(c >> 16) &&
		     h[8] == (uint8_t)(c >> 24);
	} else {
		uint16_t c = ez_zm_crc16(0, h, 5);
		ok = h[5] == (uint8_t)(c >> 8) && h[6] == (uint8_t)c;
	}
	*type = h[0];
	*arg = (uint32_t)h[1] | (uint32_t)h[2] << 8 | (uint32_t)h[3] << 16 | (uint32_t)h[4] << 24;
	return ok;
}

static void on_header(ez_zm_t *z, uint8_t type, uint32_t arg, uint32_t now);
static void on_bad_header(ez_zm_t *z);
static void on_subpacket(ez_zm_t *z, bool ok, uint32_t now);

/* After a ZDLE: the decoded byte, or a frame end ('h'..'k' as negative), or -1. */
static int unescape(uint8_t b)
{
	if (b >= ZCRCE && b <= ZCRCW) return -(int)b;
	if (b == ZRUB0) return 0x7F;
	if (b == ZRUB1) return 0xFF;
	if ((b & 0x60) == 0x40) return b ^ 0x40;
	return -1;
}

static void sub_byte(ez_zm_t *z, uint8_t b, uint32_t now)
{
	if (b == 0x11 || b == 0x13 || b == 0x91 || b == 0x93) return;   /* flow control on the line */
	if (!z->zdle && b == ZDLE) { z->zdle = true; return; }
	int v = b;
	if (z->zdle) {
		z->zdle = false;
		v = unescape(b);
		if (v == -1) { z->in_data = false; on_subpacket(z, false, now); return; }
		if (v < 0) {
			if (z->sub_end) { z->in_data = false; on_subpacket(z, false, now); return; }
			z->sub_end = -v;
			return;
		}
	}
	if (z->sub_end) {                         /* the CRC */
		z->crc_b[z->crc_n++] = (uint8_t)v;
		if (z->crc_n < (z->data32 ? 4 : 2)) return;
		uint8_t end = (uint8_t)z->sub_end;
		bool ok;
		if (z->data32) {
			uint32_t c = ~ez_zm_crc32(ez_zm_crc32(0xFFFFFFFFu, z->sub, z->sub_n), &end, 1);
			ok = z->crc_b[0] == (uint8_t)c && z->crc_b[1] == (uint8_t)(c >> 8) &&
			     z->crc_b[2] == (uint8_t)(c >> 16) && z->crc_b[3] == (uint8_t)(c >> 24);
		} else {
			uint16_t c = ez_zm_crc16(ez_zm_crc16(0, z->sub, z->sub_n), &end, 1);
			ok = z->crc_b[0] == (uint8_t)(c >> 8) && z->crc_b[1] == (uint8_t)c;
		}
		on_subpacket(z, ok, now);
		return;
	}
	if (z->sub_n >= EZ_ZM_SUBPKT_MAX) { z->in_data = false; on_subpacket(z, false, now); return; }
	z->sub[z->sub_n++] = (uint8_t)v;
}

static void start_sub(ez_zm_t *z, int which)
{
	z->in_data = true;
	z->data32 = z->hfmt == ZBIN32;
	z->sub_n = 0;
	z->sub_end = 0;
	z->crc_n = 0;
	z->zdle = false;
	z->want_sub = which;
}

static void line_byte(ez_zm_t *z, uint8_t b, uint32_t now)
{
	/* five CANs in a row: the other side gave up */
	if (b == 0x18) { if (++z->cans >= 5) { fail(z, EZ_ZM_ERR_REMOTE, false); return; } }
	else z->cans = 0;
	/* A hex header ends with CR LF (and XON): never part of what follows. */
	if (z->skip_crlf) {
		if ((b & 0x7F) == '\r' || (b & 0x7F) == '\n') { z->skip_crlf--; return; }
		z->skip_crlf = 0;
	}
	if (z->in_data) { sub_byte(z, b, now); return; }
	switch (z->hp) {
	case HP_IDLE:
		if (b == ZPAD) z->hp = HP_PAD;
		return;
	case HP_PAD:
		if (b == ZDLE) z->hp = HP_FMT;
		else if (b != ZPAD) z->hp = HP_IDLE;
		return;
	case HP_FMT:
		z->hfmt = b;
		z->hn = 0;
		z->zdle = false;
		if (b == ZHEX) z->hneed = 14;
		else if (b == ZBIN) z->hneed = 7;
		else if (b == ZBIN32) z->hneed = 9;
		else { z->hp = HP_IDLE; return; }
		z->hp = HP_BODY;
		return;
	case HP_BODY:
		if (z->hfmt == ZHEX) {
			int v = unhex(b);
			if (v < 0) { z->hp = HP_IDLE; on_bad_header(z); return; }
			if (z->hn & 1) z->hbuf[z->hn / 2] = (uint8_t)(z->hbuf[z->hn / 2] | v);
			else z->hbuf[z->hn / 2] = (uint8_t)(v << 4);
			z->hn++;
		} else {
			if (b == 0x11 || b == 0x13 || b == 0x91 || b == 0x93) return;
			if (!z->zdle && b == ZDLE) { z->zdle = true; return; }
			int v = b;
			if (z->zdle) {
				z->zdle = false;
				v = unescape(b);
				if (v < 0) { z->hp = HP_IDLE; on_bad_header(z); return; }
			}
			z->hbuf[z->hn++] = (uint8_t)v;
		}
		if (z->hn < z->hneed) return;
		z->hp = HP_IDLE;
		if (z->hfmt == ZHEX) z->skip_crlf = 2;
		uint8_t type;
		uint32_t arg;
		if (!hdr_done(z, &type, &arg)) { on_bad_header(z); return; }
		on_header(z, type, arg, now);
		return;
	}
}

/* ---- receiving ------------------------------------------------------------------ */

enum { R_INIT, R_DATA, R_SKIPPING, R_DONE };

static void rx_send(ez_zm_t *z, uint8_t type, uint32_t arg, uint32_t now)
{
	z->last_type = type;
	z->last_arg = arg;
	z->t_wait = now;
	send_hex(z, type, arg);
}

static void rx_rinit(ez_zm_t *z, uint32_t now)
{
	/* ZF0 is the header's last byte: full duplex, overlapped I/O, CRC-32;
	 * buffer size 0 (ZP0, ZP1): stream as fast as you like */
	rx_send(z, ZRINIT, (uint32_t)(CANFDX | CANOVIO | CANFC32) << 24, now);
}

void ez_zm_recv(ez_zm_t *z, ez_zm_sink_fn sink, uint32_t max_len, ez_zm_out_fn out, void *ctx, uint32_t now)
{
	memset(z, 0, sizeof *z);
	z->sink = sink;
	z->out = out;
	z->ctx = ctx;
	z->max_len = max_len;
	z->state = R_INIT;
	z->t_rx = now;
	rx_rinit(z, now);
}

/* ZFILE's subpacket: "name\0length [mtime mode ...]\0". */
static void rx_file(ez_zm_t *z, uint32_t now)
{
	uint32_t i = 0;
	while (i < z->sub_n && z->sub[i]) i++;
	uint32_t nl = i < sizeof z->name - 1 ? i : (uint32_t)sizeof z->name - 1;
	memcpy(z->name, z->sub, nl);
	z->name[nl] = 0;
	z->len_known = false;
	z->len = 0;
	if (i + 1 < z->sub_n && z->sub[i + 1] >= '0' && z->sub[i + 1] <= '9') {
		uint64_t v = 0;
		for (uint32_t k = i + 1; k < z->sub_n && z->sub[k] >= '0' && z->sub[k] <= '9' && v <= 0xFFFFFFFFu; k++)
			v = v * 10u + (uint64_t)(z->sub[k] - '0');
		z->len_known = v <= 0xFFFFFFFFu;
		z->len = (uint32_t)v;
	}
	if (z->state == R_DATA) { rx_send(z, ZRPOS, z->pos, now); return; }  /* the same ZFILE again */
	if (z->got_file) { rx_send(z, ZSKIP, 0, now); return; }               /* one file only */
	if (z->len_known && z->len > z->max_len) {
		z->err = EZ_ZM_ERR_SINK;
		rx_send(z, ZSKIP, 0, now);
		return;
	}
	z->pos = 0;
	z->state = R_DATA;
	z->tries = 0;
	rx_send(z, ZRPOS, 0, now);
}

static void rx_header(ez_zm_t *z, uint8_t type, uint32_t arg, uint32_t now)
{
	switch (type) {
	case ZRQINIT:
		if (z->state != R_DATA) rx_rinit(z, now);
		return;
	case ZSINIT:
		start_sub(z, ZSINIT);
		return;
	case ZFILE:
		start_sub(z, ZFILE);
		return;
	case ZDATA:
		if (z->state != R_DATA) return;
		if (arg != z->pos) { rx_send(z, ZRPOS, z->pos, now); return; }    /* not where we are */
		start_sub(z, ZDATA);
		return;
	case ZEOF:
		if (z->state != R_DATA || arg != z->pos) return;                   /* a stale one */
		if (z->len_known && z->pos != z->len) { fail(z, EZ_ZM_ERR_PROTOCOL, true); return; }
		z->got_file = true;
		z->state = R_INIT;
		rx_rinit(z, now);
		return;
	case ZFIN:
		send_hex(z, ZFIN, 0);
		z->state = R_DONE;
		if (z->got_file && z->err == EZ_ZM_OK) z->result = EZ_ZM_DONE;
		else fail(z, z->err != EZ_ZM_OK ? z->err : EZ_ZM_ERR_SKIPPED, false);
		return;
	case ZNAK:
		send_hex(z, z->last_type, z->last_arg);
		return;
	case ZCOMMAND:                                         /* never: a command from the line */
		fail(z, EZ_ZM_ERR_PROTOCOL, true);
		return;
	case ZABORT: case ZCAN: case ZFERR:
		fail(z, EZ_ZM_ERR_REMOTE, false);
		return;
	default:
		return;
	}
}

static void rx_subpacket(ez_zm_t *z, bool ok, uint32_t now)
{
	int which = z->want_sub;
	int end = z->sub_end;
	z->in_data = false;
	if (!ok) {
		if (++z->tries > RETRIES) { fail(z, EZ_ZM_ERR_RETRIES, true); return; }
		if (which == ZDATA) rx_send(z, ZRPOS, z->pos, now);     /* back to the last good byte */
		else rx_send(z, ZNAK, 0, now);                         /* ZFILE / ZSINIT again, please */
		return;
	}
	if (which == ZSINIT) { rx_send(z, ZACK, 0, now); return; }
	if (which == ZFILE) { rx_file(z, now); return; }
	/* ZDATA */
	if (z->len_known && z->pos + z->sub_n > z->len) { fail(z, EZ_ZM_ERR_PROTOCOL, true); return; }
	if (z->sub_n && !z->sink(z->ctx, z->sub, z->sub_n)) { fail(z, EZ_ZM_ERR_SINK, true); return; }
	z->pos += z->sub_n;
	z->total = z->pos;
	z->tries = 0;
	z->t_wait = now;
	if (end == ZCRCW || end == ZCRCQ) rx_send(z, ZACK, z->pos, now);
	if (end == ZCRCG || end == ZCRCQ) start_sub(z, ZDATA);   /* the frame continues */
}

static ez_zm_result_t rx_tick(ez_zm_t *z, uint32_t now)
{
	uint32_t limit = z->state == R_INIT && !z->got_file && z->last_type == ZRINIT ? RX_INIT_MS : WAIT_MS;
	if (now - z->t_rx < limit || now - z->t_wait < limit) return z->result;
	z->in_data = false;
	z->hp = HP_IDLE;
	int max = z->state == R_INIT && !z->got_file && z->last_type == ZRINIT ? RX_INIT_MAX : RETRIES;
	if (++z->tries >= max) return fail(z, EZ_ZM_ERR_TIMEOUT, true);
	if (z->state == R_DATA) rx_send(z, ZRPOS, z->pos, now);
	else rx_send(z, z->last_type, z->last_arg, now);
	return z->result;
}

/* ---- sending -------------------------------------------------------------------- */

enum { S_INIT, S_FILE, S_DATA, S_EOF, S_FIN, S_DONE };

static void tx_init(ez_zm_t *z, uint32_t now)
{
	static const uint8_t rz[3] = { 'r', 'z', '\r' };
	z->out(z->ctx, rz, 3);
	send_hex(z, ZRQINIT, 0);
	z->t_wait = now;
}

static void tx_file(ez_zm_t *z, uint32_t now)
{
	char info[96];
	int n = snprintf(info, sizeof info, "%s%c%lu 0 0 0 1 %lu", z->name, 0, (unsigned long)z->len, (unsigned long)z->len);
	send_bin(z, ZFILE, 0);
	send_sub(z, (const uint8_t *)info, (uint32_t)n + 1, ZCRCW);
	z->state = S_FILE;
	z->t_wait = now;
}

/* A window: ZDATA at pos, subpackets to the window's end, the last ZCRCW. */
static void tx_window(ez_zm_t *z, uint32_t now)
{
	if (z->pos >= z->len) {
		send_bin(z, ZEOF, z->len);
		z->state = S_EOF;
		z->t_wait = now;
		return;
	}
	z->wend = z->pos + z->win < z->len ? z->pos + z->win : z->len;
	send_bin(z, ZDATA, z->pos);
	for (uint32_t p = z->pos; p < z->wend; p += z->blk) {
		uint32_t n = z->wend - p < z->blk ? z->wend - p : z->blk;
		send_sub(z, z->data + p, n, p + n >= z->wend ? ZCRCW : ZCRCG);
	}
	z->state = S_DATA;
	z->t_wait = now;
}

void ez_zm_send(ez_zm_t *z, const uint8_t *data, uint32_t len, const char *name,
                ez_zm_out_fn out, void *ctx, uint32_t now)
{
	memset(z, 0, sizeof *z);
	z->sending = true;
	z->out = out;
	z->ctx = ctx;
	z->data = data;
	z->len = len;
	snprintf(z->name, sizeof z->name, "%s", name && *name ? name : "file");
	for (char *p = z->name; *p; p++) if (*p == '/' || *p == ' ') *p = '_';
	z->state = S_INIT;
	z->t_rx = now;
	z->blk = SUBPKT;
	z->win = WINDOW;
	tx_init(z, now);
}

static void tx_header(ez_zm_t *z, uint8_t type, uint32_t arg, uint32_t now)
{
	switch (type) {
	case ZRINIT:
		/* A repeated ZRINIT must not send ZFILE twice: two ZRPOS 0 would
		 * follow, and the second rewinds a transfer in progress. A lost
		 * ZFILE is resent by the timeout. */
		if (z->state == S_INIT) {
			uint8_t f0 = (uint8_t)(arg >> 24);
			z->crc32 = (f0 & CANFC32) != 0;
			z->escctl = (f0 & ESCCTL) != 0;
			z->tries = 0;
			tx_file(z, now);
		} else if (z->state == S_EOF) {
			send_hex(z, ZFIN, 0);
			z->state = S_FIN;
			z->t_wait = now;
		}
		return;
	case ZRPOS:
		if (z->state != S_FILE && z->state != S_DATA && z->state != S_EOF) return;
		if (arg > z->len) { fail(z, EZ_ZM_ERR_PROTOCOL, true); return; }
		/* Below what the receiver has acknowledged: stale, from before. */
		if (arg < z->good_pos) return;
		if (z->state != S_FILE) {
			/* A damaged window: smaller pieces arrive intact more often on a
			 * bad line. Only retries without progress count. */
			if (arg > z->good_pos) { z->good_pos = arg; z->tries = 0; }
			else if (++z->tries > RETRIES) { fail(z, EZ_ZM_ERR_RETRIES, true); return; }
			/* Shrink only when the same place fails again and again: a
			 * single repeat may be a duplicated message. */
			z->sync_repeats = arg == z->last_sync ? z->sync_repeats + 1 : 0;
			z->last_sync = arg;
			if (z->sync_repeats >= 2 && z->blk > 64u) { z->blk /= 2u; z->win = 4u * z->blk; }
		}
		z->pos = arg;
		tx_window(z, now);
		return;
	case ZACK:
		if (z->state != S_DATA || arg != z->wend) return;       /* not this window's end: stale */
		z->pos = z->wend;
		z->good_pos = z->pos;
		z->total = z->pos;
		z->tries = 0;
		if (z->blk < SUBPKT) { z->blk *= 2u; z->win = z->blk == SUBPKT ? WINDOW : 4u * z->blk; }   /* a clean window: grow back */
		tx_window(z, now);
		return;
	case ZSKIP:
		if (z->state != S_FILE) return;
		z->err = EZ_ZM_ERR_SKIPPED;
		send_hex(z, ZFIN, 0);
		z->state = S_FIN;
		z->t_wait = now;
		return;
	case ZFIN:
		if (z->state != S_FIN) return;
		{ static const uint8_t oo[2] = { 'O', 'O' }; z->out(z->ctx, oo, 2); }
		z->state = S_DONE;
		if (z->err == EZ_ZM_OK) z->result = EZ_ZM_DONE;
		else fail(z, z->err, false);
		return;
	case ZNAK:
		if (z->state == S_FILE) tx_file(z, now);
		else if (z->state == S_DATA || z->state == S_EOF) tx_window(z, now);
		else if (z->state == S_INIT) tx_init(z, now);
		return;
	case ZABORT: case ZCAN: case ZFERR:
		fail(z, EZ_ZM_ERR_REMOTE, false);
		return;
	default:
		return;
	}
}

static ez_zm_result_t tx_tick(ez_zm_t *z, uint32_t now)
{
	uint32_t limit = z->state == S_INIT ? TX_START_MS : WAIT_MS;
	if (now - z->t_wait < limit) return z->result;
	int max = z->state == S_INIT ? TX_START_MAX : RETRIES;
	if (++z->tries > max) return fail(z, EZ_ZM_ERR_TIMEOUT, true);
	z->in_data = false;
	z->hp = HP_IDLE;
	switch (z->state) {
	case S_INIT: tx_init(z, now); break;
	case S_FILE: tx_file(z, now); break;
	case S_DATA: case S_EOF: tx_window(z, now); break;
	case S_FIN:  send_hex(z, ZFIN, 0); z->t_wait = now; break;
	default: break;
	}
	return z->result;
}

/* ---- common ----------------------------------------------------------------------- */

static void on_header(ez_zm_t *z, uint8_t type, uint32_t arg, uint32_t now)
{
	if (z->sending) tx_header(z, type, arg, now);
	else rx_header(z, type, arg, now);
}

static void on_bad_header(ez_zm_t *z)
{
	if (!z->sending && z->state != R_DONE) send_hex(z, ZNAK, 0);
}

static void on_subpacket(ez_zm_t *z, bool ok, uint32_t now)
{
	if (!z->sending) rx_subpacket(z, ok, now);
	else z->in_data = false;                       /* a sender expects no data */
}

ez_zm_result_t ez_zm_input(ez_zm_t *z, const uint8_t *b, uint32_t n, uint32_t now)
{
	for (uint32_t i = 0; i < n && z->result == EZ_ZM_RUNNING; i++) {
		z->t_rx = now;
		line_byte(z, b[i], now);
	}
	return z->result;
}

ez_zm_result_t ez_zm_tick(ez_zm_t *z, uint32_t now)
{
	if (z->result != EZ_ZM_RUNNING) return z->result;
	return z->sending ? tx_tick(z, now) : rx_tick(z, now);
}
