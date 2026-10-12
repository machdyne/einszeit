/*
 * ez_store0.c -- see ez_store0.h.
 */
#include "ez_store0.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"

#define FREE  0xFFFFu
#define END   0xFFFEu
#define SEL_A 0x5A
#define SEL_B 0xA5
#define T_ENTRIES 16u
#define T_MAP     (T_ENTRIES + EZS_ENTRIES * 32u)
#define T_CRC     (EZ_FLASH_BLOCK - 4u)

/* ---- table (de)serialisation ----------------------------------------- */

static void serialise(ez_store0_t *s, uint32_t seq)
{
	uint8_t *b = s->buf;
	memset(b, 0, EZ_FLASH_BLOCK);
	memcpy(b, "EZD0", 4);
	b[4] = 1;
	ez_put_le32(b + 8, seq);
	ez_put_le32(b + 12, s->ndata);
	for (int i = 0; i < EZS_ENTRIES; i++) {
		uint8_t *p = b + T_ENTRIES + 32u * (uint32_t)i;
		if (!s->e[i].used) continue;
		memcpy(p, s->e[i].name, EZS_NAME_MAX + 1);
		ez_put_le16(p + 16, s->e[i].first);
		ez_put_le16(p + 18, 1);
		ez_put_le32(p + 20, s->e[i].len);
	}
	for (uint32_t i = 0; i < s->ndata; i++) ez_put_le16(b + T_MAP + 2u * i, s->map[i]);
	ez_put_le32(b + T_CRC, ez_crc32(b, T_CRC));
}

/* Load and fully validate a table image from s->buf into RAM. */
static bool load(ez_store0_t *s)
{
	const uint8_t *b = s->buf;
	if (memcmp(b, "EZD0", 4) != 0 || b[4] != 1 || ez_get_le32(b + 12) != s->ndata ||
	    ez_get_le32(b + T_CRC) != ez_crc32(b, T_CRC))
		return false;
	s->seq = ez_get_le32(b + 8);
	for (uint32_t i = 0; i < s->ndata; i++) s->map[i] = ez_get_le16(b + T_MAP + 2u * i);
	static uint8_t seen[EZS_MAX_DATA];
	memset(seen, 0, sizeof seen);
	for (int i = 0; i < EZS_ENTRIES; i++) {
		const uint8_t *p = b + T_ENTRIES + 32u * (uint32_t)i;
		ezs_entry_t *e = &s->e[i];
		memset(e, 0, sizeof *e);
		uint16_t flags = ez_get_le16(p + 18);
		if (flags == 0) continue;
		if (flags != 1 || p[EZS_NAME_MAX] != 0 || p[0] == 0) return false;
		e->used = true;
		memcpy(e->name, p, EZS_NAME_MAX + 1);
		e->first = ez_get_le16(p + 16);
		e->len = ez_get_le32(p + 20);
		/* chain: exact length, in range, no sharing, no cycles */
		uint32_t need = e->len / EZ_FLASH_BLOCK + (e->len % EZ_FLASH_BLOCK ? 1u : 0u), n = 0;
		uint16_t blk = e->first;
		if (need == 0 && blk != FREE) return false;
		while (need && blk != END) {
			if (blk >= s->ndata || seen[blk] || ++n > need) return false;
			seen[blk] = 1;
			blk = s->map[blk];
		}
		if (n != need) return false;
	}
	for (uint32_t i = 0; i < s->ndata; i++)
		if (!seen[i] && s->map[i] != FREE) return false;     /* orphaned block */
	return true;
}

/* ---- F-RAM selector ---------------------------------------------------- */

static ez_status_t sel_write(ez_store0_t *s, uint8_t v)
{
	uint8_t r = 0;
	if (s->fram->write(s->fram->ctx, s->sel_addr, &v, 1) != EZ_OK ||
	    s->fram->read(s->fram->ctx, s->sel_addr, &r, 1) != EZ_OK || r != v)
		return EZ_ERR_META;
	return EZ_OK;
}

/* ---- commit ------------------------------------------------------------ */

static ez_status_t commit(ez_store0_t *s)
{
	uint8_t target = (uint8_t)(1u - s->sel), chk[256];
	serialise(s, s->seq + 1);
	ez_status_t st = s->fl->erase(s->fl->ctx, target);
	if (st == EZ_OK)
		st = s->fl->program(s->fl->ctx, target * EZ_FLASH_BLOCK, s->buf, EZ_FLASH_BLOCK);
	for (uint32_t o = 0; st == EZ_OK && o < EZ_FLASH_BLOCK; o += sizeof chk) {
		st = s->fl->read(s->fl->ctx, target * EZ_FLASH_BLOCK + o, chk, sizeof chk);
		if (st == EZ_OK && memcmp(chk, s->buf + o, sizeof chk) != 0) st = EZ_ERR_MEDIA;
	}
	/* The single atomic step: point F-RAM at the new copy. */
	if (st == EZ_OK)
		st = sel_write(s, target == 0 ? SEL_A : SEL_B);
	if (st != EZ_OK) {
		s->fault = true;             /* RAM no longer known to match flash */
		return st == EZ_ERR_META ? EZ_ERR_MEDIA : st;
	}
	s->sel = target;
	s->seq++;
	s->table_writes++;
	return EZ_OK;
}

/* ---- helpers ----------------------------------------------------------- */

static char up(char ch) { return (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch; }

static bool name_eq(const char *a, const char *b)
{
	size_t i = 0;
	for (; a[i] && b[i]; i++) if (up(a[i]) != up(b[i])) return false;
	return a[i] == b[i];
}

static int find(ez_store0_t *s, const char *name)
{
	for (int i = 0; i < EZS_ENTRIES; i++)
		if (s->e[i].used && name_eq(s->e[i].name, name)) return i;
	return -1;
}

static bool name_ok(const char *n) { return n && n[0] && strlen(n) <= EZS_NAME_MAX; }

static bool ready(ez_store0_t *s, uint8_t drive) { return drive == 0 && s->mounted && !s->fault; }

static uint32_t block_addr(uint16_t blk) { return (2u + blk) * EZ_FLASH_BLOCK; }

/* The n-th block of a file's chain. */
static uint16_t nth(ez_store0_t *s, const ezs_entry_t *e, uint32_t n)
{
	uint16_t b = e->first;
	while (n-- && b < s->ndata) b = s->map[b];
	return b;
}

/* ---- ez_hal_keystore_t ------------------------------------------------- */

static bool k_present(void *ctx, uint8_t drive) { return ready(ctx, drive); }

static ez_status_t k_check(void *ctx, uint8_t drive)
{
	return ready(ctx, drive) ? EZ_OK : EZ_ERR_MEDIA_REMOVED;
}

static ez_status_t k_size(void *ctx, uint8_t drive, const char *name, uint32_t *size)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	int i = find(s, name);
	if (i < 0) return EZ_ERR_NOT_FOUND;
	*size = s->e[i].len;
	return EZ_OK;
}

static ez_status_t k_read(void *ctx, uint8_t drive, const char *name, uint32_t off,
                          void *buf, uint32_t len)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	int i = find(s, name);
	if (i < 0) return EZ_ERR_NOT_FOUND;
	if ((uint64_t)off + len > s->e[i].len) return EZ_ERR_RANGE;
	uint8_t *p = buf;
	while (len) {
		uint16_t b = nth(s, &s->e[i], off / EZ_FLASH_BLOCK);
		if (b >= s->ndata) return EZ_ERR_MEDIA;
		uint32_t o = off % EZ_FLASH_BLOCK, n = EZ_FLASH_BLOCK - o < len ? EZ_FLASH_BLOCK - o : len;
		ez_status_t st = s->fl->read(s->fl->ctx, block_addr(b) + o, p, n);
		if (st != EZ_OK) return st;
		p += n; off += n; len -= n;
	}
	return EZ_OK;
}

static ez_status_t k_create(void *ctx, uint8_t drive, const char *name)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(name)) return EZ_ERR_BAD_REQUEST;
	if (find(s, name) >= 0) return EZ_ERR_EXISTS;
	for (int i = 0; i < EZS_ENTRIES; i++) {
		if (s->e[i].used) continue;
		memset(&s->e[i], 0, sizeof s->e[i]);
		s->e[i].used = true;
		memcpy(s->e[i].name, name, strlen(name));
		s->e[i].first = FREE;
		return commit(s);
	}
	return EZ_ERR_FULL;
}

static ez_status_t k_append(void *ctx, uint8_t drive, const char *name,
                            const void *buf, uint32_t len)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	int i = find(s, name);
	if (i < 0) return EZ_ERR_NOT_FOUND;
	ezs_entry_t *e = &s->e[i];
	const uint8_t *p = buf;
	while (len) {
		uint32_t o = e->len % EZ_FLASH_BLOCK;
		uint16_t b;
		if (o == 0) {                                   /* a fresh block */
			uint32_t f = 0;
			while (f < s->ndata && s->map[f] != FREE) f++;
			if (f == s->ndata) return EZ_ERR_FULL;
			b = (uint16_t)f;
			ez_status_t st = s->fl->erase(s->fl->ctx, 2u + b);
			if (st != EZ_OK) return st;
			s->map[b] = END;
			if (e->first == FREE) e->first = b;
			else s->map[nth(s, e, e->len / EZ_FLASH_BLOCK - 1)] = b;
		} else {
			b = nth(s, e, e->len / EZ_FLASH_BLOCK);
		}
		uint32_t n = EZ_FLASH_BLOCK - o < len ? EZ_FLASH_BLOCK - o : len;
		ez_status_t st = s->fl->program(s->fl->ctx, block_addr(b) + o, p, n);
		if (st != EZ_OK) return st;
		e->len += n; p += n; len -= n;
	}
	return EZ_OK;
}

static ez_status_t k_rename(void *ctx, uint8_t drive, const char *from, const char *to)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(from) || !name_ok(to)) return EZ_ERR_BAD_REQUEST;
	int i = find(s, from), j = find(s, to);
	if (i < 0) return EZ_ERR_NOT_FOUND;
	if (j >= 0 && j != i) return EZ_ERR_EXISTS;
	memset(s->e[i].name, 0, sizeof s->e[i].name);
	memcpy(s->e[i].name, to, strlen(to));
	return commit(s);                           /* also makes appends durable */
}

static ez_status_t k_zap(void *ctx, uint8_t drive, const char *name)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	int i = find(s, name);
	if (i < 0) return EZ_ERR_NOT_FOUND;
	/* Erase the data first, then commit the table without the file. */
	uint16_t b = s->e[i].first;
	while (b < s->ndata) {
		ez_status_t st = s->fl->erase(s->fl->ctx, 2u + b);
		if (st != EZ_OK) return st;
		uint16_t nx = s->map[b];
		s->map[b] = FREE;
		b = nx;
	}
	memset(&s->e[i], 0, sizeof s->e[i]);
	return commit(s);
}

static ez_status_t k_list(void *ctx, uint8_t drive, uint32_t index,
                          char name[EZ_NAME_MAX], uint32_t *size)
{
	ez_store0_t *s = ctx;
	if (!ready(s, drive)) return EZ_ERR_MEDIA_REMOVED;
	uint32_t n = 0;
	for (int i = 0; i < EZS_ENTRIES; i++) {
		if (!s->e[i].used) continue;
		if (n++ == index) {
			memset(name, 0, EZ_NAME_MAX);
			memcpy(name, s->e[i].name, EZS_NAME_MAX + 1);
			*size = s->e[i].len;
			return EZ_OK;
		}
	}
	return EZ_ERR_NOT_FOUND;
}

/* Erase everything without ever leaving the F-RAM byte pointing at an
 * erased table: data first, then a committed empty table in the inactive
 * copy, then the old copy. An interruption leaves a mountable store. */
static ez_status_t wipe(ez_store0_t *s, bool have_table)
{
	for (uint32_t b = 0; b < s->ndata; b++) {
		ez_status_t st = s->fl->erase(s->fl->ctx, 2u + b);
		if (st != EZ_OK) { s->fault = true; return st; }
	}
	memset(s->e, 0, sizeof s->e);
	for (uint32_t i = 0; i < s->ndata; i++) s->map[i] = FREE;
	if (!have_table) { s->seq = 0; s->sel = 1; }      /* first commit targets copy A */
	s->fault = false;
	s->mounted = true;
	ez_status_t st = commit(s);
	if (st == EZ_OK)
		st = s->fl->erase(s->fl->ctx, 1u - s->sel);   /* the old copy */
	return st;
}

static ez_status_t k_wipe(void *ctx, uint8_t drive)
{
	ez_store0_t *s = ctx;
	if (drive != 0) return EZ_ERR_BAD_REQUEST;
	return wipe(s, s->mounted && !s->fault);
}

/* ---- lifecycle ----------------------------------------------------------- */

ez_status_t ez_store0_mount(ez_store0_t *s)
{
	s->mounted = false;
	s->fault = false;
	uint8_t v = 0;
	if (s->fram->read(s->fram->ctx, s->sel_addr, &v, 1) != EZ_OK) {
		s->fault = true;
		return EZ_ERR_META;
	}
	if (v == 0x00 || v == 0xFF)
		return wipe(s, false);                    /* never formatted, or device erased */
	if (v != SEL_A && v != SEL_B) {
		s->fault = true;                          /* damaged selector: no guessing */
		return EZ_ERR_MEDIA;
	}
	s->sel = v == SEL_A ? 0 : 1;
	ez_status_t st = s->fl->read(s->fl->ctx, s->sel * EZ_FLASH_BLOCK, s->buf, EZ_FLASH_BLOCK);
	if (st != EZ_OK || !load(s)) {
		s->fault = true;                          /* never fall back to the older copy */
		memset(s->e, 0, sizeof s->e);
		return EZ_ERR_MEDIA;
	}
	s->mounted = true;
	return EZ_OK;
}

ez_status_t ez_store0_init(ez_store0_t *s, const ez_flash_t *fl,
                           const ez_hal_meta_t *fram, uint32_t sel_addr)
{
	memset(s, 0, sizeof *s);
	s->fl = fl;
	s->fram = fram;
	s->sel_addr = sel_addr;
	s->ndata = fl->blocks > 2 ? fl->blocks - 2 : 0;
	if (s->ndata == 0 || s->ndata > EZS_MAX_DATA) { s->fault = true; return EZ_ERR_BAD_REQUEST; }
	s->hal = (ez_hal_keystore_t){ s, k_present, k_check, k_size, k_read, k_create, k_append,
	                              k_rename, k_zap, k_list, k_wipe, NULL };
	return ez_store0_mount(s);
}
