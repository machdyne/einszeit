/*
 * test_proto.c -- USB protocol: frames, payloads, dispatcher, client.
 *
 * The host client talks to the device dispatcher through an in-process
 * loopback, over the simulated devices of core_fixture.
 *
 * EZ-SEC-001 / EZ-IMPL-001: IMPL-API-001 (no key bytes in any response),
 * IMPL-ARCH-004 (BUSY while a job runs), IMPL-ENG-003 (aborted request
 * clears the stage), IMPL-ENG-008/009 (RESEND/RELEASE), SEC-DEC-002,
 * SEC-ENC-001 and SEC-DEC-001 end to end over the protocol; closes the
 * fw/test gap G-03 for the production protocol (fuzzing: tests/fuzz).
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_bytes.h"
#include "ez_client.h"
#include "ez_dispatch.h"

/* ---- loopback transport ---------------------------------------------------- */

#define QCAP 4096
typedef struct {
	ezdev_t *dev;
	ez_dispatch_t disp;
	uint8_t q[QCAP][EZ_FRAME_SIZE];
	int head, tail;
	unsigned long responses_firsts;
	uint8_t *seen;            /* every response byte, for the key scan */
	size_t seen_n, seen_cap;
} lb_t;

static void lb_send(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	lb_t *l = ctx;
	EZ_CHECK_MSG((l->tail + 1) % QCAP != l->head, "response queue overflow");
	memcpy(l->q[l->tail], f, EZ_FRAME_SIZE);
	l->tail = (l->tail + 1) % QCAP;
	if (f[1] & EZ_FF_FIRST) l->responses_firsts++;
	if (l->seen && l->seen_n + EZ_FRAME_PAYLOAD <= l->seen_cap) {
		uint16_t n = ez_get_le16(f + 4);
		memcpy(l->seen + l->seen_n, f + 6, n > 58 ? 58 : n);
		l->seen_n += n > 58 ? 58 : n;
	}
}
static int lb_write(void *ctx, const uint8_t f[EZ_FRAME_SIZE]) { ez_dispatch_frame(&((lb_t *)ctx)->disp, f); return 0; }
static int lb_read(void *ctx, uint8_t f[EZ_FRAME_SIZE], int timeout_ms)
{
	lb_t *l = ctx;
	(void)timeout_ms;
	if (l->head == l->tail) return 0;
	memcpy(f, l->q[l->head], EZ_FRAME_SIZE);
	l->head = (l->head + 1) % QCAP;
	return 1;
}
static const ez_devinfo_t INFO = { "test", 0xEE, 1, EZ_BUILD_DEVELOPMENT };

static lb_t *lb_new(uint64_t seed)
{
	lb_t *l = calloc(1, sizeof *l);
	l->dev = dev_new(seed);
	ez_dispatch_init(&l->disp, &l->dev->c, lb_send, l, &INFO);
	return l;
}
static void lb_free(lb_t *l) { dev_free(l->dev); free(l->seen); free(l); }
#define T(l) (&(ez_transport_t){ (l), lb_write, lb_read })

static uint8_t rsp[EZ_STAGE_SIZE + 64];
static size_t rn;

/* Long commands are jobs (round 16): run the job, then fetch its reply. */
static int call(lb_t *l, uint8_t cmd, const uint8_t *req, size_t n)
{
	int st = ez_call(T(l), cmd, req, n, rsp, sizeof rsp, &rn, 100);
	if (st == EZ_OK && ez_cmd_deferred(cmd)) {
		EZ_CHECK_EQ(rn, 0);                                  /* answered at once */
		ez_dispatch_poll(&l->disp, 1);
		st = ez_call(T(l), EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, 100);
	}
	return st;
}

/* ---- tests ------------------------------------------------------------------- */

static void t_frames(void)
{
	ez_frame_t f = { 0x20, EZ_FF_FIRST | EZ_FF_LAST, 7, 3, 58, { 0 } }, g;
	for (int i = 0; i < 58; i++) f.data[i] = (uint8_t)i;
	uint8_t b[64];
	ez_frame_encode(&f, b);
	EZ_CHECK_EQ(ez_frame_decode(b, &g), EZ_OK);
	EZ_CHECK(g.cmd == 0x20 && g.flags == 3 && g.seq == 7 && g.status == 3 && g.len == 58);
	EZ_CHECK(memcmp(g.data, f.data, 58) == 0);
	b[4] = 59;
	EZ_CHECK_EQ(ez_frame_decode(b, &g), EZ_ERR_BAD_REQUEST);
	b[4] = 1;
	for (int bit = 3; bit < 8; bit++) {
		b[1] = (uint8_t)(1u << bit);
		EZ_CHECK_EQ(ez_frame_decode(b, &g), EZ_ERR_BAD_REQUEST);   /* reserved bits */
	}
}

static void t_payload_codec(void)
{
	uint8_t buf[16];
	ez_wr_t w;
	ez_wr_init(&w, buf, sizeof buf);
	ez_wr_u32(&w, 0xA1B2C3D4); ez_wr_str(&w, "abcdefgh"); ez_wr_u16(&w, 7);
	EZ_CHECK(!w.err && w.n == 15);
	ez_wr_u16(&w, 1);
	EZ_CHECK(w.err);                                     /* over capacity */
	ez_rd_t r;
	char s[9];
	ez_rd_init(&r, buf, 15);
	EZ_CHECK_EQ(ez_rd_u32(&r), 0xA1B2C3D4);
	ez_rd_str(&r, s, sizeof s);
	EZ_CHECK(strcmp(s, "abcdefgh") == 0);
	EZ_CHECK_EQ(ez_rd_u16(&r), 7);
	EZ_CHECK(ez_rd_done(&r));
	ez_rd_init(&r, buf, 15);
	ez_rd_u32(&r);
	ez_rd_str(&r, s, 8);                                 /* too long for the buffer */
	EZ_CHECK(r.err);
	ez_rd_init(&r, buf, 10);                             /* truncated */
	ez_rd_u32(&r);
	ez_rd_str(&r, s, sizeof s);
	EZ_CHECK(r.err && !ez_rd_done(&r));
	buf[6] = 0;                                          /* embedded NUL */
	ez_rd_init(&r, buf, 15);
	ez_rd_u32(&r);
	ez_rd_str(&r, s, sizeof s);
	EZ_CHECK(r.err);
}

static int create(lb_t *l, uint32_t id, uint8_t drive, uint8_t role, const char *label)
{
	uint8_t q[64];
	ez_wr_t w;
	ez_wr_init(&w, q, sizeof q);
	ez_wr_u32(&w, id); ez_wr_u8(&w, drive); ez_wr_u8(&w, role); ez_wr_str(&w, label); ez_wr_u8(&w, 0);
	int st = call(l, EZ_CMD_SESSION_CREATE, q, w.n);
	return st == EZ_OK ? rsp[0] : -st;
}

static void t_device_and_sessions(void)
{
	lb_t *l = lb_new(1);
	EZ_CHECK_EQ(call(l, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	ez_rd_t r;
	char fw[32];
	ez_rd_init(&r, rsp, rn);
	EZ_CHECK_EQ(ez_rd_u8(&r), EZ_PROTO_VERSION);
	ez_rd_str(&r, fw, sizeof fw);
	EZ_CHECK(strcmp(fw, "test") == 0);
	ez_rd_u8(&r); ez_rd_u8(&r); ez_rd_u8(&r); ez_rd_u8(&r); ez_rd_u32(&r);   /* variant .. boot */
	ez_rd_u8(&r); ez_rd_u8(&r); ez_rd_u8(&r); ez_rd_u8(&r);                  /* drive 0 .. job */
	EZ_CHECK_EQ(ez_rd_u8(&r), EZ_BUILD_DEVELOPMENT);
	EZ_CHECK_EQ(ez_rd_u8(&r), 0);                                            /* not tainted yet */
	EZ_CHECK_EQ(ez_rd_u8(&r), 0);                    /* drive 0 protection: no guard here */
	ez_rd_u8(&r); ez_rd_u8(&r);                      /* health, detail (round 16) */
	EZ_CHECK_EQ(ez_rd_u8(&r), 0);                    /* no job running */
	ez_rd_u8(&r); ez_rd_u16(&r);
	EZ_CHECK(ez_rd_done(&r));
	/* IMPL-MODE-002: the mark survives reboots and is cleared by device erase. */
	ez_core_mark_development(&l->dev->c);
	dev_reboot(l->dev);
	EZ_CHECK(ez_core_dev_tainted(&l->dev->c));
	EZ_CHECK_EQ(ez_device_erase(&l->dev->c), EZ_OK);
	dev_reboot(l->dev);
	EZ_CHECK(!ez_core_dev_tainted(&l->dev->c));
	dev_put_key(l->dev, 1, 0x1001, 8192, 1);
	int s = create(l, 0x1001, 1, EZ_ROLE_ALICE, "bob");
	EZ_CHECK_EQ(s, 0);
	EZ_CHECK_EQ(create(l, 0x1001, 1, EZ_ROLE_ALICE, "again"), -EZ_ERR_EXISTS);
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_LIST, NULL, 0), EZ_OK);
	ez_rd_init(&r, rsp, rn);
	EZ_CHECK_EQ(ez_rd_u8(&r), 1);
	ez_wsession_t ws;
	ez_wsession_read(&r, &ws);
	EZ_CHECK(ez_rd_done(&r));
	EZ_CHECK(ws.key_id == 0x1001 && ws.tx_left == 4096 && strcmp(ws.label, "bob") == 0);
	EZ_CHECK(ws.flags & EZ_SF_IDENTITY);
	/* A destructive command must name the session by slot AND Key ID. */
	uint8_t q[6] = { 0, 0x02, 0x10, 0, 0, 0 };           /* slot 0, Key ID 0x1002 */
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_DELETE, q, 6), EZ_ERR_BAD_REQUEST);
	q[1] = 0x01;
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_DELETE, q, 6), EZ_OK);
	EZ_CHECK(sim_ks_get(&l->dev->ks, 1, "00001001.KEY") == NULL);
	/* Malformed payloads */
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_LIST, q, 1), EZ_ERR_BAD_REQUEST);    /* trailing bytes */
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_DELETE, q, 5), EZ_ERR_BAD_REQUEST);  /* short */
	EZ_CHECK_EQ(call(l, 0x7F, NULL, 0), EZ_ERR_UNSUPPORTED);
	lb_free(l);
}

static void encrypt_req(uint8_t *q, size_t *n, uint8_t slot, uint32_t id, const uint8_t *pt, uint32_t len)
{
	q[0] = slot;
	ez_put_le32(q + 1, id);
	ez_put_le32(q + 5, len);
	memcpy(q + 9, pt, len);
	*n = 9 + len;
}

static uint8_t big_pt[EZ_BUFFERED_MAX], q[EZ_BUFFERED_MAX + 64], msg[EZ_STAGE_SIZE];

/* SEC-ENC-001 / SEC-DEC-001 over the protocol, at the full buffered size,
 * with RESEND, RELEASE and the retained-output rules. */
static void t_encrypt_decrypt(void)
{
	lb_t *a = lb_new(2), *b = lb_new(3);
	dev_put_key(a->dev, 1, 0x2002, 262144, 9);
	dev_copy_key(a->dev, b->dev, 1, 0x2002);
	int sa = create(a, 0x2002, 1, EZ_ROLE_ALICE, "b"), sb = create(b, 0x2002, 1, EZ_ROLE_BOB, "a");
	EZ_CHECK(sa >= 0 && sb >= 0);
	sim_fill(big_pt, sizeof big_pt, 4);
	size_t n;
	encrypt_req(q, &n, (uint8_t)sa, 0x2002, big_pt, sizeof big_pt);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENCRYPT, q, n), EZ_OK);
	EZ_CHECK_EQ(rn, sizeof big_pt + EZ_MSG_OVERHEAD);
	memcpy(msg, rsp, rn);
	size_t mlen = rn;
	/* RESEND returns the same bytes; a second RESEND too. */
	EZ_CHECK_EQ(call(a, EZ_CMD_RESEND, NULL, 0), EZ_OK);
	EZ_CHECK(rn == mlen && memcmp(rsp, msg, mlen) == 0);
	EZ_CHECK_EQ(call(a, EZ_CMD_RELEASE, NULL, 0), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_RESEND, NULL, 0), EZ_ERR_STATE);
	/* Any other command also clears it. */
	encrypt_req(q, &n, (uint8_t)sa, 0x2002, big_pt, 100);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENCRYPT, q, n), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_RESEND, NULL, 0), EZ_ERR_STATE);
	/* Wrong Key ID for the slot: refused before any key use. */
	uint32_t tx = a->dev->c.meta.s[sa].tx_off;
	encrypt_req(q, &n, (uint8_t)sa, 0x2003, big_pt, 100);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENCRYPT, q, n), EZ_ERR_BAD_REQUEST);
	EZ_CHECK_EQ(a->dev->c.meta.s[sa].tx_off, tx);
	/* Decrypt on b, selecting the session by Key ID. */
	q[0] = 0xFF;
	ez_put_le32(q + 1, (uint32_t)mlen);
	memcpy(q + 5, msg, mlen);
	EZ_CHECK_EQ(call(b, EZ_CMD_DECRYPT, q, 5 + mlen), EZ_OK);
	EZ_CHECK(rn == sizeof big_pt && memcmp(rsp, big_pt, rn) == 0);
	EZ_CHECK(ez_is_zero(b->dev->stage, sizeof b->dev->stage));    /* released after delivery */
	EZ_CHECK_EQ(call(b, EZ_CMD_DECRYPT, q, 5 + mlen), EZ_ERR_REPLAY);
	/* Too long for buffered mode */
	encrypt_req(q, &n, (uint8_t)sa, 0x2002, big_pt, 10);
	ez_put_le32(q + 5, EZ_BUFFERED_MAX + 1);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENCRYPT, q, n), EZ_ERR_BAD_REQUEST);
	DEV_KBUF_CLEAR(a->dev);
	DEV_KBUF_CLEAR(b->dev);
	lb_free(a); lb_free(b);
}

/* Raw frames, for the transaction-level tests. */
static void raw(lb_t *l, uint8_t cmd, uint8_t flags, uint8_t seq, const uint8_t *p, uint16_t n)
{
	ez_frame_t f = { cmd, flags, seq, 0, n, { 0 } };
	uint8_t b[64];
	if (n) memcpy(f.data, p, n);
	ez_frame_encode(&f, b);
	ez_dispatch_frame(&l->disp, b);
}
static int queued(lb_t *l) { return (l->tail - l->head + QCAP) % QCAP; }

/* IMPL-ENG-003: an encryption request abandoned part-way (a new FIRST
 * frame, an ABORT, a bad sequence) leaves no plaintext and spends nothing.
 * Exactly one response per request, none for stray frames. */
static void t_interrupted_requests(void)
{
	lb_t *l = lb_new(4);
	dev_put_key(l->dev, 1, 0x3003, 8192, 2);
	int s = create(l, 0x3003, 1, EZ_ROLE_ALICE, "x");
	uint8_t h[58];
	memset(h, 0x41, sizeof h);
	h[0] = (uint8_t)s;
	ez_put_le32(h + 1, 0x3003);
	ez_put_le32(h + 5, 200);
	unsigned long r0 = l->responses_firsts;
	raw(l, EZ_CMD_ENCRYPT, EZ_FF_FIRST, 0, h, 58);       /* 49 plaintext bytes staged */
	EZ_CHECK(!ez_is_zero(l->dev->stage, sizeof l->dev->stage));
	raw(l, EZ_CMD_DEVICE_INFO, EZ_FF_FIRST | EZ_FF_LAST, 0, NULL, 0);   /* interrupts */
	EZ_CHECK(ez_is_zero(l->dev->stage, sizeof l->dev->stage));
	EZ_CHECK_EQ(l->responses_firsts - r0, 1);            /* only DEVICE_INFO answered */
	raw(l, EZ_CMD_ENCRYPT, 0, 1, h, 58);                 /* stray continuation: ignored */
	EZ_CHECK_EQ(l->responses_firsts - r0, 1);
	/* ABORT */
	raw(l, EZ_CMD_ENCRYPT, EZ_FF_FIRST, 0, h, 58);
	raw(l, EZ_CMD_ENCRYPT, EZ_FF_ABORT, 0, NULL, 0);
	EZ_CHECK(ez_is_zero(l->dev->stage, sizeof l->dev->stage));
	EZ_CHECK_EQ(l->responses_firsts - r0, 2);
	/* bad sequence: one error now, the rest dropped */
	raw(l, EZ_CMD_ENCRYPT, EZ_FF_FIRST, 0, h, 58);
	raw(l, EZ_CMD_ENCRYPT, 0, 3, h, 58);
	raw(l, EZ_CMD_ENCRYPT, 0, 4, h, 58);
	raw(l, EZ_CMD_ENCRYPT, EZ_FF_LAST, 5, h, 35);
	EZ_CHECK_EQ(l->responses_firsts - r0, 3);
	EZ_CHECK(ez_is_zero(l->dev->stage, sizeof l->dev->stage));
	EZ_CHECK_EQ(l->dev->c.meta.s[s].tx_off, 0);          /* nothing spent */
	while (queued(l)) { uint8_t f[64]; lb_read(l, f, 0); }
	DEV_KBUF_CLEAR(l->dev);
	lb_free(l);
}

/* IMPL-ARCH-004: during a generation job only read-only commands run; a
 * refused multi-frame request gets exactly one response; KEY_STATUS with
 * ABORT cancels the job and nothing of it remains. */
static void t_jobs_and_busy(void)
{
	lb_t *l = lb_new(5);
	uint8_t q[8];
	ez_put_le32(q, 16384);
	q[4] = 1;
	EZ_CHECK_EQ(call(l, EZ_CMD_KEY_GENERATE, q, 5), EZ_OK);
	EZ_CHECK_EQ(call(l, EZ_CMD_KEY_GENERATE, q, 5), EZ_ERR_BUSY);
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_LIST, NULL, 0), EZ_OK);
	EZ_CHECK_EQ(call(l, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	uint8_t pt[200] = { 0 };
	size_t n;
	encrypt_req(big_pt, &n, 0, 1, pt, 200);              /* 4 frames */
	unsigned long r0 = l->responses_firsts;
	EZ_CHECK_EQ(call(l, EZ_CMD_ENCRYPT, big_pt, n), EZ_ERR_BUSY);
	EZ_CHECK_EQ(l->responses_firsts - r0, 1);
	EZ_CHECK_EQ(queued(l), 0);
	ez_wjob_t j;
	ez_rd_t r;
	int polls = 0;
	do {
		ez_dispatch_poll(&l->disp, 4);
		EZ_CHECK_EQ(call(l, EZ_CMD_KEY_STATUS, NULL, 0), EZ_OK);
		ez_rd_init(&r, rsp, rn);
		ez_wjob_read(&r, &j);
		EZ_CHECK(ez_rd_done(&r));
		polls++;
	} while (j.running && polls < 1000);
	EZ_CHECK(j.job == 1 && j.result == EZ_OK && j.permille == 1000 && j.key_id != 0);
	/* A background sync right after (status polls are not activity):
	 * KEY_STATUS still reports the generation, finished, with its key
	 * (TR-09: 'ez key generate' printed no key ID). */
	{
		uint32_t kid = j.key_id;
		ez_dispatch_want_sync(&l->disp);
		ez_dispatch_idle(&l->disp, 1);
		ez_dispatch_idle(&l->disp, 5000);
		EZ_CHECK(l->disp.job_running && l->disp.job == 4);
		EZ_CHECK_EQ(call(l, EZ_CMD_KEY_STATUS, NULL, 0), EZ_OK);
		ez_rd_init(&r, rsp, rn);
		ez_wjob_read(&r, &j);
		EZ_CHECK(j.job == 1 && !j.running && j.result == EZ_OK && j.key_id == kid);
		ez_dispatch_poll(&l->disp, 1);
		EZ_CHECK(!l->disp.job_running);
	}
	char name[EZ_FNAME_MAX];
	ez_key_name(j.key_id, "KEY", name);
	EZ_CHECK(sim_ks_get(&l->dev->ks, 1, name) != NULL);
	/* cancel */
	EZ_CHECK_EQ(call(l, EZ_CMD_KEY_GENERATE, q, 5), EZ_OK);
	/* not yet run by the worker: cancelled before it writes anything */
	EZ_CHECK_EQ(ez_call_abort(T(l), EZ_CMD_KEY_STATUS, 100), EZ_ERR_ABORTED);
	EZ_CHECK_EQ(call(l, EZ_CMD_KEY_STATUS, NULL, 0), EZ_OK);
	ez_rd_init(&r, rsp, rn);
	ez_wjob_read(&r, &j);
	EZ_CHECK(!j.running && j.result == EZ_ERR_ABORTED);
	int keys = 0;
	for (int i = 0; i < SIM_KS_FILES; i++)
		if (l->dev->ks.d[1].f[i].used) keys++;
	EZ_CHECK_EQ(keys, 2);                                /* the first key and its .SUM */
	EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_LIST, NULL, 0), EZ_OK);   /* not busy any more */
	lb_free(l);
}

/* Import over the protocol, reporting whether a .SUM came with the key. */
static void t_import(void)
{
	lb_t *l = lb_new(6);
	static uint8_t k[16384];
	sim_fill(k, sizeof k, 8);
	sim_ks_put(&l->dev->ks, 1, "from peer.bin", k, sizeof k);
	uint8_t q[300];
	ez_wr_t w;
	ez_wr_init(&w, q, sizeof q);
	ez_wr_u8(&w, 1); ez_wr_u32(&w, 0x4004); ez_wr_u8(&w, EZ_ROLE_BOB);
	ez_wr_str(&w, "peer"); ez_wr_str(&w, "from peer.bin");
	EZ_CHECK_EQ(call(l, EZ_CMD_KEY_IMPORT, q, w.n), EZ_OK);
	EZ_CHECK(rn == 1 && rsp[0] == 0);                    /* no .SUM: warn the user */
	ez_wjob_t j;
	ez_rd_t r;
	do {
		ez_dispatch_poll(&l->disp, 4);
		call(l, EZ_CMD_KEY_STATUS, NULL, 0);
		ez_rd_init(&r, rsp, rn);
		ez_wjob_read(&r, &j);
	} while (j.running);
	EZ_CHECK(j.job == 2 && j.result == EZ_OK && j.slot == 0);
	EZ_CHECK(sim_ks_get(&l->dev->ks, 1, "00004004.SUM") != NULL);
	lb_free(l);
}

/* Robustness: random and mutated frames never crash, never answer more
 * than once per request, and no response ever contains key bytes
 * (IMPL-API-001). Afterwards the device still works. */
static void t_random_frames(void)
{
	lb_t *l = lb_new(7);
	dev_put_key(l->dev, 1, 0x5005, 65536, 3);
	int s = create(l, 0x5005, 1, EZ_ROLE_ALICE, "x");
	EZ_CHECK(s >= 0);
	l->seen_cap = 64u << 20;
	l->seen = malloc(l->seen_cap);
	static const uint8_t cmds[] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x10,0x11,0x12,0x13,0x14,0x20,0x21,
	                                0x22,0x23,0x30,0x31,0x32,0x33,0x41,0x50,0x53,0x7F };
	uint64_t rs = 0x9E3779B97F4A7C15ull;
	for (int i = 0; i < 200000; i++) {
		rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
		uint8_t f[64];
		for (int k = 0; k < 64; k++) f[k] = (uint8_t)(rs >> ((k * 7) % 56)) ^ (uint8_t)(k * 31 + i);
		if (rs & 1) {                                     /* mostly well-formed */
			f[0] = cmds[(rs >> 8) % sizeof cmds];
			f[1] = (uint8_t)((rs >> 16) & 0x07);
			f[2] = (uint8_t)((rs >> 20) & 0x03);
			f[3] = 0;
			ez_put_le16(f + 4, (uint16_t)((rs >> 24) % 59));
			if (f[0] == EZ_CMD_ENCRYPT && (rs & 2)) { f[6] = (uint8_t)s; ez_put_le32(f + 7, 0x5005); ez_put_le32(f + 11, (uint32_t)(rs >> 40) % 300); }
			if (f[0] == EZ_CMD_DEVICE_ERASE || f[0] == EZ_CMD_DRIVE_DISABLE ||
			    f[0] == EZ_CMD_SESSION_DELETE || f[0] == EZ_CMD_KEY_DELETE) f[0] = EZ_CMD_SESSION_LIST;
		}
		if (f[0] == EZ_CMD_DEVICE_ERASE || f[0] == EZ_CMD_DRIVE_DISABLE) f[0] = 0x7F;
		ez_dispatch_frame(&l->disp, f);
		if (i % 64 == 0) ez_dispatch_poll(&l->disp, 2);
		while (queued(l)) { uint8_t g[64]; lb_read(l, g, 0); }
	}
	while (ez_dispatch_poll(&l->disp, 64)) {}
	ez_dispatch_reset(&l->disp);
	/* And every valid command that returns data, many times over. */
	static const uint8_t ro[] = { EZ_CMD_SESSION_LIST, EZ_CMD_DEVICE_INFO, EZ_CMD_LOG_READ, EZ_CMD_KEY_STATUS };
	for (int i = 0; i < 2000; i++) {
		EZ_CHECK_EQ(call(l, ro[i % 4], NULL, 0), EZ_OK);
		uint8_t q2[3] = { (uint8_t)(i % 3), 0, 0 };
		int st = call(l, EZ_CMD_DRIVE_LIST, q2, 3);
		EZ_CHECK(st == EZ_OK || st == EZ_ERR_DRIVE_DISABLED);
		q2[0] = (uint8_t)s;
		if (l->dev->c.meta.s[s].state != EZ_SS_EMPTY) EZ_CHECK_EQ(call(l, EZ_CMD_SESSION_INFO, q2, 1), EZ_OK);
	}
	/* IMPL-API-001: no 16-byte window of any key appears in any response. */
	sim_file_t *kf = sim_ks_get(&l->dev->ks, 1, "00005005.KEY");
	if (kf) {
		for (uint32_t o = 0; o + 16 <= kf->len; o += 509) {
			bool found = false;
			for (size_t i = 0; i + 16 <= l->seen_n && !found; i++)
				found = l->seen[i] == kf->data[o] && memcmp(l->seen + i, kf->data + o, 16) == 0;
			EZ_CHECK_MSG(!found, "key bytes in a response");
		}
	}
	ez_test_note("%zu response bytes scanned for key material", l->seen_n);
	EZ_CHECK_EQ(call(l, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	DEV_KBUF_CLEAR(l->dev);
	lb_free(l);
}

/* While the device's console holds the core, every request gets BUSY at
 * once (one response each) and nothing in the core changes. */
static void t_external_busy(void)
{
	lb_t *l = lb_new(8);
	dev_put_key(l->dev, 1, 0x6006, 8192, 1);
	int s = create(l, 0x6006, 1, EZ_ROLE_ALICE, "x");
	EZ_CHECK(s >= 0);
	l->disp.external_busy = true;
	uint8_t snap[EZ_META_SIZE];
	memcpy(snap, l->dev->fram.mem, sizeof snap);
	EZ_CHECK_EQ(call(l, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_ERR_BUSY);
	size_t n;
	uint8_t pt[300] = { 1 };
	encrypt_req(big_pt, &n, (uint8_t)s, 0x6006, pt, 300);     /* 6 frames */
	unsigned long r0 = l->responses_firsts;
	EZ_CHECK_EQ(call(l, EZ_CMD_ENCRYPT, big_pt, n), EZ_ERR_BUSY);
	EZ_CHECK_EQ(l->responses_firsts - r0, 1);
	EZ_CHECK_EQ(ez_call_abort(T(l), EZ_CMD_KEY_STATUS, 100), EZ_ERR_BUSY);
	EZ_CHECK(memcmp(snap, l->dev->fram.mem, sizeof snap) == 0);   /* nothing written */
	EZ_CHECK(ez_is_zero(l->dev->stage, sizeof l->dev->stage));
	l->disp.external_busy = false;
	EZ_CHECK_EQ(call(l, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	lb_free(l);
}

/* Streaming over the protocol: 300,000 bytes from A to B in 512-byte
 * chunks; a tampered message fails at the end; an interrupted stream is
 * gone, and the key it used stays spent (never reused). */
static uint8_t spt[300000], smsg[300100], sout[300000];
static void t_streaming(void)
{
	lb_t *a = lb_new(10), *b = lb_new(11);
	dev_put_key(a->dev, 1, 0x7007, 1u << 20, 12);
	dev_copy_key(a->dev, b->dev, 1, 0x7007);
	int sa = create(a, 0x7007, 1, EZ_ROLE_ALICE, "b"), sb = create(b, 0x7007, 1, EZ_ROLE_BOB, "a");
	EZ_CHECK(sa >= 0 && sb >= 0);
	sim_fill(spt, sizeof spt, 13);
	uint8_t q9[9];
	q9[0] = (uint8_t)sa; ez_put_le32(q9 + 1, 0x7007); ez_put_le32(q9 + 5, sizeof spt);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_BEGIN, q9, 9), EZ_OK);
	EZ_CHECK_EQ(rn, EZ_MSG_HDR);
	memcpy(smsg, rsp, EZ_MSG_HDR);
	size_t off = EZ_MSG_HDR;
	for (size_t o = 0; o < sizeof spt; o += 512) {
		size_t n = sizeof spt - o < 512 ? sizeof spt - o : 512;
		EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt + o, n), EZ_OK);
		EZ_CHECK_EQ(rn, n);
		memcpy(smsg + off, rsp, n);
		off += n;
	}
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_END, NULL, 0), EZ_OK);
	memcpy(smsg + off, rsp, EZ_MSG_TRL);
	off += EZ_MSG_TRL;
	/* decrypt on B by streaming */
	uint8_t q17[17];
	q17[0] = 0xFF; memcpy(q17 + 1, smsg, EZ_MSG_HDR);
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_BEGIN, q17, 17), EZ_OK);
	for (size_t o = 0; o < sizeof spt; o += 512) {
		size_t n = sizeof spt - o < 512 ? sizeof spt - o : 512;
		EZ_CHECK_EQ(call(b, EZ_CMD_DEC_DATA, smsg + EZ_MSG_HDR + o, n), EZ_OK);
		memcpy(sout + o, rsp, n);
	}
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_END, smsg + EZ_MSG_HDR + sizeof spt, EZ_MSG_TRL), EZ_OK);
	EZ_CHECK(!memcmp(sout, spt, sizeof spt));
	/* tampered: the same message again would be a replay, so a new one */
	q9[0] = (uint8_t)sa; ez_put_le32(q9 + 5, 1000);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_BEGIN, q9, 9), EZ_OK);
	memcpy(q17 + 1, rsp, EZ_MSG_HDR);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt, 500), EZ_OK); memcpy(smsg, rsp, 500);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt + 500, 500), EZ_OK); memcpy(smsg + 500, rsp, 500);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_END, NULL, 0), EZ_OK);
	uint8_t trl[4]; memcpy(trl, rsp, 4);
	smsg[123] ^= 1;
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_BEGIN, q17, 17), EZ_OK);
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_DATA, smsg, 1000), EZ_ERR_BAD_REQUEST);   /* chunks are at most 512 */
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_BEGIN, q17, 17), EZ_OK);
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_DATA, smsg, 500), EZ_OK);
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_DATA, smsg + 500, 500), EZ_OK);
	EZ_CHECK_EQ(call(b, EZ_CMD_DEC_END, trl, 4), EZ_ERR_INTEGRITY);
	/* interrupted: two chunks, then another command */
	uint32_t tx0 = a->dev->c.meta.s[sa].tx_off;
	q9[0] = (uint8_t)sa; ez_put_le32(q9 + 5, 5000);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_BEGIN, q9, 9), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt, 512), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt, 512), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_DEVICE_INFO, NULL, 0), EZ_OK);
	EZ_CHECK_EQ(call(a, EZ_CMD_ENC_DATA, spt, 512), EZ_ERR_STATE);   /* the stream is gone */
	EZ_CHECK_EQ(a->dev->c.meta.s[sa].tx_off, tx0 + 1024);             /* what was sent stays spent */
	EZ_CHECK(!a->dev->c.stream_active);
	DEV_KBUF_CLEAR(a->dev);
	DEV_KBUF_CLEAR(b->dev);
	lb_free(a); lb_free(b);
}

/* Round 16: long commands are jobs. A deferred command is answered at
 * once; until the worker has run it, other commands get BUSY (read-only ones
 * still work); its reply comes from JOB_RESULT. A scheduled background sync
 * yields to a command and is resumed later. */
static void t_deferred_jobs(void)
{
	lb_t *l = lb_new(20);
	dev_put_key(l->dev, 1, 0x5150, 16384, 21);
	int s = create(l, 0x5150, 1, EZ_ROLE_ALICE, "x");
	EZ_CHECK(s >= 0);
	uint8_t q5[5] = { (uint8_t)s };
	ez_put_le32(q5 + 1, 0x5150);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_SESSION_CHECK, q5, 5, rsp, sizeof rsp, &rn, 100), EZ_OK);
	EZ_CHECK_EQ(rn, 0);                                          /* started */
	EZ_CHECK(l->disp.job_running && l->disp.job == 3);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_SESSION_LIST, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);   /* read-only */
	uint8_t q9[9] = { (uint8_t)s };
	ez_put_le32(q9 + 1, 0x5150); ez_put_le32(q9 + 5, 10);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_ENC_BEGIN, q9, 9, rsp, sizeof rsp, &rn, 100), EZ_ERR_BUSY);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_ERR_BUSY);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_KEY_STATUS, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	ez_rd_t r; ez_wjob_t j;
	ez_rd_init(&r, rsp, rn); ez_wjob_read(&r, &j);
	EZ_CHECK(j.job == 3 && j.running && j.cmd == EZ_CMD_SESSION_CHECK);
	/* with a real second-core worker, only RAM-only commands meanwhile */
	l->disp.external_worker = true;
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_SESSION_LIST, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_ERR_BUSY);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_LOG_READ, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_ERR_BUSY);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_DEVICE_INFO, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	EZ_CHECK(!ez_dispatch_poll(&l->disp, 1) || l->disp.job_running);   /* poll does not run it */
	EZ_CHECK(l->disp.job_running);
	ez_dispatch_job_run(&l->disp);                               /* "core 1" */
	l->disp.external_worker = false;
	EZ_CHECK(!l->disp.job_running);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	EZ_CHECK(rn > 0 && rsp[0] == 1);                             /* one copy */
	/* status polling (DEVICE_INFO every 300 ms) never holds the sync off */
	ez_dispatch_idle(&l->disp, 10000);
	for (uint32_t t = 10000; t <= 12100 && !l->disp.job_running; t += 300) {
		ez_call(T(l), EZ_CMD_DEVICE_INFO, NULL, 0, rsp, sizeof rsp, &rn, 100);
		ez_dispatch_want_sync(&l->disp);
		ez_dispatch_idle(&l->disp, t);
	}
	EZ_CHECK(l->disp.job_running && l->disp.job == 4);
	/* the command's result stays readable during the sync after it, and
	 * after (TR-08: the copy after 'ez key generate' failed with BUSY) */
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	EZ_CHECK(rn > 0 && rsp[0] == 1);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_KEY_STATUS, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	ez_rd_init(&r, rsp, rn); ez_wjob_read(&r, &j);
	EZ_CHECK(j.job == 3 && !j.running && j.result == EZ_OK);
	ez_dispatch_poll(&l->disp, 1);
	EZ_CHECK(!l->disp.job_running);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);
	/* background sync: scheduled after a quiet second, yields to a command */
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_SESSION_LIST, NULL, 0, rsp, sizeof rsp, &rn, 100), EZ_OK);   /* real activity */
	ez_dispatch_want_sync(&l->disp);
	ez_dispatch_idle(&l->disp, 13000);
	ez_dispatch_idle(&l->disp, 13500);
	EZ_CHECK(!l->disp.job_running);                              /* not quiet long enough */
	ez_dispatch_idle(&l->disp, 15000);
	EZ_CHECK(l->disp.job_running && l->disp.job == 4);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_ENC_BEGIN, q9, 9, rsp, sizeof rsp, &rn, 100), EZ_ERR_BUSY);
	EZ_CHECK(l->disp.yield);                                     /* asked to make way */
	ez_dispatch_poll(&l->disp, 1);
	EZ_CHECK(!l->disp.job_running);
	EZ_CHECK_EQ(ez_call(T(l), EZ_CMD_ENC_BEGIN, q9, 9, rsp, sizeof rsp, &rn, 100), EZ_OK);
	ez_call(T(l), EZ_CMD_DEVICE_INFO, NULL, 0, rsp, sizeof rsp, &rn, 100);   /* ends the stream */
	DEV_KBUF_CLEAR(l->dev);
	lb_free(l);
}

static const ez_test_case_t cases[] = {
	{ "frames",                "IMPL §9.2 (frame format)", t_frames },
	{ "payload_codec",         "IMPL §9.4 (bounds-checked decoding)", t_payload_codec },
	{ "device_and_sessions",   "IMPL §4, §9.4, IMPL-MODE-001/002", t_device_and_sessions },
	{ "encrypt_decrypt",       "SEC-ENC-001, SEC-DEC-001, SEC-DEC-003, IMPL-ENG-008/009", t_encrypt_decrypt },
	{ "interrupted_requests",  "IMPL-ENG-003, SEC-FW-003", t_interrupted_requests },
	{ "jobs_and_busy",         "IMPL-ARCH-004, SEC-ENTROPY-002", t_jobs_and_busy },
	{ "import",                "SEC-STORE-005, IMPL-CLI-006", t_import },
	{ "external_busy",         "IMPL-ARCH-004 (console holds the core)", t_external_busy },
	{ "deferred_jobs",         "IMPL-ARCH-004 (round 16: jobs, JOB_RESULT, sync yields)", t_deferred_jobs },
	{ "streaming",             "SEC-ENC-001, SEC-DEC-001/002, SEC-PTR-003 over USB", t_streaming },
	{ "random_frames",         "IMPL-API-001, SEC-FW-004, G-03", t_random_frames },
};
EZ_TEST_MAIN(cases)
