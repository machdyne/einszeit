/*
 * ez_dispatch.c -- see ez_dispatch.h for the rules and traceability.
 */
#include "ez_dispatch.h"

#include <string.h>

#include "ez_engine.h"
#include "ez_entropy.h"
#include "ez_meta.h"
#include "ez_secure.h"

/* ---- sending ------------------------------------------------------------ */

static void send_rsp(ez_dispatch_t *d, uint8_t cmd, ez_status_t st, const uint8_t *p, uint32_t n)
{
	ez_frame_t f;
	uint8_t out[EZ_FRAME_SIZE];
	uint32_t off = 0;
	uint8_t seq = 0;
	do {
		uint32_t k = n - off < EZ_FRAME_PAYLOAD ? n - off : EZ_FRAME_PAYLOAD;
		memset(&f, 0, sizeof f);
		f.cmd = cmd;
		f.status = (uint8_t)st;
		f.seq = seq++;
		f.flags = (uint8_t)((off == 0 ? EZ_FF_FIRST : 0) | (off + k == n ? EZ_FF_LAST : 0));
		f.len = (uint16_t)k;
		if (k) memcpy(f.data, p + off, k);
		ez_frame_encode(&f, out);
		d->send(d->send_ctx, out);
		off += k;
	} while (off < n);
	ez_secure_zero(&f, sizeof f);
	ez_secure_zero(out, sizeof out);
}

static void send_status(ez_dispatch_t *d, uint8_t cmd, ez_status_t st) { send_rsp(d, cmd, st, NULL, 0); }

/* ---- receive state ---------------------------------------------------- */

static void drop_request(ez_dispatch_t *d)
{
	if (d->bulk && !d->job_running) ez_release(d->c);   /* IMPL-ENG-003 */
	d->rx_active = false;
	d->bulk = false;
	d->bulk_dst = NULL;
	d->rx_n = 0;
	ez_secure_zero(d->req, sizeof d->req);
}

void ez_dispatch_init(ez_dispatch_t *d, ez_core_t *c, ez_send_fn send, void *ctx,
                      const ez_devinfo_t *info)
{
	memset(d, 0, sizeof *d);
	d->sync_wanted = true;                             /* every boot checks the mirror, fully */
	d->sync_full_pending = true;
	d->sync_period_ms = 5u * 60u * 1000u;              /* and quickly every 5 minutes */
	d->c = c;
	d->send = send;
	d->send_ctx = ctx;
	d->info = info;
	d->im.slot = -1;
}

static bool stream_cmd(uint8_t cmd)
{
	return cmd >= EZ_CMD_ENC_BEGIN && cmd <= EZ_CMD_DEC_END;
}

static void stream_abort(ez_dispatch_t *d)
{
	if (d->stream_kind) ez_stream_abort(d->c, &d->stream);
	d->stream_kind = 0;
}

void ez_dispatch_reset(ez_dispatch_t *d)
{
	stream_abort(d);
	drop_request(d);
	if (!d->job_running) ez_release(d->c);
}

static bool read_only(uint8_t cmd)
{
	switch (cmd) {
	case EZ_CMD_KEY_STATUS: case EZ_CMD_DEVICE_INFO: case EZ_CMD_SESSION_LIST:
	case EZ_CMD_SESSION_INFO: case EZ_CMD_LOG_READ: case EZ_CMD_DRIVE_INFO: case EZ_CMD_JOB_RESULT:
		return true;
	default:
		return false;
	}
}

/* With a real second-core worker, a job runs at the same time as this
 * code: only commands that touch no storage, F-RAM or card are answered
 * then (DEVICE_INFO reads RAM only). */
static bool allowed_during_job(const ez_dispatch_t *d, uint8_t cmd)
{
	if (!read_only(cmd)) return false;
	if (!d->external_worker) return true;
	return cmd == EZ_CMD_DEVICE_INFO || cmd == EZ_CMD_KEY_STATUS || cmd == EZ_CMD_JOB_RESULT;
}

/* ---- helpers -------------------------------------------------------------- */

static void fill_session(ez_core_t *c, int i, ez_wsession_t *w)
{
	const ez_session_t *s = &c->meta.s[i];
	memset(w, 0, sizeof *w);
	w->slot = (uint8_t)i;
	w->state = (uint8_t)s->state;
	w->qreason = s->qreason;
	if (s->identity) {
		w->flags |= EZ_SF_IDENTITY;
		w->role = s->role; w->drive = s->drive;
		w->key_id = s->key_id; w->key_len = s->key_len;
		memcpy(w->label, s->label, sizeof w->label - 1);
		w->tx_range = s->key_len / 2;
	}
	if (s->offsets) {
		w->flags |= EZ_SF_OFFSETS;
		w->tx_left = ez_meta_tx_remaining(s);
		w->rx_left = ez_meta_rx_remaining(s);
		if (ez_meta_tx_low(s, 20)) w->flags |= EZ_SF_TX_LOW;          /* IMPL-CLI-004 */
	}
}

/* The session named by slot and Key ID (an unverifiable record matches
 * Key ID 0 only). */
static ez_status_t named(ez_core_t *c, int slot, uint32_t key_id)
{
	if (slot < 0 || slot >= EZ_META_SESSIONS) return EZ_ERR_BAD_REQUEST;
	const ez_session_t *s = &c->meta.s[slot];
	if (s->state == EZ_SS_EMPTY) return EZ_ERR_NO_SESSION;
	if (s->identity ? s->key_id != key_id : key_id != 0) return EZ_ERR_BAD_REQUEST;
	return EZ_OK;
}

static void job_report(ez_dispatch_t *d, ez_wjob_t *j)
{
	memset(j, 0, sizeof *j);
	uint8_t job = d->job;
	bool running = d->job_running;
	ez_status_t result = d->job_result;
	/* A background sync after a command's job: report that job, finished
	 * (a waiting 'ez key generate' must read its own key's result). */
	if (job == 4 && d->ujob) { job = d->ujob; running = false; result = d->ujob_result; }
	j->job = job;
	j->running = running;
	j->result = (uint8_t)result;
	j->slot = 0xFF;
	if (job == 1) {
		j->key_id = d->kg.key_id;
		j->fail = d->kg.fail;
		j->permille = (uint16_t)ez_keygen_progress(&d->kg);
	} else if (job == 2) {
		j->key_id = d->im.key_id;
		j->fail = d->im.fail;
		j->have_sum = d->im.have_sum;
		j->bad = d->im.bad; j->first_bad = d->im.first_bad; j->dups = d->im.dups;
		j->permille = (uint16_t)(d->im.units ? (uint64_t)d->im.unit * 1000u / d->im.units : 0);
		if (d->im.slot >= 0) j->slot = (uint8_t)d->im.slot;
		if (!running && result == EZ_OK) j->replicate = (uint8_t)d->c->last_replicate;
	} else if (job == 3 || job == 4) {
		j->cmd = job == 3 ? d->jcmd : 0;
		j->permille = job == d->job ? d->c->progress : 1000u;
	}
}

/* ---- execution ------------------------------------------------------------ */

/* Run one command. The reply goes to out (or, for the few commands that
 * reply from the stage, is sent directly and *sent is set). Used both for
 * ordinary commands and, on the worker, for deferred ones (jobs). */
static ez_status_t run(ez_dispatch_t *d, uint8_t cmd, const uint8_t *req, uint32_t rq_n,
                       uint8_t *out, uint32_t cap, uint32_t *out_n, bool *sent)
{
	ez_core_t *c = d->c;
	ez_rd_t r;
	ez_wr_t w;
	*sent = false;
	*out_n = 0;
	ez_rd_init(&r, req, rq_n);
	ez_wr_init(&w, out, cap);
	ez_status_t st = EZ_OK;
	char label[EZ_LABEL_MAX + 1], name[EZ_NAME_MAX];

	switch (cmd) {
	case EZ_CMD_SESSION_LIST: {
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		uint8_t n = 0;
		for (int i = 0; i < EZ_META_SESSIONS; i++) if (c->meta.s[i].state != EZ_SS_EMPTY) n++;
		ez_wr_u8(&w, n);
		for (int i = 0; i < EZ_META_SESSIONS; i++) {
			if (c->meta.s[i].state == EZ_SS_EMPTY) continue;
			ez_wsession_t ws;
			fill_session(c, i, &ws);
			ez_wsession_write(&w, &ws);
		}
		break;
	}
	case EZ_CMD_SESSION_INFO: {
		int slot = ez_rd_u8(&r);
		if (!ez_rd_done(&r) || slot >= EZ_META_SESSIONS) { st = EZ_ERR_BAD_REQUEST; break; }
		if (c->meta.s[slot].state == EZ_SS_EMPTY) { st = EZ_ERR_NO_SESSION; break; }
		ez_wsession_t ws;
		fill_session(c, slot, &ws);
		ez_wsession_write(&w, &ws);
		break;
	}
	case EZ_CMD_SESSION_CREATE: {
		uint32_t id = ez_rd_u32(&r);
		uint8_t drive = ez_rd_u8(&r), role = ez_rd_u8(&r);
		ez_rd_str(&r, label, sizeof label);
		uint8_t flags = ez_rd_u8(&r);
		if (!ez_rd_done(&r) || (flags & ~EZ_SESS_CRITICAL)) { st = EZ_ERR_BAD_REQUEST; break; }
		int slot = -1;
		st = ez_session_create_flags(c, id, drive, role, label, flags, &slot);
		if (st == EZ_OK) {
			ez_wr_u8(&w, (uint8_t)slot);
			ez_wr_u8(&w, (uint8_t)c->last_replicate);
			ez_wr_u8(&w, (uint8_t)c->last_critical);        /* IMPL-AV-005 */
		}
		break;
	}
	case EZ_CMD_SESSION_DELETE: case EZ_CMD_SESSION_RESOLVE: case EZ_CMD_SESSION_SKIP: {
		int slot = ez_rd_u8(&r);
		uint32_t id = ez_rd_u32(&r);
		uint8_t force = cmd == EZ_CMD_SESSION_DELETE ? ez_rd_u8(&r) : 0;
		if (!ez_rd_done(&r) || force > 1) { st = EZ_ERR_BAD_REQUEST; break; }
		if ((st = named(c, slot, id)) != EZ_OK) break;
		if (cmd == EZ_CMD_SESSION_DELETE) st = ez_session_delete(c, slot, force == 1);
		else if (cmd == EZ_CMD_SESSION_RESOLVE) st = ez_session_resolve(c, slot);
		else {
			uint32_t units = 0;
			st = ez_session_skip(c, slot, &units);
			ez_wr_u32(&w, units);
		}
		break;
	}
	case EZ_CMD_SESSION_CRITICAL: {
		int slot = ez_rd_u8(&r);
		uint32_t id = ez_rd_u32(&r);
		uint8_t on = ez_rd_u8(&r);
		if (!ez_rd_done(&r) || on > 1) { st = EZ_ERR_BAD_REQUEST; break; }
		if ((st = named(c, slot, id)) != EZ_OK) break;
		st = ez_session_set_critical(c, slot, on == 1);
		break;
	}
	case EZ_CMD_JOB_RESULT:
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		/* The last command's job, even with a background sync running
		 * after it (TR-08: 'ez key generate' could not copy to the card:
		 * BUSY). The sync never writes jres. */
		if (d->job_running && d->job != 4) { st = EZ_ERR_BUSY; break; }
		if (d->ujob != 3) { st = EZ_ERR_STATE; break; }
		st = d->ujob_result;
		if (st == EZ_OK) ez_wr_bytes(&w, d->jres, d->jres_n);
		break;
	case EZ_CMD_SESSION_CHECK: case EZ_CMD_SESSION_REPAIR: {
		int slot = ez_rd_u8(&r);
		uint32_t id = ez_rd_u32(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		if ((st = named(c, slot, id)) != EZ_OK) break;
		if (cmd == EZ_CMD_SESSION_REPAIR) {
			uint8_t n = 0;
			st = ez_session_repair(c, slot, &n);
			ez_wr_u8(&w, n);
			if (st == EZ_ERR_KEY_DAMAGED) st = EZ_OK, ez_wr_u8(&w, 1);   /* some units lost in every copy */
			else ez_wr_u8(&w, 0);
			if (st != EZ_OK) w.n = 0;
			break;
		}
		ez_check_t ck;
		if ((st = ez_session_check(c, slot, &ck)) != EZ_OK) break;
		ez_wr_u8(&w, ck.copies); ez_wr_u32(&w, ck.units); ez_wr_u32(&w, ck.lost);
		for (int k = 0; k < ck.copies; k++) {
			ez_wr_u8(&w, ck.copy[k].present); ez_wr_u8(&w, ck.copy[k].has_key); ez_wr_u32(&w, ck.copy[k].bad);
		}
		ez_wr_u32(&w, c->failovers);
		ez_wr_u8(&w, ck.critical); ez_wr_u8(&w, ck.d0_state); ez_wr_u32(&w, ck.d0_bad);
		break;
	}
	case EZ_CMD_KEY_GENERATE: {
		uint32_t len = ez_rd_u32(&r);
		uint8_t drive = ez_rd_u8(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		st = ez_dispatch_start_keygen(d, drive, len);
		break;
	}
	case EZ_CMD_KEY_IMPORT: {
		uint8_t drive = ez_rd_u8(&r);
		uint32_t id = ez_rd_u32(&r);
		uint8_t role = ez_rd_u8(&r);
		ez_rd_str(&r, label, sizeof label);
		ez_rd_str(&r, name, sizeof name);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		st = ez_dispatch_start_import(d, drive, name, id, role, label);
		if (st == EZ_OK) ez_wr_u8(&w, d->im.have_sum);   /* IMPL-CLI-006 warning on the host */
		break;
	}
	case EZ_CMD_KEY_STATUS: {
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		ez_wjob_t j;
		job_report(d, &j);
		ez_wjob_write(&w, &j);
		break;
	}
	case EZ_CMD_KEY_COPY: {
		uint32_t id = ez_rd_u32(&r);
		uint8_t from = ez_rd_u8(&r), to = ez_rd_u8(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		st = ez_key_copy(c, id, from, to);
		if (st == EZ_OK) ez_wr_u8(&w, (uint8_t)c->last_replicate);
		break;
	}
	case EZ_CMD_KEY_DELETE: {
		uint32_t id = ez_rd_u32(&r);
		uint8_t drive = ez_rd_u8(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		st = ez_key_delete(c, drive, id);
		break;
	}
	case EZ_CMD_ENCRYPT: {
		const uint8_t *o; uint32_t n;
		st = named(c, d->slot, d->key_id);
		if (st == EZ_OK) st = ez_encrypt_buffered(c, d->slot, d->bulk_need, &o, &n);
		if (st == EZ_OK) { send_rsp(d, cmd, EZ_OK, o, n); *sent = true; return EZ_OK; }   /* retained (IMPL-ENG-008) */
		ez_release(c);
		break;
	}
	case EZ_CMD_DECRYPT: {
		const uint8_t *o; uint32_t n;
		st = ez_decrypt_buffered(c, d->slot, d->bulk_need, &o, &n);
		if (st == EZ_OK) { send_rsp(d, cmd, EZ_OK, o, n); ez_release(c); *sent = true; return EZ_OK; }
		ez_release(c);
		break;
	}
	/* ---- streaming (messages over 64 KiB) ---------------------------------- */
	case EZ_CMD_ENC_BEGIN: {
		int slot = ez_rd_u8(&r);
		uint32_t id = ez_rd_u32(&r), len = ez_rd_u32(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		stream_abort(d);
		if ((st = named(c, slot, id)) != EZ_OK) break;
		uint8_t hdr[EZ_MSG_HDR];
		st = ez_enc_stream_begin(c, &d->stream, slot, len, hdr);
		if (st == EZ_OK) { d->stream_kind = 1; ez_wr_bytes(&w, hdr, sizeof hdr); }
		break;
	}
	case EZ_CMD_DEC_BEGIN: {
		uint8_t sl = ez_rd_u8(&r), hdr[EZ_MSG_HDR];
		for (unsigned i = 0; i < EZ_MSG_HDR; i++) hdr[i] = ez_rd_u8(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		stream_abort(d);
		st = ez_dec_stream_begin(c, &d->stream, sl == 0xFF ? -1 : sl, hdr);
		if (st == EZ_OK) d->stream_kind = 2;
		break;
	}
	case EZ_CMD_ENC_DATA: case EZ_CMD_DEC_DATA: {
		if (d->stream_kind != (cmd == EZ_CMD_ENC_DATA ? 1 : 2)) { st = EZ_ERR_STATE; break; }
		if (d->rx_n == 0) { st = EZ_ERR_BAD_REQUEST; break; }
		memcpy(d->rsp, d->req, d->rx_n);
		st = cmd == EZ_CMD_ENC_DATA ? ez_enc_stream_update(c, &d->stream, d->rsp, d->rx_n)
		                            : ez_dec_stream_update(c, &d->stream, d->rsp, d->rx_n);
		if (st == EZ_OK) w.n = d->rx_n;             /* the chunk, transformed in place */
		else { ez_secure_zero(d->rsp, d->rx_n); stream_abort(d); }
		break;
	}
	case EZ_CMD_ENC_END: {
		if (d->stream_kind != 1 || !ez_rd_done(&r)) { st = d->stream_kind != 1 ? EZ_ERR_STATE : EZ_ERR_BAD_REQUEST; break; }
		uint8_t trl[EZ_MSG_TRL];
		st = ez_enc_stream_end(c, &d->stream, trl);
		d->stream_kind = 0;
		if (st == EZ_OK) ez_wr_bytes(&w, trl, sizeof trl);
		break;
	}
	case EZ_CMD_DEC_END: {
		uint8_t trl[EZ_MSG_TRL];
		for (unsigned i = 0; i < EZ_MSG_TRL; i++) trl[i] = ez_rd_u8(&r);
		if (d->stream_kind != 2 || !ez_rd_done(&r)) { st = d->stream_kind != 2 ? EZ_ERR_STATE : EZ_ERR_BAD_REQUEST; break; }
		st = ez_dec_stream_end(c, &d->stream, trl);
		d->stream_kind = 0;
		break;
	}
	case EZ_CMD_RESEND: {
		uint32_t n = 0;
		const uint8_t *o = ez_retained(c, &n);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		if (!o) { st = EZ_ERR_STATE; break; }
		send_rsp(d, cmd, EZ_OK, o, n);                       /* unchanged, no key access */
		*sent = true; return EZ_OK;
	}
	case EZ_CMD_RELEASE:
		ez_release(c);
		break;
	case EZ_CMD_DRIVE_LIST: {
		uint8_t drive = ez_rd_u8(&r);
		uint16_t start = ez_rd_u16(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		uint8_t count = 0, more = 0;
		ez_wr_u8(&w, 0);                                     /* count, patched below */
		for (uint32_t i = start;; i++) {
			uint32_t size;
			ez_status_t s2 = ez_drive_list(c, drive, i, name, &size);
			if (s2 == EZ_ERR_NOT_FOUND) break;
			if (s2 != EZ_OK) { st = s2; break; }
			if (w.n + 5 + strlen(name) + 1 > sizeof d->rsp || count == 255) { more = 1; break; }
			ez_wr_u32(&w, size);
			ez_wr_str(&w, name);
			count++;
		}
		d->rsp[0] = count;
		ez_wr_u8(&w, more);
		break;
	}
	case EZ_CMD_DRIVE_INFO: {
		uint8_t drive = ez_rd_u8(&r);
		if (!ez_rd_done(&r) || drive >= EZ_DRIVES) { st = EZ_ERR_BAD_REQUEST; break; }
		ez_wr_u8(&w, c->ks->present(c->ks->ctx, drive));
		ez_wr_u8(&w, drive == 0 ? c->meta.drive0_enabled : 1);
		ez_wr_u8(&w, (uint8_t)ez_core_drive_usable(c, drive));
		ez_wr_u8(&w, c->ks->copies ? c->ks->copies(c->ks->ctx, drive) : 1);   /* SEC-AVAIL-003 */
		break;
	}
	case EZ_CMD_DRIVE_ENABLE: case EZ_CMD_DRIVE_DISABLE: {
		uint8_t drive = ez_rd_u8(&r);
		if (!ez_rd_done(&r) || drive != 0) { st = EZ_ERR_BAD_REQUEST; break; }
		st = cmd == EZ_CMD_DRIVE_ENABLE ? ez_drive_enable0(c) : ez_drive_disable0(c);
		break;
	}
	case EZ_CMD_DRIVE_FORMAT: {
		uint8_t drive = ez_rd_u8(&r), copies = ez_rd_u8(&r);
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		st = ez_drive_format(c, drive, copies);
		break;
	}
	case EZ_CMD_DRIVE_REPAIR: {
		uint8_t drive = ez_rd_u8(&r), n = 0;
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		if ((st = ez_drive_repair(c, drive, &n)) == EZ_OK) ez_wr_u8(&w, n);
		break;
	}
	case EZ_CMD_RANDOM: {
		uint16_t n = ez_rd_u16(&r);
		if (!ez_rd_done(&r) || n == 0 || n > 1024) { st = EZ_ERR_BAD_REQUEST; break; }
		/* Fresh TRNG output, never key material (IMPL-API-001). */
		if (c->trng->read(c->trng->ctx, d->rsp, n) != EZ_OK) { ez_secure_zero(d->rsp, n); st = EZ_ERR_ENTROPY; break; }
		send_rsp(d, cmd, EZ_OK, d->rsp, n);
		ez_secure_zero(d->rsp, n);
		*sent = true; return EZ_OK;
	}
	case EZ_CMD_ENTROPY_TEST: {
		uint32_t n = ez_rd_u32(&r);
		if (!ez_rd_done(&r) || n < 2560 || n > 65536 || n % 512) { st = EZ_ERR_BAD_REQUEST; break; }
		ez_monitor_t mon;
		ez_accept_t acc;
		uint8_t mf = 0;
		ez_mon_init(&mon);
		ez_acc_init(&acc);
		for (uint32_t o = 0; o < n && st == EZ_OK; o += 512) {
			if (c->trng->read(c->trng->ctx, c->kbuf, 512) != EZ_OK) st = EZ_ERR_ENTROPY;
			else { mf |= ez_mon_feed(&mon, c->kbuf, 512); ez_acc_feed(&acc, c->kbuf, 512); }
			ez_secure_zero(c->kbuf, sizeof c->kbuf);
		}
		uint8_t af = ez_acc_finish(&acc);
		ez_mon_clear(&mon);
		ez_secure_zero(&acc, sizeof acc);
		if (st == EZ_OK) { ez_wr_u8(&w, mf); ez_wr_u8(&w, af); }
		break;
	}
	case EZ_CMD_DEVICE_INFO: {
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		uint8_t present = 0;
		for (uint8_t i = 0; i < EZ_DRIVES; i++) if (c->ks->present(c->ks->ctx, i)) present |= (uint8_t)(1u << i);
		ez_wr_u8(&w, EZ_PROTO_VERSION);
		ez_wr_str(&w, d->info->fw_version);
		ez_wr_u8(&w, d->info->variant);
		ez_wr_u8(&w, d->info->hw_rev);
		ez_wr_u8(&w, c->trng->profile);
		ez_wr_u8(&w, (uint8_t)c->meta.dev);
		ez_wr_u32(&w, c->meta.boot_count);
		ez_wr_u8(&w, c->meta.drive0_enabled);
		ez_wr_u8(&w, present);
		ez_wr_u8(&w, ez_core_intent_pending(c));
		ez_wr_u8(&w, d->job_running);
		ez_wr_u8(&w, d->info->build);                       /* IMPL-MODE-001 */
		ez_wr_u8(&w, ez_core_dev_tainted(c));               /* IMPL-MODE-002 */
		ez_wr_u8(&w, (uint8_t)(ez_core_drive0_protected(c) + 1));  /* 0 n/a, 1 missing, 2 verified */
		/* round 16: health, its detail bits, the running job and its progress */
		ez_wr_u8(&w, d->job_running && d->job == 4 ? (uint8_t)EZ_HEALTH_SYNCING : c->health);
		ez_wr_u8(&w, c->health_detail);
		ez_wr_u8(&w, d->job_running ? d->job : 0);
		ez_wr_u8(&w, d->job_running && d->job == 3 ? d->jcmd : 0);
		/* A generation keeps its own progress; the core's is the last sync's
		 * (TR-08: 'device info' said 100% while 'ez key generate' said 7%). */
		uint16_t pm = d->c->progress;
		if (d->job_running && d->job == 1) pm = (uint16_t)ez_keygen_progress(&d->kg);
		else if (d->job_running && d->job == 2 && d->im.units) pm = (uint16_t)((uint64_t)d->im.unit * 1000u / d->im.units);
		ez_wr_u16(&w, pm);
		break;
	}
	case EZ_CMD_DEVICE_ERASE:
		st = ez_rd_done(&r) ? ez_device_erase(c) : EZ_ERR_BAD_REQUEST;
		break;
	case EZ_CMD_DEVICE_REPAIR:
		st = ez_rd_done(&r) ? ez_meta_repair(&c->meta) : EZ_ERR_BAD_REQUEST;
		break;
	case EZ_CMD_LOG_READ: {
		if (!ez_rd_done(&r)) { st = EZ_ERR_BAD_REQUEST; break; }
		ez_event_t ev[EZ_META_LOG_ENTRIES];
		int n = ez_meta_log_read(&c->meta, ev, EZ_META_LOG_ENTRIES);
		ez_wr_u8(&w, (uint8_t)(n < 0 ? 0 : n));
		for (int i = 0; i < n; i++) {
			ez_wr_u32(&w, ev[i].seq); ez_wr_u32(&w, ev[i].boot); ez_wr_u32(&w, ev[i].time);
			ez_wr_u8(&w, ev[i].type); ez_wr_u8(&w, ev[i].detail);
			ez_wr_u32(&w, ev[i].key_id); ez_wr_u32(&w, ev[i].arg);
			ez_wr_u8(&w, ev[i].host_time);
		}
		break;
	}
	default:
		st = EZ_ERR_UNSUPPORTED;
	}
	if (w.err) st = EZ_ERR_BAD_REQUEST;
	*out_n = st == EZ_OK ? (uint32_t)w.n : 0;
	return st;
}

bool ez_dispatch_submit(ez_dispatch_t *d, uint8_t cmd, const uint8_t *req, uint32_t n)
{
	if (d->job_running || n > sizeof d->jreq) return false;
	memcpy(d->jreq, req, n);
	d->jreq_n = n;
	d->jcmd = cmd;
	d->jres_n = 0;
	d->c->progress = 0;
	d->cancel = false;
	d->job = 3;
	d->job_result = EZ_PENDING;
	d->cur_ticket = ++d->ticket;
	__sync_synchronize();                    /* the job's arguments before the flag (second core) */
	d->job_pending = true;
	d->job_running = true;
	return true;
}

/* Key generation and import as jobs, for the protocol and the terminal
 * interface alike. EZ_OK when started. */
ez_status_t ez_dispatch_start_keygen(ez_dispatch_t *d, uint8_t drive, uint32_t len)
{
	if (d->job_running) return EZ_ERR_BUSY;
	ez_status_t st = ez_keygen_start(d->c, &d->kg, drive, len);
	if (st != EZ_PENDING) return st;
	d->job = 1; d->cancel = false; d->job_result = EZ_PENDING;
	d->cur_ticket = ++d->ticket;
	__sync_synchronize();
	d->job_pending = true; d->job_running = true;
	return EZ_OK;
}

ez_status_t ez_dispatch_start_import(ez_dispatch_t *d, uint8_t drive, const char *name, uint32_t id,
                                     uint8_t role, const char *label)
{
	if (d->job_running) return EZ_ERR_BUSY;
	ez_status_t st = ez_import_start(d->c, &d->im, drive, name, id, role, label);
	if (st != EZ_PENDING) return st;
	d->job = 2; d->cancel = false; d->job_result = EZ_PENDING;
	d->cur_ticket = ++d->ticket;
	__sync_synchronize();
	d->job_pending = true; d->job_running = true;
	return EZ_OK;
}

/* A long command becomes a job (deferred) and is answered at once. */
static void exec(ez_dispatch_t *d)
{
	if (ez_cmd_deferred(d->cmd)) {
		ez_dispatch_submit(d, d->cmd, d->req, d->rx_n);
		send_rsp(d, d->cmd, EZ_OK, NULL, 0);
		return;
	}
	uint32_t n;
	bool sent;
	ez_status_t st = run(d, d->cmd, d->req, d->rx_n, d->rsp, sizeof d->rsp, &n, &sent);
	if (!sent) send_rsp(d, d->cmd, st, st == EZ_OK ? d->rsp : NULL, n);
	ez_secure_zero(d->rsp, sizeof d->rsp);
}

/* ---- frame intake --------------------------------------------------------------- */

/* Refuse the request now; if it has more frames, drop them silently. */
static void fail(ez_dispatch_t *d, uint8_t cmd, ez_status_t st, bool last)
{
	drop_request(d);
	send_status(d, cmd, st);
	d->discard = !last;
	d->discard_cmd = cmd;
}

void ez_dispatch_frame(ez_dispatch_t *d, const uint8_t in[EZ_FRAME_SIZE])
{
	ez_frame_t f;
	bool last = (in[1] & EZ_FF_LAST) != 0;
	if (ez_frame_decode(in, &f) != EZ_OK) {
		/* Answer only a frame that starts a request (exactly one response). */
		if (in[1] & EZ_FF_FIRST) fail(d, in[0], EZ_ERR_BAD_REQUEST, last);
		else if (d->rx_active) fail(d, d->cmd, EZ_ERR_BAD_REQUEST, last);
		return;
	}

	if (d->external_busy) {
		/* Answer each request (and each ABORT) once, touching nothing. */
		if (f.flags & (EZ_FF_FIRST | EZ_FF_ABORT)) {
			d->discard = !last && !(f.flags & EZ_FF_ABORT);
			d->discard_cmd = f.cmd;
			send_status(d, f.cmd, EZ_ERR_BUSY);
		}
		ez_secure_zero(&f, sizeof f);
		return;
	}

	if (f.flags & EZ_FF_ABORT) {
		bool cancel_job = f.cmd == EZ_CMD_KEY_STATUS && d->job_running;
		drop_request(d);
		if (cancel_job && (d->job == 1 || d->job == 2)) {
			d->cancel = true;                     /* the worker stops the job */
			if (!d->external_worker) ez_dispatch_job_run(d);
		}
		send_status(d, f.cmd, EZ_ERR_ABORTED);
		ez_secure_zero(&f, sizeof f);
		return;
	}

	if (f.flags & EZ_FF_FIRST) {
		if (d->rx_active) drop_request(d);           /* the old request is abandoned */
		d->discard = false;
		if (f.seq != 0) { fail(d, f.cmd, EZ_ERR_BAD_REQUEST, last); return; }
		if (d->job_running && !allowed_during_job(d, f.cmd)) {
			if (d->job == 4) d->yield = true;        /* a background sync makes way */
			fail(d, f.cmd, EZ_ERR_BUSY, last);
			return;
		}
		/* Status queries are not activity: a program polling the device's
		 * status must never hold off mirror maintenance (round 22). */
		if (f.cmd != EZ_CMD_DEVICE_INFO && f.cmd != EZ_CMD_KEY_STATUS && f.cmd != EZ_CMD_JOB_RESULT)
			d->activity = true;
		/* A stream ends with any command that does not continue it. */
		if (d->stream_kind && !stream_cmd(f.cmd)) stream_abort(d);
		/* IMPL-ENG-008: any command other than RESEND/RELEASE clears retained output. */
		if (f.cmd != EZ_CMD_RESEND && f.cmd != EZ_CMD_RELEASE && !d->job_running) ez_release(d->c);
		d->rx_active = true;
		d->cmd = f.cmd;
		d->seq = 0;
		d->rx_n = 0;
		d->bulk = false;
		uint32_t used = 0;
		if (f.cmd == EZ_CMD_ENCRYPT || f.cmd == EZ_CMD_DECRYPT) {
			ez_rd_t r;
			ez_rd_init(&r, f.data, f.len);
			uint8_t slot = ez_rd_u8(&r);
			d->key_id = f.cmd == EZ_CMD_ENCRYPT ? ez_rd_u32(&r) : 0;
			uint32_t len = ez_rd_u32(&r);
			if (r.err) { fail(d, f.cmd, EZ_ERR_BAD_REQUEST, last); return; }
			d->slot = f.cmd == EZ_CMD_DECRYPT && slot == 0xFF ? -1 : slot;
			d->bulk_dst = f.cmd == EZ_CMD_ENCRYPT ? ez_stage_plaintext(d->c, len) : ez_stage_message(d->c, len);
			if (!d->bulk_dst) { fail(d, f.cmd, EZ_ERR_BAD_REQUEST, last); return; }
			d->bulk = true;
			d->bulk_need = len;
			d->bulk_got = 0;
			used = (uint32_t)r.i;
		}
		f.len = (uint16_t)(f.len - used);
		memmove(f.data, f.data + used, f.len);
	} else {
		if (!d->rx_active) {
			/* the rest of a refused request, or a stray frame: no response */
			if (d->discard && f.cmd == d->discard_cmd && last) d->discard = false;
			ez_secure_zero(&f, sizeof f);
			return;
		}
		if (f.cmd != d->cmd || f.seq != (uint8_t)(d->seq + 1)) {
			fail(d, d->cmd, EZ_ERR_BAD_REQUEST, last);
			ez_secure_zero(&f, sizeof f);
			return;
		}
		d->seq = f.seq;
	}

	if (d->bulk) {
		if (f.len > d->bulk_need - d->bulk_got) { fail(d, d->cmd, EZ_ERR_BAD_REQUEST, last); ez_secure_zero(&f, sizeof f); return; }
		memcpy(d->bulk_dst + d->bulk_got, f.data, f.len);
		d->bulk_got += f.len;
	} else {
		if (f.len > EZ_REQ_MAX - d->rx_n) { fail(d, d->cmd, EZ_ERR_BAD_REQUEST, last); return; }
		memcpy(d->req + d->rx_n, f.data, f.len);
		d->rx_n += f.len;
	}
	ez_secure_zero(&f, sizeof f);

	if (last) {
		if (d->bulk && d->bulk_got != d->bulk_need) { fail(d, d->cmd, EZ_ERR_BAD_REQUEST, true); return; }
		d->rx_active = false;
		exec(d);
		d->bulk = false;
		d->bulk_dst = NULL;
		ez_secure_zero(d->req, sizeof d->req);
		d->rx_n = 0;
	}
}

/* Run the pending job to completion. On the device this is called on the
 * second core; everywhere else from ez_dispatch_poll(). While it runs, the
 * dispatcher answers only read-only commands, so nothing else touches the
 * core, the card or the metadata. */
void ez_dispatch_job_run(ez_dispatch_t *d)
{
	if (!d->job_pending) return;
	__sync_synchronize();                    /* see the job's arguments */
	d->job_pending = false;
	ez_status_t st = EZ_OK;
	switch (d->job) {
	case 1:
		do {
			if (d->cancel) { ez_keygen_cancel(d->c, &d->kg); st = EZ_ERR_ABORTED; break; }
			st = ez_keygen_step(d->c, &d->kg, 1);    /* one unit at a time: a cancel is seen promptly */
		} while (st == EZ_PENDING);
		break;
	case 2:
		do {
			if (d->cancel) { ez_import_cancel(d->c, &d->im); st = EZ_ERR_ABORTED; break; }
			st = ez_import_step(d->c, &d->im, 1);
		} while (st == EZ_PENDING);
		break;
	case 3: {
		uint32_t n = 0;
		bool sent;
		st = run(d, d->jcmd, d->jreq, d->jreq_n, d->jres, sizeof d->jres, &n, &sent);
		d->jres_n = n;
		ez_secure_zero(d->jreq, sizeof d->jreq);
		break;
	}
	case 4:
		d->c->yield = &d->yield;        /* cleared when scheduled, so an early request is kept */
		st = d->sync_full ? ez_sync(d->c) : ez_sync_quick(d->c);
		d->c->yield = NULL;
		if (st == EZ_ERR_BUSY) { d->sync_wanted = true; d->sync_full_pending = d->sync_full; }   /* resume */
		break;
	default:
		break;
	}
	d->job_result = st;
	if (d->job != 4) { d->ujob_result = st; d->ujob = d->job; }
	d->ticket_result[d->cur_ticket % 8u] = st;
	if (d->job != 4) { d->sync_wanted = true; d->sync_full_pending = true; }   /* storage may have changed */
	__sync_synchronize();
	d->done_ticket = d->cur_ticket;
	d->job_running = false;
}

bool ez_dispatch_job_pending(const ez_dispatch_t *d) { return d->job_pending; }
uint32_t ez_dispatch_last_ticket(const ez_dispatch_t *d) { return d->ticket; }
bool ez_dispatch_ticket_done(const ez_dispatch_t *d, uint32_t t, ez_status_t *result)
{
	if ((int32_t)(d->done_ticket - t) < 0) return false;          /* jobs run in ticket order */
	__sync_synchronize();
	if (result) *result = d->ticket_result[t % 8u];
	return true;
}
void ez_dispatch_want_sync(ez_dispatch_t *d) { d->sync_wanted = true; d->sync_full_pending = true; }

void ez_dispatch_idle(ez_dispatch_t *d, uint32_t now_ms)
{
	if (d->activity) { d->activity = false; d->last_ms = now_ms; return; }
	if (d->c->failovers != d->failovers_seen) {           /* a read needed another copy */
		d->failovers_seen = d->c->failovers;
		d->sync_wanted = true;
		d->sync_full_pending = true;
	}
	if (d->sync_period_ms && now_ms - d->last_sync_ms >= d->sync_period_ms) d->sync_wanted = true;
	if (!d->sync_wanted || d->job_running || d->stream_kind || d->rx_active) return;
	if (now_ms - d->last_ms < 1000u) return;               /* a second of quiet first */
	d->sync_wanted = false;
	d->sync_full = d->sync_full_pending;
	d->sync_full_pending = false;
	d->last_sync_ms = now_ms;
	if (d->sync_full) d->last_full_ms = now_ms ? now_ms : 1;
	else d->last_quick_ms = now_ms ? now_ms : 1;
	d->yield = false;
	d->job = 4;
	d->c->progress = 0;
	d->job_result = EZ_PENDING;
	d->cur_ticket = ++d->ticket;
	__sync_synchronize();
	d->job_pending = true;
	d->job_running = true;
}

bool ez_dispatch_poll(ez_dispatch_t *d, uint32_t units)
{
	(void)units;
	if (!d->external_worker) ez_dispatch_job_run(d);
	return d->job_running;
}
