/*
 * ez_dispatch.h -- device-side command dispatcher (EZ-IMPL-001 §9.4)
 *
 * Feeds received 64-byte frames to the core and sends response frames
 * through a callback. Transport-independent: the firmware calls it from
 * the USB HID callbacks, the virtual device from its socket loop.
 *
 *   ez_dispatch_init(&d, &core, send_fn, ctx, &info);
 *   on every received frame:   ez_dispatch_frame(&d, frame);
 *   in the main loop:          ez_dispatch_poll(&d, 4);   (advances jobs)
 *   on transport reset:        ez_dispatch_reset(&d);
 *
 * Rules enforced here:
 *   - IMPL-ARCH-004: while a generation or import job runs, only read-only
 *     commands are accepted; everything else gets BUSY.
 *   - IMPL-ENG-003: a request aborted, interrupted by a new FIRST frame, or
 *     malformed is discarded and the staging buffer cleared.
 *   - IMPL-ENG-008/009: retained ciphertext survives only RESEND/RELEASE;
 *     any other command clears it.
 *   - Exactly one response per request (one per FIRST frame, or per ABORT
 *     frame). A request refused before its LAST frame is answered at once
 *     and its remaining frames are dropped silently; stray continuation
 *     frames are ignored. The host therefore never sees a stale response.
 *   - While external_busy is set (the owner of the core is using it, e.g.
 *     the device console), every request is answered BUSY at once and the
 *     core is not touched. Set it only with no request being received
 *     (call ez_dispatch_reset() first).
 *   - IMPL-API-001: no response carries key bytes or anything computed over
 *     them (tests check every response).
 *   - Session commands that change state name the session by slot AND Key
 *     ID; a mismatch is BAD_REQUEST, so a stale host view cannot hit the
 *     wrong session.
 */
#ifndef EZ_DISPATCH_H
#define EZ_DISPATCH_H

#include "ez_core.h"
#include "ez_engine.h"
#include "ez_import.h"
#include "ez_keygen.h"
#include "ez_proto.h"

#define EZ_REQ_MAX  512u
#define EZ_RSP_MAX  2048u

typedef void (*ez_send_fn)(void *ctx, const uint8_t frame[EZ_FRAME_SIZE]);

#define EZ_BUILD_PRODUCTION  0u
#define EZ_BUILD_DEVELOPMENT 1u
#define EZ_BUILD_VIRTUAL     2u

typedef struct {
	const char *fw_version;
	uint8_t variant;         /* 1 HID, 2 CDC, 3 composite, 0x10 development, 0xEE virtual */
	uint8_t hw_rev;
	uint8_t build;           /* EZ_BUILD_* (IMPL-MODE-001) */
} ez_devinfo_t;

typedef struct {
	ez_core_t *c;
	ez_send_fn send;
	void *send_ctx;
	const ez_devinfo_t *info;

	/* request being received */
	bool     rx_active;
	bool     discard;           /* drop the rest of a refused request */
	bool     external_busy;     /* the device is busy elsewhere (e.g. its console): answer BUSY, touch nothing */
	uint8_t  discard_cmd;
	uint8_t  cmd, seq;
	uint32_t rx_n;
	uint8_t  req[EZ_REQ_MAX];
	bool     bulk;              /* ENCRYPT/DECRYPT: data goes to the stage */
	uint8_t *bulk_dst;
	uint32_t bulk_need, bulk_got;
	int      slot;
	uint32_t key_id;

	/* a stream in progress (EZ-IMPL-001 §9.4): 0 none, 1 encrypt, 2 decrypt.
	 * Any other command, or a transport reset, aborts it. */
	uint8_t     stream_kind;
	ez_stream_t stream;

	/* jobs (round 16): 1 generation, 2 import, 3 deferred command, 4 sync.
	 * On the device the second core runs them (external_worker); elsewhere
	 * ez_dispatch_poll() runs them inline. */
	volatile uint8_t  job;
	volatile bool     job_running, job_pending, cancel, yield;
	volatile ez_status_t job_result;
	/* The last job started by a command (1-3), and its result: KEY_STATUS
	 * reports it, not a background sync that started after it finished. */
	volatile uint8_t  ujob;
	volatile ez_status_t ujob_result;
	bool     external_worker;
	bool     sync_wanted, activity, sync_full, sync_full_pending;
	uint32_t last_ms, last_sync_ms, failovers_seen;
	uint32_t last_full_ms, last_quick_ms;  /* when each kind of sync last started (0: never) */
	/* Tickets: every job started gets the next number; its result is kept
	 * under it, so a waiter reads its own job's result even if another job
	 * (a background sync) ran in between. */
	uint32_t ticket, cur_ticket;
	volatile uint32_t done_ticket;
	ez_status_t ticket_result[8];
	uint32_t sync_period_ms;     /* quick sync this often (0: never); full sync on events */
	uint8_t  jcmd;
	uint32_t jreq_n, jres_n;
	uint8_t  jreq[EZ_REQ_MAX];
	uint8_t  jres[EZ_RSP_MAX];
	ez_keygen_t kg;
	ez_import_t im;

	uint8_t  rsp[EZ_RSP_MAX];
} ez_dispatch_t;

void ez_dispatch_init(ez_dispatch_t *d, ez_core_t *c, ez_send_fn send, void *ctx,
                      const ez_devinfo_t *info);
void ez_dispatch_frame(ez_dispatch_t *d, const uint8_t frame[EZ_FRAME_SIZE]);
/* Without an external worker: run a pending job; true while one is running. */
bool ez_dispatch_poll(ez_dispatch_t *d, uint32_t units);
/* The worker (second core): run the pending job to completion. */
bool ez_dispatch_job_pending(const ez_dispatch_t *d);
void ez_dispatch_job_run(ez_dispatch_t *d);
/* Call regularly with a millisecond clock: starts the background sync when
 * wanted (boot, card change, after a job) and the device has been quiet. */
void ez_dispatch_idle(ez_dispatch_t *d, uint32_t now_ms);
void ez_dispatch_want_sync(ez_dispatch_t *d);
/* The ticket of the job just started; whether ticket t is done (and its
 * result). Results are kept for the last 8 jobs. */
uint32_t ez_dispatch_last_ticket(const ez_dispatch_t *d);
bool ez_dispatch_ticket_done(const ez_dispatch_t *d, uint32_t t, ez_status_t *result);
/* Start a deferred command as a job from local code (the development shell). */
bool ez_dispatch_submit(ez_dispatch_t *d, uint8_t cmd, const uint8_t *req, uint32_t n);
ez_status_t ez_dispatch_start_keygen(ez_dispatch_t *d, uint8_t drive, uint32_t len);
ez_status_t ez_dispatch_start_import(ez_dispatch_t *d, uint8_t drive, const char *name, uint32_t id,
                                     uint8_t role, const char *label);
/* Transport lost: discard any partial request and clear the stage (unless
 * a job owns it). Jobs keep running. */
void ez_dispatch_reset(ez_dispatch_t *d);

#endif /* EZ_DISPATCH_H */
