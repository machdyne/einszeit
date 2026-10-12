/* ez_client.c -- see ez_client.h */
#include "ez_client.h"

#include <string.h>

static int send_frames(const ez_transport_t *t, uint8_t cmd, uint8_t extra_flags,
                       const uint8_t *req, size_t n)
{
	ez_frame_t f;
	uint8_t out[EZ_FRAME_SIZE];
	size_t off = 0;
	uint8_t seq = 0;
	do {
		size_t k = n - off < EZ_FRAME_PAYLOAD ? n - off : EZ_FRAME_PAYLOAD;
		memset(&f, 0, sizeof f);
		f.cmd = cmd;
		f.seq = seq++;
		f.flags = (uint8_t)(extra_flags | (off == 0 ? EZ_FF_FIRST : 0) | (off + k == n ? EZ_FF_LAST : 0));
		f.len = (uint16_t)k;
		if (k) memcpy(f.data, req + off, k);
		ez_frame_encode(&f, out);
		if (t->write(t->ctx, out) != 0) return EZ_CALL_IO;
		off += k;
	} while (off < n);
	memset(out, 0, sizeof out);
	return 0;
}

static int recv_rsp(const ez_transport_t *t, uint8_t cmd, uint8_t *rsp, size_t cap,
                    size_t *rsp_len, int timeout_ms)
{
	uint8_t in[EZ_FRAME_SIZE];
	ez_frame_t f;
	size_t n = 0, frames = 0;
	int status = -1;
	for (;;) {
		int r = t->read(t->ctx, in, timeout_ms);
		if (r == 0) return EZ_CALL_TIMEOUT;
		if (r < 0) return EZ_CALL_IO;
		if (ez_frame_decode(in, &f) != EZ_OK || f.cmd != cmd) return EZ_CALL_PROTOCOL;
		/* The sequence number wraps modulo 256; the position does not. */
		if (frames == 0 ? !(f.flags & EZ_FF_FIRST) || f.seq != 0
		                : (f.flags & EZ_FF_FIRST) || f.seq != (uint8_t)frames)
			return EZ_CALL_PROTOCOL;
		if (frames == 0) status = f.status;
		else if (f.status != status) return EZ_CALL_PROTOCOL;
		frames++;
		if (f.len) {
			if (!rsp || cap - n < f.len) return EZ_CALL_TOOBIG;
			memcpy(rsp + n, f.data, f.len);
			n += f.len;
		}
		if (f.flags & EZ_FF_LAST) break;
	}
	memset(&f, 0, sizeof f);
	memset(in, 0, sizeof in);
	if (rsp_len) *rsp_len = n;
	return status;
}

/* Discard anything left over from an earlier, failed exchange. */
static void drain(const ez_transport_t *t)
{
	uint8_t in[EZ_FRAME_SIZE];
	while (t->read(t->ctx, in, 0) == 1) {}
	memset(in, 0, sizeof in);
}

int ez_call(const ez_transport_t *t, uint8_t cmd, const uint8_t *req, size_t req_len,
            uint8_t *rsp, size_t rsp_cap, size_t *rsp_len, int timeout_ms)
{
	if (rsp_len) *rsp_len = 0;
	drain(t);
	int r = send_frames(t, cmd, 0, req, req_len);
	if (r < 0) return r;
	return recv_rsp(t, cmd, rsp, rsp_cap, rsp_len, timeout_ms);
}

int ez_call_abort(const ez_transport_t *t, uint8_t cmd, int timeout_ms)
{
	drain(t);
	int r = send_frames(t, cmd, EZ_FF_ABORT, NULL, 0);
	if (r < 0) return r;
	return recv_rsp(t, cmd, NULL, 0, NULL, timeout_ms);
}

const char *ez_call_error(int st)
{
	switch (st) {
	case EZ_CALL_IO:       return "device connection failed";
	case EZ_CALL_TIMEOUT:  return "device did not respond";
	case EZ_CALL_PROTOCOL: return "protocol error (malformed response)";
	case EZ_CALL_TOOBIG:   return "response too large";
	default:               return ez_status_name((ez_status_t)st);
	}
}
