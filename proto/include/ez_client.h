/*
 * ez_client.h -- host side of the protocol: one call = one transaction.
 *
 * Transport-independent; `ez` uses it over the virtual-device socket now
 * and over hidapi next. Portable C11.
 *
 *   uint8_t rsp[2048]; size_t n;
 *   int st = ez_call(&t, EZ_CMD_DEVICE_INFO, NULL, 0, rsp, sizeof rsp, &n);
 *   st < 0: transport failure (EZ_CALL_*); otherwise the device's ez_status_t.
 */
#ifndef EZ_CLIENT_H
#define EZ_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "ez_proto.h"

#define EZ_CALL_IO        (-1)   /* transport write/read failed */
#define EZ_CALL_TIMEOUT   (-2)   /* no response in time */
#define EZ_CALL_PROTOCOL  (-3)   /* malformed or out-of-sequence response */
#define EZ_CALL_TOOBIG    (-4)   /* response larger than the caller's buffer */

typedef struct {
	void *ctx;
	/* 0 on success */
	int (*write)(void *ctx, const uint8_t frame[EZ_FRAME_SIZE]);
	/* 1 frame read, 0 timeout, <0 error */
	int (*read)(void *ctx, uint8_t frame[EZ_FRAME_SIZE], int timeout_ms);
} ez_transport_t;

int ez_call(const ez_transport_t *t, uint8_t cmd, const uint8_t *req, size_t req_len,
            uint8_t *rsp, size_t rsp_cap, size_t *rsp_len, int timeout_ms);
/* Send a single ABORT frame for cmd and read its response. */
int ez_call_abort(const ez_transport_t *t, uint8_t cmd, int timeout_ms);
const char *ez_call_error(int st);

#endif
