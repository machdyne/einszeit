/*
 * ez_xfer.h -- one file transfer, protocol detected automatically.
 *
 * The protocol modules (ez_xmodem, ez_zmodem) know nothing of each other;
 * this layer picks one, so a user need not know what their terminal speaks:
 *   receiving: listens as a ZMODEM receiver first: one ZRINIT (terminals
 *              may open their ZMODEM upload by themselves), then quiet,
 *              answering only a ZMODEM sender's ZRQINIT. Every ZMODEM header
 *              carries a CAN, and two CANs cancel an XMODEM sender. After 6 s
 *              without one, asks with 'C' as an XMODEM receiver (XMODEM
 *              senders wait a minute for it); a ZMODEM sender that starts
 *              later is still recognised by its ZPAD ZDLE. Asking with 'C'
 *              first would make lrzsz's sz fall back to YMODEM.
 *   sending:   starts as a ZMODEM sender ("rz\r" and ZRQINIT, so terminals
 *              start their receiver by themselves); an XMODEM receiver asks
 *              with 'C' or NAK, and the transfer switches.
 * Once data flows, the protocol is fixed.
 */
#ifndef EZ_XFER_H
#define EZ_XFER_H

#include <stdbool.h>
#include <stdint.h>

#include "ez_xmodem.h"
#include "ez_zmodem.h"

typedef enum { EZ_XF_NONE, EZ_XF_XMODEM, EZ_XF_ZMODEM } ez_xf_proto_t;
typedef enum { EZ_XF_RUNNING, EZ_XF_DONE, EZ_XF_FAILED } ez_xf_result_t;

typedef void (*ez_xf_out_fn)(void *ctx, const uint8_t *b, uint32_t n);
typedef bool (*ez_xf_sink_fn)(void *ctx, const uint8_t *b, uint32_t n);

typedef struct {
	ez_xf_proto_t proto;
	bool sending, locked;
	uint8_t prev;                 /* receiving: the byte before, to spot ZPAD ZDLE */
	uint32_t t0;                  /* receiving: when the ZMODEM-first phase began */
	union { ez_xm_t xm; ez_zm_t zm; } u;
	/* kept to restart in the other protocol */
	ez_xf_out_fn out;
	ez_xf_sink_fn sink;
	void *ctx;
	const uint8_t *data;
	uint32_t len, max_len;
	char name[64];
} ez_xf_t;

void ez_xf_recv(ez_xf_t *x, ez_xf_sink_fn sink, uint32_t max_len, ez_xf_out_fn out, void *ctx, uint32_t now_ms);
/* Receiving, when a ZMODEM sender has already been seen (its first bytes). */
void ez_xf_recv_zmodem(ez_xf_t *x, ez_xf_sink_fn sink, uint32_t max_len, ez_xf_out_fn out, void *ctx,
                       const uint8_t *seen, uint32_t n, uint32_t now_ms);
void ez_xf_send(ez_xf_t *x, const uint8_t *data, uint32_t len, const char *name,
                ez_xf_out_fn out, void *ctx, uint32_t now_ms);
ez_xf_result_t ez_xf_input(ez_xf_t *x, const uint8_t *b, uint32_t n, uint32_t now_ms);
ez_xf_result_t ez_xf_tick(ez_xf_t *x, uint32_t now_ms);
void ez_xf_cancel(ez_xf_t *x);
const char *ez_xf_error(const ez_xf_t *x);
const char *ez_xf_proto_name(const ez_xf_t *x);
/* Receiving by XMODEM: the file arrives padded to a block with SUB (0x1A). */
bool ez_xf_padded(const ez_xf_t *x);

#endif
