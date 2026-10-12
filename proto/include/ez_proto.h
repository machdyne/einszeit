/*
 * ez_proto.h -- Einszeit USB protocol, version 1 (EZ-IMPL-001 §9.2, §9.4)
 *
 * Frames are 64 bytes. A transaction is a FIRST...LAST run of request frames
 * followed by a FIRST...LAST run of response frames. The request payload
 * is the concatenation of the request frames' payloads; likewise the
 * response. Payload fields are little-endian and decoded with the bounds-
 * checked reader below: any short or over-long payload is BAD_REQUEST.
 *
 * Shared by the device dispatcher and the host client. Portable C11.
 */
#ifndef EZ_PROTO_H
#define EZ_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ez_status.h"

#define EZ_PROTO_VERSION   1u
#define EZ_FRAME_SIZE      64u
#define EZ_FRAME_PAYLOAD   58u

/* Frame flags */
#define EZ_FF_FIRST        0x01u
#define EZ_FF_LAST         0x02u
#define EZ_FF_ABORT        0x04u
#define EZ_FF_RESERVED     0xF8u   /* bits 3..7, bit 7 reserved for host-link protection */

/* Command codes (EZ-IMPL-001 §4) */
enum {
	EZ_CMD_SESSION_LIST    = 0x01, EZ_CMD_SESSION_CREATE  = 0x02, EZ_CMD_SESSION_DELETE = 0x03,
	EZ_CMD_SESSION_INFO    = 0x04, EZ_CMD_SESSION_RESOLVE = 0x05, EZ_CMD_SESSION_SKIP   = 0x06,
	EZ_CMD_SESSION_CHECK   = 0x07, EZ_CMD_SESSION_REPAIR  = 0x08, EZ_CMD_SESSION_CRITICAL = 0x09,
	EZ_CMD_JOB_RESULT      = 0x0C,
	EZ_CMD_KEY_GENERATE    = 0x10, EZ_CMD_KEY_COPY        = 0x11, EZ_CMD_KEY_DELETE     = 0x12,
	EZ_CMD_KEY_STATUS      = 0x13, EZ_CMD_KEY_IMPORT      = 0x14,
	EZ_CMD_ENCRYPT         = 0x20, EZ_CMD_DECRYPT         = 0x21, EZ_CMD_RESEND         = 0x22,
	EZ_CMD_RELEASE         = 0x23,
	EZ_CMD_ENC_BEGIN       = 0x24, EZ_CMD_ENC_DATA        = 0x25, EZ_CMD_ENC_END        = 0x26,
	EZ_CMD_DEC_BEGIN       = 0x27, EZ_CMD_DEC_DATA        = 0x28, EZ_CMD_DEC_END        = 0x29,
	EZ_CMD_DRIVE_LIST      = 0x30, EZ_CMD_DRIVE_INFO      = 0x31, EZ_CMD_DRIVE_ENABLE   = 0x32,
	EZ_CMD_DRIVE_DISABLE   = 0x33, EZ_CMD_DRIVE_FORMAT    = 0x34, EZ_CMD_DRIVE_REPAIR    = 0x35,
	EZ_CMD_ENTROPY_TEST    = 0x40, EZ_CMD_RANDOM          = 0x41,
	EZ_CMD_DEVICE_INFO     = 0x50, EZ_CMD_DEVICE_ERASE    = 0x51, EZ_CMD_DEVICE_REPAIR  = 0x52,
	EZ_CMD_LOG_READ        = 0x53,
};

/* ---- frames ------------------------------------------------------------ */

typedef struct {
	uint8_t  cmd, flags, seq, status;
	uint16_t len;
	uint8_t  data[EZ_FRAME_PAYLOAD];
} ez_frame_t;

void        ez_frame_encode(const ez_frame_t *f, uint8_t out[EZ_FRAME_SIZE]);
/* EZ_ERR_BAD_REQUEST for a length over 58 or reserved flag bits set. */
ez_status_t ez_frame_decode(const uint8_t in[EZ_FRAME_SIZE], ez_frame_t *f);

/* ---- payload reader / writer --------------------------------------------- */

typedef struct { const uint8_t *p; size_t n, i; bool err; } ez_rd_t;
typedef struct { uint8_t *p; size_t cap, n; bool err; } ez_wr_t;

void     ez_rd_init(ez_rd_t *r, const uint8_t *p, size_t n);
uint8_t  ez_rd_u8(ez_rd_t *r);
uint16_t ez_rd_u16(ez_rd_t *r);
uint32_t ez_rd_u32(ez_rd_t *r);
/* String: u8 length then bytes; copied NUL-terminated into out (cap incl.
 * NUL). Error if too long for out, or containing NUL. */
void     ez_rd_str(ez_rd_t *r, char *out, size_t cap);
/* True if everything was read exactly, with no error. */
bool     ez_rd_done(const ez_rd_t *r);

void     ez_wr_init(ez_wr_t *w, uint8_t *p, size_t cap);
void     ez_wr_u8(ez_wr_t *w, uint8_t v);
void     ez_wr_u16(ez_wr_t *w, uint16_t v);
void     ez_wr_u32(ez_wr_t *w, uint32_t v);
void     ez_wr_str(ez_wr_t *w, const char *s);
void     ez_wr_bytes(ez_wr_t *w, const void *b, size_t n);

/* ---- payload layouts (EZ-IMPL-001 §9.4) ---------------------------------- */

/* One session as returned by SESSION_LIST and SESSION_INFO. */
#define EZ_SF_IDENTITY  0x01u
#define EZ_SF_OFFSETS   0x02u
#define EZ_SF_TX_LOW    0x04u
typedef struct {
	uint8_t  slot, state, qreason, role, drive, flags;
	uint32_t key_id, key_len, tx_left, rx_left, tx_range;
	char     label[16];
} ez_wsession_t;

void ez_wsession_write(ez_wr_t *w, const ez_wsession_t *s);
void ez_wsession_read(ez_rd_t *r, ez_wsession_t *s);

/* KEY_STATUS response */
typedef struct {
	uint8_t  job;          /* 0 none, 1 generation, 2 import */
	uint8_t  running;      /* 1 while EZ_PENDING */
	uint8_t  result;       /* ez_status_t once finished */
	uint8_t  fail;         /* acceptance / failure bits */
	uint8_t  have_sum;     /* import: a .SUM came with the key */
	uint8_t  slot;         /* import: session created (0xFF none) */
	uint16_t permille;
	uint32_t key_id, bad, first_bad, dups;
	uint8_t  replicate;    /* import: result of copying to the other copies (ez_status_t) */
	uint8_t  cmd;          /* job 3: the deferred command */
} ez_wjob_t;

/* Jobs (EZ-IMPL-001 §9.4, round 16): long commands answer at once and run
 * as a job; the host polls KEY_STATUS and fetches the reply with JOB_RESULT.
 * Job kinds: 1 generation, 2 import, 3 deferred command, 4 background sync. */
static inline int ez_cmd_deferred(uint8_t cmd)
{
	switch (cmd) {
	case EZ_CMD_SESSION_CREATE: case EZ_CMD_SESSION_DELETE:
	case EZ_CMD_SESSION_CHECK:  case EZ_CMD_SESSION_REPAIR: case EZ_CMD_SESSION_CRITICAL:
	case EZ_CMD_KEY_COPY:       case EZ_CMD_KEY_DELETE:
	case EZ_CMD_DRIVE_ENABLE:   case EZ_CMD_DRIVE_DISABLE:
	case EZ_CMD_DRIVE_FORMAT:   case EZ_CMD_DRIVE_REPAIR:
	case EZ_CMD_DEVICE_ERASE:   case EZ_CMD_ENTROPY_TEST:
		return 1;
	default:
		return 0;
	}
}

void ez_wjob_write(ez_wr_t *w, const ez_wjob_t *j);
void ez_wjob_read(ez_rd_t *r, ez_wjob_t *j);

#endif /* EZ_PROTO_H */
