/* ez_msg.c -- see ez_msg.h. SEC-ENC-004, SEC-TX-002. */
#include "ez_msg.h"

#include <string.h>

#include "ez_bytes.h"
#include "ez_meta.h"

void ez_msg_hdr_encode(const ez_msg_hdr_t *h, uint8_t out[EZ_MSG_HDR])
{
	ez_put_le16(out, EZ_MAGIC);
	out[2] = EZ_MSG_VERSION;
	out[3] = 0;
	ez_put_le32(out + 4, h->key_id);
	ez_put_le32(out + 8, h->offset);
	ez_put_le32(out + 12, h->length);
}

ez_status_t ez_msg_hdr_decode(const uint8_t in[EZ_MSG_HDR], ez_msg_hdr_t *h)
{
	memset(h, 0, sizeof *h);
	if (ez_get_le16(in) != EZ_MAGIC || in[2] != EZ_MSG_VERSION || in[3] != 0)
		return EZ_ERR_BAD_REQUEST;
	h->key_id = ez_get_le32(in + 4);
	h->offset = ez_get_le32(in + 8);
	h->length = ez_get_le32(in + 12);
	if (h->key_id == 0 || (uint64_t)h->offset + h->length > 0xFFFFFFFFull)
		return EZ_ERR_BAD_REQUEST;
	return EZ_OK;
}
