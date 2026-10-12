/*
 * test_primitives.c -- CRC, byte order and secure clearing.
 *
 * EZ-SEC-001: SEC-FW-002 (clears not elided), SEC-META-001 (integrity
 * primitives behave to their published check values).
 */
#include <string.h>

#include "ez_bytes.h"
#include "ez_crc.h"
#include "ez_secure.h"
#include "ez_test.h"

static void t_crc32_check_value(void)
{
	EZ_CHECK_EQ(ez_crc32("123456789", 9), 0xCBF43926u);
	EZ_CHECK_EQ(ez_crc32("", 0), 0u);
	/* incremental equals one-shot */
	uint32_t c = ez_crc32_update(EZ_CRC32_INIT, "1234", 4);
	c = ez_crc32_update(c, "56789", 5);
	EZ_CHECK_EQ(ez_crc32_final(c), 0xCBF43926u);
}

static void t_crc16_check_value(void)
{
	EZ_CHECK_EQ(ez_crc16("123456789", 9), 0x29B1);
}

static void t_le_roundtrip(void)
{
	uint8_t b[4];
	ez_put_le32(b, 0xA1B2C3D4u);
	EZ_CHECK(b[0] == 0xD4 && b[1] == 0xC3 && b[2] == 0xB2 && b[3] == 0xA1);
	EZ_CHECK_EQ(ez_get_le32(b), 0xA1B2C3D4u);
	ez_put_le16(b, 0xBEEF);
	EZ_CHECK(b[0] == 0xEF && b[1] == 0xBE);
	EZ_CHECK_EQ(ez_get_le16(b), 0xBEEF);
}

/* SEC-FW-002: the clear is performed through volatile stores; the test
 * checks behaviour, and ez_secure.c is the inspection evidence. */
static void t_secure_zero(void)
{
	uint8_t buf[257];
	memset(buf, 0xA5, sizeof buf);
	ez_secure_zero(buf, sizeof buf);
	EZ_CHECK(ez_is_zero(buf, sizeof buf));
	buf[100] = 1;
	EZ_CHECK(!ez_is_zero(buf, sizeof buf));
	ez_secure_zero(buf, 0);   /* zero length is a no-op */
	EZ_CHECK_EQ(buf[100], 1);
}

static const ez_test_case_t cases[] = {
	{ "crc32_check_value", "SEC-META-001", t_crc32_check_value },
	{ "crc16_check_value", "SEC-META-001, SEC-PTR-001", t_crc16_check_value },
	{ "le_roundtrip", "IMPL-ARCH-002", t_le_roundtrip },
	{ "secure_zero", "SEC-FW-002, SEC-FW-003", t_secure_zero },
};
EZ_TEST_MAIN(cases)
