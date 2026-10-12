/*
 * hal_fram.c -- ez_hal_meta_t over SPI0 for the MB85RS16 (2 KB F-RAM).
 * Minimal production driver; register sequence as in fw/test/src/ez_fram.c.
 *
 * The contract of ez_hal_meta.h holds natively: F-RAM writes each byte as it
 * is clocked in (byte-atomic, ascending order) with no write buffer.
 * EZ-SEC-001 traceability: SEC-META-002 (atomicity rests on this part).
 */
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/gpio.h"

#include "board.h"
#include "hal_rp2350.h"

#define OP_WREN  0x06
#define OP_WRDI  0x04
#define OP_RDSR  0x05
#define OP_READ  0x03
#define OP_WRITE 0x02
#define FRAM_SIZE 2048u

static inline void cs(bool low)
{
	asm volatile("nop \n nop \n nop");
	gpio_put(FRAM_SS_PIN, low ? 0 : 1);
	asm volatile("nop \n nop \n nop");
}

static void cmd(uint8_t op) { cs(true); spi_write_blocking(FRAM_SPI, &op, 1); cs(false); }

static uint8_t rdsr(void)
{
	uint8_t tx[2] = { OP_RDSR, 0xff }, rx[2] = { 0 };
	cs(true); spi_write_read_blocking(FRAM_SPI, tx, rx, 2); cs(false);
	return rx[1];
}

void hal_fram_init(void)
{
	spi_init(FRAM_SPI, FRAM_BAUD_DEFAULT);
	spi_set_format(FRAM_SPI, 8, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);
	gpio_set_function(FRAM_SCLK_PIN, GPIO_FUNC_SPI);
	gpio_set_function(FRAM_MOSI_PIN, GPIO_FUNC_SPI);
	gpio_set_function(FRAM_MISO_PIN, GPIO_FUNC_SPI);
	gpio_init(FRAM_SS_PIN);
	gpio_set_dir(FRAM_SS_PIN, GPIO_OUT);
	gpio_put(FRAM_SS_PIN, 1);
}

bool hal_fram_probe(uint8_t *sr_idle, uint8_t *sr_wren)
{
	*sr_idle = rdsr();
	cmd(OP_WREN);
	*sr_wren = rdsr();
	cmd(OP_WRDI);
	uint8_t after = rdsr();
	return (*sr_wren & 0x02) && !(after & 0x02);
}

static ez_status_t f_read(void *ctx, uint32_t addr, void *buf, uint32_t len)
{
	(void)ctx;
	if (addr > FRAM_SIZE || len > FRAM_SIZE - addr) return EZ_ERR_META;
	uint8_t hdr[3] = { OP_READ, (uint8_t)(addr >> 8), (uint8_t)addr };
	cs(true);
	spi_write_blocking(FRAM_SPI, hdr, 3);
	spi_read_blocking(FRAM_SPI, 0xff, buf, len);
	cs(false);
	return EZ_OK;
}

static ez_status_t f_write(void *ctx, uint32_t addr, const void *buf, uint32_t len)
{
	(void)ctx;
	if (addr > FRAM_SIZE || len > FRAM_SIZE - addr) return EZ_ERR_META;
	uint8_t hdr[3] = { OP_WRITE, (uint8_t)(addr >> 8), (uint8_t)addr };
	cmd(OP_WREN);
	cs(true);
	spi_write_blocking(FRAM_SPI, hdr, 3);
	spi_write_blocking(FRAM_SPI, buf, len);
	cs(false);
	return EZ_OK;
}

const ez_hal_meta_t hal_fram = { NULL, FRAM_SIZE, f_read, f_write };
