/*
 * pico_shim.h -- the few pico-sdk functions the firmware's SD code uses,
 * for running it on the host against sim_sdcard (tests/hwsim). Time is
 * virtual: it advances with every SPI byte and every sleep, so the
 * driver's timeouts behave deterministically.
 */
#ifndef PICO_SHIM_H
#define PICO_SHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct spi_inst { int id; } spi_inst_t;
extern spi_inst_t sim_spi0, sim_spi1;
#define spi0 (&sim_spi0)
#define spi1 (&sim_spi1)
typedef uint64_t absolute_time_t;

#define GPIO_IN 0
#define GPIO_OUT 1
#define GPIO_FUNC_SPI 1
#define GPIO_FUNC_SIO 5
#define SPI_CPOL_0 0
#define SPI_CPHA_0 0
#define SPI_MSB_FIRST 1
#define PICO_ERROR_TIMEOUT (-1)
#define PICO_ERROR_NO_DATA (-3)

uint32_t spi_init(spi_inst_t *s, uint32_t baud);
uint32_t spi_set_baudrate(spi_inst_t *s, uint32_t baud);
void spi_set_format(spi_inst_t *s, unsigned bits, unsigned cpol, unsigned cpha, unsigned order);
int spi_write_blocking(spi_inst_t *s, const uint8_t *src, size_t len);
int spi_read_blocking(spi_inst_t *s, uint8_t tx, uint8_t *dst, size_t len);
int spi_write_read_blocking(spi_inst_t *s, const uint8_t *src, uint8_t *dst, size_t len);

void gpio_init(unsigned pin);
void gpio_set_dir(unsigned pin, bool out);
void gpio_put(unsigned pin, bool v);
bool gpio_get(unsigned pin);
void gpio_pull_up(unsigned pin);
void gpio_pull_down(unsigned pin);
void gpio_set_function(unsigned pin, unsigned fn);

uint64_t time_us_64(void);
void sleep_ms(uint32_t ms);
void sleep_us(uint64_t us);
void busy_wait_us(uint64_t us);
absolute_time_t get_absolute_time(void);
absolute_time_t make_timeout_time_ms(uint32_t ms);
absolute_time_t make_timeout_time_us(uint64_t us);
int64_t absolute_time_diff_us(absolute_time_t from, absolute_time_t to);
static inline void tight_loop_contents(void) {}
#endif
