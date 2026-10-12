/*
 * sim_sdcard.h -- an SD card in SPI mode, emulated byte by byte, for
 * running the firmware's own SD driver, block layer and card module on the
 * host (tests/hwsim). Misbehaviour modelled on what V1 showed (TR-07):
 *   write_busy_us       busy after each block write
 *   erase_bg_us         after an ERASE the card keeps working in the
 *                       background: writes stay busy until this has passed
 *   wedge_on_busy_reset CMD0 while busy leaves the card unresponsive until
 *                       power is cut (sim_sd_power_cycle)
 * plus removal, address errors, CSD write protection, and a power cut
 * after a number of block writes.
 */
#ifndef SIM_SDCARD_H
#define SIM_SDCARD_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
	uint32_t blocks;
	uint64_t write_busy_us, erase_busy_us_per_mib, erase_bg_us;
	bool     wedge_on_busy_reset;
	long     cut_after_writes;          /* <0: never */
	/* Every stall_every writes, stall_us of internal work that progresses
	 * only while the card is released (CS high): TR-07's Transcend. */
	unsigned long stall_every;
	uint64_t stall_us;
} sim_sd_cfg_t;

void sim_sd_init(const sim_sd_cfg_t *cfg);   /* a new card, inserted and powered */
void sim_sd_free(void);
void sim_sd_remove(void);
void sim_sd_insert(void);                    /* insertion is a power-up */
void sim_sd_power_cycle(void);
bool sim_sd_wedged(void);
bool sim_sd_tmp_wp(void);
unsigned long sim_sd_writes(void);
/* Raw access for test setup and checks (no protocol). */
void sim_sd_raw_read(uint32_t lba, uint8_t out[512]);
void sim_sd_raw_write(uint32_t lba, const uint8_t in[512]);
uint64_t sim_now_us(void);
void sim_sd_set_write_busy_us(uint64_t us);
void sim_sd_make_busy(uint64_t us);
void sim_sd_slow_next_writes(long n, uint64_t us);
#endif
