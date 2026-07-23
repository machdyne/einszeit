/*
 * Einszeit Firmware
 *
 * Copyright (c) 2023 CNLohr
 * Copyright (c) 2025 Lone Dynamics Corporation. All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "rv003usb.h"
#include "ch32fun.h"

#define EZ_KEY_LEN (1024 * 1024 * 4)

#define CH32V003_SPI_IMPLEMENTATION
#define CH32V003_SPI_NSS_SOFTWARE_ANY_MANUAL
#define CH32V003_SPI_SPEED_HZ 1000000
#define CH32V003_SPI_DIRECTION_2LINE_TXRX
#define CH32V003_SPI_CLK_MODE_POL0_PHA0

#define I2C_DELAY_US 1  // 5us delay = ~100kHz I2C
//#define I2C_DELAY_US 5  // 5us delay = ~100kHz I2C

#define ATSHA_ZONE_DATA       0x02  // Data zone (vs Config=0x00 or OTP=0x01)
#define ATSHA_SLOT_SIZE       32    // Size in bytes of each data slot
#define ATSHA_SLOT_COUNT      4     // Number of data slots available
                                    // (ideally this would be 16)

#include "ch32fun/extralibs/ch32v003_SPI.h"

#define ATSHA204A_I2C_ADDR  0x64

#define I2C_SDA	1
#define I2C_SCL	2
#define SPI_SS		4
#define LED			2

#define EZ_CMD_PING 0x00
#define EZ_CMD_STATUS 0x01
#define EZ_CMD_IDENTIFY 0x10
#define EZ_CMD_KEY_GEN 0x11
#define EZ_CMD_COPY 0x20
#define EZ_CMD_ERASE 0x50

#define EZ_CMD_META_LOAD 0x60

#define EZ_CMD_RAND 0x80

#define EZ_CMD_ENCRYPT 0xa0
#define EZ_CMD_DECRYPT 0xb0
#define EZ_CMD_DECRYPT_SELF 0xb1
#define EZ_CMD_INC 0xc0

#define EZ_CMD_DUMP_CONFIG 0xd0
#define EZ_CMD_LOCK 0xf0

void i2c_scan(void);
void i2c_init(uint32_t pclk_mhz, uint32_t speed_hz);
int i2c_write(uint8_t addr, const uint8_t *data, uint8_t len);
int i2c_read(uint8_t addr, uint8_t *data, uint8_t len);
static uint16_t atsha_crc(const uint8_t *data, uint8_t len);
void atsha204a_wake(void);
int atsha204a_get_random(uint8_t *out32);

int atsha204a_dump_config(void);
int atsha204a_factory_lock(void);
int atsha204a_lock(uint8_t zone);

int atsha204a_load_eeprom(uint8_t *out, uint8_t slot_id);
int atsha204a_save_eeprom(const uint8_t *data, uint8_t slot_id);

void flash_read(uint8_t *buf, uint32_t addr, uint32_t size);
void flash_write(const uint8_t *buf, uint32_t addr, uint32_t size);
void flash_erase(void);
int32_t flash_read_id(void);

void ez_generate_keys(void);
int ez_identity(void);
int ez_identify(uint8_t id);
uint32_t ez_send_ptr(void);

int ez_update_meta(uint32_t send_ptr_inc, bool boot_ctr_inc);
int ez_find_current_metadata(uint8_t *out_meta);

#pragma pack(1)
typedef struct ez_meta {

   uint16_t magic;
   uint32_t seq;
   uint32_t send_ptr;
   uint32_t boot_ctr;
   uint8_t id;
   uint8_t reserved[16];
   uint8_t crc;

} ez_meta_t;

// Allow reading and writing to the scratchpad via HID control messages.
uint8_t scratch[255];

volatile uint8_t start = 0;

uint8_t do_key_gen = 0;
uint32_t key_gen;
uint32_t key_len = EZ_KEY_LEN;

int main()
{
	SystemInit();

	Delay_Ms(1); // Ensures USB re-enumeration after bootloader or reset; Spec demand >2.5µs ( TDDIS )
	usb_setup();

	GPIOD->CFGLR &= ~(0xf<<(4*LED));
	GPIOD->CFGLR |= (GPIO_Speed_10MHz | GPIO_CNF_OUT_PP)<<(4*LED);

	i2c_init(48, 100000);
	Delay_Ms(1);

	SPI_init();
	SPI_begin_8();
	Delay_Ms(1);

   uint32_t flash_id = flash_read_id();
   printf("Flash ID: 0x%06X\r\n", flash_id);

	GPIOC->CFGLR &= ~(0xf<<(4*SPI_SS));
	GPIOC->CFGLR |= (GPIO_Speed_50MHz | GPIO_CNF_OUT_PP)<<(4*SPI_SS);
	GPIOC->BSHR = (1<<(16+SPI_SS));

	// main loop

	while(1)
	{
#if RV003USB_EVENT_DEBUGGING	// doesn't work without this?
      uint32_t * ue = GetUEvent();
      if( ue )
      {
         printf( "%lu %lx %lx %lx\n", ue[0], ue[1], ue[2], ue[3] );
      }
#endif

		if (start && scratch[0] == 0xaa && scratch[1] == 0x00) {

			// scratch formats:
			// 0xaa 0x00 <cmd> <arg> <arg> <arg>
			// response:
			// 0xaa 0x01 <response data>

			// LED on
			GPIOD->BSHR = (1<<LED);

			if (scratch[2] == EZ_CMD_PING) {

				scratch[2] = 0x99;
				scratch[3] = 0x89;
				scratch[4] = 0x79;
				scratch[5] = 0x69;

			}

			if (scratch[2] == EZ_CMD_STATUS) {

				scratch[2] = 0x01;
				scratch[3] = (key_gen >> 24) & 0xff;
				scratch[4] = (key_gen >> 16) & 0xff;
				scratch[5] = (key_gen >> 8) & 0xff;
				scratch[6] = key_gen & 0xff;

			}

			if (scratch[2] == EZ_CMD_COPY) {

				uint32_t key_offset = scratch[3] |
					scratch[4] << 8 |
					scratch[5] << 16 |
					scratch[6] << 24;

				uint8_t chunk_size = scratch[7];

				if (chunk_size > 128) {
					printf("bad chunk size\r\n");
					scratch[2] = 0;
					return;
				}

				printf(" writing %d bytes at offset %lu\r\n",
					chunk_size, key_offset);

				uint8_t kbuf[128];
				memcpy(kbuf, &scratch[8], chunk_size);
				flash_write(kbuf, key_offset, chunk_size);
				scratch[2] = 0x01;

			}

			if (scratch[2] == EZ_CMD_IDENTIFY) {

				uint8_t identity = scratch[3];
				int r = ez_identify(identity);

				if (r == 0 && identity == 0) {
					key_gen = 0;
					do_key_gen = 1;
				}

				scratch[2] = (r == 0);

			}

			if (scratch[2] == EZ_CMD_META_LOAD) {

				uint8_t metadata[32];

				int r = ez_find_current_metadata(metadata);

				scratch[2] = (r >= 0);
				memcpy(&scratch[3], metadata, 32);

			}

			if (scratch[2] == EZ_CMD_RAND) {

			//	printf("CMD: RAND\r\n");

				uint8_t random_bytes[32];


			//	printf("get_random\r\n");
				int r = atsha204a_get_random(random_bytes);

				scratch[2] = (r == 0);

				if (r == 0) {
//					printf("Random bytes:\r\n");
					for(int i=0;i<32;i++) {
//						printf("%02X ", random_bytes[i]);
						scratch[3+i] = random_bytes[i];
					}
//					printf("\r\n");
				} else {
					printf("ATSHA204A error: %d\r\n", r);
					// error could be due to sleeping
					printf("wake\r\n");
					atsha204a_wake();
				}

			}

			if (scratch[2] == EZ_CMD_ERASE) {

				if (ez_erase() == 0)
					scratch[2] = 1;
				else
					scratch[2] = 0;

			}

			if (scratch[2] == EZ_CMD_ENCRYPT) {

				int id = ez_identity();
				uint32_t send_ptr = ez_send_ptr();
				uint32_t flash_addr = send_ptr;
				uint8_t len = scratch[3];

				if (id < 0 || send_ptr == 0xffffffff) {
					scratch[2] = 0;
					return;
				}

				if (id == 1) flash_addr |= 0x200000;

				uint32_t offset = scratch[4] |
					scratch[5] << 8 |
					scratch[6] << 16 |
					scratch[7] << 24;

				flash_addr += offset;

				printf("encrypting\r\n");
				printf(" id: %02X\r\n", id);
				printf(" send_ptr: %08X\r\n", send_ptr);
				printf(" offset: %08X\r\n", offset);
				printf(" flash_addr: %08X\r\n", flash_addr);
				printf(" len: %02X\r\n", len);

				uint8_t kbuf[256];
				flash_read(kbuf, flash_addr, len);

				printf(" kbuf: ");
				for(int i = 0; i < len; i++) {
					printf("%02X ", kbuf[i]);
				}
				printf("\r\n");

				// return the base send_ptr
				scratch[4] = (send_ptr >> 24) & 0xff;
				scratch[5] = (send_ptr >> 16) & 0xff;
				scratch[6] = (send_ptr >> 8) & 0xff;
				scratch[7] = send_ptr & 0xff;

				// encrypt chunk
				for (int i = 0 ; i < len; i++) {
					scratch[8+i] = scratch[8+i] ^ kbuf[i];
				}

				scratch[2] = 1;

			}

			if (scratch[2] == EZ_CMD_DECRYPT || scratch[2] == EZ_CMD_DECRYPT_SELF)
			{

				int id = ez_identity();
				uint32_t flash_addr;
				uint8_t len = scratch[3];

				if (id != 0 && id != 1) {
					scratch[2] = 0;
					return;
				}

				if (scratch[2] == EZ_CMD_DECRYPT_SELF) {
					// use our own key
					if (id == 0) flash_addr = 0x000000;
					else flash_addr = 0x200000;
				} else {
					// use identity-opposite key
					if (id == 0) flash_addr = 0x200000;
					else flash_addr = 0x000000;
				}

				uint32_t offset = scratch[4] |
					scratch[5] << 8 |
					scratch[6] << 16 |
					scratch[7] << 24;

				flash_addr += offset;

				printf("decrypting\r\n");
				printf(" id: %02X\r\n", id);
				printf(" offset: %08X\r\n", offset);
				printf(" flash_addr: %08X\r\n", flash_addr);
				printf(" len: %02X\r\n", len);

				uint8_t kbuf[256];
				flash_read(kbuf, flash_addr, len);

				printf(" kbuf: ");
				for(int i = 0; i < len; i++) {
					printf("%02X ", kbuf[i]);
				}
				printf("\r\n");

				// decrypt chunk
				for (int i = 0 ; i < len; i++) {
					scratch[8+i] = scratch[8+i] ^ kbuf[i];
				}

				scratch[2] = 1;

			}

			if (scratch[2] == EZ_CMD_INC) {

				uint32_t send_ptr_inc = scratch[3] |
					scratch[4] << 8 |
					scratch[5] << 16 |
					scratch[6] << 24;

				printf("incrementing send_ptr by %lu", send_ptr_inc);

				ez_update_meta(send_ptr_inc, false);

				scratch[2] = 1;

			}

			if (scratch[2] == EZ_CMD_LOCK) {

				printf("scan\r\n");
				i2c_scan();

				printf("begin factory lock\r\n");
				int r = atsha204a_factory_lock();

				scratch[2] = (r == 0);

			}

			if (scratch[2] == EZ_CMD_DUMP_CONFIG) {
				printf("CMD: DUMP_CONFIG\r\n");
    
				int result = atsha204a_dump_config();
    
				if (result == 0) {
					scratch[2] = 1;  // Success
				} else {
					scratch[2] = 0;  // Failure
					scratch[3] = result;  // Error code
					printf("Failed to dump config (error %d)\r\n", result);
				}
			}

			// LED off
			GPIOD->BSHR = (1<<(16+LED));


			scratch[1] = 0x01;	// this means response

			start = 0;
		}

		if (do_key_gen) {
			ez_generate_keys();
		}

	}
}


// Microsecond delay
void delay_us(uint32_t us) {
    volatile uint32_t count = us * 12;
    while(count--);
}

void i2c_init(uint32_t pclk_mhz, uint32_t speed_hz)
{
    printf("Initializing correct open-drain I2C...\r\n");
    
    RCC->APB2PCENR |= RCC_APB2Periph_GPIOC;

    // CRITICAL: Set output data to 1 BEFORE configuring as open-drain
    GPIOC->BSHR = (1 << I2C_SDA) | (1 << I2C_SCL);
    
    // Configure as open-drain outputs
    GPIOC->CFGLR &= ~(0xF << (4*I2C_SDA));
    GPIOC->CFGLR |= (GPIO_Speed_50MHz | GPIO_CNF_OUT_OD) << (4*I2C_SDA);
    GPIOC->CFGLR &= ~(0xF << (4*I2C_SCL));
    GPIOC->CFGLR |= (GPIO_Speed_50MHz | GPIO_CNF_OUT_OD) << (4*I2C_SCL);
    
    delay_us(100);
    printf("Open-drain I2C initialized\r\n");
}

// Release line (set ODR bit = 1, pin goes Hi-Z, pulled high by resistor)
static void sda_release(void) {
    GPIOC->BSHR = (1 << I2C_SDA);
}

static void scl_release(void) {
    GPIOC->BSHR = (1 << I2C_SCL);
}

// Pull line low (set ODR bit = 0, pin actively sinks current)
static void sda_low(void) {
    GPIOC->BSHR = (1 << (16+I2C_SDA));
}

static void scl_low(void) {
    GPIOC->BSHR = (1 << (16+I2C_SCL));
}

// Read line state
static bool sda_read(void) {
    return (GPIOC->INDR >> I2C_SDA) & 1;
}

static bool scl_read(void) {
    return (GPIOC->INDR >> I2C_SCL) & 1;
}

// Wait for SCL to go high (clock stretching support)
static void scl_wait_high(void) {
    uint32_t timeout = 10000;
    while(!scl_read() && timeout--) {
        delay_us(1);
    }
}

static void i2c_start(void)
{
    // Ensure both lines are released (idle state)
    sda_release();
    scl_release();
    delay_us(I2C_DELAY_US);
    
    // START: SDA goes low while SCL is high
    sda_low();
    delay_us(I2C_DELAY_US);
    scl_low();
    delay_us(I2C_DELAY_US);
}

static void i2c_stop(void)
{
    // Ensure SCL is low
    scl_low();
    delay_us(I2C_DELAY_US);
    
    // SDA low (if not already)
    sda_low();
    delay_us(I2C_DELAY_US);
    
    // STOP: SCL high then SDA high
    scl_release();
    scl_wait_high();  // Wait for clock stretching
    delay_us(I2C_DELAY_US);
    sda_release();
    delay_us(I2C_DELAY_US);
}

static bool i2c_write_byte(uint8_t byte)
{
    // Send 8 bits, MSB first
    for(int i = 7; i >= 0; i--) {
        // Set data bit while SCL is low
        if(byte & (1 << i)) {
            sda_release();  // Logic 1: release SDA
        } else {
            sda_low();      // Logic 0: pull SDA low
        }
        delay_us(I2C_DELAY_US);
        
        // Clock pulse
        scl_release();
        scl_wait_high();  // Wait for clock stretching
        delay_us(I2C_DELAY_US);
        scl_low();
        delay_us(I2C_DELAY_US);
    }
    
    // Read ACK bit
    sda_release();  // Release SDA for slave to control
    delay_us(I2C_DELAY_US);
    
    scl_release();
    scl_wait_high();  // Wait for clock stretching
    delay_us(I2C_DELAY_US);
    
    // Read ACK (0 = ACK, 1 = NACK)
    bool ack = !sda_read();
    
    scl_low();
    delay_us(I2C_DELAY_US);
    
    return ack;
}

static uint8_t i2c_read_byte(bool send_ack)
{
    uint8_t byte = 0;
    
    // Release SDA to let slave drive it
    sda_release();
    
    // Read 8 bits, MSB first
    for(int i = 7; i >= 0; i--) {
        delay_us(I2C_DELAY_US);
        
        // Clock high
        scl_release();
        scl_wait_high();  // Wait for clock stretching
        delay_us(I2C_DELAY_US);
        
        // Sample data bit
        if(sda_read()) {
            byte |= (1 << i);
        }
        
        // Clock low
        scl_low();
        delay_us(I2C_DELAY_US);
    }
    
    // Send ACK/NACK
    if(send_ack) {
        sda_low();      // ACK: pull SDA low
    } else {
        sda_release();  // NACK: release SDA
    }
    delay_us(I2C_DELAY_US);
    
    // Clock pulse for ACK/NACK
    scl_release();
    scl_wait_high();
    delay_us(I2C_DELAY_US);
    scl_low();
    delay_us(I2C_DELAY_US);
    
    return byte;
}

int i2c_write(uint8_t addr, const uint8_t *data, uint8_t len)
{
    i2c_start();
    
    // Send address with write bit (0)
    if(!i2c_write_byte(addr << 1)) {
        i2c_stop();
        return -1; // Address NACK
    }
    
    // Send data bytes
    for(uint8_t i = 0; i < len; i++) {
        if(!i2c_write_byte(data[i])) {
            i2c_stop();
            return -2; // Data NACK
        }
    }
    
    i2c_stop();
    return 0;
}

int i2c_read(uint8_t addr, uint8_t *data, uint8_t len)
{
    if(len == 0) return 0;
    
    i2c_start();
    
    // Send address with read bit (1)
    if(!i2c_write_byte((addr << 1) | 1)) {
        i2c_stop();
        return -1; // Address NACK
    }
    
    // Read data bytes
    for(uint8_t i = 0; i < len; i++) {
        bool send_ack = (i < len - 1); // ACK all bytes except last
        data[i] = i2c_read_byte(send_ack);
    }
    
    i2c_stop();
    return 0;
}

void i2c_scan(void)
{
    printf("Scanning I2C bus (bit-bang)...\r\n");
    int found_count = 0;
    
    for(uint8_t addr = 0x08; addr < 0x78; addr++) {
        i2c_start();
        
        if(i2c_write_byte(addr << 1)) {
            printf("Device found at address 0x%02X\r\n", addr);
            found_count++;
        }
        
        i2c_stop();
        delay_us(100); // Small delay between attempts
    }
    
    printf("I2C scan complete: %d devices found\r\n", found_count);
}


// --

static uint16_t atsha_crc(const uint8_t *data, uint8_t len)
{
    uint16_t crc = 0;
    
    for(uint8_t i = 0; i < len; i++) {
        for(uint8_t shift = 0x01; shift > 0x00; shift <<= 1) {
            uint8_t data_bit = (data[i] & shift) ? 1 : 0;
            uint8_t crc_bit = crc >> 15;
            crc <<= 1;
            if((data_bit ^ crc_bit) != 0) {
                crc ^= 0x8005;
            }
        }
    }
    
	return crc;
}

void atsha204a_wake(void)
{
    printf("waking\r\n");
    
    // Standard wake sequence
    sda_release();
    scl_release();
    Delay_Ms(5);
    
    scl_release();
    sda_low();
    delay_us(100);
    sda_release();
    Delay_Ms(10);
   
    uint8_t wordaddr = 0x00;
    if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
        printf("Wake: failed to set read pointer (write 0x00)\r\n");
        return;
    }
 
    // CRITICAL: Read and consume the wake token
    uint8_t wake_token[4];
    if(i2c_read(ATSHA204A_I2C_ADDR, wake_token, 4) == 0) {
        printf("Wake token: %02X %02X %02X %02X\r\n", 
               wake_token[0], wake_token[1], wake_token[2], wake_token[3]);
        
        // Verify it's the expected wake token
//        if(wake_token[0] == 0x04 && wake_token[1] == 0x11) {
//            printf("Valid wake token received\r\n");
//        } else {
//            printf("Unexpected wake token\r\n");
//        }
    } else {
        printf("Failed to read wake token\r\n");
    }
    
//    printf("Wake sequence complete\r\n");
}

// Now try reading config after properly handling wake token
void read_config_properly(void)
{
    printf("Reading config after proper wake token handling...\r\n");
    
    atsha204a_wake();
    
    // Reset address counter
    uint8_t reset_addr = 0x00;
    if(i2c_write(ATSHA204A_I2C_ADDR, &reset_addr, 1) == 0) {
        // Now read actual config data
        uint8_t config_data[4];
        if(i2c_read(ATSHA204A_I2C_ADDR, config_data, 4) == 0) {
            printf("Config word 0: %02X %02X %02X %02X\r\n", 
                   config_data[0], config_data[1], config_data[2], config_data[3]);
            
            // Check for expected serial number prefix
            if(config_data[0] == 0x01 && config_data[1] == 0x23) {
                printf("Found expected serial number prefix!\r\n");
            }
        }
    }
}

int atsha204a_get_random(uint8_t *out32)
{
  //  printf("Getting random data...\r\n");
    
    // Build RANDOM command
    uint8_t cmd[7];
    cmd[0] = 0x07;   // count
    cmd[1] = 0x1B;   // RANDOM opcode
    cmd[2] = 0x00;   // param1 (0x00 = automatic seed update)
    cmd[3] = 0x00;   // param2 LSB
    cmd[4] = 0x00;   // param2 MSB
    uint16_t crc = atsha_crc(cmd, 5);
    cmd[5] = crc & 0xFF;
    cmd[6] = crc >> 8;

    // Send with command word address
    uint8_t txbuf[8];
    txbuf[0] = 0x03;
    memcpy(&txbuf[1], cmd, 7);
    
    if(i2c_write(ATSHA204A_I2C_ADDR, txbuf, 8) != 0) {
        printf("Command write failed\r\n");
        return -1;
    }

    Delay_Ms(50);

    // Try reading response directly without setting address first
    uint8_t rxbuf[35];

        // Device may have gone to sleep - try waking and reading
     //   printf("Device may be asleep, trying wake...\r\n");
     //   atsha204a_wake();
        
        // Set read pointer
        uint8_t wordaddr = 0x00;
        if(i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
            printf("Address write failed after wake\r\n");
            return -2;
        }
        
        int read_result = i2c_read(ATSHA204A_I2C_ADDR, rxbuf, 35);
        if(read_result != 0) {
            printf("Read failed after wake: %d\r\n", read_result);
            return -3;
       }

    // Check response length
    if(rxbuf[0] != 0x23) {
        if(rxbuf[0] == 0x04) {
            printf("Error response: 0x%02X\r\n", rxbuf[1]);
            return -10;
        }
        printf("Unexpected length: 0x%02X\r\n", rxbuf[0]);
        return -4;
    }

    // Verify CRC
    uint16_t resp_crc = rxbuf[33] | (rxbuf[34] << 8);
    uint16_t calc_crc = atsha_crc(rxbuf, 33);
//    printf("Response CRC: 0x%04X, Calculated: 0x%04X\r\n", resp_crc, calc_crc);
    
    if(resp_crc != calc_crc) {
        printf("CRC mismatch!\r\n");
        return -5;
    }

    // Copy random bytes
    memcpy(out32, &rxbuf[1], 32);

 //   printf("Successfully got 32 random bytes!\r\n");
    return 0;
}

/**
 * Configure all slots with a different approach
 * Using a carefully timed approach that works with the ATSHA204A
 *
 * @return  0 on success, negative error code on failure
 */
int atsha204a_configure_all_slots(void)
{
    printf("Config slots\r\n");
    
    int failures = 0;
    
    // Try writing to one word at a time, with more timing delay
    for (uint8_t addr = 0x05; addr <= 0x0c; addr++) {
        printf("Addr %02X\r\n", addr);
        
        // Wake up the device before each write
        // This is critical - complete new wake sequence for each write
        atsha204a_wake();
        
        // Build WRITE command with correct CRC calculation
        uint8_t write_cmd[11];
        write_cmd[0] = 11;          // Length (11 bytes)
        write_cmd[1] = 0x12;        // WRITE opcode
        write_cmd[2] = 0x00;        // Config zone
        write_cmd[3] = addr;        // Address
        write_cmd[4] = 0x00;        // MSB
        
        // Set slot config to 0x0000_0000
        write_cmd[5] = 0x00;        // LSB of first slot
        write_cmd[6] = 0x00;        // MSB of first slot
        write_cmd[7] = 0x00;        // LSB of second slot
        write_cmd[8] = 0x00;        // MSB of second slot
        
        // Calculate CRC over all bytes before CRC
        uint16_t crc = atsha_crc(write_cmd, 9);
        write_cmd[9] = crc & 0xFF;
        write_cmd[10] = crc >> 8;
        
        printf("CMD: ");
        for(int i = 0; i < 11; i++) {
            printf("%02X ", write_cmd[i]);
        }
        printf("\r\n");
        
        // Send command with command word address
        uint8_t txbuf[12];
        txbuf[0] = 0x03;  // Command word address
        memcpy(&txbuf[1], write_cmd, 11);
        
        if (i2c_write(ATSHA204A_I2C_ADDR, txbuf, 12) != 0) {
            printf("Write err\r\n");
            failures++;
            continue;
        }
        
        Delay_Ms(50);
        
        // Set read pointer
        uint8_t wordaddr = 0x00;
        if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
            printf("Ptr err\r\n");
            failures++;
            continue;
        }
        
        // Read response
        uint8_t resp[4];
        if (i2c_read(ATSHA204A_I2C_ADDR, resp, 4) != 0) {
            printf("Read err\r\n");
            failures++;
            continue;
        }
        
        // Print the response for debugging
        printf("RESP: ");
        for(int i = 0; i < 4; i++) {
            printf("%02X ", resp[i]);
        }
        printf("\r\n");
        
        if (resp[0] != 0x04 || resp[1] != 0x00) {
            printf("Err %02X\r\n", resp[1]);
            failures++;
            continue;
        }
        
        // Verify the write by reading back
        atsha204a_wake();
        
        // Build READ command
        uint8_t cmd[7];
        cmd[0] = 0x07;        // Length
        cmd[1] = 0x02;        // READ
        cmd[2] = 0x00;        // Config zone
        cmd[3] = addr;        // Word address
        cmd[4] = 0x00;        // MSB
        
        // Calculate CRC
        crc = atsha_crc(cmd, 5);
        cmd[5] = crc & 0xFF;
        cmd[6] = crc >> 8;
        
        // Send command
        txbuf[0] = 0x03;
        memcpy(&txbuf[1], cmd, 7);
        
        if (i2c_write(ATSHA204A_I2C_ADDR, txbuf, 8) != 0) {
            printf("Verify err\r\n");
            continue;
        }
        
        Delay_Ms(25);
        
        // Set read pointer
        if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
            printf("Verify ptr err\r\n");
            continue;
        }
        
        // Read response
        uint8_t vresp[7];
        if (i2c_read(ATSHA204A_I2C_ADDR, vresp, 7) != 0) {
            printf("Verify read err\r\n");
            continue;
        }
        
        // Print verification result
        printf("VERIFY: ");
        for(int i = 1; i < 5; i++) {
            printf("%02X ", vresp[i]);
        }
        printf("\r\n");
        
        printf("OK\r\n");
        
        // Add delay between operations
        Delay_Ms(10);
    }
    
    if (failures > 0) {
        printf("%d errors\r\n", failures);
        return -failures;
    }
    
    printf("All slots OK\r\n");
    return 0;
}

int atsha204a_lock(uint8_t zone)
{

    printf("Sending LOCK config command for zone %d ...\r\n", zone);

	atsha204a_wake();
    
    // Build command packet
    uint8_t cmd[7];
    cmd[0] = 0x07;      // Count
    cmd[1] = 0x17;      // Opcode = LOCK
    cmd[2] = zone;      // Param1 (0x00=Config, 0x01=Data/OTP, 0x80=Config without CRC check)
    cmd[3] = 0x00;      // Param2 LSB
    cmd[4] = 0x00;      // Param2 MSB
    
    // Calculate CRC on command bytes only
    uint16_t crc = atsha_crc(cmd, 5);
    cmd[5] = crc & 0xFF;
    cmd[6] = (crc >> 8) & 0xFF;

    printf("Command: ");
    for(int i = 0; i < 7; i++) {
        printf("%02X ", cmd[i]);
    }
    
    uint8_t txbuf[8];
    txbuf[0] = 0x03;  // Command word address
    memcpy(&txbuf[1], cmd, 7);
    
    printf("Full TX buffer: ");
    for(int i = 0; i < 8; i++) {
        printf("%02X ", txbuf[i]);
    }
    printf("\r\n");
    
    // Send command
    if(i2c_write(ATSHA204A_I2C_ADDR, txbuf, 8) != 0) {
        printf("LOCK: I2C write failed\r\n");
        return -1;
    }
    
    // Wait for execution
    printf("Waiting for LOCK execution...\r\n");
    Delay_Ms(50);
    
    // Set read pointer to 0x00
    uint8_t wordaddr = 0x00;
    if(i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
        printf("LOCK: failed to set read pointer\r\n");
        return -2;
    }
    
    // Read response
    uint8_t resp[4];
    if(i2c_read(ATSHA204A_I2C_ADDR, resp, 4) != 0) {
        printf("LOCK: failed to read response\r\n");
        return -3;
    }
    
    printf("LOCK response: %02X %02X %02X %02X\r\n",
           resp[0], resp[1], resp[2], resp[3]);
    
    // Check response
    if(resp[0] != 0x04) {
        printf("LOCK: invalid length byte %02X\r\n", resp[0]);
        return -4;
    }
    
    if(resp[1] != 0x00) {
        printf("LOCK: error code %02X\r\n", resp[1]);
        return -5;
    }
    
    // Verify CRC of response
    uint16_t resp_crc = resp[2] | (resp[3] << 8);
    uint16_t calc_crc = atsha_crc(resp, 2);
    printf("Response CRC: 0x%04X, Calculated: 0x%04X\r\n", resp_crc, calc_crc);
    
    if(resp_crc == calc_crc) {
        printf("LOCK: zone successfully locked!\r\n");
        return 0;
    } else {
        printf("LOCK: CRC mismatch\r\n");
        return -6;
    }
}

/**
 * Read 32 bytes from a data slot in the ATSHA204A
 *
 * @param out      Buffer to store the 32 bytes (must be pre-allocated)
 * @param slot_id  Slot number to read (0-15)
 * @return         0 on success, negative on error
 */
int atsha204a_load_eeprom(uint8_t *out, uint8_t slot_id)
{
    if (slot_id >= ATSHA_SLOT_COUNT) {
        return -1;  // Invalid slot
    }
    
    // Wake up the device
    atsha204a_wake();
    
    // Build READ command for 32-byte read
    uint8_t cmd[7];
    cmd[0] = 0x07;                 // Length (7 bytes)
    cmd[1] = 0x02;                 // READ opcode
    cmd[2] = 0x82;                 // Zone = Data (0x02) + 32-byte read (0x80)
    cmd[3] = (slot_id << 3);       // Address (slot number << 3)
    cmd[4] = 0x00;                 // Address MSB
    
    // Calculate CRC
    uint16_t crc = atsha_crc(cmd, 5);
    cmd[5] = crc & 0xFF;
    cmd[6] = crc >> 8;
    
    // Send command
    uint8_t txbuf[8];
    txbuf[0] = 0x03;  // Command word address
    memcpy(&txbuf[1], cmd, 7);
    
    if (i2c_write(ATSHA204A_I2C_ADDR, txbuf, 8) != 0) {
        return -2;  // Send failed
    }
    
    // Wait for execution
    Delay_Ms(5);
    
    // Set read pointer
    uint8_t wordaddr = 0x00;
    if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
        return -3;  // Pointer failed
    }
    
    // Read response (35 bytes: 1 count + 32 data + 2 CRC)
    uint8_t resp[35];
    if (i2c_read(ATSHA204A_I2C_ADDR, resp, 35) != 0) {
        return -4;  // Read failed
    }
    
    // Check for error response
    if (resp[0] == 0x04) {
        return -5;  // Device error
    }
    
    // Verify expected length
    if (resp[0] != 0x23) {  // 0x23 = 35 bytes
        return -6;  // Wrong length
    }
    
	for (int i = 0; i < 32; i++) {
		printf(" %2x ", resp[1+i]);
	}
	printf("\n");

    // Copy data (skip first byte which is count)
    memcpy(out, &resp[1], 32);
    
    return 0;
}

/**
 * Write 32 bytes to a data slot in the ATSHA204A
 *
 * @param data     32-byte data to write
 * @param slot_id  Slot number to write (0-15)
 * @return         0 on success, negative on error
 */
int atsha204a_save_eeprom(const uint8_t *data, uint8_t slot_id)
{
    if (slot_id >= ATSHA_SLOT_COUNT) {
        return -1;  // Invalid slot
    }
    
    // Wake up the device
    atsha204a_wake();
    
    // Build WRITE command
    uint8_t cmd[39];
    cmd[0] = 39;                  // Length (39 bytes)
    cmd[1] = 0x12;                // WRITE opcode
    cmd[2] = 0x82;                // Zone = Data (32 bytes)
    cmd[3] = (slot_id << 3);      // Address (slot number << 3)
    cmd[4] = 0x00;                // Address MSB
    
    // Copy the 32 bytes of data
    memcpy(&cmd[5], data, 32);
    
    // Calculate CRC
    uint16_t crc = atsha_crc(cmd, 37);
    cmd[37] = crc & 0xFF;
    cmd[38] = crc >> 8;
    
    // Send command
    uint8_t txbuf[40];
    txbuf[0] = 0x03;  // Command word address
    memcpy(&txbuf[1], cmd, 39);
    
    if (i2c_write(ATSHA204A_I2C_ADDR, txbuf, 40) != 0) {
        return -2;  // Send failed
    }
    
    // Wait for execution
    Delay_Ms(100);
    
    // Set read pointer
    uint8_t wordaddr = 0x00;
    if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
        return -3;  // Pointer failed
    }

    Delay_Ms(10);
    
    // Read response
    uint8_t resp[4];
    if (i2c_read(ATSHA204A_I2C_ADDR, resp, 4) != 0) {
        return -4;  // Read failed
    }
    
    // Check response
    if (resp[0] != 0x04 || resp[1] != 0x00) {
        return -5;  // Error response
    }
    
    return 0;
}

/**
 * Helper function: Calculate CRC8 checksum for metadata integrity verification
 *
 * @param data  Data buffer to calculate CRC over
 * @param len   Length of data in bytes
 * @return      8-bit CRC value
 */
uint8_t calculate_crc8(const uint8_t *data, uint8_t len)
{
    uint8_t crc = 0;
    for (uint8_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ 0x07; // CRC-8 polynomial 0x07
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/**
 * Helper: Find the most recent valid metadata slot
 * 
 * Scans all 16 metadata slots and returns the slot ID with the
 * highest valid sequence number.
 *
 * @param out_meta  If not NULL, fills with the current metadata
 * @return          Slot ID of current metadata, or -1 if none found
 */
int ez_find_current_metadata(uint8_t *out_meta)
{
    uint8_t metabuf[32];
    int current_slot = -1;
    uint32_t highest_seq = 0;
    bool found_valid = false;
    
    // Check all slots
    for (uint8_t slot = 0; slot < ATSHA_SLOT_COUNT; slot++) {
        if (atsha204a_load_eeprom(metabuf, slot) != 0) {
            printf("Skipping slot %d (read failed)\r\n", slot);
            continue;
        }

 #pragma pack(push, 1)
        ez_meta_t *meta = (ez_meta_t *)metabuf;
 #pragma pack(pop)
        
        // Check magic number (should be 0x455A)
        if (meta->magic != 0x455a) {
            printf("Slot %d: Invalid magic (not 0x455A)\r\n", slot);
            continue;
        }
        
        // Verify CRC (over first 31 bytes, CRC at index 31)
        uint8_t calc_crc = calculate_crc8(meta, 31);
        if (calc_crc != meta->crc) {
            printf("Slot %d: CRC mismatch (calc=%02X, stored=%02X)\r\n", 
                   slot, calc_crc, meta->crc);
            continue;
        }
        
        // Extract sequence number (4 bytes at index 2-5)
        printf("Slot %d: Valid metadata, sequence = %lu\r\n", slot, meta->seq);
        
        // Keep track of highest sequence number
        if (!found_valid || meta->seq > highest_seq) {
            found_valid = true;
            highest_seq = meta->seq;
            current_slot = slot;
            if (out_meta) {
                memcpy(out_meta, meta, 32);
            }
        }
    }
    
    if (current_slot >= 0) {
        printf("Current metadata in slot %d (seq=%lu)\r\n", current_slot, highest_seq);
    } else {
        printf("No valid metadata found\r\n");
    }
    
    return current_slot;
}

/**
 * Update metadata and write to the next available slot
 *
 * Reads current metadata, updates fields, and writes to next slot
 * (current slot + 1) % 16
 *
 * @param send_ptr_inc   Amount to increment send_ptr (or 0 to leave unchanged)
 * @param boot_ctr       True to increment boot counter (or 0 to leave unchanged)
 * @return               0 on success, negative error code on failure
 */
int ez_update_meta(uint32_t send_ptr_inc, bool boot_ctr_inc)
{
    uint8_t metabuf[32];
    
    // Find current metadata
    int current_slot = ez_find_current_metadata(metabuf);
    
    // no valid metadata found
    if (current_slot < 0) {
		return -1;

    }

 #pragma pack(push, 1)
 	ez_meta_t *meta = (ez_meta_t *)metabuf;
 #pragma pack(pop)

	// increment sequence id
	meta->seq++;

	// increment values if requested
	if (send_ptr_inc) meta->send_ptr += send_ptr_inc;
	if (boot_ctr_inc) meta->boot_ctr++;

    // Calculate new CRC
    metabuf[31] = calculate_crc8(metabuf, 31);

    // Calculate next slot
    int next_slot = (current_slot + 1) % ATSHA_SLOT_COUNT;
    
    // Write to the next slot
    int result = atsha204a_save_eeprom(meta, next_slot);
    if (result != 0) {
        printf("Failed to update metadata (error %d)\r\n", result);
        return result;
    }
    
    printf("Updated metadata written to slot %d\r\n", next_slot);
    return 0;
}

/**
 * Dump the ATSHA204A configuration zone - corrected addressing
 *
 * @return  0 on success, negative error code on failure
 */
int atsha204a_dump_config(void)
{
    printf("Config dump:\r\n");
    
    // Wake up the device
    atsha204a_wake();
    
    // Read each word in the config zone
    for (uint8_t word = 0x00; word <= 0x15; word++) {
        // Build READ command
        uint8_t cmd[7];
        cmd[0] = 0x07;        // Length
        cmd[1] = 0x02;        // READ
        cmd[2] = 0x00;        // Config zone
        cmd[3] = word;        // Word address (0-15)
        cmd[4] = 0x00;        // Address MSB
        
        // Calculate CRC
        uint16_t crc = atsha_crc(cmd, 5);
        cmd[5] = crc & 0xFF;
        cmd[6] = crc >> 8;
        
        // Send command
        uint8_t txbuf[8];
        txbuf[0] = 0x03;
        memcpy(&txbuf[1], cmd, 7);
        
        if (i2c_write(ATSHA204A_I2C_ADDR, txbuf, 8) != 0) {
            printf("Send error @%02X\r\n", word);
            continue;
        }
        
        Delay_Ms(5);
        
        // Set read pointer
        uint8_t wordaddr = 0x00;
        if (i2c_write(ATSHA204A_I2C_ADDR, &wordaddr, 1) != 0) {
            printf("Ptr error @%02X\r\n", word);
            continue;
        }
        
        // Read response (7 bytes: 1 count + 4 data + 2 CRC)
        uint8_t resp[7];
        if (i2c_read(ATSHA204A_I2C_ADDR, resp, 7) != 0) {
            printf("Read error @%02X\r\n", word);
            continue;
        }
        
        // Check response
        if (resp[0] == 0x04 && resp[1] != 0x00) {
            printf("Err %02X @%02X\r\n", resp[1], word);
            continue;
        }
        
        if (resp[0] != 0x07) {
            printf("Bad len %02X\r\n", resp[0]);
            continue;
        }
        
        // Print word number and data (4 bytes)
        printf("%02X: %02X %02X %02X %02X\r\n", 
               word, resp[1], resp[2], resp[3], resp[4]);
    }
    
    return 0;
}

int atsha204a_factory_lock(void) {

	int result;

	printf("config slots\r\n");
	result = atsha204a_configure_all_slots();
	if (result != 0) {
		printf("Failed to configure slots (error %d)\r\n", result);
		return -1;
	}
   
	printf("lock config zone\r\n");
	result = atsha204a_lock(0x80);
	if (result != 0) {
		printf("Failed to lock config zone (error %d)\r\n", result);
		return -1;
	}
  
	printf("lock data zone\r\n");
	result = atsha204a_lock(0x81);
	if (result != 0) {
		printf("Failed to lock data zone (error %d)\r\n", result);
		return -1;
	}

	return 0;

}

// FLASH

// SPI Flash commands for generic NOR flash
#define FLASH_CMD_WRITE_ENABLE      0x06
#define FLASH_CMD_WRITE_DISABLE     0x04
#define FLASH_CMD_READ_STATUS       0x05
#define FLASH_CMD_READ_DATA         0x03
#define FLASH_CMD_PAGE_PROGRAM      0x02
#define FLASH_CMD_SECTOR_ERASE      0x20
#define FLASH_CMD_CHIP_ERASE        0xC7

// Helper function to select the flash chip
static inline void flash_select(void) {
    GPIOC->BSHR = (1<<(16+SPI_SS)); // Set SS low to select
    Delay_Us(5); // Short delay
}

// Helper function to deselect the flash chip
static inline void flash_deselect(void) {
    GPIOC->BSHR = (1<<SPI_SS); // Set SS high to deselect
    Delay_Us(5); // Short delay
}

// Helper function to send a single command byte
static void flash_send_command(uint8_t cmd) {
    SPI_write_8(cmd);
    SPI_wait_transmit_finished();
    SPI_read_8(); // Dummy read to clear RXNE
}

// Helper function to wait until the flash is not busy
static void flash_wait_ready(void) {
    uint8_t status = 0;
    flash_select();
    flash_send_command(FLASH_CMD_READ_STATUS);
    
    do {
        SPI_write_8(0x00); // Dummy write
        SPI_wait_TX_complete();
        SPI_wait_RX_available();
        status = SPI_read_8();
    } while (status & 0x01); // Wait while busy bit is set
    
    flash_deselect();
}

// Enable write operations on the flash
static void flash_write_enable(void) {
    flash_select();
    flash_send_command(FLASH_CMD_WRITE_ENABLE);
    flash_deselect();
}

/**
 * Erase the entire flash chip
 */
void flash_erase(void) {
    // Enable write operations
    flash_write_enable();
    
    // Send chip erase command
    flash_select();
    flash_send_command(FLASH_CMD_CHIP_ERASE);
    flash_deselect();
    
    // Wait for erase to complete
    flash_wait_ready();
}

/**
 * Read data from flash
 * 
 * @param buf   Buffer to store the read data
 * @param addr  Flash address to read from
 * @param size  Number of bytes to read
 */
void flash_read(uint8_t *buf, uint32_t addr, uint32_t size) {
    if (size == 0) return;
    
    flash_select();
    
    // Send read command
    flash_send_command(FLASH_CMD_READ_DATA);
    
    // Send 24-bit address (MSB first)
    flash_send_command((addr >> 16) & 0xFF); // Address high byte
    flash_send_command((addr >> 8) & 0xFF);  // Address middle byte
    flash_send_command(addr & 0xFF);         // Address low byte
    
		printf("flash read (@ %08X): ", addr);

    // Read data
    for (uint32_t i = 0; i < size; i++) {
        SPI_write_8(0x00); // Dummy write to generate clock
        SPI_wait_TX_complete();
        SPI_wait_RX_available();
        buf[i] = SPI_read_8();

		printf(" %02x ", buf[i]);

    }
    
		printf("\n");

    flash_deselect();
}

/**
 * Write data to flash
 * 
 * @param buf   Buffer containing data to write
 * @param addr  Flash address to write to
 * @param size  Number of bytes to write
 */
void flash_write(const uint8_t *buf, uint32_t addr, uint32_t size) {
    if (size == 0) return;
    
    // Most flash chips can only write up to a page at a time (typically 256 bytes)
    uint32_t page_size = 256; // Typical page size for most SPI flash
    uint32_t current_addr = addr;
    uint32_t bytes_left = size;
    uint32_t current_index = 0;
    
    while (bytes_left > 0) {
        // Calculate bytes to write in current page
        // We need to stop at page boundary
        uint32_t page_offset = current_addr % page_size;
        uint32_t bytes_this_page = page_size - page_offset;
        if (bytes_this_page > bytes_left) {
            bytes_this_page = bytes_left;
        }
        
        // Enable write operations
        flash_write_enable();
        
        // Send page program command
        flash_select();
        flash_send_command(FLASH_CMD_PAGE_PROGRAM);
        
        // Send 24-bit address (MSB first)
        flash_send_command((current_addr >> 16) & 0xFF); // Address high byte
        flash_send_command((current_addr >> 8) & 0xFF);  // Address middle byte
        flash_send_command(current_addr & 0xFF);         // Address low byte
        
        // Send data to program
        for (uint32_t i = 0; i < bytes_this_page; i++) {
            SPI_write_8(buf[current_index + i]);
            SPI_wait_transmit_finished();
            SPI_read_8(); // Dummy read to clear RXNE
        }
        
        flash_deselect();
        
        // Wait for programming to complete
        flash_wait_ready();
        
        // Update variables for next page
        bytes_left -= bytes_this_page;
        current_addr += bytes_this_page;
        current_index += bytes_this_page;
    }
}

int32_t flash_read_id(void) {
       uint32_t id = 0;
       flash_select();
       flash_send_command(0x9F); // JEDEC ID command
       
       // Read manufacturer ID
       SPI_write_8(0x00);
       SPI_wait_TX_complete();
       SPI_wait_RX_available();
       id = (SPI_read_8() << 16);
       
       // Read memory type
       SPI_write_8(0x00);
       SPI_wait_TX_complete();
       SPI_wait_RX_available();
       id |= (SPI_read_8() << 8);
       
       // Read capacity
       SPI_write_8(0x00);
       SPI_wait_TX_complete();
       SPI_wait_RX_available();
       id |= SPI_read_8();
       
       flash_deselect();
       return id;
}

// USB HID

void usb_handle_user_in_request( struct usb_endpoint * e, uint8_t * scratchpad, int endp, uint32_t sendtok, struct rv003usb_internal * ist )
{
	// Make sure we only deal with control messages.  Like get/set feature reports.
	if( endp )
	{
		usb_send_empty( sendtok );
	}
}

void usb_handle_user_data( struct usb_endpoint * e, int current_endpoint, uint8_t * data, int len, struct rv003usb_internal * ist )
{
	//LogUEvent( SysTick->CNT, current_endpoint, e->count, 0xaaaaaaaa );
	int offset = e->count<<3;
	int torx = e->max_len - offset;
	if( torx > len ) torx = len;
	if( torx > 0 )
	{
		memcpy( scratch + offset, data, torx );
		e->count++;
		if( ( e->count << 3 ) >= e->max_len )
		{
			start = e->max_len;
		}
	}
}

void usb_handle_hid_get_report_start( struct usb_endpoint * e, int reqLen, uint32_t lValueLSBIndexMSB )
{
	if( reqLen > sizeof( scratch ) ) reqLen = sizeof( scratch );
	e->opaque = scratch;
	e->max_len = reqLen;
}

void usb_handle_hid_set_report_start( struct usb_endpoint * e, int reqLen, uint32_t lValueLSBIndexMSB )
{
	if( reqLen > sizeof( scratch ) ) reqLen = sizeof( scratch );
	e->max_len = reqLen;
}


void usb_handle_other_control_message( struct usb_endpoint * e, struct usb_urb * s, struct rv003usb_internal * ist )
{
   LogUEvent( SysTick->CNT, s->wRequestTypeLSBRequestMSB, s->lValueLSBIndexMSB, s->wLength );
}

// --

int ez_identity(void) {

    uint8_t meta[32];
    
    // Find current metadata
    int current_slot = ez_find_current_metadata(meta);
    
    // no valid metadata found
    if (current_slot < 0) {
		return -1;
    }

	if (meta[14] == 0 || meta[14] == 1)
		return meta[14];
	else
		return -1;

}

uint32_t ez_send_ptr(void) {

	uint32_t send_ptr;
	uint8_t metabuf[32];
    
	// Find current metadata
	int current_slot = ez_find_current_metadata(metabuf);
    
	// no valid metadata found
	if (current_slot < 0) {
		return 0xffffffff;
	}

 #pragma pack(push, 1)
	ez_meta_t *meta = (ez_meta_t *)metabuf;
 #pragma pack(pop)

	return meta->send_ptr;

}

int ez_erase(void) {

	uint8_t metadata[32];
	bzero(metadata, 32);

	for (int i = 0; i < ATSHA_SLOT_COUNT; i++) {

		printf("erasing slot %d\r\n", i);

		int result = atsha204a_save_eeprom(metadata, i);
		if (result != 0) {
			printf("Failed to write metadata (error %d)\r\n", result);
			return -1;
		}

		Delay_Ms(50);

	}

	printf("erasing flash\r\n");

	flash_erase();

	printf("done\r\n");

	return 0;

}

/**
 * Initialize device with identity and set up metadata
 * 
 * @param id  Identity (0=Alice, 1=Bob)
 * @return    0 on success, negative error code on failure
 */
int ez_identify(uint8_t id)
{
    printf("Initializing as %s\r\n", id == 0 ? "ALICE" : "BOB");
    
	ez_meta_t meta;
	memset(&meta, 0, sizeof(meta));
	uint8_t *meta_ptr = (uint8_t *)&meta;

	meta.magic = 0x455a;
	meta.seq = 1;
	meta.send_ptr = 0;
	meta.boot_ctr = 1;
	meta.id = id;

	// Calculate CRC
	uint8_t crcbuf[31];
	memcpy(crcbuf, &meta, 31);
	meta.crc = calculate_crc8(crcbuf, 31); 
    
	// Write the initial metadata to slot 0
	int result = atsha204a_save_eeprom(meta_ptr, 0);
	if (result != 0) {
		printf("Failed to write metadata (error %d)\r\n", result);
		return -2;
	}
    
    // Verify the write by reading it back
    uint8_t verify_buffer[32];
    result = atsha204a_load_eeprom(verify_buffer, 0);
    if (result != 0) {
        printf("Failed to verify metadata (error %d)\r\n", result);
        return -3;
    }
    
    // Check magic number and CRC
    if (verify_buffer[1] != 0x45 || verify_buffer[0] != 0x5A ||
        verify_buffer[31] != meta_ptr[31]) {
        printf("Verification failed - metadata mismatch\r\n");
        return -4;
    }
    
    printf("Device successfully initialized as %s\r\n", id == 0 ? "ALICE" : "BOB");
    return 0;
}


void ez_generate_keys(void) {

	uint8_t random_bytes[32];

	printf("wake\r\n");
	atsha204a_wake();

	printf("get_random\r\n");
	int r = atsha204a_get_random(random_bytes);

	if (r == 0) {
		key_gen += 32;
	}

	if ((key_gen % 1024) == 0) {
		printf(" %d / %d\r\n", key_gen, key_len);
	}

	if (key_gen == key_len) {
		printf("key gen done\n");
		do_key_gen = 0;	
	}

}
