/*
 * Einszeit Utility
 * Copyright (c) 2025 Lone Dynamics Corporation. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include "hidapi.h"

#define KEY_FILENAME "ez.key"

#define USB_MFG_ID 0x16d0
#define USB_DEV_ID 0x1475

// --

struct hid_device *usb_hd = NULL;

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

ez_meta_t metadata;

#define DELAY() usleep(1000);

// --

void show_usage(char **argv);
char *ez_get_message(void);
char *base64_encode(const unsigned char *data, size_t in_len);
unsigned char *base64_decode(const char *encoded, size_t *out_length);
uint32_t crc32(const void *data, size_t len);

void ez_get_metadata(void);
void ez_dump_metadata(void);

void show_usage(char **argv) {
   printf("usage: %s [-hcE] [-i <a[lice]|b[ob]> | -s msg | -r msg]\n" \
      " -h\tdisplay help\n" \
      " -i\tinitialize device as either alice or bob\n" \
      " -c\tcopy keys to device\n" \
      " -r\tread message\n" \
      " -w\twrite message\n" \
      " -d\tdump config\n" \
      " -D\tdebug mode\n" \
      " -E\terase device\n" \
      " -M\tdump metadata\n" \
      " -R\tget random data\n" \
      " -L\tlock configuration\n",
      argv[0]);
}

enum { MODE_PING, MODE_STATUS, MODE_IDENTIFY, MODE_COPY,
	MODE_READ, MODE_READ_SELF, MODE_WRITE, MODE_KEY, MODE_ERASE,
	MODE_META, MODE_RAND, MODE_LOCK, MODE_DUMP_CONFIG, MODE_META_SET_PTR };

#define EZ_CMD_PING 0x00
#define EZ_CMD_STATUS 0x01
#define EZ_CMD_IDENTIFY 0x10
#define EZ_CMD_COPY 0x20
#define EZ_CMD_ERASE 0x50
#define EZ_CMD_META_LOAD 0x60
#define EZ_CMD_META_SET_PTR 0x70
#define EZ_CMD_RAND 0x80
#define EZ_CMD_ENCRYPT 0xa0
#define EZ_CMD_DECRYPT 0xb0
#define EZ_CMD_DECRYPT_SELF 0xb1
#define EZ_CMD_INC 0xc0
#define EZ_CMD_DUMP_CONFIG 0xd0
#define EZ_CMD_LOCK 0xf0

int debug = 0;

int main(int argc, char *argv[]) {

   int opt;
	int mode = MODE_PING;
	int identity = 0;
	uint32_t ptr;

	uint8_t cbuf[255];
	bzero(cbuf, 255);

   while ((opt = getopt(argc, argv, "hsi:crvwkdMLREDp:")) != -1) {
      switch (opt) {
         case 'h': show_usage(argv); return(0); break;
         case 's': mode = MODE_STATUS; break;
         case 'i':
				mode = MODE_IDENTIFY;
				if (optarg && tolower(optarg[0]) == 'b') identity = 1;
				break;
         case 'c': mode = MODE_COPY; break;
         case 'r': mode = MODE_READ; break;
         case 'v': mode = MODE_READ_SELF; break;
         case 'w': mode = MODE_WRITE; break;
         case 'k': mode = MODE_KEY; break;
         case 'p':
				ptr = atol(optarg);
				mode = MODE_META_SET_PTR;
				break;
         case 'M': mode = MODE_META; break;
         case 'R': mode = MODE_RAND; break;
         case 'L': mode = MODE_LOCK; break;
         case 'E': mode = MODE_ERASE; break;
         case 'd': mode = MODE_DUMP_CONFIG; break;
         case 'D': debug = 1; break;
      }
   }

	usb_hd = (struct hid_device *)hid_open( USB_MFG_ID, USB_DEV_ID, L"0000");
	if (!usb_hd) {
		fprintf( stderr, "Error: Failed to open device.\n" );
		exit(1);
	}

	ez_get_metadata();
	ez_dump_metadata();

	if (mode == MODE_PING) {

		// ...
	
	} else if (mode == MODE_STATUS) {

		printf("status:\n");
		cbuf[2] = EZ_CMD_STATUS;
		hidapi_rpc(cbuf);

		uint32_t key_gen =
			cbuf[3] << 24 |
			cbuf[4] << 16 |
			cbuf[5] << 8 |
			cbuf[6];

		printf("key_gen: %li\n", key_gen);

	} else if (mode == MODE_IDENTIFY) {

		printf("identity: %i\n", identity);

		cbuf[2] = EZ_CMD_IDENTIFY;
		cbuf[3] = identity;
		hidapi_rpc(cbuf);

		if (cbuf[2] == 1) {
			printf("identity set to %i\n", identity);
		} else {
			printf("failed to set identity\n");
		}

	} else if (mode == MODE_COPY) {

		FILE *f = fopen(KEY_FILENAME, "r");
		uint8_t kbuf[128];

		if (fseek(f, 0, SEEK_END) != 0) {
			printf("Error: Failed to seek to end of file\n");
			fclose(f);
			return -2;
		}
    
		size_t key_size = ftell(f);
		if (key_size < 0) {
			printf("Error: Failed to determine file size\n");
			fclose(f);
			return -3;
		}

		rewind(f);

		printf("Copying keys to device ...\n");

		for (size_t k = 0; k < key_size; k += 128) {

			size_t chunk_size = fread(kbuf, 1, 128, f);

			cbuf[2] = EZ_CMD_COPY;

			// set offset
			cbuf[3] = (uint8_t)(k & 0xff);
			cbuf[4] = (uint8_t)((k >> 8) & 0xff);
			cbuf[5] = (uint8_t)((k >> 16) & 0xff);
			cbuf[6] = (uint8_t)((k >> 24) & 0xff);
			cbuf[7] = chunk_size;

			for (int i = 0; i < chunk_size; i++) {
				cbuf[8+i] = kbuf[i];
			}

			hidapi_rpc(cbuf);

			if (cbuf[2] == 0) {
				printf("Copy failed.\n");
				return;
			}

			if ((k % 1024) == 0)
				printf(" %lu / %lu\n", k, key_size);

		}

		printf("Copy completed.\n");

	} else if (mode == MODE_READ || mode == MODE_READ_SELF) {

		char *buf_enc = ez_get_message();
		if (buf_enc == NULL) {
			printf("Failed to get message\n");
			return;
		}

		size_t len_ct;
		unsigned char *buf_ct = base64_decode(buf_enc, &len_ct);

    // Extract key pointer and message length
    uint32_t key_ptr, msg_len;
    memcpy(&key_ptr, buf_ct, 4);
    memcpy(&msg_len, buf_ct + 4, 4);
    
    printf("Key pointer: 0x%08x\n", key_ptr);
    printf("Message length: %u bytes\n", msg_len);
    
	 uint8_t *buf_pt = calloc(1, msg_len + 1);

    // Verify data length matches expected length
    if (len_ct != 8 + msg_len + 4) {
        printf("Warning: Decoded length (%zu) doesn't match expected length (%u)\n", 
               len_ct, 8 + msg_len + 4);
    }
    
    // Verify CRC32 checksum
    uint32_t received_crc, calculated_crc;
    memcpy(&received_crc, buf_ct + len_ct - 4, 4);
    calculated_crc = crc32(buf_ct, len_ct - 4);

    if (received_crc != calculated_crc) {
        printf("CRC check failed: received 0x%08x, calculated 0x%08x\n", 
               received_crc, calculated_crc);
        free(buf_ct);
        free(buf_enc);
        return -1;
    }

		for (int i = 0; i < len_ct; i++) {
			printf(" %.02x", buf_ct[i]);
		}
		printf("\n");

		if (mode == MODE_READ_SELF)
			cbuf[2] = EZ_CMD_DECRYPT_SELF;
		else
			cbuf[2] = EZ_CMD_DECRYPT;

		for (size_t i = 0; i < msg_len; i += 32) {
			size_t chunk_len = (msg_len- i < 32) ? (msg_len - i) : 32;
			printf("decrypting chunk (%lu bytes)\n", chunk_len);
			cbuf[3] = chunk_len;

			// offset
			cbuf[4] = (uint8_t)((key_ptr + i) & 0xff);
			cbuf[5] = (uint8_t)(((key_ptr + i) << 8) & 0xff);
			cbuf[6] = (uint8_t)(((key_ptr + i) << 16) & 0xff);
			cbuf[7] = (uint8_t)(((key_ptr + i) << 24) & 0xff);

			memcpy(&cbuf[8], (unsigned char *)(buf_ct + 8 + i), chunk_len);

			for (int i = 0; i < 32; i++) {
				printf(" %.2x ", cbuf[8+i]);
			}
			printf("\n");

			hidapi_rpc(cbuf);

			if (cbuf[2] == 1) {

				printf("chunk decrypted (offset: %lu)\n", i);

				for (int i = 0; i < 32; i++) {
					printf(" %.2x ", cbuf[8+i]);
				}

				printf("\n");
				memcpy(buf_pt + i, &cbuf[8], chunk_len);

			} else {
				free(buf_ct);
				printf("chunk failed to decrypt\n");
				return;
			}

		}

		printf("Decrypted message:\n%s\n", buf_pt);

		free(buf_ct);
		free(buf_enc);
		free(buf_pt);

	} else if (mode == MODE_WRITE) {

		printf("input message (CTRL-D on new line to finish, CTRL-C to cancel):\n");

		char *buf_pt = ez_get_message();

		uint32_t send_ptr;
		uint32_t len = strlen(buf_pt);
		uint32_t len_final = len + 12;
		char *buf_ct = malloc(len_final);

		if (buf_ct == NULL) {
			printf("failed to malloc buf_ct\n");
			return;
		}

		cbuf[2] = EZ_CMD_ENCRYPT;

		for (size_t i = 0; i < len; i += 32) {
			size_t chunk_len = (len - i < 32) ? (len - i) : 32;
			printf("encrypting chunk (%lu bytes)\n", chunk_len);
			cbuf[3] = chunk_len;

			// offset
			cbuf[4] = (uint8_t)(i & 0xff);
			cbuf[5] = (uint8_t)((i << 8) & 0xff);
			cbuf[6] = (uint8_t)((i << 16) & 0xff);
			cbuf[7] = (uint8_t)((i << 24) & 0xff);

			memcpy(&cbuf[8], (unsigned char *)(buf_pt + i), chunk_len);

			for (int i = 0; i < 32; i++) {
				printf(" %.2x ", cbuf[8+i]);
			}
			printf("\n");

			hidapi_rpc(cbuf);

			if (cbuf[2] == 1) {

				send_ptr =
					cbuf[4] << 24 |
					cbuf[5] << 16 |
					cbuf[6] << 8 |
					cbuf[7];

				printf("chunk encrypted (send_ptr: %lu offset: %lu)\n",
					send_ptr, i);

				for (int i = 0; i < 32; i++) {
					printf(" %.2x ", cbuf[8+i]);
				}

				printf("\n");
				memcpy(buf_ct + 8 + i, &cbuf[8], chunk_len);

			} else {
				free(buf_ct);
				printf("chunk failed to encrypt\n");
				return;
			}

		}
		printf("done\n");

		// message header/footer
		memcpy(buf_ct, &send_ptr, 4);
		memcpy(buf_ct + 4, &len, 4);
		uint32_t crc = crc32(buf_ct, len_final - 4);
		memcpy(buf_ct + len_final - 4, &crc, 4);

		// increment send pointer
		bzero(cbuf, 255);
		cbuf[2] = EZ_CMD_INC;
		cbuf[3] = (uint8_t)(len & 0xff);
		cbuf[4] = (uint8_t)((len << 8) & 0xff);
		cbuf[5] = (uint8_t)((len << 16) & 0xff);
		cbuf[6] = (uint8_t)((len << 24) & 0xff);
		hidapi_rpc(cbuf);

		if (cbuf[2] == 1) {
			printf("key_ptr increment succeeded (%lu bytes).\n", len);
		} else {
			printf("key_ptr increment failed.\n");
			return;
		}

		// send pointer is incremented, display message

		char *buf_ct64 = base64_encode(buf_ct, len_final);
	
		printf("Encrypted message:\n%s\n", buf_ct64);

//		free(buf_ct);
//		free(buf_ct64);
		free(buf_pt);

	} else if (mode == MODE_KEY) {

    FILE *ft = fopen(KEY_FILENAME, "r");

    if (ft) {
		printf("File '%s' already exists.\n", KEY_FILENAME);
		fclose(ft);
		return;
    }

   FILE *f = fopen(KEY_FILENAME, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    unsigned char cbuf[64];
    unsigned char key_buf[32];
    unsigned int key_gen = 0;
    unsigned int key_len = 1024 * 1024 * 4; // 4MB

    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    printf("Generating key data:\n");

    // Establish initial timing baseline
    int initial_chunks = 32;
    for (int i = 0; i < initial_chunks && key_gen < key_len; i++) {
        cbuf[2] = EZ_CMD_RAND;
        hidapi_rpc(cbuf);
        if (cbuf[2] == 1) {
            memcpy(key_buf, &cbuf[3], 32);
            fwrite(key_buf, 1, 32, f);
            key_gen += 32;
        }
    }

    struct timespec after_initial;
    clock_gettime(CLOCK_MONOTONIC, &after_initial);

    double initial_time =
        (after_initial.tv_sec - start_time.tv_sec) +
        (after_initial.tv_nsec - start_time.tv_nsec) / 1e9;
    double rate_avg = (initial_time > 0) ? (key_gen / initial_time) : 1024.0; // bytes/sec

    while (key_gen < key_len) {
        cbuf[2] = EZ_CMD_RAND;
        hidapi_rpc(cbuf);
        if (cbuf[2] == 1) {
            memcpy(key_buf, &cbuf[3], 32);
            fwrite(key_buf, 1, 32, f);
            key_gen += 32;

            if ((key_gen % 4096) == 0 || key_gen >= key_len) {
                clock_gettime(CLOCK_MONOTONIC, &current_time);
                double elapsed =
                    (current_time.tv_sec - start_time.tv_sec) +
                    (current_time.tv_nsec - start_time.tv_nsec) / 1e9;

                if (elapsed > 0) {
                    double inst_rate = key_gen / elapsed;
                    // smooth with exponential moving average
                    rate_avg = 0.9 * rate_avg + 0.1 * inst_rate;
                }

                double remaining = key_len - key_gen;
                double eta = (rate_avg > 0) ? (remaining / rate_avg) : 0;

                int rem_h = (int)(eta / 3600);
                int rem_m = (int)((eta - rem_h * 3600) / 60);
                int rem_s = (int)(eta - rem_h * 3600 - rem_m * 60);

                double pct = (100.0 * key_gen) / key_len;
                printf(" %u / %u bytes (%.1f%%) - %.2f KB/s - ETA: %dh %02dm %02ds\r",
                       key_gen, key_len, pct,
                       rate_avg / 1024.0,
                       rem_h, rem_m, rem_s);
                fflush(stdout);
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &current_time);
    double total_time =
        (current_time.tv_sec - start_time.tv_sec) +
        (current_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("\nKey generation complete! Generated %u bytes in %.2f seconds (%.2f KB/s).\n",
           key_gen, total_time, (key_gen / 1024.0) / total_time);

    fclose(f);

	} else if (mode == MODE_META) {

		printf("scanning for metadata ...\n");

		cbuf[2] = EZ_CMD_META_LOAD;
		hidapi_rpc(cbuf);

		if (cbuf[2] == 0) {
			printf("no metadata found\n");
		} else {

			for (int i = 0; i < 32; i++) {
				printf("%.2x ", cbuf[3+i]);
			}
			printf("\n");

		}

	} else if (mode == MODE_RAND) {

		cbuf[2] = 0x80;
		hidapi_rpc(cbuf);

		if (cbuf[2] == 1) {

			for (int i = 0; i < 32; i++) {
				printf("%.2x ", cbuf[3+i]);
			}
			printf("\n");

		}

	} else if (mode == MODE_LOCK) {

		cbuf[2] = EZ_CMD_LOCK;
		hidapi_rpc(cbuf);

	} else if (mode == MODE_ERASE) {

		cbuf[2] = EZ_CMD_ERASE;
		hidapi_rpc(cbuf);

		if (cbuf[2] == 0)
			printf("erase failed\n");
		else
			printf("erase successful\n");

	} else if (mode == MODE_DUMP_CONFIG) {

		cbuf[2] = EZ_CMD_DUMP_CONFIG;
		hidapi_rpc(cbuf);

	} else {

		show_usage(argv);

	}

	return 0;

}

void hidapi_rpc(uint8_t *buf) {
	buf[0] = 0xaa;
	buf[1] = 0x00;
	int r = hid_send_feature_report(usb_hd, buf, 255);
	if (r != 255) {
		fprintf(stderr, "hidapi_send_get failed (r = %d)\n", r);
		fprintf(stderr, " error: %s\n", hid_error(usb_hd));
	}
	retry:;
	r = hid_get_feature_report(usb_hd, buf, 255);
	//printf("buf: %x %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
	if (r != 255 || buf[0] != 0xaa) {
		fprintf(stderr, "hidapi_send_get failed (r = %d)\n", r);
		fprintf(stderr, " error: %s\n", hid_error(usb_hd));
	}
	if (buf[1] != 0x01) goto retry;
}

// --

char *ez_get_message(void) {
    size_t bufsize = 1024;
    size_t len = 0;
    char *buffer = malloc(bufsize);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }

    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= bufsize) {
            bufsize *= 2;
            char *newbuf = realloc(buffer, bufsize);
            if (!newbuf) {
                perror("realloc");
                free(buffer);
                return NULL;
            }
            buffer = newbuf;
        }
        buffer[len++] = (char)c;
    }

    if (ferror(stdin)) {
        perror("Error reading stdin");
        free(buffer);
        return NULL;
    }

    buffer[len] = '\0';
    return buffer;
}

char *base64_encode(const unsigned char *data, size_t in_len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    // Output length: 4 * ceil(in_len / 3)
    size_t out_len = 4 * ((in_len + 2) / 3);

    char *out = malloc(out_len + 1); // +1 for NUL
    if (!out) {
        perror("malloc");
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < in_len;) {
        uint32_t octet_a = i < in_len ? data[i++] : 0;
        uint32_t octet_b = i < in_len ? data[i++] : 0;
        uint32_t octet_c = i < in_len ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = alphabet[(triple >> 18) & 0x3F];
        out[j++] = alphabet[(triple >> 12) & 0x3F];
        out[j++] = (i > in_len + 1) ? '=' : alphabet[(triple >> 6) & 0x3F];
        out[j++] = (i > in_len) ? '=' : alphabet[triple & 0x3F];
    }

    out[j] = '\0';
    return out;
}

/* ===============================
 * Base64 Decode
 * =============================== */
unsigned char *base64_decode(const char *encoded, size_t *out_len) {
    static const unsigned char decode_table[256] = {
        [0 ... 255] = 0xFF,
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
        ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
        ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25,
        ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
        ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
        ['y'] = 50, ['z'] = 51,
        ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61,
        ['+'] = 62, ['/'] = 63
    };

    size_t encoded_len = strlen(encoded);
    size_t valid_len = 0;

    // Count valid base64 chars (ignore whitespace)
    for (size_t i = 0; i < encoded_len; i++) {
        unsigned char c = encoded[i];
        if (decode_table[c] != 0xFF || c == '=') valid_len++;
    }

    if (valid_len % 4 != 0) {
        errno = EINVAL;
        return NULL; // Not valid Base64
    }

    size_t decoded_len = (valid_len / 4) * 3;

    // Adjust for padding
    if (encoded_len >= 1 && encoded[encoded_len - 1] == '=') decoded_len--;
    if (encoded_len >= 2 && encoded[encoded_len - 2] == '=') decoded_len--;

    unsigned char *out = malloc(decoded_len);
    if (!out) {
        perror("malloc");
        return NULL;
    }

    size_t i = 0, j = 0;
    unsigned char block[4];
    int block_len = 0;

    for (size_t k = 0; k < encoded_len; k++) {
        unsigned char c = encoded[k];
        if (c == '=' || decode_table[c] != 0xFF) {
            block[block_len++] = c;
            if (block_len == 4) {
                uint32_t val = 0;
                int pad = 0;

                for (int b = 0; b < 4; b++) {
                    if (block[b] == '=') {
                        block[b] = 'A';
                        pad++;
                    }
                    val = (val << 6) | decode_table[block[b]];
                }

                if (j < decoded_len) out[j++] = (val >> 16) & 0xFF;
                if (j < decoded_len && pad < 2) out[j++] = (val >> 8) & 0xFF;
                if (j < decoded_len && pad < 1) out[j++] = val & 0xFF;

                block_len = 0;
            }
        }
    }

    *out_len = j;
    return out;
}

uint32_t crc32(const void *data, size_t len) {
    const uint8_t *buf = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    const uint32_t polynomial = 0xEDB88320;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
        }
    }
    
    return crc ^ 0xFFFFFFFF;
}

void ez_get_metadata(void) {

	uint8_t cbuf[255];
	bzero(cbuf, 255);

	printf("scanning for metadata ...\n");

	cbuf[2] = EZ_CMD_META_LOAD;
	hidapi_rpc(cbuf);

	if (cbuf[2] == 0) {
		printf("no metadata found\n");
	} else {
		printf("metadata found:");
		for (int i = 0; i < 32; i++) {
			printf(" %.2x ", cbuf[3 + i]);
		}
		printf("\n");
		memcpy(&metadata, &cbuf[3], 32);
	}

}

void ez_dump_metadata(void) {

	printf("magic: %04x\n", metadata.magic);
	printf("seq: %08x\n", metadata.seq);
	printf("send_ptr: %08x\n", metadata.send_ptr);
	printf("boot_ctr: %08x\n", metadata.boot_ctr);
	printf("id: %02x (%s)\n", metadata.id, metadata.id ? "bob" : "alice");
	printf("crc: %02x\n", metadata.crc);

}
