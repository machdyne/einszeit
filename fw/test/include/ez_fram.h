/*
 * EZ-SEC-001 traceability (see docs/EZ-TEST-TRACEABILITY.md):
 *   SEC-PTR-002    FRAM is metadata storage on V1 and holds OTP offsets;
 *                  every write path here is gated by ez_guard_permit_storage()
 *   SEC-META-003   the guard prevents silent destruction of session records
 *   SEC-UI-005     raw dump is compile-time disabled by default
 *
 * Bench validation firmware. Not a production artifact.
 */

#ifndef EZ_FRAM_H
#define EZ_FRAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Standard SPI FRAM opcodes (MB85RS / FM25V / CY15B families all share these). */
#define FRAM_OP_WREN   0x06
#define FRAM_OP_WRDI   0x04
#define FRAM_OP_RDSR   0x05
#define FRAM_OP_WRSR   0x01
#define FRAM_OP_READ   0x03
#define FRAM_OP_WRITE  0x02
#define FRAM_OP_RDID   0x9F
#define FRAM_OP_FSTRD  0x0B
#define FRAM_OP_SLEEP  0xB9

/* Status register bits. */
#define FRAM_SR_WEL    0x02
#define FRAM_SR_BP0    0x04
#define FRAM_SR_BP1    0x08
#define FRAM_SR_WPEN   0x80

typedef struct {
    uint8_t  id[9];
    uint8_t  id_len;
    const char *vendor;      /* decoded from the JEDEC manufacturer code */
    const char *part;        /* best-effort part guess, "unknown" if not in table */
    uint32_t density_bytes;  /* from the ID table, 0 if unknown */
} ez_fram_id_t;

/*
 * Result of a non-destructive presence probe that does not rely on RDID.
 *
 * Not every SPI FRAM implements opcode 0x9F. The original Fujitsu MB85RS64
 * family (including the MB85RS64PNF used on Blaustahl) predates the Device ID
 * command; sending 0x9F to one of those parts clocks out nothing and the host
 * sees all zeroes. Diagnosing that as a dead bus is wrong and sends you
 * looking for a hardware fault that is not there.
 *
 * RDSR (0x05) and the WREN/WRDI pair are supported by every SPI FRAM ever
 * made, so toggling the write-enable latch and watching it follow is a
 * conclusive, non-destructive test that the part is alive and the bus works
 * in both directions.
 */
typedef struct {
    bool     rdid_supported;   /* 0x9F returned something other than 00/FF   */
    bool     miso_alive;       /* MISO was not stuck at one level            */
    bool     wel_toggles;      /* WREN set WEL and WRDI cleared it           */
    uint8_t  sr_idle, sr_wren, sr_wrdi;
    bool     present;          /* wel_toggles: the authoritative answer      */
} ez_fram_probe_t;

bool ez_fram_probe(ez_fram_probe_t *pr);

typedef struct {
    bool     present;
    uint32_t size_bytes;     /* measured by address aliasing */
    bool     size_confirmed;
    uint8_t  addr_bytes;     /* 2 for <=64 Kbit..512 Kbit parts, 3 above */
} ez_fram_geom_t;

typedef struct {
    bool     id_ok;
    bool     sr_ok;          /* WEL set/clear via WREN/WRDI behaved            */
    bool     bus_ok;         /* MISO is not stuck at 0x00 or 0xFF              */
    bool     patterns_ok;
    bool     addressing_ok;  /* address-unique pattern read back exactly       */
    uint32_t bytes_tested;
    uint32_t first_error_addr;
    uint8_t  first_error_expected, first_error_got;
    uint32_t error_count;
} ez_fram_result_t;

void  ez_fram_init(uint32_t baud);
uint32_t ez_fram_set_baud(uint32_t baud);

bool  ez_fram_read_id(ez_fram_id_t *id);
uint8_t ez_fram_read_status(void);
bool  ez_fram_write_status(uint8_t v);

void  ez_fram_read(uint32_t addr, uint8_t *buf, size_t len);
void  ez_fram_write(uint32_t addr, const uint8_t *buf, size_t len);

/* Detects density by writing markers at increasing powers of two and looking
 * for the address wrap. Destructive over the whole device. */
bool  ez_fram_detect_size(ez_fram_geom_t *g);

/* Non-destructive outside [addr, addr+len): saves, tests, restores. */
bool  ez_fram_test_region(uint32_t addr, uint32_t len, ez_fram_result_t *r,
                          uint8_t *scratch, size_t scratch_len);

/* Full-device destructive test: patterns + address uniqueness + PRNG. */
bool  ez_fram_test_full(uint32_t size_bytes, ez_fram_result_t *r,
                        void (*progress)(uint32_t done, uint32_t total));

/* Read/write throughput at the current baud, using a scratch region. */
void  ez_fram_bench(uint32_t addr, uint32_t len, uint8_t *scratch,
                    uint32_t *write_bps, uint32_t *read_bps, bool *verify_ok);

void  ez_fram_geom_defaults(ez_fram_geom_t *g);

#endif /* EZ_FRAM_H */
