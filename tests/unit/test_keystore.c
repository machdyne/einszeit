/*
 * test_keystore.c -- key storage HAL conformance, run against both
 * backends: the in-memory simulator (which the other suites rely on) and
 * the FatFs port (ports/fatfs) on RAM disks. If the two diverge, the other
 * suites' results would not carry over to the firmware; this suite is what
 * ties them together.
 *
 * Three backends: the simulator, FatFs on FAT-formatted RAM disks, and
 * FatFs on exFAT-formatted RAM disks (as most microSDXC cards arrive).
 *
 * Followed by FatFs-only tests on raw media: erased keys leave no bytes
 * behind, keys on drive 0 never share a 4 KiB erase block, and a complete
 * device over FatFs interoperates with one over the simulator.
 *
 * EZ-SEC-001: SEC-STORE-001, SEC-HW-002, SEC-FW-003, SEC-PTR-004 (erasure
 * on a real filesystem), SEC-TEST-MEDIA-001 (a) over FatFs;
 * EZ-IMPL-001 IMPL-FS-001, ez_hal_keystore.h contract.
 */
#include <stdlib.h>
#include <string.h>

#include "core_fixture.h"
#include "ez_import.h"
#include "ez_ks_fatfs.h"
#include "sim_blockdev.h"

/* ---- backends -------------------------------------------------------- */

typedef struct {
	const char *name;
	ez_hal_keystore_t *hal;
	void (*remove)(uint8_t d);
	void (*insert)(uint8_t d);
	void (*swap_next)(uint8_t d);
	void (*fresh)(void);
	int  fatfs;
} backend_t;

static sim_ks_t *g_sim;
static sim_bd_t g_bd[3];
static ez_ks_fatfs_t g_fat;

static void sim_fresh(void)
{
	if (!g_sim) g_sim = calloc(1, sizeof *g_sim);
	else sim_ks_free(g_sim);
	sim_ks_init(g_sim);
}
static void sim_rm(uint8_t d) { sim_ks_remove(g_sim, d); }
static void sim_in(uint8_t d) { sim_ks_insert(g_sim, d); }
static void sim_sw(uint8_t d) { sim_ks_swap_after(g_sim, d, 0); }

static void fat_fresh(void)
{
	for (int i = 0; i < 3; i++) if (g_bd[i].mem) sim_bd_free(&g_bd[i]);
	sim_bd_init(&g_bd[0], 4096, 512, 0xFF, true);     /* 2 MiB NOR partition */
	sim_bd_init(&g_bd[1], 512, 8192, 0x00, false);    /* 4 MiB microSD */
	sim_bd_init(&g_bd[2], 512, 4096, 0x00, false);    /* 2 MiB second slot */
	ez_ks_fatfs_init(&g_fat, &g_bd[0].bd, &g_bd[1].bd, &g_bd[2].bd);
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, 0), EZ_OK);           /* formats drive 0 */
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, 1), EZ_ERR_MEDIA);    /* blank card: no FS */
	EZ_CHECK_EQ(g_fat.hal.wipe(&g_fat, 1), EZ_OK);              /* "card formatted FAT" */
	EZ_CHECK_EQ(g_fat.hal.wipe(&g_fat, 2), EZ_OK);
}
/* A card formatted exFAT, as most microSDXC cards arrive. */
static void format_exfat(uint8_t d)
{
	static uint8_t work[FF_MAX_SS];
	char p[3] = { (char)('0' + d), ':', 0 };
	ez_ks_fatfs_unmount(&g_fat, d);
	MKFS_PARM opt = { FM_EXFAT | FM_SFD, 1, 0, 0, 0 };
	EZ_CHECK_EQ(f_mkfs(p, &opt, work, sizeof work), FR_OK);
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, d), EZ_OK);
	EZ_CHECK_EQ(g_fat.fs[d].fs_type, FS_EXFAT);
}

static void exfat_fresh(void)
{
	for (int i = 0; i < 3; i++) if (g_bd[i].mem) sim_bd_free(&g_bd[i]);
	sim_bd_init(&g_bd[0], 4096, 512, 0xFF, true);
	sim_bd_init(&g_bd[1], 512, 32768, 0x00, false);   /* 16 MiB */
	sim_bd_init(&g_bd[2], 512, 32768, 0x00, false);
	ez_ks_fatfs_init(&g_fat, &g_bd[0].bd, &g_bd[1].bd, &g_bd[2].bd);
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, 0), EZ_OK);
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, 1), EZ_ERR_MEDIA);
	format_exfat(1);
	format_exfat(2);
}

static void fat_rm(uint8_t d) { sim_bd_remove(&g_bd[d]); }
static void fat_in(uint8_t d) { sim_bd_insert(&g_bd[d]); ez_ks_fatfs_mount(&g_fat, d); }
static void fat_sw(uint8_t d) { sim_bd_swap_after(&g_bd[d], 0); }

#define NBACKENDS 3
static backend_t backends[NBACKENDS];

static void setup_backends(void)
{
	sim_fresh();
	backends[0] = (backend_t){ "sim", &g_sim->hal, sim_rm, sim_in, sim_sw, sim_fresh, 0 };
	backends[1] = (backend_t){ "fatfs", &g_fat.hal, fat_rm, fat_in, fat_sw, fat_fresh, 1 };
	backends[2] = (backend_t){ "exfat", &g_fat.hal, fat_rm, fat_in, fat_sw, exfat_fresh, 1 };
}

#define H(b) (b)->hal
#define CALL(b, fn, ...) H(b)->fn(H(b)->ctx, __VA_ARGS__)

static void port_buffers_clear(const backend_t *b)
{
	if (!b->fatfs) return;
	EZ_CHECK_MSG(ez_is_zero(&g_fat.fil, sizeof g_fat.fil), "FatFs FIL not cleared");
	EZ_CHECK_MSG(ez_is_zero(&g_fat.fno, sizeof g_fat.fno), "FatFs FILINFO not cleared");
}

/* ---- conformance ----------------------------------------------------- */

static uint8_t data[300000], back[300000];

static void conf_files(const backend_t *b)
{
	b->fresh();
	uint32_t sz;
	for (uint8_t d = 0; d < 3; d++) {
		EZ_CHECK(H(b)->present(H(b)->ctx, d));
		EZ_CHECK_EQ(CALL(b, check, d), EZ_OK);
		EZ_CHECK_EQ(CALL(b, size, d, "A1B2C3D4.KEY", &sz), EZ_ERR_NOT_FOUND);
		EZ_CHECK_EQ(CALL(b, append, d, "A1B2C3D4.KEY", data, 1), EZ_ERR_NOT_FOUND);
		EZ_CHECK_EQ(CALL(b, create, d, "A1B2C3D4.KEY"), EZ_OK);
		EZ_CHECK_EQ(CALL(b, create, d, "A1B2C3D4.KEY"), EZ_ERR_EXISTS);
		EZ_CHECK_EQ(CALL(b, size, d, "A1B2C3D4.KEY", &sz), EZ_OK);
		EZ_CHECK_EQ(sz, 0);
		sim_fill(data, sizeof data, 1000 + d);
		/* append in odd pieces that straddle 512 and 4096 boundaries */
		uint32_t off = 0;
		static const uint32_t pieces[] = { 1, 511, 512, 513, 4095, 4097, 50000, 7 };
		for (int i = 0; off < 140000; i++) {
			uint32_t n = pieces[i % 8];
			EZ_CHECK_EQ(CALL(b, append, d, "A1B2C3D4.KEY", data + off, n), EZ_OK);
			off += n;
			port_buffers_clear(b);
		}
		EZ_CHECK_EQ(CALL(b, size, d, "A1B2C3D4.KEY", &sz), EZ_OK);
		EZ_CHECK_EQ(sz, off);
		for (uint32_t o = 0; o + 600 < off; o += 9973) {
			memset(back, 0, 600);
			EZ_CHECK_EQ(CALL(b, read, d, "A1B2C3D4.KEY", o, back, 600), EZ_OK);
			EZ_CHECK(memcmp(back, data + o, 600) == 0);
			port_buffers_clear(b);
		}
		EZ_CHECK_EQ(CALL(b, read, d, "A1B2C3D4.KEY", off - 10, back, 11), EZ_ERR_RANGE);
		EZ_CHECK_EQ(CALL(b, read, d, "NOPE.KEY", 0, back, 1), EZ_ERR_NOT_FOUND);
	}
}

static void conf_rename_zap_list(const backend_t *b)
{
	b->fresh();
	sim_fill(data, 20000, 7);
	EZ_CHECK_EQ(CALL(b, create, 1, "0000AAAA.TMP"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, append, 1, "0000AAAA.TMP", data, 20000), EZ_OK);
	EZ_CHECK_EQ(CALL(b, create, 1, "0000BBBB.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, rename, 1, "0000AAAA.TMP", "0000BBBB.KEY"), EZ_ERR_EXISTS);
	EZ_CHECK_EQ(CALL(b, rename, 1, "0000CCCC.TMP", "0000DDDD.KEY"), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(CALL(b, rename, 1, "0000AAAA.TMP", "0000AAAA.KEY"), EZ_OK);
	uint32_t sz;
	EZ_CHECK_EQ(CALL(b, size, 1, "0000AAAA.TMP", &sz), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(CALL(b, read, 1, "0000AAAA.KEY", 0, back, 20000), EZ_OK);
	EZ_CHECK(memcmp(back, data, 20000) == 0);
	/* list */
	char name[EZ_NAME_MAX];
	int seen = 0;
	for (uint32_t i = 0; CALL(b, list, 1, i, name, &sz) == EZ_OK; i++) {
		if (strcmp(name, "0000AAAA.KEY") == 0) { EZ_CHECK_EQ(sz, 20000); seen |= 1; }
		if (strcmp(name, "0000BBBB.KEY") == 0) { EZ_CHECK_EQ(sz, 0); seen |= 2; }
		EZ_CHECK(i < 10);
	}
	EZ_CHECK_EQ(seen, 3);
	EZ_CHECK_EQ(CALL(b, list, 1, 99, name, &sz), EZ_ERR_NOT_FOUND);
	/* zap */
	EZ_CHECK_EQ(CALL(b, zap, 1, "0000AAAA.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, size, 1, "0000AAAA.KEY", &sz), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(CALL(b, zap, 1, "0000AAAA.KEY"), EZ_ERR_NOT_FOUND);
	if (b->fatfs)
		for (uint32_t o = 0; o + 32 <= 20000; o += 512)
			EZ_CHECK_MSG(!sim_bd_contains(&g_bd[1], data + o, 32), "zapped key bytes remain on the medium");
	port_buffers_clear(b);
}

static void conf_removal(const backend_t *b)
{
	b->fresh();
	sim_fill(data, 4096, 9);
	EZ_CHECK_EQ(CALL(b, create, 1, "00000001.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, append, 1, "00000001.KEY", data, 4096), EZ_OK);
	b->remove(1);
	uint32_t sz;
	EZ_CHECK(!H(b)->present(H(b)->ctx, 1));
	EZ_CHECK_EQ(CALL(b, check, 1), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(CALL(b, size, 1, "00000001.KEY", &sz), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(CALL(b, read, 1, "00000001.KEY", 0, back, 10), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(CALL(b, create, 1, "00000002.KEY"), EZ_ERR_MEDIA_REMOVED);
	EZ_CHECK_EQ(CALL(b, zap, 1, "00000001.KEY"), EZ_ERR_MEDIA_REMOVED);
	/* other drives unaffected */
	EZ_CHECK_EQ(CALL(b, check, 2), EZ_OK);
	b->insert(1);
	EZ_CHECK_EQ(CALL(b, check, 1), EZ_OK);
	EZ_CHECK_EQ(CALL(b, read, 1, "00000001.KEY", 0, back, 4096), EZ_OK);
	EZ_CHECK(memcmp(back, data, 4096) == 0);
	/* A different card in the slot: check() fails until it is mounted. */
	b->swap_next(1);
	EZ_CHECK_EQ(CALL(b, check, 1), EZ_ERR_MEDIA_REMOVED);
	b->insert(1);
	EZ_CHECK_EQ(CALL(b, check, 1), EZ_OK);
}

static void conf_wipe(const backend_t *b)
{
	b->fresh();
	sim_fill(data, 30000, 11);
	EZ_CHECK_EQ(CALL(b, create, 0, "00000005.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, append, 0, "00000005.KEY", data, 30000), EZ_OK);
	EZ_CHECK_EQ(H(b)->wipe(H(b)->ctx, 0), EZ_OK);
	uint32_t sz;
	char name[EZ_NAME_MAX];
	EZ_CHECK_EQ(CALL(b, size, 0, "00000005.KEY", &sz), EZ_ERR_NOT_FOUND);
	EZ_CHECK_EQ(CALL(b, list, 0, 0, name, &sz), EZ_ERR_NOT_FOUND);
	if (b->fatfs)
		for (uint32_t o = 0; o + 32 <= 30000; o += 512)
			EZ_CHECK_MSG(!sim_bd_contains(&g_bd[0], data + o, 32), "wiped key bytes remain on flash");
	/* usable afterwards */
	EZ_CHECK_EQ(CALL(b, create, 0, "00000006.KEY"), EZ_OK);
	EZ_CHECK_EQ(CALL(b, append, 0, "00000006.KEY", data, 100), EZ_OK);
}

#define FOR_BACKENDS(fn) static void t_##fn(void) { \
	setup_backends(); \
	for (int i = 0; i < NBACKENDS; i++) fn(&backends[i]); }
FOR_BACKENDS(conf_files)
FOR_BACKENDS(conf_rename_zap_list)
FOR_BACKENDS(conf_removal)
FOR_BACKENDS(conf_wipe)

/* Long and non-ASCII names (UTF-8), case-insensitive lookup, and refusal
 * (never truncation) of names that are too long. */
static void conf_long_names(const backend_t *b)
{
	b->fresh();
	static const char *lname = "Schl\xc3\xbcssel von Bob \xe2\x80\x93 2026-10-05 (Laptop).bin";
	sim_fill(data, 5000, 21);
	for (uint8_t d = 1; d < 3; d++) {
		EZ_CHECK_EQ(CALL(b, create, d, lname), EZ_OK);
		EZ_CHECK_EQ(CALL(b, append, d, lname, data, 5000), EZ_OK);
		char name[EZ_NAME_MAX];
		uint32_t sz;
		int seen = 0;
		for (uint32_t i = 0; CALL(b, list, d, i, name, &sz) == EZ_OK; i++)
			if (strcmp(name, lname) == 0) { seen = 1; EZ_CHECK_EQ(sz, 5000); }
		EZ_CHECK_MSG(seen, "long UTF-8 name not listed verbatim");
		EZ_CHECK_EQ(CALL(b, rename, d, lname, "A0B1C2D3.KEY"), EZ_OK);
		EZ_CHECK_EQ(CALL(b, size, d, "a0b1c2d3.key", &sz), EZ_OK);       /* case-insensitive */
		EZ_CHECK_EQ(sz, 5000);
		EZ_CHECK_EQ(CALL(b, read, d, "A0B1C2D3.KEY", 0, back, 5000), EZ_OK);
		EZ_CHECK(memcmp(back, data, 5000) == 0);
		/* 255 bytes: accepted. 256: refused, not truncated. */
		char n255[256], n256[257];
		memset(n255, 'k', 255); n255[255] = 0; memcpy(n255 + 251, ".key", 4);
		memset(n256, 'k', 256); n256[256] = 0;
		EZ_CHECK_EQ(CALL(b, create, d, n255), EZ_OK);
		EZ_CHECK_EQ(CALL(b, size, d, n255, &sz), EZ_OK);
		EZ_CHECK_EQ(CALL(b, create, d, n256), EZ_ERR_BAD_REQUEST);
		EZ_CHECK_EQ(CALL(b, rename, d, n255, n256), EZ_ERR_BAD_REQUEST);
		EZ_CHECK_EQ(CALL(b, size, d, n255, &sz), EZ_OK);                  /* untouched */
		port_buffers_clear(b);
	}
}
FOR_BACKENDS(conf_long_names)

/* ---- a complete device over FatFs ------------------------------------ */

typedef struct {
	sim_fram_t fram;
	sim_trng_t trng;
	ez_core_t  c;
	uint8_t    stage[EZ_STAGE_SIZE];
} fatdev_t;

static fatdev_t *fatdev_new_fs(uint64_t seed, int exfat)
{
	if (exfat) exfat_fresh(); else fat_fresh();
	fatdev_t *d = calloc(1, sizeof *d);
	sim_fram_init(&d->fram, 0xFF);
	sim_trng_init(&d->trng, seed);
	EZ_CHECK_EQ(ez_core_init(&d->c, &d->fram.hal, &g_fat.hal, &d->trng.hal,
	                         d->stage, sizeof d->stage), EZ_OK);
	EZ_CHECK_EQ(ez_device_erase(&d->c), EZ_OK);
	EZ_CHECK_EQ(ez_ks_fatfs_mount(&g_fat, 1), EZ_OK);    /* (device erase leaves the card mounted) */
	return d;
}

static fatdev_t *fatdev_new(uint64_t seed) { return fatdev_new_fs(seed, 0); }

static void fatdev_reboot(fatdev_t *d)
{
	sim_fram_power_on(&d->fram);
	for (uint8_t i = 0; i < 3; i++) ez_ks_fatfs_mount(&g_fat, i);
	ez_core_init(&d->c, &d->fram.hal, &g_fat.hal, &d->trng.hal, d->stage, sizeof d->stage);
}

static ez_status_t run_keygen(ez_core_t *c, uint8_t drive, uint32_t len, uint32_t *id)
{
	ez_keygen_t kg;
	ez_status_t st = ez_keygen_start(c, &kg, drive, len);
	while (st == EZ_PENDING) st = ez_keygen_step(c, &kg, 16);
	*id = kg.key_id;
	return st;
}

static uint8_t pt[100000], msg[100100], dec[100000];

/* Keygen on FatFs; exchange with a simulator-backed peer both ways. */
static void t_fatfs_device_interop(void)
{
	fatdev_t *a = fatdev_new(0xFA7);
	uint32_t id;
	EZ_CHECK_EQ(run_keygen(&a->c, 1, 262144, &id), EZ_OK);
	int sa = -1;
	EZ_CHECK_EQ(ez_session_create(&a->c, id, 1, EZ_ROLE_DEFAULT, "bob", &sa), EZ_OK);
	EZ_CHECK_EQ(a->c.meta.s[sa].role, EZ_ROLE_ALICE);
	/* "Physical transfer" of the key to bob's (simulator) device. */
	ezdev_t *b = dev_new(0xB0B);
	static uint8_t key[262144];
	char name[EZ_FNAME_MAX];
	ez_key_name(id, "KEY", name);
	EZ_CHECK_EQ(g_fat.hal.read(&g_fat, 1, name, 0, key, sizeof key), EZ_OK);
	sim_ks_put(&b->ks, 1, name, key, sizeof key);
	static uint8_t sum[EZ_SUM_HDR + 8 * 64];
	char sname[EZ_FNAME_MAX];
	ez_key_name(id, "SUM", sname);
	uint32_t ssz = ez_sum_size(sizeof key);
	EZ_CHECK_EQ(g_fat.hal.read(&g_fat, 1, sname, 0, sum, ssz), EZ_OK);
	sim_ks_put(&b->ks, 1, sname, sum, ssz);
	int sb = dev_session(b, id, 1, EZ_ROLE_DEFAULT, "alice");
	EZ_CHECK_EQ(b->c.meta.s[sb].role, EZ_ROLE_BOB);
	uint32_t n, m;
	for (int r = 0; r < 4; r++) {
		uint32_t len = r == 3 ? 100000 : 1000u * (uint32_t)(r + 1);
		sim_fill(pt, len, (uint64_t)r);
		/* alice (FatFs) -> bob */
		uint8_t *p = ez_stage_plaintext(&a->c, len);
		const uint8_t *o;
		if (len <= EZ_BUFFERED_MAX) {
			memcpy(p, pt, len);
			EZ_CHECK_EQ(ez_encrypt_buffered(&a->c, sa, len, &o, &n), EZ_OK);
			memcpy(msg, o, n);
			ez_release(&a->c);
		} else {
			ez_release(&a->c);
			ez_stream_t s;
			EZ_CHECK_EQ(ez_enc_stream_begin(&a->c, &s, sa, len, msg), EZ_OK);
			for (uint32_t i = 0; i < len; i += 58) {
				uint32_t c = len - i < 58 ? len - i : 58;
				memcpy(msg + 16 + i, pt + i, c);
				EZ_CHECK_EQ(ez_enc_stream_update(&a->c, &s, msg + 16 + i, c), EZ_OK);
			}
			EZ_CHECK_EQ(ez_enc_stream_end(&a->c, &s, msg + 16 + len), EZ_OK);
			n = len + EZ_MSG_OVERHEAD;
		}
		EZ_CHECK_EQ(dev_decrypt_stream(b, -1, msg, n, 61, dec, &m), EZ_OK);
		EZ_CHECK(m == len && memcmp(dec, pt, len) == 0);
		/* bob -> alice (FatFs) */
		EZ_CHECK_EQ(dev_encrypt_stream(b, sb, pt, len, 58, msg, &n), EZ_OK);
		if (len <= EZ_BUFFERED_MAX) {
			p = ez_stage_message(&a->c, n);
			memcpy(p, msg, n);
			EZ_CHECK_EQ(ez_decrypt_buffered(&a->c, -1, n, &o, &m), EZ_OK);
			EZ_CHECK(m == len && memcmp(o, pt, len) == 0);
			ez_release(&a->c);
		} else {
			ez_stream_t s;
			EZ_CHECK_EQ(ez_dec_stream_begin(&a->c, &s, -1, msg), EZ_OK);
			for (uint32_t i = 0; i < len; i += 61) {
				uint32_t c = len - i < 61 ? len - i : 61;
				memcpy(dec + i, msg + 16 + i, c);
				EZ_CHECK_EQ(ez_dec_stream_update(&a->c, &s, dec + i, c), EZ_OK);
			}
			EZ_CHECK_EQ(ez_dec_stream_end(&a->c, &s, msg + 16 + len), EZ_OK);
			EZ_CHECK(memcmp(dec, pt, len) == 0);
		}
		DEV_KBUF_CLEAR(b);
		EZ_CHECK(ez_is_zero(a->c.kbuf, sizeof a->c.kbuf));
	}
	/* Offsets survive a reboot over FatFs. */
	uint32_t tx = a->c.meta.s[sa].tx_off, rx = a->c.meta.s[sa].rx_off;
	fatdev_reboot(a);
	EZ_CHECK_EQ(a->c.meta.s[sa].state, EZ_SS_VALID);
	EZ_CHECK_EQ(a->c.meta.s[sa].tx_off, tx);
	EZ_CHECK_EQ(a->c.meta.s[sa].rx_off, rx);
	/* SEC-PTR-004 on a real filesystem: no key bytes remain on the card. */
	EZ_CHECK_EQ(ez_session_delete(&a->c, sa, false), EZ_OK);
	for (uint32_t o = 0; o + 32 <= sizeof key; o += 4096)
		EZ_CHECK_MSG(!sim_bd_contains(&g_bd[1], key + o, 32), "deleted key bytes remain on the card");
	dev_free(b);
	free(a);
}

/* SEC-TEST-MEDIA-001 (a) over FatFs: the card disappears before each of the
 * block-device calls a buffered encryption makes (FatFs's own sector reads
 * included). */
static void removal_sweep(int exfat)
{
	fatdev_t *a = fatdev_new_fs(0xFA8, exfat);
	uint32_t id;
	EZ_CHECK_EQ(run_keygen(&a->c, 1, 65536, &id), EZ_OK);
	int s = -1;
	EZ_CHECK_EQ(ez_session_create(&a->c, id, 1, EZ_ROLE_ALICE, "x", &s), EZ_OK);
	sim_fill(pt, 3000, 3);
	unsigned long k;
	for (k = 0; k < 5000; k++) {
		uint32_t tx = a->c.meta.s[s].tx_off;
		sim_bd_remove_after(&g_bd[1], (long)k);
		unsigned long before = g_bd[1].calls;
		uint8_t *p = ez_stage_plaintext(&a->c, 3000);
		memcpy(p, pt, 3000);
		const uint8_t *o; uint32_t n;
		ez_status_t st = ez_encrypt_buffered(&a->c, s, 3000, &o, &n);
		unsigned long used = g_bd[1].calls - before;
		EZ_CHECK(ez_is_zero(a->c.kbuf, sizeof a->c.kbuf));
		if (st == EZ_OK) {
			EZ_CHECK(used <= k);
			EZ_CHECK_EQ(a->c.meta.s[s].tx_off, tx + 3000);
			break;
		}
		EZ_CHECK_MSG(st == EZ_ERR_MEDIA_REMOVED, "removal not reported as removal");
		EZ_CHECK(o == NULL && ez_is_zero(a->stage, sizeof a->stage));
		EZ_CHECK_EQ(a->c.meta.s[s].tx_off, tx);
		sim_bd_insert(&g_bd[1]);
		g_bd[1].remove_after = -1;
		fatdev_reboot(a);
		EZ_CHECK_EQ(a->c.meta.s[s].state, EZ_SS_VALID);
	}
	EZ_CHECK(k > 3 && k < 5000);
	ez_test_note("%s: removal injected before each of %lu block-device calls",
	             exfat ? "exFAT" : "FAT", k);
	free(a);
}
static void t_fatfs_removal_sweep(void) { removal_sweep(0); removal_sweep(1); }

/* IMPL-FS-001: keys on drive 0 never share an erase block; disabling the
 * drive leaves no key bytes in flash (IMPL-DRV-002). */
static void t_fatfs_drive0(void)
{
	fatdev_t *a = fatdev_new(0xFA9);
	EZ_CHECK_EQ(ez_drive_enable0(&a->c), EZ_OK);
	uint32_t id1, id2;
	EZ_CHECK_EQ(run_keygen(&a->c, 0, 8192 + 512, &id1), EZ_OK);
	EZ_CHECK_EQ(run_keygen(&a->c, 0, 9216, &id2), EZ_OK);
	static uint8_t k1[9216], k2[9216];
	char n1[EZ_FNAME_MAX], n2[EZ_FNAME_MAX];
	ez_key_name(id1, "KEY", n1); ez_key_name(id2, "KEY", n2);
	EZ_CHECK_EQ(g_fat.hal.read(&g_fat, 0, n1, 0, k1, 8704), EZ_OK);
	EZ_CHECK_EQ(g_fat.hal.read(&g_fat, 0, n2, 0, k2, 9216), EZ_OK);
	/* Locate both keys' 4 KiB blocks in raw flash: no block holds bytes
	 * of both. */
	size_t total = (size_t)g_bd[0].sectors * 4096;
	int owner_conflict = 0, found1 = 0, found2 = 0;
	for (size_t blk = 0; blk < total; blk += 4096) {
		int has1 = 0, has2 = 0;
		for (uint32_t o = 0; o + 16 <= 8704; o += 16) {
			if (memmem(g_bd[0].mem + blk, 4096, k1 + o, 16)) { has1 = 1; break; }
		}
		for (uint32_t o = 0; o + 16 <= 9216; o += 16) {
			if (memmem(g_bd[0].mem + blk, 4096, k2 + o, 16)) { has2 = 1; break; }
		}
		found1 += has1; found2 += has2;
		if (has1 && has2) owner_conflict = 1;
	}
	EZ_CHECK_EQ(found1, 3);           /* 8704 bytes -> 3 blocks */
	EZ_CHECK_EQ(found2, 3);           /* 9216 bytes -> 3 blocks */
	EZ_CHECK_MSG(!owner_conflict, "two keys share an erase block");
	EZ_CHECK_EQ(ez_drive_disable0(&a->c), EZ_OK);
	for (uint32_t o = 0; o + 32 <= 8704; o += 512)
		EZ_CHECK(!sim_bd_contains(&g_bd[0], k1 + o, 32));
	for (uint32_t o = 0; o + 32 <= 9216; o += 512)
		EZ_CHECK(!sim_bd_contains(&g_bd[0], k2 + o, 32));
	free(a);
}

/* SEC-TEST-PTR-004 over FatFs: the card disappears before each block-device
 * call of a session deletion (FatFs erases cluster by cluster). The session
 * is never usable over a partly erased key, and the deletion completes
 * once the card is back, leaving no key bytes on the medium. */
static void delete_sweep(int exfat)
{
	unsigned long k;
	for (k = 0; k < 400; k++) {
		fatdev_t *a = fatdev_new_fs(0xFAA, exfat);
		uint32_t id;
		EZ_CHECK_EQ(run_keygen(&a->c, 1, 16384, &id), EZ_OK);
		int s = -1;
		EZ_CHECK_EQ(ez_session_create(&a->c, id, 1, EZ_ROLE_BOB, "x", &s), EZ_OK);
		static uint8_t key[16384];
		char name[EZ_FNAME_MAX];
		ez_key_name(id, "KEY", name);
		EZ_CHECK_EQ(g_fat.hal.read(&g_fat, 1, name, 0, key, sizeof key), EZ_OK);
		sim_bd_remove_after(&g_bd[1], (long)k);
		ez_status_t st = ez_session_delete(&a->c, s, false);
		g_bd[1].remove_after = -1;
		sim_bd_insert(&g_bd[1]);
		fatdev_reboot(a);
		const ez_session_t *ss = &a->c.meta.s[s];
		/* Completed: directly, or at the reboot with the card back
		 * (IMPL-INT-001). Never usable over a partly erased key. */
		EZ_CHECK_MSG(ss->state == EZ_SS_EMPTY, "interrupted deletion not completed");
		EZ_CHECK(!ez_core_intent_pending(&a->c));
		for (uint32_t o = 0; o + 32 <= sizeof key; o += 1024)
			EZ_CHECK_MSG(!sim_bd_contains(&g_bd[1], key + o, 32), "key bytes remain after deletion");
		free(a);
		if (st == EZ_OK) break;
	}
	EZ_CHECK(k > 3 && k < 400);
	ez_test_note("%s: deletion interrupted before each of %lu block-device calls",
	             exfat ? "exFAT" : "FAT", k);
}
static void t_fatfs_delete_sweep(void) { delete_sweep(0); delete_sweep(1); }

/* A device whose card is exFAT: generate, import a long-named key from
 * another source, exchange messages, delete without leaving key bytes. */
static void t_exfat_device(void)
{
	fatdev_t *a = fatdev_new_fs(0xEF1, 1);
	EZ_CHECK_EQ(g_fat.fs[1].fs_type, FS_EXFAT);
	uint32_t id;
	EZ_CHECK_EQ(run_keygen(&a->c, 1, 65536, &id), EZ_OK);
	int sa = -1;
	EZ_CHECK_EQ(ez_session_create(&a->c, id, 1, EZ_ROLE_DEFAULT, "own", &sa), EZ_OK);
	/* A key received from another source, under a long name. */
	static uint8_t foreign[32768];
	sim_fill(foreign, sizeof foreign, 0xF0E);
	static const char *fname = "key from alice \xe2\x80\x94 meeting 2026-10-05.bin";
	EZ_CHECK_EQ(g_fat.hal.create(&g_fat, 1, fname), EZ_OK);
	EZ_CHECK_EQ(g_fat.hal.append(&g_fat, 1, fname, foreign, sizeof foreign), EZ_OK);
	ez_import_t im;
	ez_status_t ist = ez_import_start(&a->c, &im, 1, fname, 0x00ABCDEF, EZ_ROLE_BOB, "alice");
	while (ist == EZ_PENDING) ist = ez_import_step(&a->c, &im, 4);
	EZ_CHECK_EQ(ist, EZ_OK);
	int sb = im.slot;
	uint32_t sz;
	EZ_CHECK_EQ(g_fat.hal.size(&g_fat, 1, fname, &sz), EZ_ERR_NOT_FOUND);       /* renamed */
	EZ_CHECK_EQ(g_fat.hal.size(&g_fat, 1, "00ABCDEF.KEY", &sz), EZ_OK);
	/* The peer (simulator device) holding the same foreign key as alice. */
	ezdev_t *p = dev_new(0xEF2);
	sim_ks_put(&p->ks, 1, "00ABCDEF.KEY", foreign, sizeof foreign);
	put_sum(&p->ks, 1, 0x00ABCDEF, foreign, sizeof foreign, 0x5A5A);
	int sp = dev_session(p, 0x00ABCDEF, 1, EZ_ROLE_ALICE, "bob");
	uint32_t n, m;
	sim_fill(pt, 5000, 1);
	EZ_CHECK_EQ(dev_encrypt(p, sp, pt, 5000, msg, &n), EZ_OK);
	uint8_t *st = ez_stage_message(&a->c, n);
	memcpy(st, msg, n);
	const uint8_t *o;
	EZ_CHECK_EQ(ez_decrypt_buffered(&a->c, -1, n, &o, &m), EZ_OK);
	EZ_CHECK(m == 5000 && memcmp(o, pt, 5000) == 0);
	ez_release(&a->c);
	/* Offsets survive a reboot; deletion leaves no key bytes on exFAT. */
	fatdev_reboot(a);
	EZ_CHECK_EQ(a->c.meta.s[sb].rx_off, 5000);
	EZ_CHECK_EQ(ez_session_delete(&a->c, sb, false), EZ_OK);
	for (uint32_t off = 0; off + 32 <= sizeof foreign; off += 1024)
		EZ_CHECK_MSG(!sim_bd_contains(&g_bd[1], foreign + off, 32), "key bytes remain on exFAT");
	EZ_CHECK_EQ(a->c.meta.s[sa].state, EZ_SS_VALID);
	dev_free(p);
	free(a);
}

static const ez_test_case_t cases[] = {
	{ "conf_files",             "ez_hal_keystore contract, SEC-FW-003", t_conf_files },
	{ "conf_rename_zap_list",   "ez_hal_keystore contract, SEC-STORE-001", t_conf_rename_zap_list },
	{ "conf_removal",           "ez_hal_keystore contract, SEC-HW-002, IMPL-ENG-010", t_conf_removal },
	{ "conf_wipe",              "ez_hal_keystore contract, SEC-STORE-001, IMPL-DRV-002", t_conf_wipe },
	{ "conf_long_names",        "ez_hal_keystore contract (names), IMPL-KEY-004", t_conf_long_names },
	{ "exfat_device",           "SEC-ENC-001, SEC-DEC-001, SEC-PTR-004 (exFAT), IMPL-KEY-004", t_exfat_device },
	{ "fatfs_device_interop",   "SEC-ENC-001, SEC-DEC-001, SEC-PTR-004 (FatFs), SEC-STORE-001", t_fatfs_device_interop },
	{ "fatfs_removal_sweep",    "SEC-TEST-MEDIA-001 (a) (FAT, exFAT), SEC-HW-002", t_fatfs_removal_sweep },
	{ "fatfs_delete_sweep",     "SEC-TEST-PTR-004 (FAT, exFAT), SEC-PTR-004", t_fatfs_delete_sweep },
	{ "fatfs_drive0",           "IMPL-FS-001, IMPL-DRV-002, SEC-STORE-001", t_fatfs_drive0 },
};
EZ_TEST_MAIN(cases)
