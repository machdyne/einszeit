/*
 * vdev.c -- virtual Einszeit device, for tests only
 *
 *   ez-vdev <state-dir> [--socket <path>] [--mirror] [--term <path>] [--worker] [--trng-rate <B/s>]
 *
 * --worker:    run jobs on a second thread, as the device runs them on core 1
 * --trng-rate: slow key generation down, to watch and interrupt it in tests
 *
 * --term: serve the terminal interface (EZ-UI-001) on a second socket;
 *         connect with: socat -,raw,echo=0 UNIX-CONNECT:<path>
 *
 * --mirror: drive 1 is kept as two copies, drive1/ and drive2/ (SEC-AVAIL-003).
 *
 * Runs the production core and protocol dispatcher on the host over
 * persistent state, reachable through a Unix socket that carries the same
 * 64-byte frames as USB HID. `ez --virtual <path>` talks to it.
 *
 *   <state-dir>/fram.bin    2 KiB metadata store (F-RAM)
 *   <state-dir>/flash.bin   2 MiB drive 0 flash (NOR semantics)
 *   <state-dir>/drive1/     drive 1 (the "card"); remove the directory to
 *   <state-dir>/drive2/       simulate removal
 *
 * FOR TESTING ONLY. Keys generated here come from the operating system's
 * random generator, not a hardware TRNG, and the state files are ordinary
 * files. Never use a virtual device for real secrets. Its TRNG profile is
 * 0xEE, recorded in every generation event.
 *
 * POSIX (Linux, macOS).
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "ez_core.h"
#include "ez_dispatch.h"
#include "ez_ks_mirror.h"
#include "ez_ui.h"
#include "ez_ks_route.h"
#include "ez_secure.h"
#include "ez_store0.h"

#define FRAM_SIZE   2048u
#define FLASH_BLKS  512u

static char base[4096];
static int fram_fd = -1, flash_fd = -1;

static void die(const char *what) { perror(what); exit(1); }

static int open_sized(const char *name, size_t size, uint8_t fill)
{
	char p[4200];
	snprintf(p, sizeof p, "%s/%s", base, name);
	int fd = open(p, O_RDWR | O_CREAT, 0600);
	if (fd < 0) die(p);
	struct stat st;
	if (fstat(fd, &st) != 0) die(p);
	if ((size_t)st.st_size != size) {
		uint8_t ff[4096];
		memset(ff, fill, sizeof ff);
		if (ftruncate(fd, 0) != 0) die(p);
		for (size_t o = 0; o < size; o += sizeof ff)
			if (pwrite(fd, ff, size - o < sizeof ff ? size - o : sizeof ff, (off_t)o) < 0) die(p);
	}
	return fd;
}

static int full_pread(int fd, void *b, size_t n, off_t o)  { return pread(fd, b, n, o) == (ssize_t)n ? 0 : -1; }
static int full_pwrite(int fd, const void *b, size_t n, off_t o) { return pwrite(fd, b, n, o) == (ssize_t)n ? 0 : -1; }

/* ---- F-RAM ------------------------------------------------------------------ */
static ez_status_t fr_read(void *c, uint32_t a, void *b, uint32_t n)
{ (void)c; return a <= FRAM_SIZE && n <= FRAM_SIZE - a && !full_pread(fram_fd, b, n, a) ? EZ_OK : EZ_ERR_META; }
static ez_status_t fr_write(void *c, uint32_t a, const void *b, uint32_t n)
{ (void)c; return a <= FRAM_SIZE && n <= FRAM_SIZE - a && !full_pwrite(fram_fd, b, n, a) ? EZ_OK : EZ_ERR_META; }
static const ez_hal_meta_t fram = { NULL, FRAM_SIZE, fr_read, fr_write };

/* ---- flash (NOR: erase to 0xFF, program clears bits) --------------------------- */
static ez_status_t fl_read(void *c, uint32_t a, void *b, uint32_t n)
{ (void)c; return !full_pread(flash_fd, b, n, a) ? EZ_OK : EZ_ERR_MEDIA; }
static ez_status_t fl_erase(void *c, uint32_t blk)
{
	(void)c;
	uint8_t ff[EZ_FLASH_BLOCK];
	memset(ff, 0xFF, sizeof ff);
	return blk < FLASH_BLKS && !full_pwrite(flash_fd, ff, sizeof ff, (off_t)blk * EZ_FLASH_BLOCK) ? EZ_OK : EZ_ERR_MEDIA;
}
static ez_status_t fl_program(void *c, uint32_t a, const void *b, uint32_t n)
{
	(void)c;
	uint8_t cur[EZ_FLASH_BLOCK];
	const uint8_t *p = b;
	while (n) {
		uint32_t k = n < sizeof cur ? n : sizeof cur;
		if (full_pread(flash_fd, cur, k, a)) return EZ_ERR_MEDIA;
		for (uint32_t i = 0; i < k; i++) cur[i] &= p[i];
		if (full_pwrite(flash_fd, cur, k, a)) return EZ_ERR_MEDIA;
		a += k; p += k; n -= k;
	}
	ez_secure_zero(cur, sizeof cur);
	return EZ_OK;
}
static const ez_flash_t flash = { NULL, FLASH_BLKS, fl_read, fl_erase, fl_program };

/* ---- drives 1 and 2 as directories (FatFs-like: case-insensitive names) ------------- */
static void drive_dir(uint8_t d, char *out, size_t cap) { snprintf(out, cap, "%s/drive%u", base, d); }

static bool name_ok(const char *n)
{
	size_t l = strlen(n);
	return l > 0 && l < EZ_NAME_MAX && !strchr(n, '/') && strcmp(n, ".") && strcmp(n, "..");
}

/* Find the actual file name matching `name` case-insensitively. */
static bool resolve(uint8_t d, const char *name, char *path, size_t cap)
{
	char dir[4200];
	drive_dir(d, dir, sizeof dir);
	DIR *h = opendir(dir);
	if (!h) return false;
	struct dirent *e;
	bool found = false;
	while ((e = readdir(h)) != NULL)
		if (strcasecmp(e->d_name, name) == 0) { snprintf(path, cap, "%s/%s", dir, e->d_name); found = true; break; }
	closedir(h);
	return found;
}

static bool dk_present(void *c, uint8_t d)
{
	(void)c;
	char dir[4200];
	struct stat st;
	drive_dir(d, dir, sizeof dir);
	return d >= 1 && d <= 2 && stat(dir, &st) == 0 && S_ISDIR(st.st_mode);
}
static ez_status_t dk_check(void *c, uint8_t d) { return dk_present(c, d) ? EZ_OK : EZ_ERR_MEDIA_REMOVED; }
static ez_status_t dk_size(void *c, uint8_t d, const char *n, uint32_t *size)
{
	char p[4500];
	struct stat st;
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(n)) return EZ_ERR_BAD_REQUEST;
	if (!resolve(d, n, p, sizeof p) || stat(p, &st) != 0) return EZ_ERR_NOT_FOUND;
	if (st.st_size > 0xFFFFFFFFll) return EZ_ERR_KEY_PARAM;
	*size = (uint32_t)st.st_size;
	return EZ_OK;
}
static ez_status_t dk_read(void *c, uint8_t d, const char *n, uint32_t o, void *b, uint32_t len)
{
	char p[4500];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(n) || !resolve(d, n, p, sizeof p)) return EZ_ERR_NOT_FOUND;
	int fd = open(p, O_RDONLY);
	if (fd < 0) return EZ_ERR_NOT_FOUND;
	struct stat st;
	ez_status_t r = fstat(fd, &st) == 0 && (uint64_t)o + len <= (uint64_t)st.st_size
	                ? (full_pread(fd, b, len, o) ? EZ_ERR_MEDIA : EZ_OK) : EZ_ERR_RANGE;
	close(fd);
	return r;
}
static ez_status_t dk_create(void *c, uint8_t d, const char *n)
{
	char p[4500], dir[4200];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(n)) return EZ_ERR_BAD_REQUEST;
	if (resolve(d, n, p, sizeof p)) return EZ_ERR_EXISTS;
	drive_dir(d, dir, sizeof dir);
	snprintf(p, sizeof p, "%s/%s", dir, n);
	int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) return EZ_ERR_MEDIA;
	fsync(fd);
	close(fd);
	return EZ_OK;
}
static ez_status_t dk_append(void *c, uint8_t d, const char *n, const void *b, uint32_t len)
{
	char p[4500];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(n) || !resolve(d, n, p, sizeof p)) return EZ_ERR_NOT_FOUND;
	int fd = open(p, O_WRONLY | O_APPEND);
	if (fd < 0) return EZ_ERR_MEDIA;
	ez_status_t r = write(fd, b, len) == (ssize_t)len && fsync(fd) == 0 ? EZ_OK : EZ_ERR_MEDIA;
	close(fd);
	return r;
}
static ez_status_t dk_rename(void *c, uint8_t d, const char *from, const char *to)
{
	char p[4500], q[4500], dir[4200];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(from) || !name_ok(to)) return EZ_ERR_BAD_REQUEST;
	if (!resolve(d, from, p, sizeof p)) return EZ_ERR_NOT_FOUND;
	if (resolve(d, to, q, sizeof q) && strcasecmp(from, to) != 0) return EZ_ERR_EXISTS;
	drive_dir(d, dir, sizeof dir);
	snprintf(q, sizeof q, "%s/%s", dir, to);
	return rename(p, q) == 0 ? EZ_OK : EZ_ERR_MEDIA;
}
/* SEC-STORE-001: overwrite with zeros and sync before unlinking. On a real
 * card the FatFs port does the same in place; on a host file system the
 * underlying blocks are outside our control (test use only). */
static ez_status_t dk_zap(void *c, uint8_t d, const char *n)
{
	char p[4500];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	if (!name_ok(n) || !resolve(d, n, p, sizeof p)) return EZ_ERR_NOT_FOUND;
	int fd = open(p, O_WRONLY);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0) { if (fd >= 0) close(fd); return EZ_ERR_MEDIA; }
	uint8_t z[4096] = { 0 };
	for (off_t o = 0; o < st.st_size; o += (off_t)sizeof z) {
		size_t k = st.st_size - o < (off_t)sizeof z ? (size_t)(st.st_size - o) : sizeof z;
		if (full_pwrite(fd, z, k, o)) { close(fd); return EZ_ERR_MEDIA; }
	}
	fsync(fd);
	close(fd);
	return unlink(p) == 0 ? EZ_OK : EZ_ERR_MEDIA;
}
static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static ez_status_t dk_list(void *c, uint8_t d, uint32_t index, char name[EZ_NAME_MAX], uint32_t *size)
{
	char dir[4200], p[4500];
	if (!dk_present(c, d)) return EZ_ERR_MEDIA_REMOVED;
	drive_dir(d, dir, sizeof dir);
	DIR *h = opendir(dir);
	if (!h) return EZ_ERR_MEDIA_REMOVED;
	char *names[1024];
	size_t n = 0;
	struct dirent *e;
	while ((e = readdir(h)) != NULL && n < 1024) {
		snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
		struct stat st;
		if (e->d_name[0] == '.' || stat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
		names[n++] = strdup(e->d_name);
	}
	closedir(h);
	qsort(names, n, sizeof names[0], cmpstr);          /* stable order for indices */
	ez_status_t r = EZ_ERR_NOT_FOUND;
	if (index < n && strlen(names[index]) < EZ_NAME_MAX) {
		struct stat st;
		snprintf(p, sizeof p, "%s/%s", dir, names[index]);
		memset(name, 0, EZ_NAME_MAX);
		memcpy(name, names[index], strlen(names[index]));
		*size = stat(p, &st) == 0 ? (uint32_t)st.st_size : 0;
		r = EZ_OK;
	}
	for (size_t i = 0; i < n; i++) free(names[i]);
	return r;
}
static ez_status_t dk_wipe(void *c, uint8_t d)
{
	char name[EZ_NAME_MAX];
	uint32_t size;
	while (dk_list(c, d, 0, name, &size) == EZ_OK)
		if (dk_zap(c, d, name) != EZ_OK) return EZ_ERR_MEDIA;
	return dk_present(c, d) ? EZ_OK : EZ_ERR_MEDIA_REMOVED;
}
static const ez_hal_keystore_t dirks = { NULL, dk_present, dk_check, dk_size, dk_read, dk_create,
                                         dk_append, dk_rename, dk_zap, dk_list, dk_wipe, NULL };

/* ---- "TRNG": the OS generator, clearly labelled ---------------------------------- */
static int urandom_fd = -1;
static uint32_t trng_rate;              /* --trng-rate: bytes per second, 0 unlimited */
static ez_status_t tr_read(void *c, void *b, uint32_t n)
{
	(void)c;
	uint8_t *p = b;
	if (trng_rate) usleep((useconds_t)((uint64_t)n * 1000000u / trng_rate));
	while (n) {
		ssize_t k = read(urandom_fd, p, n);
		if (k <= 0) return EZ_ERR_ENTROPY;
		p += k; n -= (uint32_t)k;
	}
	return EZ_OK;
}
static const ez_hal_trng_t trng = { NULL, 0xEE, tr_read };

static uint32_t host_time(void *c, bool *host) { (void)c; *host = true; return (uint32_t)time(NULL); }

/* IMPL-AV-007: "formatting" a virtual card empties its directories. The
 * number of copies is fixed when ez-vdev starts (--mirror). */
static bool vdev_mirrored;
static ez_status_t vdev_format(void *ctx, uint8_t drive, uint8_t copies)
{
	(void)ctx;
	if (drive != 1) return EZ_ERR_BAD_REQUEST;
	if (copies != (vdev_mirrored ? 2 : 1)) return EZ_ERR_UNSUPPORTED;
	ez_status_t st = dk_wipe(NULL, 1);
	if (st == EZ_OK && vdev_mirrored) st = dk_wipe(NULL, 2);
	return st;
}

/* ---- socket loop ----------------------------------------------------------------- */
static int client = -1;
static void send_frame(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	(void)ctx;
	if (client >= 0 && write(client, f, EZ_FRAME_SIZE) != EZ_FRAME_SIZE) { close(client); client = -1; }
}

static int read_frame(int fd, uint8_t f[EZ_FRAME_SIZE])
{
	size_t got = 0;
	while (got < EZ_FRAME_SIZE) {
		ssize_t k = read(fd, f + got, EZ_FRAME_SIZE - got);
		if (k <= 0) return -1;
		got += (size_t)k;
	}
	return 0;
}

static ez_store0_t store0;
static ez_ks_route_t route;
static ez_ks_mirror_t mirror;
static ez_core_t core;
static uint8_t stage[EZ_STAGE_SIZE];
static ez_dispatch_t disp;
static const ez_devinfo_t info = { "virtual-0.1", 0xEE, 0, EZ_BUILD_VIRTUAL };

static ez_ui_t ui;
static int *ui_fd;

/* --worker: the second core, as a thread. */
static void *worker_main(void *arg)
{
	(void)arg;
	for (;;) {
		if (ez_dispatch_job_pending(&disp)) ez_dispatch_job_run(&disp);
		else usleep(1000);
	}
	return NULL;
}
static void ui_write(void *ctx, const char *b, uint32_t n)
{
	(void)ctx;
	if (ui_fd && *ui_fd >= 0)
		while (n) { ssize_t k = write(*ui_fd, b, n); if (k <= 0) return; b += k; n -= (uint32_t)k; }
}

int main(int argc, char **argv)
{
	const char *sock = NULL, *term = NULL;
	bool worker = false;
	if (argc < 2) { fprintf(stderr, "usage: ez-vdev <state-dir> [--socket <path>]\n"); return 2; }
	snprintf(base, sizeof base, "%s", argv[1]);
	bool mirrored = false;
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock = argv[++i];
		else if (!strcmp(argv[i], "--mirror")) mirrored = true;
		else if (!strcmp(argv[i], "--term") && i + 1 < argc) term = argv[++i];
		else if (!strcmp(argv[i], "--worker")) worker = true;
		else if (!strcmp(argv[i], "--trng-rate") && i + 1 < argc) trng_rate = (uint32_t)atoi(argv[++i]);
	}
	char sockbuf[4200];
	if (!sock) { snprintf(sockbuf, sizeof sockbuf, "%s/ez.sock", base); sock = sockbuf; }
	mkdir(base, 0700);
	char d1[4200];
	drive_dir(1, d1, sizeof d1);
	mkdir(d1, 0700);
	if (mirrored) { drive_dir(2, d1, sizeof d1); mkdir(d1, 0700); }
	signal(SIGPIPE, SIG_IGN);
	if ((urandom_fd = open("/dev/urandom", O_RDONLY)) < 0) die("/dev/urandom");
	fram_fd = open_sized("fram.bin", FRAM_SIZE, 0x00);          /* a new device: uninitialised */
	flash_fd = open_sized("flash.bin", (size_t)FLASH_BLKS * EZ_FLASH_BLOCK, 0xFF);   /* erased NOR */

	core.meta.time_fn = host_time;
	vdev_mirrored = mirrored;
	core.format = vdev_format;
	ez_store0_init(&store0, &flash, &fram, EZ_META_STORE0_SEL);
	if (mirrored) {
		ez_mirror_vol_t v[2] = { { &dirks, 1 }, { &dirks, 2 } };
		ez_ks_mirror_init(&mirror, &dirks, 1, v, 2);
		ez_ks_route_init(&route, &store0.hal, &mirror.hal);
	} else {
		ez_ks_route_init(&route, &store0.hal, &dirks);
	}
	ez_core_init(&core, &fram, &route.hal, &trng, stage, sizeof stage);
	ez_dispatch_init(&disp, &core, send_frame, NULL, &info);
	disp.sync_period_ms = 2000;                       /* quick checks often, for the tests */

	int srv = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	if (srv < 0 || strlen(sock) >= sizeof a.sun_path) die("socket");
	strcpy(a.sun_path, sock);
	unlink(sock);
	if (bind(srv, (struct sockaddr *)&a, sizeof a) != 0 || listen(srv, 1) != 0) die(sock);
	fprintf(stderr,
	        "ez-vdev: virtual Einszeit device on %s (state in %s)\n"
	        "ez-vdev: TEST USE ONLY -- keys come from the OS random generator, not a TRNG.\n", sock, base);

	/* The terminal interface (EZ-UI-001) on a second socket, if asked for. */
	int tsrv = -1, tcli = -1;
	if (term) {
		tsrv = socket(AF_UNIX, SOCK_STREAM, 0);
		struct sockaddr_un ta = { .sun_family = AF_UNIX };
		snprintf(ta.sun_path, sizeof ta.sun_path, "%s", term);
		unlink(term);
		if (bind(tsrv, (struct sockaddr *)&ta, sizeof ta) != 0 || listen(tsrv, 1) != 0) die(term);
		ui_fd = &tcli;
		static char text[EZ_UI_TEXT_CAP];                  /* the editor's text (Send), uploads, downloads */
		ez_ui_env_t env = { ui_write, NULL, &core, &disp, "vdev", "virtual-device", false, NULL, NULL, text, sizeof text };
		ez_ui_init(&ui, &env);
	}
	if (worker) {
		disp.external_worker = true;
		pthread_t th;
		if (pthread_create(&th, NULL, worker_main, NULL) != 0) die("pthread_create");
	}
	uint8_t f[EZ_FRAME_SIZE];
	for (;;) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		uint32_t ms = (uint32_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
		ez_dispatch_idle(&disp, ms);                      /* background sync */
		if (term) ez_ui_tick(&ui, ms);
		struct pollfd p[3];
		int np = 0, ih = -1, its = -1, itc = -1;
		ih = np; p[np++] = (struct pollfd){ client < 0 ? srv : client, POLLIN, 0 };
		if (term) { its = np; p[np++] = (struct pollfd){ tcli < 0 ? tsrv : tcli, POLLIN, 0 }; }
		int r = poll(p, (nfds_t)np, disp.job_running && !disp.external_worker ? 0 : 50);
		if (r <= 0) { if (disp.job_running) ez_dispatch_poll(&disp, 16); continue; }
		(void)itc;
		if (p[ih].revents) {
			if (client < 0) client = accept(srv, NULL, NULL);
			else if (read_frame(client, f) != 0) { close(client); client = -1; ez_dispatch_reset(&disp); }
			else ez_dispatch_frame(&disp, f);
		}
		if (term && p[its].revents) {
			if (tcli < 0) { tcli = accept(tsrv, NULL, NULL); if (tcli >= 0) ez_ui_reset(&ui); }
			else {
				uint8_t b[256];
				ssize_t k = read(tcli, b, sizeof b);
				if (k <= 0) { close(tcli); tcli = -1; }
				else ez_ui_input(&ui, b, (uint32_t)k, ms);
			}
		}
	}
}
