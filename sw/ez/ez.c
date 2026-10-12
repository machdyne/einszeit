/*
 * ez.c -- Einszeit host CLI (EZ-IMPL-001 §10)
 *
 *   ez [--virtual <socket>] <command> ...       (or EZ_VIRTUAL=<socket>)
 *
 * Talks to a device over USB HID (vendored hidapi), or to the virtual
 * device (ez-vdev) with --virtual. Streaming for messages over 64 KiB
 * follows.
 *
 * Rules kept here:
 *   IMPL-CLI-001 / SEC-UI-003  confirmations are read from the controlling
 *                              terminal, never from standard input (which
 *                              may carry plaintext); without a terminal the
 *                              CLI refuses unless --yes is given.
 *   IMPL-CLI-003               plaintext is written only after the device
 *                              reports success.
 *   IMPL-CLI-004 / SEC-UI-001  low-capacity warnings.
 *   IMPL-CLI-005 / 006         deletion and import warnings.
 *   SEC-FW-003 (host side)     plaintext and message buffers are cleared.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "ez_base64.h"
#include "ez_bytes.h"
#include "ez_client.h"
#include "ez_core.h"
#include "ez_meta.h"
#include "ez_msg.h"
#include "ez_proto.h"
#include "transport.h"

#define TO_SHORT   10000
#define TO_LONG   600000

static ez_transport_t T;
static uint8_t rsp[EZ_STAGE_SIZE + 64];
static size_t rn;
static volatile sig_atomic_t interrupted;

static void on_sigint(int s) { (void)s; interrupted = 1; }

static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "ez: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static const char *hint(int st)
{
	switch (st) {
	case EZ_ERR_QUARANTINED: return " (the session is quarantined: see 'ez session info')";
	case EZ_ERR_CAPACITY:    return " (not enough key left in this session)";
	case EZ_ERR_DRIVE_DISABLED: return " (internal storage, drive 0, is off: 'ez drive enable 0')";
	case EZ_ERR_MEDIA_REMOVED: return " (the card is missing or was changed)";
	case EZ_ERR_UNVERIFIED:  return " (the key has no .SUM: use 'ez session import')";
	case EZ_ERR_BUSY:        return " (a key generation or import is running: 'ez key status')";
	case EZ_ERR_KEY_DAMAGED: return " (key data failed verification; for sending, 'ez session skip' moves past it)";
	case EZ_ERR_DEVICE:      return " (the device is not initialised or its record is damaged: see 'ez device info')";
	case EZ_ERR_PROTECTION:  return " (internal storage's flash protection is not in place: install the partition table, see TR-06)";
	default: return "";
	}
}

/* SEC-AVAIL-002: before every write to key storage. */
static void maintenance_warning(void)
{
	fprintf(stderr, "Writing key storage: do not disconnect the device or remove the card until this finishes.\n");
}

static void replicate_report(uint8_t st)
{
	if (st != EZ_OK)
		fprintf(stderr, "warning: not every copy of the key could be written (%s); the key works from the copies\n"
		                "that verify. Run 'ez session check' and 'ez session repair' when the storage is healthy.\n",
		        ez_status_name((ez_status_t)st));
}

/* ---- jobs and a busy device (round 16) ------------------------------------- */
static const char *cmd_word(uint8_t cmd)
{
	switch (cmd) {
	case EZ_CMD_SESSION_CREATE: return "creating the session";
	case EZ_CMD_SESSION_DELETE: return "deleting";
	case EZ_CMD_SESSION_CHECK:  return "checking";
	case EZ_CMD_SESSION_REPAIR: return "repairing";
	case EZ_CMD_KEY_COPY:       return "copying";
	case EZ_CMD_KEY_DELETE:     return "erasing";
	case EZ_CMD_DRIVE_FORMAT:   return "formatting";
	case EZ_CMD_DRIVE_REPAIR:   return "repairing the drive";
	case EZ_CMD_DRIVE_ENABLE:   return "turning internal storage on";
	case EZ_CMD_DRIVE_DISABLE:  return "erasing internal storage";
	case EZ_CMD_DEVICE_ERASE:   return "erasing the device";
	case EZ_CMD_ENTROPY_TEST:   return "testing the TRNG";
	default:                    return "working";
	}
}

/* The device's job, from the end of DEVICE_INFO (0 if none or older firmware). */
static uint8_t g_health, g_detail;
static bool g_force;
static void device_job(uint8_t *job, uint8_t *jcmd, uint16_t *pm)
{
	*job = 0; *jcmd = 0; *pm = 0;
	size_t k = 0;
	static uint8_t b[1024];
	if (ez_call(&T, EZ_CMD_DEVICE_INFO, NULL, 0, b, sizeof b, &k, TO_SHORT) != EZ_OK) return;
	ez_rd_t r;
	char fw[64];
	ez_rd_init(&r, b, k);
	ez_rd_u8(&r); ez_rd_str(&r, fw, sizeof fw);
	for (int s = 0; s < 4; s++) ez_rd_u8(&r);
	ez_rd_u32(&r);
	for (int s = 0; s < 7; s++) ez_rd_u8(&r);
	g_health = ez_rd_u8(&r); g_detail = ez_rd_u8(&r);
	uint8_t j = ez_rd_u8(&r), c = ez_rd_u8(&r);
	uint16_t p = ez_rd_u16(&r);
	if (!r.err) { *job = j; *jcmd = c; *pm = p; }
}

static void progress_line(const char *what, uint16_t pm)
{
	if (isatty(2)) fprintf(stderr, "\r%s ... %u%%   ", what, pm / 10u);
}

/* Wait while the device works on a job (it answers BUSY meanwhile). A
 * background sync makes way within a moment. */
static void wait_device(void)
{
	bool said = false;
	for (int i = 0; ; i++) {
		uint8_t job, jcmd; uint16_t pm;
		device_job(&job, &jcmd, &pm);
		if (!job) break;
		const char *what = job == 4 ? "syncing the card mirror" : job == 1 ? "generating a key" :
		                   job == 2 ? "importing a key" : cmd_word(jcmd);
		if (!said) { fprintf(stderr, "ez: device busy (%s), waiting...\n", what); said = true; }
		progress_line(what, pm);
		struct timespec ts = { 0, 300 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	if (said && isatty(2)) fprintf(stderr, "\r%40s\r", "");
}

static int call(uint8_t cmd, const uint8_t *req, size_t n, int timeout)
{
	for (;;) {
		int st = ez_call(&T, cmd, req, n, rsp, sizeof rsp, &rn, timeout);
		if (st < 0) die("%s", ez_call_error(st));
		if (st == EZ_ERR_BUSY && cmd != EZ_CMD_KEY_STATUS && cmd != EZ_CMD_JOB_RESULT) {
			wait_device();
			continue;                                    /* then ask again */
		}
		if (st == EZ_OK && ez_cmd_deferred(cmd)) {          /* a job: wait, then fetch its reply */
			uint16_t pm = 0;
			for (;;) {
				size_t k = 0;
				static uint8_t b[1024];
				int s2 = ez_call(&T, EZ_CMD_KEY_STATUS, NULL, 0, b, sizeof b, &k, TO_SHORT);
				if (s2 < 0) die("%s", ez_call_error(s2));
				ez_rd_t r; ez_wjob_t j;
				ez_rd_init(&r, b, k); ez_wjob_read(&r, &j);
				if (!j.running) break;
				if (j.permille != pm) { pm = j.permille; progress_line(cmd_word(cmd), pm); }
				struct timespec ts = { 0, 100 * 1000 * 1000 };
				nanosleep(&ts, NULL);
			}
			if (pm && isatty(2)) fprintf(stderr, "\r%40s\r", "");
			st = ez_call(&T, EZ_CMD_JOB_RESULT, NULL, 0, rsp, sizeof rsp, &rn, TO_SHORT);
			if (st < 0) die("%s", ez_call_error(st));
		}
		return st;
	}
}

static void need_ok(const char *what, int st)
{
	if (st != EZ_OK) die("%s: %s%s", what, ez_status_name((ez_status_t)st), hint(st));
}

/* ---- confirmation on the controlling terminal (IMPL-CLI-001, SEC-UI-003) ---- */
static void confirm(bool yes, const char *expect, const char *fmt, ...)
{
	if (yes) return;
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) die("no terminal for confirmation: refusing (use --yes to confirm non-interactively)");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(tty, fmt, ap);
	va_end(ap);
	fprintf(tty, "Type %s to continue: ", expect);
	fflush(tty);
	char line[64] = { 0 };
	if (!fgets(line, sizeof line, tty)) line[0] = 0;
	fclose(tty);
	line[strcspn(line, "\r\n")] = 0;
	if (strcmp(line, expect) != 0) die("cancelled");
}

/* ---- sessions ------------------------------------------------------------------------ */
static ez_wsession_t S[EZ_META_SESSIONS];
static int nS;

static void load_sessions(void)
{
	need_ok("session list", call(EZ_CMD_SESSION_LIST, NULL, 0, TO_SHORT));
	ez_rd_t r;
	ez_rd_init(&r, rsp, rn);
	nS = ez_rd_u8(&r);
	if (nS > EZ_META_SESSIONS) die("protocol error");
	for (int i = 0; i < nS; i++) ez_wsession_read(&r, &S[i]);
	if (!ez_rd_done(&r)) die("protocol error in session list");
}

static const ez_wsession_t *find(const char *label, bool for_send)
{
	load_sessions();
	const ez_wsession_t *hit = NULL;
	int usable = 0;
	for (int i = 0; i < nS; i++) {
		if (label && (S[i].flags & EZ_SF_IDENTITY) && strcmp(S[i].label, label) == 0) return &S[i];
		if (!label && S[i].state == EZ_SS_VALID) { usable++; hit = &S[i]; }
	}
	if (label) die("no session labelled '%s' ('ez session list')", label);
	if (for_send && usable == 1) return hit;
	die(usable ? "several sessions: name one" : "no usable session");
	return NULL;
}

static const char *state_name(uint8_t st)
{
	static const char *n[] = { "empty", "valid", "exhausted", "QUARANTINED" };
	return st < 4 ? n[st] : "?";
}

static void print_session(const ez_wsession_t *s, bool details)
{
	if (!(s->flags & EZ_SF_IDENTITY)) {
		printf("[%2u] ?  record damaged, QUARANTINED (reason 0x%02x): 'ez session delete' with --force\n", s->slot, s->qreason);
		return;
	}
	printf("%-15s  key %08X  drive %u  %-5s  %s", s->label, s->key_id, s->drive,
	       s->role ? "bob" : "alice", state_name(s->state));
	if (s->state == EZ_SS_QUARANTINED) printf(" (reason 0x%02x)", s->qreason);
	printf("\n");
	if (s->flags & EZ_SF_OFFSETS) {
		printf("    send: %u of %u bytes left%s    receive: %u bytes left\n", s->tx_left, s->tx_range,
		       s->flags & EZ_SF_TX_LOW ? "  ** LOW **" : "", s->rx_left);
	}
	if (details) printf("    key length %u bytes, slot %u\n", s->key_len, s->slot);
}

static uint8_t q[EZ_STAGE_SIZE + 64];

static void session_cmd(int argc, char **argv)
{
	if (argc < 1) die("session: list | info | create | import | delete | skip | resolve");
	const char *sub = argv[0], *label = argc > 1 && argv[1][0] != '-' ? argv[1] : NULL;
	uint32_t key_id = 0;
	int drive = 1, role = EZ_ROLE_DEFAULT;
	bool yes = false, force = false, critical = false;
	const char *file = NULL;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--key-id") && i + 1 < argc) key_id = (uint32_t)strtoul(argv[++i], NULL, 16);
		else if (!strcmp(argv[i], "--drive") && i + 1 < argc) drive = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--role") && i + 1 < argc) { i++; role = !strcmp(argv[i], "alice") ? EZ_ROLE_ALICE : !strcmp(argv[i], "bob") ? EZ_ROLE_BOB : -1; }
		else if (!strcmp(argv[i], "--yes")) yes = true;
		else if (!strcmp(argv[i], "--force")) force = true;
		else if (!strcmp(argv[i], "--spare") || !strcmp(argv[i], "--critical")) critical = true;   /* --critical: the old name */
		else if (argv[i][0] != '-' && i == 2) file = argv[i];
	}
	if (role < 0) die("--role must be alice or bob");
	ez_wr_t w;
	ez_wr_init(&w, q, sizeof q);
	if (!strcmp(sub, "list")) {
		load_sessions();
		if (!nS) printf("no sessions\n");
		for (int i = 0; i < nS; i++) print_session(&S[i], false);
	} else if (!strcmp(sub, "info")) {
		if (!label) die("session info <label>");
		print_session(find(label, false), true);
	} else if (!strcmp(sub, "create")) {
		if (!label || !key_id) die("session create <label> --key-id <hex> [--drive n] [--role alice|bob] [--spare]");
		ez_wr_u32(&w, key_id); ez_wr_u8(&w, (uint8_t)drive); ez_wr_u8(&w, (uint8_t)role); ez_wr_str(&w, label);
		ez_wr_u8(&w, critical ? 1 : 0);
		maintenance_warning();
		need_ok("session create", call(EZ_CMD_SESSION_CREATE, q, w.n, TO_LONG));
		if (rn >= 2) replicate_report(rsp[1]);
		if (critical && rn >= 3) {
			if (rsp[2] == EZ_OK) printf("spare copy made in internal storage (drive 0)\n");
			else fprintf(stderr, "warning: no spare copy in internal storage (%s%s): only the card's copies exist\n",
			             ez_status_name((ez_status_t)rsp[2]), hint(rsp[2]));
		}
		printf("session '%s' created\n", label);
	} else if (!strcmp(sub, "import")) {
		if (!label || !file || !key_id) die("session import <label> <file> --key-id <hex> [--drive n] [--role alice|bob]");
		ez_wr_u8(&w, (uint8_t)drive); ez_wr_u32(&w, key_id); ez_wr_u8(&w, (uint8_t)role);
		ez_wr_str(&w, label); ez_wr_str(&w, file);
		if (w.err) die("label or file name too long");
		maintenance_warning();
		need_ok("import", call(EZ_CMD_KEY_IMPORT, q, w.n, TO_SHORT));
		if (rn == 1 && rsp[0] == 0)
			fprintf(stderr, "warning: no integrity file (.SUM) came with this key. It is checked\n"
			                "statistically and for duplicated blocks, but this copy cannot be compared\n"
			                "with the original. Copy the generating device's .SUM with the key\n"
			                "whenever possible.\n");                       /* IMPL-CLI-006 */
		extern uint32_t wait_job(const char *what);
		wait_job("import");
		printf("session '%s' created from %s\n", label, file);
	} else if (!strcmp(sub, "delete")) {
		if (!label) die("session delete <label> [--yes] [--force]");
		const ez_wsession_t *s = find(label, false);
		/* IMPL-CLI-005 */
		confirm(yes, "YES", force
		        ? "This removes session '%s' WITHOUT erasing its key file. The file stays on its\n"
		          "medium and must be destroyed by you; it must never start a new session.\n"
		        : "This erases the key file of session '%s' and removes the session. A copy of\n"
		          "the key made earlier must never be used to start a new session: its first\n"
		          "bytes have already been used.\n", label);
		ez_wr_u8(&w, s->slot); ez_wr_u32(&w, s->key_id); ez_wr_u8(&w, force);
		maintenance_warning();
		need_ok("session delete", call(EZ_CMD_SESSION_DELETE, q, w.n, TO_LONG));
		printf("session '%s' deleted%s\n", label, force ? " (key file NOT erased; logged)" : ", key erased");
	} else if (!strcmp(sub, "spare") || !strcmp(sub, "critical")) {     /* critical: the old name */
		if (!label || !file || (strcmp(file, "on") && strcmp(file, "off"))) die("session spare <label> on|off");
		const ez_wsession_t *s = find(label, false);
		bool on = !strcmp(file, "on");
		maintenance_warning();
		ez_wr_u8(&w, s->slot); ez_wr_u32(&w, s->key_id); ez_wr_u8(&w, on ? 1 : 0);
		need_ok("session spare", call(EZ_CMD_SESSION_CRITICAL, q, w.n, TO_LONG));
		printf("'%s' %s\n", label, on ? "has a spare copy in internal storage" : "has no spare copy any more: it is erased");
	} else if (!strcmp(sub, "check") || !strcmp(sub, "repair")) {
		if (!label) die("session %s <label>", sub);
		const ez_wsession_t *s = find(label, false);
		bool repair = !strcmp(sub, "repair");
		if (repair) {
			confirm(yes, "YES", "This rewrites damaged or missing copies of the key of '%s' from the units\n"
			                    "that verify, one copy at a time.\n", label);
			maintenance_warning();
		}
		ez_wr_u8(&w, s->slot); ez_wr_u32(&w, s->key_id);
		need_ok(sub, call(repair ? EZ_CMD_SESSION_REPAIR : EZ_CMD_SESSION_CHECK, q, w.n, TO_LONG));
		ez_rd_t r;
		ez_rd_init(&r, rsp, rn);
		if (repair) {
			uint8_t n = ez_rd_u8(&r), lost = ez_rd_u8(&r);
			printf("%u cop%s rewritten%s\n", n, n == 1 ? "y" : "ies",
			       lost ? "; some units verify in NO copy and cannot be recovered" : "");
			/* Show the result, including copies whose volume is unavailable. */
			char *args[2] = { (char *)"check", (char *)label };
			session_cmd(2, args);
		} else {
			uint8_t nc = ez_rd_u8(&r);
			uint32_t units = ez_rd_u32(&r), lost = ez_rd_u32(&r);
			printf("key %08X: %u units of 4 KiB, %u cop%s\n", s->key_id, units, nc, nc == 1 ? "y" : "ies");
			for (int k = 0; k < nc && k < EZ_COPIES_MAX; k++) {
				uint8_t present = ez_rd_u8(&r), has = ez_rd_u8(&r);
				uint32_t bad = ez_rd_u32(&r);
				printf("  copy %d: %s\n", k, !present ? "volume not available ('ez drive repair 1')" : !has ? "missing or not this key"
				       : bad ? "DAMAGED" : "ok");
				if (present && has && bad) printf("          %u unit(s) fail verification\n", bad);
			}
			uint32_t fo = ez_rd_u32(&r);
			uint8_t crit = ez_rd_u8(&r), d0 = ez_rd_u8(&r);
			uint32_t d0bad = ez_rd_u32(&r);
			if (crit) {
				static const char *d0s[] = { "not checked (internal storage not usable)", "missing", "ok", "DAMAGED" };
				printf("  spare copy (internal): %s", d0s[d0 < 4 ? d0 : 0]);
				if (d0 == 3) printf(", %u unit(s) fail verification", d0bad);
				printf("\n");
			}
			if (lost) printf("  %u unit(s) verify in NO copy: that part of the key is lost\n", lost);
			else if (nc > 1) printf("  every unit verifies in at least one copy%s\n",
			                        fo ? " (units have been served from other copies)" : "");
		}
	} else if (!strcmp(sub, "skip") || !strcmp(sub, "resolve")) {
		if (!label) die("session %s <label>", sub);
		const ez_wsession_t *s = find(label, false);
		bool skip = !strcmp(sub, "skip");
		if (skip) confirm(yes, "YES", "This moves the send position of '%s' past the damaged part of its key.\n"
		                              "The skipped key is wasted; nothing is ever reused.\n", label);
		ez_wr_u8(&w, s->slot); ez_wr_u32(&w, s->key_id);
		need_ok(sub, call(skip ? EZ_CMD_SESSION_SKIP : EZ_CMD_SESSION_RESOLVE, q, w.n, TO_LONG));
		if (skip) printf("skipped %u damaged unit(s) (up to %u bytes)\n", ez_get_le32(rsp), ez_get_le32(rsp) * 4096u);
		else printf("session '%s' resolved\n", label);
	} else die("session: unknown subcommand '%s'", sub);
}

/* ---- jobs ------------------------------------------------------------------------- */
uint32_t wait_job(const char *what)
{
	ez_wjob_t j;
	signal(SIGINT, on_sigint);
	int last = -1;
	for (;;) {
		if (interrupted) {
			ez_call_abort(&T, EZ_CMD_KEY_STATUS, TO_SHORT);
			fprintf(stderr, "\n");
			die("%s cancelled", what);
		}
		need_ok("status", call(EZ_CMD_KEY_STATUS, NULL, 0, TO_SHORT));
		ez_rd_t r;
		ez_rd_init(&r, rsp, rn);
		ez_wjob_read(&r, &j);
		if (!j.running) break;
		if (j.permille / 10 != last && isatty(2)) { fprintf(stderr, "\r%s: %u%%", what, j.permille / 10); last = j.permille / 10; }
		struct timespec ts = { 0, 200 * 1000000L };
		nanosleep(&ts, NULL);
	}
	if (last >= 0) fprintf(stderr, j.result == EZ_OK ? "\r%s: 100%%\n" : "\n", what);
	signal(SIGINT, SIG_DFL);
	if (j.result != EZ_OK) {
		if (j.bad) fprintf(stderr, "%u unit(s) do not match the key's .SUM (first: unit %u): damaged in transfer\n", j.bad, j.first_bad);
		if (j.dups) fprintf(stderr, "%u duplicated 4 KiB block(s): this is not usable key material\n", j.dups);
		if (j.fail & 0x7F) fprintf(stderr, "statistical tests failed (bits 0x%02x)\n", j.fail & 0x7F);
		if (j.fail & 0x80) fprintf(stderr, "failed on storage, hardware or cancellation (not a statistical test)\n");
		die("%s: %s", what, ez_status_name((ez_status_t)j.result));
	}
	if (j.job == 1) printf("key %08X generated\n", j.key_id);
	if (j.job == 2) replicate_report(j.replicate);
	return j.key_id;
}

static void key_cmd(int argc, char **argv)
{
	if (argc < 1) die("key: generate | copy | delete | status");
	uint8_t req[16];
	ez_wr_t w;
	ez_wr_init(&w, req, sizeof req);
	int drive = 1, from = -1, to = -1;
	bool yes = false, direct = false;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--drive") && i + 1 < argc) drive = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--from") && i + 1 < argc) from = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--to") && i + 1 < argc) to = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--direct")) direct = true;
		else if (!strcmp(argv[i], "--yes")) yes = true;
	}
	if (!strcmp(argv[0], "generate")) {
		/* Presets (EZ-IMPL-001 §2.3): 128K, 256K (default), 512K, 2M; or bytes. */
		uint32_t len = 256u * 1024u;
		if (argc >= 2 && argv[1][0] != '-') {
			char *end;
			unsigned long v = strtoul(argv[1], &end, 0);
			if (*end == 'K' || *end == 'k') v *= 1024ul;
			else if (*end == 'M' || *end == 'm') v *= 1024ul * 1024ul;
			else if (*end) die("key generate [size: 128K, 256K (default), 512K, 2M, or bytes] [--drive n]");
			len = (uint32_t)v;
		}
		fprintf(stderr, "generating %u KiB (about %u min at 2.3 kbit/s); keep the device connected\n",
		        len / 1024u, (unsigned)((uint64_t)len * 8u / 2264u / 60u) + 1u);
		/* IMPL-AV-006: when drive 0 is usable, generate there (power-safe)
		 * and copy the finished key to the card in one burst, so the card
		 * is written for seconds instead of the whole generation. */
		bool staged = false;
		if (drive != 0 && !direct) {
			need_ok("device info", call(EZ_CMD_DEVICE_INFO, NULL, 0, TO_SHORT));
			ez_rd_t r;
			char fw[64];
			ez_rd_init(&r, rsp, rn);
			ez_rd_u8(&r); ez_rd_str(&r, fw, sizeof fw);
			for (int s2 = 0; s2 < 4; s2++) ez_rd_u8(&r);
			ez_rd_u32(&r);
			uint8_t d0 = ez_rd_u8(&r), present = ez_rd_u8(&r);
			for (int s2 = 0; s2 < 4; s2++) ez_rd_u8(&r);
			uint8_t prot = ez_rd_u8(&r);
			staged = !r.err && d0 && (present & 1) && prot != 1;
		}
		ez_wr_u32(&w, len); ez_wr_u8(&w, (uint8_t)(staged ? 0 : drive));
		maintenance_warning();
		need_ok("key generate", call(EZ_CMD_KEY_GENERATE, req, w.n, TO_SHORT));
		uint32_t id = wait_job("generate");
		if (staged) {
			uint8_t cr[8];
			ez_wr_t cw;
			ez_wr_init(&cw, cr, sizeof cr);
			ez_wr_u32(&cw, id); ez_wr_u8(&cw, 0); ez_wr_u8(&cw, (uint8_t)drive);
			fprintf(stderr, "copying to drive %d...\n", drive);
			int st = call(EZ_CMD_KEY_COPY, cr, cw.n, TO_LONG);
			if (st != EZ_OK)
				die("the key was generated on drive 0 but could not be copied to drive %d (%s); it remains on drive 0",
				    drive, ez_status_name((ez_status_t)st));
			ez_wr_init(&cw, cr, sizeof cr);
			ez_wr_u32(&cw, id); ez_wr_u8(&cw, 0);
			st = call(EZ_CMD_KEY_DELETE, cr, cw.n, TO_LONG);
			if (st != EZ_OK)
				fprintf(stderr, "warning: the copy on drive 0 could not be erased (%s): 'ez key delete %08X --drive 0'\n",
				        ez_status_name((ez_status_t)st), id);
			printf("key %08X on drive %d (generated on drive 0, copied, erased there)\n", id, drive);
		}
	} else if (!strcmp(argv[0], "status")) {
		need_ok("status", call(EZ_CMD_KEY_STATUS, NULL, 0, TO_SHORT));
		ez_rd_t r; ez_wjob_t j;
		ez_rd_init(&r, rsp, rn);
		ez_wjob_read(&r, &j);
		static const char *jn[] = { "none", "generation", "import" };
		printf("job: %s, %s, %u.%u%%, result %s\n", jn[j.job < 3 ? j.job : 0], j.running ? "running" : "finished",
		       j.permille / 10, j.permille % 10, j.running ? "-" : ez_status_name((ez_status_t)j.result));
	} else if (!strcmp(argv[0], "copy")) {
		if (argc < 2 || from < 0 || to < 0) die("key copy <keyid> --from n --to n");
		ez_wr_u32(&w, (uint32_t)strtoul(argv[1], NULL, 16)); ez_wr_u8(&w, (uint8_t)from); ez_wr_u8(&w, (uint8_t)to);
		maintenance_warning();
		need_ok("key copy", call(EZ_CMD_KEY_COPY, req, w.n, TO_LONG));
		if (rn >= 1) replicate_report(rsp[0]);
		printf("copied, with its .SUM, verified\n");
	} else if (!strcmp(argv[0], "delete")) {
		if (argc < 2) die("key delete <keyid> --drive n [--yes]");
		confirm(yes, "YES", "This erases key %s on drive %d; sessions using it are quarantined.\n", argv[1], drive);
		ez_wr_u32(&w, (uint32_t)strtoul(argv[1], NULL, 16)); ez_wr_u8(&w, (uint8_t)drive);
		maintenance_warning();
		need_ok("key delete", call(EZ_CMD_KEY_DELETE, req, w.n, TO_LONG));
		printf("key erased\n");
	} else die("key: unknown subcommand '%s'", argv[0]);
}

/* ---- encryption ------------------------------------------------------------------------ */

static FILE *out_file(const char *path)
{
	FILE *f = path ? fopen(path, "wb") : stdout;
	if (!f) die("%s: %s", path, strerror(errno));
	return f;
}

/* Read all of a file or standard input (up to 256 MiB). */
static uint8_t *read_any(const char *path, size_t *len)
{
	FILE *f = path ? fopen(path, "rb") : stdin;
	if (!f) die("%s: %s", path, strerror(errno));
	size_t cap = 1 << 20, n = 0, k;
	uint8_t *b = malloc(cap);
	if (!b) die("out of memory");
	while ((k = fread(b + n, 1, cap - n, f)) > 0) {
		n += k;
		if (n == cap) {
			if (cap >= (256u << 20)) die("input larger than 256 MiB");
			cap *= 2;
			uint8_t *nb = realloc(b, cap);
			if (!nb) die("out of memory");
			b = nb;
		}
	}
	if (path) fclose(f);
	*len = n;
	return b;
}

static void write_message(const char *out, bool raw, const uint8_t *m, size_t n)
{
	FILE *f = out_file(out);
	if (raw) fwrite(m, 1, n, f);
	else {
		char *t = malloc(((n + 2) / 3) * 4 + 4);
		if (!t) die("out of memory");
		size_t k = ez_b64_encode(m, n, t);
		for (size_t o = 0; o < k; o += 76) fprintf(f, "%.*s\n", (int)(k - o < 76 ? k - o : 76), t + o);
		free(t);
	}
	if (out) fclose(f); else fflush(f);
}

/* Messages over 64 KiB, or --stream (EZ-IMPL-001 §9.4): lockstep 512-byte
 * chunks; the device commits each chunk's key before releasing it. */
#define CHUNK 512
static void encrypt_stream(const ez_wsession_t *s, uint8_t *pt, size_t n, const char *out, bool raw)
{
	uint8_t q9[9];
	q9[0] = s->slot; ez_put_le32(q9 + 1, s->key_id); ez_put_le32(q9 + 5, (uint32_t)n);
	need_ok("encrypt", call(EZ_CMD_ENC_BEGIN, q9, 9, TO_SHORT));
	uint8_t *m = malloc(n + EZ_MSG_OVERHEAD);
	if (!m) die("out of memory");
	memcpy(m, rsp, EZ_MSG_HDR);
	for (size_t o = 0; o < n; o += CHUNK) {
		size_t k = n - o < CHUNK ? n - o : CHUNK;
		int st = ez_call(&T, EZ_CMD_ENC_DATA, pt + o, k, rsp, sizeof rsp, &rn, TO_SHORT);
		wipe(pt + o, k);
		if (st != EZ_OK || rn != k)
			die("encryption stopped after %zu of %zu bytes (%s); the key used so far is spent and the message is lost",
			    o, n, st < 0 ? ez_call_error(st) : ez_status_name((ez_status_t)st));
		memcpy(m + EZ_MSG_HDR + o, rsp, k);
		if (isatty(2) && (o / CHUNK) % 64 == 0) fprintf(stderr, "\rencrypt: %zu%%", o * 100 / n);
	}
	if (isatty(2)) fprintf(stderr, "\r");
	need_ok("encrypt", call(EZ_CMD_ENC_END, NULL, 0, TO_SHORT));
	memcpy(m + EZ_MSG_HDR + n, rsp, EZ_MSG_TRL);
	write_message(out, raw, m, n + EZ_MSG_OVERHEAD);
	free(m);
}

static void decrypt_stream(int slot, const uint8_t *m, size_t mlen, const char *out)
{
	if (mlen < EZ_MSG_OVERHEAD) die("input is not an Einszeit message");
	size_t n = mlen - EZ_MSG_OVERHEAD;
	uint8_t q17[17];
	q17[0] = (uint8_t)slot; memcpy(q17 + 1, m, EZ_MSG_HDR);
	need_ok("decrypt", call(EZ_CMD_DEC_BEGIN, q17, 17, TO_SHORT));
	uint8_t *pt = malloc(n ? n : 1);
	if (!pt) die("out of memory");
	for (size_t o = 0; o < n; o += CHUNK) {
		size_t k = n - o < CHUNK ? n - o : CHUNK;
		int st = call(EZ_CMD_DEC_DATA, m + EZ_MSG_HDR + o, k, TO_SHORT);
		if (st != EZ_OK) { wipe(pt, o); die("decrypt: %s%s", ez_status_name((ez_status_t)st), hint(st)); }
		memcpy(pt + o, rsp, k);
	}
	int st = call(EZ_CMD_DEC_END, m + EZ_MSG_HDR + n, EZ_MSG_TRL, TO_SHORT);
	if (st != EZ_OK) { wipe(pt, n); die("decrypt: %s%s", ez_status_name((ez_status_t)st), hint(st)); }
	FILE *f = out_file(out);                       /* IMPL-CLI-003: only after the CRC verified */
	fwrite(pt, 1, n, f);
	if (out) fclose(f); else fflush(f);
	wipe(pt, n);
	free(pt);
}

static uint8_t data[EZ_STAGE_SIZE + 64];
static char text[(EZ_STAGE_SIZE + 64) * 2];

static void encrypt_cmd(int argc, char **argv, bool dec)
{
	const char *label = NULL, *in = NULL, *out = NULL;
	bool yes = false, raw = false, stream = false;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-i") && i + 1 < argc) in = argv[++i];
		else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
		else if (!strcmp(argv[i], "--yes")) yes = true;
		else if (!strcmp(argv[i], "--raw")) raw = true;
		else if (!strcmp(argv[i], "--stream")) stream = true;
		else if (argv[i][0] != '-') label = argv[i];
	}
	if (!dec) {
		const ez_wsession_t *s = find(label, true);
		size_t n = 0;
		uint8_t *all = read_any(in, &n);
		if (!n) die("nothing to encrypt");
		bool streaming = stream || n > EZ_BUFFERED_MAX;
		if (!streaming) { memcpy(data, all, n); wipe(all, n); }
		if (s->state != EZ_SS_VALID) die("session '%s' is %s", s->label, state_name(s->state));
		if (n > s->tx_left) die("message needs %zu bytes of key; session '%s' has %u left", n, s->label, s->tx_left);
		if (s->flags & EZ_SF_TX_LOW)
			fprintf(stderr, "warning: session '%s' has only %u of %u bytes left to send\n", s->label, s->tx_left, s->tx_range);
		confirm(yes, "y", "Encrypt %zu bytes with session '%s'? This uses %zu bytes of key;\n"
		                  "%u bytes will remain for sending.\n", n, s->label, n, s->tx_left - (uint32_t)n);
		if (streaming) {
			encrypt_stream(s, all, n, out, raw);
			free(all);
			return;
		}
		free(all);
		q[0] = s->slot;
		ez_put_le32(q + 1, s->key_id);
		ez_put_le32(q + 5, (uint32_t)n);
		memcpy(q + 9, data, n);
		wipe(data, n);
		int st = ez_call(&T, EZ_CMD_ENCRYPT, q, 9 + n, rsp, sizeof rsp, &rn, TO_SHORT);
		wipe(q, 9 + n);
		for (int tries = 0; st < 0 && tries < 3; tries++)     /* IMPL-ENG-008: recover a lost response */
			st = ez_call(&T, EZ_CMD_RESEND, NULL, 0, rsp, sizeof rsp, &rn, TO_SHORT);
		if (st < 0) die("%s (the key may have been used; the message is lost)", ez_call_error(st));
		need_ok("encrypt", st);
		FILE *f = out_file(out);
		if (raw) fwrite(rsp, 1, rn, f);
		else {
			size_t m = ez_b64_encode(rsp, rn, text);
			for (size_t o = 0; o < m; o += 76) fprintf(f, "%.*s\n", (int)(m - o < 76 ? m - o : 76), text + o);
		}
		if (out) fclose(f); else fflush(f);
		ez_call(&T, EZ_CMD_RELEASE, NULL, 0, NULL, 0, NULL, TO_SHORT);
	} else {
		int slot = 0xFF;
		if (label) slot = find(label, false)->slot;
		size_t n = 0, mlen = 0;
		uint8_t *inb = read_any(in, &n), *msg;
		while (n && inb[n - 1] == 0x1A) n--;          /* XMODEM's padding (a file downloaded from a device) */
		if (n >= 2 && inb[0] == 0x5A && inb[1] == 0x45) {   /* raw message */
			msg = inb;
			mlen = n;
		} else {
			msg = malloc(n + 4);
			if (!msg) die("out of memory");
			ez_b64_dec_t d;
			ez_b64_dec_init(&d);
			if (ez_b64_dec_update(&d, (const char *)inb, n, msg, &mlen) != EZ_OK || ez_b64_dec_final(&d) != EZ_OK)
				die("input is neither an Einszeit message nor base64");
			free(inb);
		}
		if (stream || mlen > EZ_STAGE_SIZE) {
			decrypt_stream(slot, msg, mlen, out);
			free(msg);
			return;
		}
		memcpy(data, msg, mlen);
		free(msg);
		q[0] = (uint8_t)slot;
		ez_put_le32(q + 1, (uint32_t)mlen);
		memcpy(q + 5, data, mlen);
		int st = call(EZ_CMD_DECRYPT, q, 5 + mlen, TO_SHORT);
		wipe(q, 5 + mlen);
		need_ok("decrypt", st);                 /* IMPL-CLI-003: nothing written before success */
		FILE *f = out_file(out);
		fwrite(rsp, 1, rn, f);
		if (out) fclose(f); else fflush(f);
	}
	wipe(rsp, sizeof rsp);
	wipe(text, sizeof text);
	wipe(data, sizeof data);
}

/* ---- drives, device, log, tests ---------------------------------------------------------- */
static void drive_cmd(int argc, char **argv)
{
	if (argc < 1) die("drive: list | info | enable 0 | disable 0 | format 1");
	int drive = 1, copies = 2;
	bool yes = false, erase_all = false;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--drive") && i + 1 < argc) drive = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--yes")) yes = true;
		else if (!strcmp(argv[i], "--copies") && i + 1 < argc) copies = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--erase")) erase_all = true;
		else if (argv[i][0] != '-') drive = atoi(argv[i]);
	}
	uint8_t req[4] = { (uint8_t)drive, 0, 0 };
	if (!strcmp(argv[0], "repair")) {
		maintenance_warning();
		need_ok("drive repair", call(EZ_CMD_DRIVE_REPAIR, req, 1, TO_LONG));
		printf("%u copy volume(s) recreated%s\n", rn ? rsp[0] : 0,
		       rn && rsp[0] ? "; now run 'ez session repair <label>' for each session on this drive" : "");
		return;
	}
	if (!strcmp(argv[0], "format")) {
		if (drive != 1 || copies < 1 || copies > 2) die("drive format 1 [--copies 1|2] [--yes]");
		confirm(yes, "YES", "This ERASES the whole card in drive %d and formats it to keep %d cop%s of every\n"
		                    "key. Every key file on it is destroyed. Sessions must be deleted first.\n",
		        drive, copies, copies == 1 ? "y" : "ies");
		maintenance_warning();
		req[1] = (uint8_t)(copies | (erase_all ? 0x80 : 0));
		need_ok("drive format", call(EZ_CMD_DRIVE_FORMAT, req, 2, TO_LONG * 2));
		printf("drive %d formatted: %d cop%s of every key\n", drive, copies, copies == 1 ? "y" : "ies");
		return;
	}
	if (!strcmp(argv[0], "list")) {
		uint16_t start = 0;
		for (;;) {
			ez_put_le16(req + 1, start);
			need_ok("drive list", call(EZ_CMD_DRIVE_LIST, req, 3, TO_SHORT));
			ez_rd_t r;
			ez_rd_init(&r, rsp, rn);
			uint8_t n = ez_rd_u8(&r);
			char name[EZ_NAME_MAX];
			for (int i = 0; i < n; i++) {
				uint32_t size = ez_rd_u32(&r);
				ez_rd_str(&r, name, sizeof name);
				printf("%10u  %s\n", size, name);
			}
			uint8_t more = ez_rd_u8(&r);
			if (!ez_rd_done(&r)) die("protocol error");
			if (!more) break;
			start = (uint16_t)(start + n);
		}
	} else if (!strcmp(argv[0], "info")) {
		need_ok("drive info", call(EZ_CMD_DRIVE_INFO, req, 1, TO_SHORT));
		printf("drive %d: %s, %s, %s", drive, rsp[0] ? "present" : "absent", rsp[1] ? "enabled" : "disabled",
		       rsp[2] ? ez_status_name((ez_status_t)rsp[2]) : "usable");
		if (rn >= 4) printf(", %u cop%s of every key", rsp[3], rsp[3] == 1 ? "y" : "ies");
		printf("\n");
	} else if (!strcmp(argv[0], "enable") || !strcmp(argv[0], "disable")) {
		bool en = !strcmp(argv[0], "enable");
		if (drive != 0) die("only drive 0 can be enabled or disabled");
		confirm(yes, "YES", en ? "Drive 0 is internal storage, the device's flash. Anyone holding BOOT while connecting\n"
		                         "can read it unless partition protection is in place (OI-02).\n"
		                       : "This ERASES everything on drive 0, then disables it.\n");
		if (!en) maintenance_warning();
		need_ok(argv[0], call(en ? EZ_CMD_DRIVE_ENABLE : EZ_CMD_DRIVE_DISABLE, req, 1, TO_LONG));
		printf("drive 0 %s\n", en ? "enabled" : "erased and disabled");
	} else die("drive: unknown subcommand '%s'", argv[0]);
}

static void device_cmd(int argc, char **argv)
{
	bool yes = argc > 1 && !strcmp(argv[1], "--yes");
	if (argc < 1 || !strcmp(argv[0], "info")) {
		need_ok("device info", call(EZ_CMD_DEVICE_INFO, NULL, 0, TO_SHORT));
		ez_rd_t r;
		char fw[64];
		ez_rd_init(&r, rsp, rn);
		uint8_t pv = ez_rd_u8(&r);
		ez_rd_str(&r, fw, sizeof fw);
		uint8_t var = ez_rd_u8(&r), hw = ez_rd_u8(&r), prof = ez_rd_u8(&r), dev = ez_rd_u8(&r);
		uint32_t boots = ez_rd_u32(&r);
		uint8_t d0 = ez_rd_u8(&r), present = ez_rd_u8(&r), intent = ez_rd_u8(&r), job = ez_rd_u8(&r);
		uint8_t build = ez_rd_u8(&r), taint = ez_rd_u8(&r);     /* absent on older firmware: 0 */
		uint8_t prot = ez_rd_u8(&r);                            /* 0 n/a, 1 missing, 2 verified */
		static const char *ds[] = { "UNINITIALISED ('ez device erase')", "valid", "FAULT ('ez device repair'; on a new device 'ez device erase')" };
		printf("firmware   %s (protocol %u, variant 0x%02x, hardware rev %u)%s\n", fw, pv, var, hw,
		       var == 0xEE ? "  ** VIRTUAL DEVICE: test use only **" : "");
		printf("metadata   %s, boot %u\n", dev < 3 ? ds[dev] : "?", boots);
		printf("internal   drive 0, %s%s", d0 ? "on" : "off", present & 1 ? "" : " (absent)");
		if (prot == 2) printf("; flash protection verified (bootloader and Non-secure access denied)");
		else if (prot == 1) printf("; flash protection MISSING: cannot be used (install the partition table, TR-06)");
		printf("\ncard       drive 1, %s\n", present & 2 ? "present" : "absent");
		if (present & 4) printf("drive 2    present\n");
		printf("trng       profile 0x%02x%s\n", prof, prof == 0xEE ? " (OS generator, not a TRNG)" : "");
		if (intent) printf("pending    an interrupted deletion will complete when its drive is present\n");
		uint8_t health = ez_rd_u8(&r), detail = ez_rd_u8(&r), rjob = ez_rd_u8(&r), rjcmd = ez_rd_u8(&r);
		uint16_t rpm = ez_rd_u16(&r);
		static const char *hs[] = { "not yet checked", "ok", "syncing", "DEGRADED" };
		if (!r.err) {
			printf("mirror     %s", health < 4 ? hs[health] : "?");
			if (health == 3) printf(" (detail 0x%02x): recommend waiting for nominal state", detail);
			printf("\n");
			if (rjob) printf("job        %s, %u%%\n", rjob == 4 ? "syncing the card mirror" : rjob == 1 ? "generating a key" :
			                 rjob == 2 ? "importing a key" : cmd_word(rjcmd), rpm / 10u);
		} else if (job) printf("job        running ('ez key status')\n");
		if (build == 1) printf("build      DEVELOPMENT: a compromised computer can extract keys. Never use for real secrets.\n");
		else if (build == 0) printf("build      production\n");
		if (taint) printf("WARNING    development firmware has run on this device since its last erase;\n"
		                  "           keys on it may have been exposed. Erase before real use ('ez device erase').\n");
	} else if (!strcmp(argv[0], "erase")) {
		confirm(yes, "YES", "This ERASES every key file on every enabled drive and all sessions.\n");
		maintenance_warning();
		need_ok("device erase", call(EZ_CMD_DEVICE_ERASE, NULL, 0, TO_LONG));
		printf("device erased\n");
	} else if (!strcmp(argv[0], "repair")) {
		confirm(yes, "YES", "This rewrites a faulty device record (drive 0 is disabled).\n");
		need_ok("device repair", call(EZ_CMD_DEVICE_REPAIR, NULL, 0, TO_SHORT));
		printf("device record rewritten\n");
	} else die("device: info | erase | repair");
}

static void log_cmd(void)
{
	need_ok("log", call(EZ_CMD_LOG_READ, NULL, 0, TO_SHORT));
	static const char *tn[] = { "?", "key accepted", "key rejected", "rollback", "quarantine", "device init",
	                            "drive 0 on", "drive 0 off", "entropy fault", "device repair", "session deleted",
	                            "session removed WITHOUT erasing key", "key imported", "skip" };
	ez_rd_t r;
	ez_rd_init(&r, rsp, rn);
	int n = ez_rd_u8(&r);
	for (int i = 0; i < n; i++) {
		uint32_t seq = ez_rd_u32(&r), boot = ez_rd_u32(&r), t = ez_rd_u32(&r);
		uint8_t type = ez_rd_u8(&r), detail = ez_rd_u8(&r);
		uint32_t key = ez_rd_u32(&r), arg = ez_rd_u32(&r);
		uint8_t host = ez_rd_u8(&r);
		char when[32];
		if (host) { time_t tt = t; strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", localtime(&tt)); }
		else snprintf(when, sizeof when, "boot %u +%us", boot, t);
		printf("#%-4u %-20s %-36s detail 0x%02x key %08X arg %u\n", seq, when, type < 14 ? tn[type] : "?",
		       detail, key, arg);
	}
	if (!n) printf("log empty\n");
	if (!ez_rd_done(&r)) die("protocol error");
}

static void test_cmd(int argc, char **argv)
{
	uint8_t req[4];
	if (argc >= 1 && !strcmp(argv[0], "random")) {
		uint16_t n = (uint16_t)(argc > 1 ? atoi(argv[1]) : 32);
		ez_put_le16(req, n);
		need_ok("random", call(EZ_CMD_RANDOM, req, 2, TO_LONG));
		for (size_t i = 0; i < rn; i++) printf("%02x%s", rsp[i], i % 32 == 31 ? "\n" : "");
		if (rn % 32) printf("\n");
	} else if (argc >= 1 && !strcmp(argv[0], "entropy")) {
		uint32_t n = (uint32_t)(argc > 1 ? atoi(argv[1]) : 16384);
		ez_put_le32(req, n);
		need_ok("entropy test", call(EZ_CMD_ENTROPY_TEST, req, 4, TO_LONG));
		printf("%u bytes of fresh TRNG output: monitor 0x%02x, acceptance 0x%02x (%s)\n", n, rsp[0], rsp[1],
		       rsp[0] | rsp[1] ? "FAILED" : "pass");
	} else die("test: entropy [bytes] | random [n]");
}

static void usage(void)
{
	fprintf(stderr,
	        "usage: ez [--device <serial> | --virtual <socket>] <command>\n"
	        "  session list | info <l> | create <l> --key-id <hex> [--drive n] [--role alice|bob] [--spare]\n"
	        "          import <l> <file> --key-id <hex> [--drive n] [--role r]\n"
	        "          delete <l> [--yes] [--force] | skip <l> [--yes] | resolve <l>\n"
	        "          check <l> | repair <l> [--yes]        (copies of the key)\n"
	        "          spare <l> on|off                       (a spare copy in internal storage)\n"
	        "  key     generate [128K|256K|512K|2M|<bytes>] [--drive n] [--direct] | copy <id> --from n --to n\n"
	        "          delete <id> --drive n | status          (default size 256K)\n"
	        "  encrypt [<label>] [--yes] [-i file] [-o file] [--raw] [--stream]   (streams above 64 KiB)\n"
	        "  decrypt [<label>] [-i file] [-o file] [--stream]\n"
	        "  drive   list [n] | info [n] | enable 0 | disable 0 | format 1 [--copies 1|2] [--erase] | repair 1\n"
	        "  device  info | erase | repair | list\n"
	        "  log\n"
	        "  test    entropy [bytes] | random [n]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	const char *vpath = getenv("EZ_VIRTUAL"), *serial = NULL;
	int i = 1;
	for (; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "--virtual")) vpath = argv[i + 1];
		else if (!strcmp(argv[i], "--device")) serial = argv[i + 1];
		else break;
	}
	if (i >= argc || !strcmp(argv[i], "--help") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "help")) usage();
	if (!strcmp(argv[i], "device") && i + 1 < argc && !strcmp(argv[i + 1], "list") && !vpath) {
		transport_hid_list();
		return 0;
	}
	char err[160];
	if (vpath) {
		if (transport_vdev_open(vpath, &T) != 0) die("cannot connect to the virtual device at %s: %s", vpath, strerror(errno));
	} else if (transport_hid_open(serial, &T, err, sizeof err) != 0) {
		die("%s", err);
	}
	const char *c = argv[i++];
	if (!(strcmp(c, "session") == 0 && i < argc && strcmp(argv[i], "delete") == 0)) {
		int o = i;
		for (int k = i; k < argc; k++) {
			if (!strcmp(argv[k], "--force")) { g_force = true; continue; }
			argv[o++] = argv[k];
		}
		argc = o;
	}
	/* IMPL-MODE-001/002: warn on every command to a development image or a
	 * device that has run one since its last erase. */
	if (strcmp(c, "device")) {
		size_t k = 0;
		if (ez_call(&T, EZ_CMD_DEVICE_INFO, NULL, 0, rsp, sizeof rsp, &k, TO_SHORT) == EZ_OK) {
			ez_rd_t r;
			char fw[64];
			ez_rd_init(&r, rsp, k);
			ez_rd_u8(&r); ez_rd_str(&r, fw, sizeof fw);
			for (int s = 0; s < 4; s++) ez_rd_u8(&r);
			ez_rd_u32(&r);
			for (int s = 0; s < 4; s++) ez_rd_u8(&r);
			uint8_t build = ez_rd_u8(&r), taint = ez_rd_u8(&r);
			if (!r.err && build == 1)
				fprintf(stderr, "ez: warning: DEVELOPMENT firmware; never use it for real secrets\n");
			if (!r.err && taint)
				fprintf(stderr, "ez: warning: development firmware has run on this device since its last erase\n");
			ez_rd_u8(&r);                                       /* drive 0 protection */
			g_health = ez_rd_u8(&r); g_detail = ez_rd_u8(&r);
			if (r.err) g_health = 0;
		}
		/* Round 16: the card mirror's health. While degraded, nothing is
		 * written to the card without --force (deletion is never blocked). */
		const char *sub = i < argc ? argv[i] : "";
		bool writes = (!strcmp(c, "key") && (!strcmp(sub, "generate") || !strcmp(sub, "import") || !strcmp(sub, "copy"))) ||
		              (!strcmp(c, "session") && (!strcmp(sub, "create") || !strcmp(sub, "repair") || !strcmp(sub, "skip"))) ||
		              (!strcmp(c, "drive") && (!strcmp(sub, "format") || !strcmp(sub, "repair") || !strcmp(sub, "enable")));
		if (g_health == 3) {
			static const char *why[] = { "a card copy could not be repaired", "a key's spare copy is missing",
			                             "some key data verifies in no copy", "one of the card's two copies is unavailable" };
			fprintf(stderr, "ez: warning: system degraded (");
			for (int b = 0, first = 1; b < 4; b++)
				if (g_detail & (1u << b)) { fprintf(stderr, "%s%s", first ? "" : "; ", why[b]); first = 0; }
			fprintf(stderr, "); recommend waiting for nominal state\n");
			if (writes && !g_force)
				die("not writing to the card while degraded; add --force to proceed anyway");
		} else if (g_health == 2) {
			fprintf(stderr, "ez: note: the device is syncing its card mirror\n");
		}
	}
	int n = argc - i;
	char **a = argv + i;
	if (!strcmp(c, "session")) session_cmd(n, a);
	else if (!strcmp(c, "key")) key_cmd(n, a);
	else if (!strcmp(c, "encrypt")) encrypt_cmd(n, a, false);
	else if (!strcmp(c, "decrypt")) encrypt_cmd(n, a, true);
	else if (!strcmp(c, "drive")) drive_cmd(n, a);
	else if (!strcmp(c, "device")) device_cmd(n, a);
	else if (!strcmp(c, "log")) log_cmd();
	else if (!strcmp(c, "test")) test_cmd(n, a);
	else usage();
	return 0;
}
