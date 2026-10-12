/*
 * ez_ui.c -- see ez_ui.h and docs/einszeit-ui.md (EZ-UI-001).
 */
#include "ez_ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ez_bytes.h"
#include "ez_engine.h"
#include "ez_keygen.h"
#include "ez_meta.h"
#include "ez_proto.h"
#include "ez_secure.h"

/* The key manager's multi-step actions (round 18). */
enum { FL_NONE, FL_NEW, FL_IMPORT, FL_EXPORT, FL_DELETE, FL_SKIP, FL_RESOLVE, FL_BACKUP };

/* ---- VT100 output ----------------------------------------------------------- */

static void out(ez_ui_t *ui, const char *s) { ui->env.write(ui->env.ctx, s, (uint32_t)strlen(s)); }

/* Scratch buffers are static, not on the stack: on the RP2350 each core's
 * stack is a 4 KB scratch bank, and the interface runs on core 0 only, one
 * call at a time. */
static void outf(ez_ui_t *ui, const char *fmt, ...)
{
	static char b[600];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	out(ui, b);
}

static void at(ez_ui_t *ui, int r, int c) { outf(ui, "\033[%d;%dH", r, c); }
#define INV   "\033[7m"
#define BOLD  "\033[1m"
#define NORM  "\033[0m"
#define EOL   "\033[K"
#define SAVE  "\0337"
#define REST  "\0338"

/* A separator row: plain ASCII, the same on every terminal. */
static void hline(ez_ui_t *ui, int r)
{
	char b[200];
	int n = ui->cols < (int)sizeof b - 1 ? ui->cols : (int)sizeof b - 1;
	memset(b, '-', (size_t)n);
	b[n] = 0;
	at(ui, r, 1);
	out(ui, b);
}

/* ---- device facts (RAM only: safe while a job runs on the other core) -------- */

static const char *menu_names[EZ_UI_SCREENS] = { "Home", "Send", "Receive", "Keys", "Device", "CLI", "Help" };
static const char menu_keys[EZ_UI_SCREENS] = { 'h', 's', 'r', 'k', 'd', 'c', '?' };

static int key_count(const ez_ui_t *ui, int *critical)
{
	int n = 0;
	if (critical) *critical = 0;
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &ui->env.core->meta.s[i];
		if (s->state == EZ_SS_EMPTY) continue;
		n++;
		if (critical && (s->flags & EZ_SESS_CRITICAL)) (*critical)++;
	}
	return n;
}

static const char *cmd_word(uint8_t cmd)
{
	switch (cmd) {
	case EZ_CMD_SESSION_CREATE: return "creating a session";
	case EZ_CMD_SESSION_DELETE: return "deleting";
	case EZ_CMD_SESSION_CHECK:  return "checking";
	case EZ_CMD_SESSION_REPAIR: return "repairing";
	case EZ_CMD_KEY_COPY:       return "copying";
	case EZ_CMD_KEY_DELETE:     return "erasing a key";
	case EZ_CMD_DRIVE_FORMAT:   return "formatting the card";
	case EZ_CMD_DRIVE_REPAIR:   return "repairing the card";
	case EZ_CMD_DRIVE_ENABLE:   return "turning internal storage on";
	case EZ_CMD_DRIVE_DISABLE:  return "erasing internal storage";
	case EZ_CMD_DEVICE_ERASE:   return "erasing the device";
	case EZ_CMD_ENTROPY_TEST:   return "testing the TRNG";
	default:                    return "working";
	}
}

static void job_text(const ez_ui_t *ui, char *o, size_t cap)
{
	const ez_dispatch_t *d = ui->env.disp;
	if (!d->job_running) { snprintf(o, cap, "idle"); return; }
	unsigned pct = ui->env.core->progress / 10u;
	switch (d->job) {
	case 1: snprintf(o, cap, "generating a key"); break;
	case 2: snprintf(o, cap, "importing a key"); break;
	case 3: snprintf(o, cap, "%s %u%%", cmd_word(d->jcmd), pct); break;
	case 4: snprintf(o, cap, "syncing the mirror %u%%", pct); break;
	default: snprintf(o, cap, "working"); break;
	}
}

static const char *mirror_text(const ez_ui_t *ui)
{
	if (ui->env.disp->job_running && ui->env.disp->job == 4) return "syncing";
	switch (ui->env.core->health) {
	case EZ_HEALTH_OK:       return "ok";
	case EZ_HEALTH_DEGRADED: return "DEGRADED";
	case EZ_HEALTH_SYNCING:  return "syncing";
	default:                 return "not yet checked";
	}
}

static void card_text(const ez_ui_t *ui, char *o, uint32_t cap)
{
	if (ui->env.card_info) { ui->env.card_info(ui->env.ctx, o, cap); return; }
	const ez_hal_keystore_t *ks = ui->env.core->ks;
	uint8_t n = ks->copies ? ks->copies(ks->ctx, 1) : 1;
	snprintf(o, cap, "%s%s", ks->present(ks->ctx, 1) ? "present" : "absent",
	         ks->present(ks->ctx, 1) && n > 1 ? ", 2 copies" : "");
}

static const char *drive0_text(const ez_ui_t *ui)
{
	ez_core_t *c = ui->env.core;
	int prot = ez_core_drive0_protected(c);
	if (!c->meta.drive0_enabled) return prot == 0 ? "off (protection missing)" : "off";
	return prot == 1 ? "on, protected" : "on";
}

/* ---- the frame: menu bar and status line ------------------------------------- */

static void draw_menu(ez_ui_t *ui)
{
	at(ui, 1, 1);
	out(ui, NORM EOL);
	for (int i = 0; i < EZ_UI_SCREENS; i++) {
		bool hi = ui->menu_focus ? i == ui->menu_at : i == ui->screen;
		outf(ui, " %s%s%s ", hi ? INV : "", menu_names[i], hi ? NORM : "");
	}
	at(ui, 1, ui->cols - 10);
	out(ui, "[Einszeit]");
	hline(ui, 2);
}

static void status_string(ez_ui_t *ui, char *o, size_t cap)
{
	char card[40], job[48];
	int crit;
	int n = key_count(ui, &crit);
	card_text(ui, card, sizeof card);
	job_text(ui, job, sizeof job);
	snprintf(o, cap, " Keys %d | Mirror %s | Card %s | Internal %s | %s", n, mirror_text(ui), card,
	         ui->env.core->meta.drive0_enabled ? "on" : "off", job);
}

static void draw_status(ez_ui_t *ui, bool force)
{
	char s[160];
	status_string(ui, s, sizeof s);
	if (!force && !strcmp(s, ui->status_shown)) return;
	snprintf(ui->status_shown, sizeof ui->status_shown, "%s", s);
	out(ui, SAVE);
	at(ui, ui->rows, 1);
	out(ui, INV);
	outf(ui, "%-*.*s", ui->cols - 1, ui->cols - 1, s);
	out(ui, NORM REST);
}

/* ---- Home ------------------------------------------------------------------------ */

static const char *logo[] = {
	" ________________________________",
	"|  _|   |   |  _|_  |  _|  |_   _|",
	"|  _|   |   |_  |  _|  _|   |   |",
	"|___|___|_|_|___|___|___|___|___|",
};

static int home_lines(ez_ui_t *ui, char l[12][EZ_UI_LINE])
{
	ez_core_t *c = ui->env.core;
	char card[40], job[48], a[48];
	int crit, n = key_count(ui, &crit), k = 0;
	card_text(ui, card, sizeof card);
	job_text(ui, job, sizeof job);
	snprintf(l[k++], EZ_UI_LINE, "Device   %-24s  Mirror   %s", ui->env.board_id ? ui->env.board_id : "?", mirror_text(ui));
	snprintf(a, sizeof a, "%d", n);
	if (crit) snprintf(a + strlen(a), sizeof a - strlen(a), " (%d with a spare copy)", crit);
	snprintf(l[k++], EZ_UI_LINE, "Keys     %-24s  Card     %s", a, card);
	snprintf(l[k++], EZ_UI_LINE, "Internal %-24s  Job      %s", drive0_text(ui), job);
	snprintf(l[k++], EZ_UI_LINE, "Firmware %-24s  %s", ui->env.fw_version ? ui->env.fw_version : "?",
	         ui->env.development ? "DEVELOPMENT: never for real secrets" : "");
	l[k++][0] = 0;
	/* Warnings: everything critical is on Home (EZ-UI-001 §4). */
	static const char *why[] = { "a card copy could not be repaired", "a key's spare copy is missing",
	                             "some key data is in no copy", "one of the card's two copies is unavailable" };
	if (ui->notice[0] && k < 11) snprintf(l[k++], EZ_UI_LINE, "* %s", ui->notice);
	if (c->health == EZ_HEALTH_DEGRADED && k < 11) {
		snprintf(l[k], EZ_UI_LINE, "! DEGRADED:");
		for (int b = 0; b < 4; b++)
			if (c->health_detail & (1u << b)) snprintf(l[k] + strlen(l[k]), EZ_UI_LINE - strlen(l[k]), " %s;", why[b]);
		k++;
	}
	if (c->meta.dev != EZ_DEV_VALID && k < 11)
		snprintf(l[k++], EZ_UI_LINE, "! The device is not initialised: Device, or 'erase' in the CLI.");
	if (ez_core_dev_tainted(c) && k < 11)
		snprintf(l[k++], EZ_UI_LINE, "! Development firmware has run on this device since its last erase.");
	if (ez_core_intent_pending(c) && k < 11)
		snprintf(l[k++], EZ_UI_LINE, "! A deletion is waiting for its drive.");
	for (int i = 0; i < EZ_META_SESSIONS && k < 11; i++) {
		const ez_session_t *s = &c->meta.s[i];
		if (s->state == EZ_SS_QUARANTINED)
			snprintf(l[k++], EZ_UI_LINE, "! Key '%s' needs attention (quarantined, reason 0x%02x).", s->identity ? s->label : "?", s->qreason);
		else if (s->state == EZ_SS_VALID && s->offsets && ez_meta_tx_low(s, 10))
			snprintf(l[k++], EZ_UI_LINE, "! Key '%s' is running low: %lu bytes left to send.", s->label,
			         (unsigned long)ez_meta_tx_remaining(s));
	}
	while (k < 12) l[k++][0] = 0;
	return k;
}

#define HOME_ROW 10

static void draw_home(ez_ui_t *ui, bool force)
{
	static char l[12][EZ_UI_LINE];
	home_lines(ui, l);
	if (force) {
		for (int i = 0; i < 4; i++) { at(ui, 4 + i, 6); out(ui, logo[i]); }
		at(ui, ui->rows - 2, 6);
		out(ui, "Left/Right and Enter, or press a letter:  H S R K D C ?    Esc: the menu");
	}
	out(ui, SAVE);
	for (int i = 0; i < 12 && HOME_ROW + i < ui->rows - 3; i++) {
		if (!force && !strcmp(l[i], ui->panel_shown[i])) continue;
		memcpy(ui->panel_shown[i], l[i], EZ_UI_LINE);
		at(ui, HOME_ROW + i, 6);
		bool warn = l[i][0] == '!';
		outf(ui, "%s%s%s" EOL, warn ? INV : "", l[i], warn ? NORM : "");
	}
	out(ui, REST);
}

/* ---- Keys (round 17: the list and details; actions in round 18) -------------- */

static int key_slot(ez_ui_t *ui, int idx)
{
	int n = 0;
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		if (ui->env.core->meta.s[i].state == EZ_SS_EMPTY) continue;
		if (n++ == idx) return i;
	}
	return -1;
}

static void bar(char *o, size_t cap, uint32_t left, uint32_t total)
{
	int f = total ? (int)((uint64_t)left * 8u / total) : 0;
	char b[11];
	b[0] = '[';
	for (int i = 0; i < 8; i++) b[1 + i] = i < f ? '#' : '.';
	b[9] = ']';
	b[10] = 0;
	snprintf(o, cap, "%s %4luK", b, (unsigned long)(left / 1024u));
}

static void draw_keys(ez_ui_t *ui)
{
	ez_core_t *c = ui->env.core;
	static const char *st[] = { "empty", "VALID", "QUARANTINED", "erasing" };
	int n = key_count(ui, NULL);
	if (ui->key_at >= n) ui->key_at = n ? n - 1 : 0;
	at(ui, 3, 1);
	if (ui->key_detail && n) {
		int i = key_slot(ui, ui->key_at);
		const ez_session_t *s = &c->meta.s[i];
		outf(ui, BOLD "  Key '%s'" NORM EOL "\r\n" EOL "\r\n", s->identity ? s->label : "?");
		outf(ui, "  Key ID        %08lX\r\n", (unsigned long)s->key_id);
		outf(ui, "  Size          %lu bytes (%lu to send, %lu to receive)\r\n", (unsigned long)s->key_len,
		     (unsigned long)(s->key_len / 2u), (unsigned long)(s->key_len / 2u));
		outf(ui, "  Where         %s%s\r\n", s->drive == 0 ? "internal storage" : "the card",
		     s->flags & EZ_SESS_CRITICAL ? ", with a spare copy in internal storage" : "");
		outf(ui, "  Role          %s\r\n", s->role ? "bob" : "alice");
		outf(ui, "  State         %s", s->state < 4 ? st[s->state] : "?");
		if (s->state == EZ_SS_QUARANTINED) outf(ui, " (reason 0x%02x)", s->qreason);
		out(ui, "\r\n");
		if (s->offsets) {
			outf(ui, "  Send left     %lu bytes\r\n", (unsigned long)ez_meta_tx_remaining(s));
			outf(ui, "  Receive left  %lu bytes\r\n", (unsigned long)ez_meta_rx_remaining(s));
		}
		out(ui, "\r\n  The copies' health: 'key <label> check' in the CLI.\r\n");
		at(ui, ui->rows - 2, 3);
		out(ui, "Esc: back to the list" EOL);
		return;
	}
	out(ui, BOLD "  Label        Key ID    Where        Role  Send left        Receive left" NORM EOL);
	for (int r = 0; r < n && 4 + r < ui->rows - 3; r++) {
		int i = key_slot(ui, r);
		const ez_session_t *s = &c->meta.s[i];
		char where[20], sb[32], rb[32];
		snprintf(where, sizeof where, "%s%s", s->drive == 0 ? "internal" : "card",
		         s->flags & EZ_SESS_CRITICAL ? "+spare" : "");
		where[12] = 0;
		at(ui, 4 + r, 1);
		bool sel = r == ui->key_at;
		out(ui, sel ? INV "> " : "  ");
		if (s->state == EZ_SS_VALID && s->offsets) {
			bar(sb, sizeof sb, ez_meta_tx_remaining(s), s->key_len / 2u);
			bar(rb, sizeof rb, ez_meta_rx_remaining(s), s->key_len / 2u);
			outf(ui, "%-12.12s %08lX  %-12s %-5s %-16s %s", s->identity ? s->label : "?", (unsigned long)s->key_id,
			     where, s->role ? "bob" : "alice", sb, rb);
		} else {
			outf(ui, "%-12.12s %08lX  %-12s %-5s %s", s->identity ? s->label : "?", (unsigned long)s->key_id,
			     where, s->role ? "bob" : "alice", s->state < 4 ? st[s->state] : "?");
		}
		out(ui, NORM EOL);
	}
	if (!n) { at(ui, 5, 3); out(ui, "No keys yet: N makes a new one, I imports one from the card."); }
	/* A key being generated (here, or from a computer). */
	const ez_dispatch_t *dj = ui->env.disp;
	at(ui, 4 + (n < ui->rows - 8 ? n : ui->rows - 8) + (n ? 1 : 2), 3);
	if (dj->job_running && dj->job == 1)
		outf(ui, INV " %s: generating, %u%%  (C cancels) " NORM EOL,
		     ui->flow == FL_NEW ? ui->f_label : "a new key", (unsigned)ez_keygen_progress(&dj->kg) / 10u);
	else out(ui, EOL);
	at(ui, ui->rows - 2, 2);
	out(ui, "Enter details  N new  I import  X export  P spare  D delete  S skip  Q resolve" EOL);
}

/* ---- Device, Send, Receive, Help ---------------------------------------------- */

static void draw_device(ez_ui_t *ui)
{
	ez_core_t *c = ui->env.core;
	ez_dispatch_t *d = ui->env.disp;
	char card[40], job[48];
	card_text(ui, card, sizeof card);
	job_text(ui, job, sizeof job);
	static const char *ds[] = { "not initialised", "valid", "FAULT" };
	at(ui, 3, 1);
	outf(ui, BOLD "  Device" NORM "\r\n\r\n");
	outf(ui, "  Firmware      %s (%s)\r\n", ui->env.fw_version ? ui->env.fw_version : "?",
	     ui->env.development ? "development" : "production");
	outf(ui, "  Board ID      %s\r\n", ui->env.board_id ? ui->env.board_id : "?");
	outf(ui, "  Metadata      %s, boot %lu\r\n", c->meta.dev < 3 ? ds[c->meta.dev] : "?", (unsigned long)c->meta.boot_count);
	outf(ui, "  Internal      %s\r\n", drive0_text(ui));
	outf(ui, "  Card          %s\r\n", card);
	outf(ui, "  Mirror        %s (detail 0x%02x)\r\n", mirror_text(ui), c->health_detail);
	outf(ui, "  Failovers     %lu since boot\r\n", (unsigned long)c->failovers);
	outf(ui, "  Last checks   full %s, quick %s\r\n", d->last_full_ms ? "done" : "not yet", d->last_quick_ms ? "done" : "not yet");
	outf(ui, "  Job           %s\r\n\r\n", job);
	out(ui, "  Maintenance is in the CLI: 'card format', 'mirror check', 'erase', 'log'.\r\n");
}

static void draw_text(ez_ui_t *ui, const char *const *lines)
{
	at(ui, 3, 1);
	for (int i = 0; lines[i]; i++) outf(ui, "  %s\r\n", lines[i]);
}

static const char *help_text[] = {
	"Help", "",
	"Menu       Left/Right and Enter, or a letter: H Home, S Send, R Receive,",
	"           K Keys, D Device, C CLI, ? Help. Esc returns to the menu.",
	"Home       The device at a glance: everything that needs attention.",
	"Send       Write a message and encrypt it for one of your keys.",
	"Receive    Paste a message and decrypt it (up to 64 KiB).",
	"Keys       Your keys: how much is left, where they are, their health.",
	"Device     Details, and where maintenance lives.",
	"CLI        Commands for advanced use and diagnostics ('help' there).",
	"",
	"Where keys are kept",
	"Card       The microSD card. It holds two copies of every key (copy A and",
	"           copy B, the card mirror), so one damaged copy loses nothing.",
	"Internal   Internal storage: flash memory inside the device.",
	"Spare copy An extra copy of a card key in internal storage, in case the",
	"           card is lost or fails (Keys: P).",
	"",
	"Ctrl-L redraws the screen. The status line at the bottom is always current.",
	NULL };

/* ---- the CLI ------------------------------------------------------------------- */

static void cli_prompt(ez_ui_t *ui)
{
	at(ui, ui->rows - 1, 1);
	outf(ui, EOL "ez> %.*s", ui->line_len, ui->line);
}

void ez_ui_printf(ez_ui_t *ui, const char *fmt, ...)
{
	static char b[600], o[1200];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	size_t k = 0;
	for (size_t i = 0; b[i] && k + 2 < sizeof o; i++) {
		if (b[i] == '\n') o[k++] = '\r';
		o[k++] = b[i];
	}
	o[k] = 0;
	out(ui, o);
}

#define P(...) ez_ui_printf(ui, __VA_ARGS__)

static bool drive_arg(const char *a, uint8_t *drive, int *copy)
{
	*copy = -1;
	if (!a || !strcmp(a, "card") || !strcmp(a, "sd") || !strcmp(a, "1")) { *drive = 1; return true; }
	if (!strcmp(a, "internal") || !strcmp(a, "flash") || !strcmp(a, "0") || !strcmp(a, "d0")) { *drive = 0; return true; }
	if (!strcmp(a, "a") || !strcmp(a, "b")) { *drive = 1; *copy = a[0] - 'a'; return true; }
	return false;
}

static int find_label(ez_ui_t *ui, const char *label)
{
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &ui->env.core->meta.s[i];
		if (s->state != EZ_SS_EMPTY && s->identity && !strcmp(s->label, label)) return i;
	}
	return -1;
}

static void cli_keys(ez_ui_t *ui)
{
	static const char *st[] = { "empty", "valid", "QUARANTINED", "erasing" };
	int any = 0;
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &ui->env.core->meta.s[i];
		if (s->state == EZ_SS_EMPTY) continue;
		any = 1;
		P("%-12s %08lX %-5s %-5s %s%s", s->identity ? s->label : "?", (unsigned long)s->key_id,
		  s->drive ? "card" : "internal", s->role ? "bob" : "alice", s->state < 4 ? st[s->state] : "?",
		  s->flags & EZ_SESS_CRITICAL ? " +spare" : "");
		if (s->state == EZ_SS_VALID && s->offsets)
			P("  send %lu, receive %lu left", (unsigned long)ez_meta_tx_remaining(s), (unsigned long)ez_meta_rx_remaining(s));
		P("\n");
	}
	if (!any) P("no keys\n");
}

static void cli_ls(ez_ui_t *ui, const char *arg)
{
	uint8_t drive;
	int copy;
	if (!drive_arg(arg, &drive, &copy)) { P("ls [card|1|a|b|internal|0]\n"); return; }
	const ez_hal_keystore_t *ks = ui->env.core->ks;
	if (copy >= 0 && (!ks->copies || ks->copies(ks->ctx, 1) < 2)) { P("the card is not mirrored\n"); return; }
	uint8_t addr = copy >= 0 ? EZ_COPY(1, copy) : drive;
	if (drive == 0 && !ui->env.core->meta.drive0_enabled) { P("internal storage is off\n"); return; }
	static char name[EZ_NAME_MAX];
	uint32_t size, i = 0;
	ez_status_t st;
	while ((st = ks->list(ks->ctx, addr, i, name, &size)) == EZ_OK) { P("%10lu  %s\n", (unsigned long)size, name); i++; }
	if (st != EZ_ERR_NOT_FOUND) P("%s\n", ez_status_name(st));
	else P("%lu file(s)\n", (unsigned long)i);
}

static void cli_status(ez_ui_t *ui)
{
	char card[40], job[48];
	card_text(ui, card, sizeof card);
	job_text(ui, job, sizeof job);
	P("firmware  %s%s\n", ui->env.fw_version ? ui->env.fw_version : "?", ui->env.development ? " (development)" : "");
	P("internal  %s\ncard      %s\nmirror    %s (detail 0x%02x)\njob       %s\n", drive0_text(ui), card,
	  mirror_text(ui), ui->env.core->health_detail, job);
}

static void cli_log(ez_ui_t *ui)
{
	ez_event_t ev[EZ_META_LOG_ENTRIES];
	int n = ez_meta_log_read(&ui->env.core->meta, ev, EZ_META_LOG_ENTRIES);
	for (int i = 0; i < n; i++)
		P("#%-5lu boot %-4lu type %02x detail %02x key %08lX arg %lu\n", (unsigned long)ev[i].seq,
		  (unsigned long)ev[i].boot, ev[i].type, ev[i].detail, (unsigned long)ev[i].key_id, (unsigned long)ev[i].arg);
	if (n <= 0) P("the log is empty\n");
}

/* A long command: submitted as a job, the result printed when it ends. */
static void cli_job(ez_ui_t *ui, uint8_t cmd, const uint8_t *req, uint32_t n)
{
	if (!ez_dispatch_submit(ui->env.disp, cmd, req, n)) {
		if (ui->env.disp->job == 4) { ui->env.disp->yield = true; P("the device is finishing a background check; try again in a moment\n"); }
		else P("busy: a job is running\n");
		return;
	}
	ui->wait_job = cmd;
	ui->f_ticket = ez_dispatch_last_ticket(ui->env.disp);
	P("%s...\n", cmd_word(cmd));
}

static void cli_job_done(ez_ui_t *ui)
{
	ez_dispatch_t *d = ui->env.disp;
	uint8_t cmd = (uint8_t)ui->wait_job;
	ui->wait_job = 0;
	if (ui->f_result != EZ_OK) { P("%s: %s\n", cmd_word(cmd), ez_status_name(ui->f_result)); return; }
	if (cmd == EZ_CMD_SESSION_CHECK) {
		ez_rd_t r;
		ez_rd_init(&r, d->jres, d->jres_n);
		uint8_t nc = ez_rd_u8(&r);
		uint32_t units = ez_rd_u32(&r), lost = ez_rd_u32(&r);
		P("%lu units of 4 KiB, %u cop%s\n", (unsigned long)units, nc, nc == 1 ? "y" : "ies");
		for (int k = 0; k < nc && k < EZ_COPIES_MAX; k++) {
			uint8_t p = ez_rd_u8(&r), h = ez_rd_u8(&r);
			uint32_t bad = ez_rd_u32(&r);
			P("  copy %d: %s\n", k, !p ? "volume not available" : !h ? "missing" : bad ? "DAMAGED" : "ok");
		}
		ez_rd_u32(&r);
		uint8_t crit = ez_rd_u8(&r), d0 = ez_rd_u8(&r);
		static const char *d0s[] = { "not checked", "missing", "ok", "DAMAGED" };
		if (crit) P("  spare copy (internal): %s\n", d0 < 4 ? d0s[d0] : "?");
		if (lost) P("  %lu unit(s) verify in NO copy\n", (unsigned long)lost);
	} else {
		P("%s: done\n", cmd_word(cmd));
	}
}

static void cli_help(ez_ui_t *ui)
{
	P("keys, k                    list keys\n"
	  "key <label> [info|check]   one key: details, or check every copy\n"
	  "ls, l [card|a|b|internal]  list files (card = 1, a/b = one card copy, internal = 0)\n"
	  "status, s                  device, storage, mirror, job\n"
	  "mirror [check]             the card mirror's health; 'check' starts a full check\n"
	  "card format [1|2] [erase]  format the card (asks for YES)\n"
	  "erase                      erase the device (asks for YES)\n"
	  "log                        the event log\n"
	  "menu, Esc                  back to the menu\n");
	if (ui->env.cli_ext) P("(development commands are also accepted: see 'dev')\n");
}

static void cli_exec(ez_ui_t *ui, char *line)
{
	char *argv[8] = { 0 };
	int argc = 0;
	for (char *t = strtok(line, " "); t && argc < 8; t = strtok(NULL, " ")) argv[argc++] = t;
	if (ui->confirm) {
		int what = ui->confirm;
		ui->confirm = 0;
		if (!argc || strcmp(argv[0], "YES")) { P("cancelled\n"); return; }
		if (what == 1) cli_job(ui, EZ_CMD_DEVICE_ERASE, NULL, 0);
		else { uint8_t q[2] = { 1, (uint8_t)ui->confirm_arg[0] }; cli_job(ui, EZ_CMD_DRIVE_FORMAT, q, 2); }
		return;
	}
	if (!argc) return;
	const char *c = argv[0];
	bool busy = ui->env.disp->job_running;
	if (!strcmp(c, "help") || !strcmp(c, "?")) { cli_help(ui); return; }
	if (!strcmp(c, "status") || !strcmp(c, "s")) { cli_status(ui); return; }
	if (!strcmp(c, "keys") || !strcmp(c, "k")) { cli_keys(ui); return; }
	if (!strcmp(c, "menu") || !strcmp(c, "exit")) { ui->screen = EZ_UI_HOME; ui->menu_focus = true; ui->menu_at = 0; ez_ui_redraw(ui); return; }
	if (busy) { P("busy: the device is working on a job; wait for it to finish\n"); return; }
	if (!strcmp(c, "ls") || !strcmp(c, "l")) { cli_ls(ui, argv[1]); return; }
	if (!strcmp(c, "log")) { cli_log(ui); return; }
	if (!strcmp(c, "mirror")) {
		if (argv[1] && !strcmp(argv[1], "check")) { ez_dispatch_want_sync(ui->env.disp); P("a full check starts within a few seconds\n"); }
		else P("mirror %s (detail 0x%02x)\n", mirror_text(ui), ui->env.core->health_detail);
		return;
	}
	if (!strcmp(c, "key") && argv[1]) {
		int s = find_label(ui, argv[1]);
		if (s < 0) { P("no key '%s'\n", argv[1]); return; }
		if (argv[2] && !strcmp(argv[2], "check")) {
			uint8_t q[5] = { (uint8_t)s };
			ez_put_le32(q + 1, ui->env.core->meta.s[s].key_id);
			cli_job(ui, EZ_CMD_SESSION_CHECK, q, 5);
		} else {
			const ez_session_t *ss = &ui->env.core->meta.s[s];
			P("key %08lX, %lu bytes, %s%s, %s\n", (unsigned long)ss->key_id, (unsigned long)ss->key_len,
			  ss->drive ? "card" : "internal", ss->flags & EZ_SESS_CRITICAL ? " + spare copy" : "", ss->role ? "bob" : "alice");
		}
		return;
	}
	if (!strcmp(c, "card") && argv[1] && !strcmp(argv[1], "format")) {
		int copies = argv[2] ? argv[2][0] - '0' : 2;
		if (copies < 1 || copies > 2) { P("card format [1|2] [erase]\n"); return; }
		ui->confirm_arg[0] = (char)(copies | (argv[3] && !strcmp(argv[3], "erase") ? 0x80 : 0));
		ui->confirm = 2;
		P("This ERASES the whole card (sessions on it must be deleted first). Type YES to continue.\n");
		return;
	}
	if (!strcmp(c, "erase")) {
		ui->confirm = 1;
		P("This ERASES every key and session on this device. Type YES to continue.\n");
		return;
	}
	if (ui->env.cli_ext && ui->env.cli_ext(ui->env.ctx, argc, argv)) return;
	P("unknown command '%s' ('help')\n", c);
}

/* ---- dialogs (round 18) ---------------------------------------------------------- */

enum { DLG_NONE, DLG_INPUT, DLG_PICK, DLG_YN, DLG_TYPE, DLG_INFO, DLG_WAIT };
enum { ANS_CANCEL = -1, ANS_OK = 1, ANS_JOB = 1000, ANS_CARD = 1001 };

#define DLG_ROW 5
#define DLG_COL 8
#define DLG_W   64

static void dlg_row(ez_ui_t *ui, int r, const char *text, bool inv)
{
	at(ui, DLG_ROW + r, DLG_COL);
	outf(ui, "| %s%-*.*s%s |", inv ? INV : "", DLG_W - 4, DLG_W - 4, text, inv ? NORM : "");
}

static void draw_dialog(ez_ui_t *ui)
{
	if (!ui->dlg) return;
	char edge[DLG_W + 1], t[96];
	memset(edge, '-', DLG_W);
	edge[0] = edge[DLG_W - 1] = '+';
	edge[DLG_W] = 0;
	int r = 0;
	at(ui, DLG_ROW + r++, DLG_COL); out(ui, edge);
	snprintf(t, sizeof t, "%s", ui->dlg_title);
	at(ui, DLG_ROW + r++, DLG_COL); outf(ui, "| " BOLD "%-*.*s" NORM " |", DLG_W - 4, DLG_W - 4, t);
	dlg_row(ui, r++, "", false);
	for (int i = 0; i < 5; i++) if (ui->dlg_msg[i][0]) dlg_row(ui, r++, ui->dlg_msg[i], false);
	if (ui->dlg == DLG_PICK) {
		dlg_row(ui, r++, "", false);
		for (int i = 0; i < ui->dlg_nopt; i++) {
			snprintf(t, sizeof t, "%s %s", i == ui->dlg_at ? ">" : " ", ui->dlg_opt[i]);
			dlg_row(ui, r++, t, i == ui->dlg_at);
		}
	}
	if (ui->dlg == DLG_INPUT || ui->dlg == DLG_TYPE) {
		dlg_row(ui, r++, "", false);
		snprintf(t, sizeof t, "> %s_", ui->dlg_in);
		dlg_row(ui, r++, t, false);
	}
	dlg_row(ui, r++, ui->dlg_err, ui->dlg_err[0] != 0);
	const char *hint = ui->dlg == DLG_PICK ? "Up/Down and Enter; Esc cancels" :
	                   ui->dlg == DLG_YN ? "Y yes, N no" :
	                   ui->dlg == DLG_INFO ? "Press any key" :
	                   ui->dlg == DLG_WAIT && ui->flow == FL_NEW && ui->f_job && ui->env.disp->job == 1 ?
	                       "Esc: continue in the background    C: cancel" :
	                   ui->dlg == DLG_WAIT ? "Please wait" :
	                   "Enter to accept; Esc cancels";
	dlg_row(ui, r++, hint, false);
	at(ui, DLG_ROW + r, DLG_COL); out(ui, edge);
	/* blank what a taller previous dialog left below */
	for (int i = r + 1; i <= ui->dlg_rows; i++) {
		at(ui, DLG_ROW + i, DLG_COL);
		outf(ui, "%*s", DLG_W, "");
	}
	ui->dlg_rows = r;
}

static void dlg_open(ez_ui_t *ui, int kind, const char *title)
{
	ui->dlg = kind;
	snprintf(ui->dlg_title, sizeof ui->dlg_title, "%s", title);
	memset(ui->dlg_msg, 0, sizeof ui->dlg_msg);
	ui->dlg_nopt = ui->dlg_at = ui->dlg_ilen = 0;
	ui->dlg_in[0] = ui->dlg_err[0] = 0;
}
#define MSG(i, ...) snprintf(ui->dlg_msg[i], sizeof ui->dlg_msg[i], __VA_ARGS__)
#define OPT(...) snprintf(ui->dlg_opt[ui->dlg_nopt++], sizeof ui->dlg_opt[0], __VA_ARGS__)

static void dlg_close(ez_ui_t *ui) { ui->dlg = DLG_NONE; }

/* ---- the key manager's actions (EZ-UI-001 §8) --------------------------------------- */


static void flow_next(ez_ui_t *ui, int ans);
static void send_open(ez_ui_t *ui, int slot);
static void upload_encrypt(ez_ui_t *ui, int ans);
static void receive_open(ez_ui_t *ui);

static void flow_end(ez_ui_t *ui)
{
	ui->flow = FL_NONE;
	ui->step = 0;                                        /* an info box leaves 99: it must not outlive its flow */
	ui->f_pend = 0;
	ui->f_job = false;
	ui->f_card = 0;
	dlg_close(ui);
	ez_ui_redraw(ui);
}

static void info(ez_ui_t *ui, const char *title, const char *m0, const char *m1)
{
	if (ui->f_detached) {                              /* it ran in the background */
		snprintf(ui->notice, sizeof ui->notice, "%s: %s%s%s", title, m0, m1 ? " " : "", m1 ? m1 : "");
		ui->flow = FL_NONE;
		ui->f_job = false;
		ui->f_detached = false;
		if (ui->screen == EZ_UI_HOME && !ui->menu_focus) draw_home(ui, false);
		else if (ui->screen == EZ_UI_HOME) draw_home(ui, false);
		else if (ui->screen == EZ_UI_KEYS && !ui->dlg) draw_keys(ui);
		return;
	}
	dlg_open(ui, DLG_INFO, title);
	MSG(0, "%s", m0);
	if (m1) MSG(1, "%s", m1);
	ui->step = 99;                                       /* any key ends the flow */
	draw_dialog(ui);
}

static void wait_dlg(ez_ui_t *ui, const char *title, const char *m0)
{
	if (ui->f_detached) return;                        /* running in the background */
	dlg_open(ui, DLG_WAIT, title);
	MSG(0, "%s", m0);
	draw_dialog(ui);
}

/* Start a flow's job. If the device is busy, keep the request and start it
 * when the device is free (a background sync is asked to make way). */
static bool pend_start(ez_ui_t *ui);

static bool start_job(ez_ui_t *ui, uint8_t cmd, const uint8_t *req, uint32_t n, const char *what)
{
	if (n > sizeof ui->f_pend_req) { info(ui, "Busy", "The device is working on something else.", NULL); return false; }
	ui->f_pend = 1;
	ui->f_pend_cmd = cmd;
	memcpy(ui->f_pend_req, req, n);
	ui->f_pend_n = n;
	wait_dlg(ui, what, "Working...");
	pend_start(ui);
	return true;
}

/* true when started (or nothing to start). */
static bool pend_start(ez_ui_t *ui)
{
	ez_dispatch_t *d = ui->env.disp;
	if (!ui->f_pend) return true;
	if (d->job_running) { if (d->job == 4) d->yield = true; return false; }
	ez_status_t st = EZ_OK;
	if (ui->f_pend == 1) st = ez_dispatch_submit(d, ui->f_pend_cmd, ui->f_pend_req, ui->f_pend_n) ? EZ_OK : EZ_ERR_BUSY;
	else if (ui->f_pend == 2) st = ez_dispatch_start_keygen(d, ui->f_staged ? 0 : ui->f_drive, ui->f_len);
	else st = ez_dispatch_start_import(d, 1, ui->f_files[0], ui->f_id, ui->f_role, ui->f_label);
	if (st == EZ_ERR_BUSY) return false;
	ui->f_pend = 0;
	if (st != EZ_OK) {                                   /* could not start: the flow sees it as the result */
		ui->f_result = st;
		ui->f_job = false;
		flow_next(ui, ANS_JOB);
		return true;
	}
	ui->f_ticket = ez_dispatch_last_ticket(d);
	ui->f_job = true;
	return true;
}

static bool card_present(ez_ui_t *ui)
{
	const ez_hal_keystore_t *ks = ui->env.core->ks;
	return ks->present(ks->ctx, 1);
}

static bool label_ok(ez_ui_t *ui, const char *l)
{
	if (!*l) { snprintf(ui->dlg_err, sizeof ui->dlg_err, "a label is needed"); return false; }
	for (const char *p = l; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.')) {
			snprintf(ui->dlg_err, sizeof ui->dlg_err, "letters, digits, - _ . only");
			return false;
		}
	if (find_label(ui, l) >= 0) { snprintf(ui->dlg_err, sizeof ui->dlg_err, "'%s' is already a key", l); return false; }
	return true;
}

static void flow_start(ez_ui_t *ui, int fl)
{
	if (ui->env.disp->job_running) { info(ui, "Busy", "The device is working on something else; try again.", NULL); ui->flow = FL_NONE; return; }
	ui->flow = fl;
	ui->step = 0;
	ui->f_force = ui->f_staged = ui->f_tmp0 = false;
	if (fl != FL_NEW && fl != FL_IMPORT) {
		int i = key_slot(ui, ui->key_at);
		if (i < 0) { ui->flow = FL_NONE; return; }
		const ez_session_t *s = &ui->env.core->meta.s[i];
		ui->f_slot = i;
		ui->f_id = s->key_id;
		ui->f_len = s->key_len;
		ui->f_drive = s->drive;
		ui->f_flags = s->flags;
		snprintf(ui->f_label, sizeof ui->f_label, "%s", s->identity ? s->label : "");
	}
	flow_next(ui, 0);
}

static void new_key(ez_ui_t *ui, int ans)
{
	static const uint32_t sizes[] = { 64u << 10, 128u << 10, 256u << 10, 512u << 10, 2u << 20 };
	ez_core_t *c = ui->env.core;
	bool d0 = c->meta.drive0_enabled && ez_core_drive_usable(c, 0) == EZ_OK;
	switch (ui->step) {
	case 0:
		dlg_open(ui, DLG_PICK, "New key: size");
		OPT("64 KiB    send up to 32 KiB     about 4 minutes");
		OPT("128 KiB   send up to 64 KiB     about 8 minutes");
		OPT("256 KiB   send up to 128 KiB    about 15 minutes");
		OPT("512 KiB   send up to 256 KiB    about 30 minutes");
		OPT("2 MiB     send up to 1 MiB      about 2 hours");
		ui->dlg_at = 2;
		ui->step = 1;
		break;
	case 1:
		ui->f_len = sizes[ans];
		dlg_open(ui, DLG_INPUT, "New key: label");
		MSG(0, "A short name for the other party, e.g. 'alice'.");
		ui->step = 2;
		break;
	case 2:
		if (!label_ok(ui, ui->dlg_in)) break;
		snprintf(ui->f_label, sizeof ui->f_label, "%s", ui->dlg_in);
		dlg_open(ui, DLG_PICK, "New key: where to keep it");
		{
			int m = 0;
			if (card_present(ui)) {
				OPT("On the card");
				MSG(m++, "On the card: you can take the card with you.");
				if (d0) {
					OPT("On the card, with a spare copy");
					MSG(m++, "With a spare copy: also kept in internal storage,");
					MSG(m++, "in case the card is lost or fails.");
				}
			}
			if (d0) { OPT("Internal storage only"); MSG(m++, "Internal storage only: no card needed."); }
		}
		if (!ui->dlg_nopt) { info(ui, "New key", "No card, and internal storage is off: nowhere to keep a key.", NULL); return; }
		ui->step = 3;
		break;
	case 3: {
		const char *o = ui->dlg_opt[ans];
		ui->f_drive = strstr(o, "only") ? 0 : 1;
		ui->f_flags = strstr(o, "spare") ? EZ_SESS_CRITICAL : 0;
		ui->f_staged = ui->f_drive == 1 && d0;
		dlg_open(ui, DLG_YN, "New key: confirm");
		MSG(0, "Generate %lu KiB for '%s'?", (unsigned long)(ui->f_len >> 10), ui->f_label);
		MSG(1, "Kept %s%s.", ui->f_drive ? "on the card" : "in internal storage", ui->f_flags ? ", with a spare copy" : "");
		MSG(2, "You will be 'alice'; the other party imports it as 'bob'.");
		ui->step = 4;
		break;
	}
	case 4: {
		if (ans != 1) { flow_end(ui); return; }
		ui->f_detached = false;
		ui->step = 5;
		ui->f_pend = 2;
		wait_dlg(ui, "Generating the key", "The TRNG is filling the key; this takes a while.");
		pend_start(ui);
		break;
	}
	case 5: {
		ez_dispatch_t *d = ui->env.disp;
		if (ui->f_result == EZ_ERR_ABORTED) { info(ui, "New key", "Generating was cancelled; nothing was kept.", NULL); return; }
		if (ui->f_result != EZ_OK) { info(ui, "New key", "Generation failed:", ez_status_name(ui->f_result)); return; }
		ui->f_id = d->kg.key_id;
		ui->step = 6;
		if (ui->f_staged) {
			uint8_t q[6];
			ez_put_le32(q, ui->f_id); q[4] = 0; q[5] = 1;
			start_job(ui, EZ_CMD_KEY_COPY, q, 6, "Copying the key to the card");
			break;
		}
		flow_next(ui, ANS_JOB);
		break;
	}
	case 6:
		if (ui->f_staged) {
			if (ui->f_result != EZ_OK) { info(ui, "New key", "Copying to the card failed (the key stays in internal storage):", ez_status_name(ui->f_result)); return; }
			uint8_t q[5];
			ez_put_le32(q, ui->f_id); q[4] = 0;
			ui->step = 7;
			start_job(ui, EZ_CMD_KEY_DELETE, q, 5, "Erasing the copy in internal storage");
			break;
		}
		ui->step = 7;
		/* fall through */
	case 7: {
		uint8_t q[32];
		ez_wr_t w;
		ez_wr_init(&w, q, sizeof q);
		ez_wr_u32(&w, ui->f_id); ez_wr_u8(&w, ui->f_drive); ez_wr_u8(&w, EZ_ROLE_ALICE);
		ez_wr_str(&w, ui->f_label); ez_wr_u8(&w, ui->f_flags);
		ui->step = 8;
		start_job(ui, EZ_CMD_SESSION_CREATE, q, (uint32_t)w.n, "Creating the session");
		break;
	}
	case 8:
		if (ui->f_result != EZ_OK) { info(ui, "New key", "Creating the session failed:", ez_status_name(ui->f_result)); return; }
		if (ui->f_detached) { info(ui, "New key", "", NULL); snprintf(ui->notice, sizeof ui->notice, "Key '%s' is ready.", ui->f_label); if (ui->screen == EZ_UI_HOME) draw_home(ui, false); else if (ui->screen == EZ_UI_KEYS) draw_keys(ui); break; }
		info(ui, "New key", "The key is ready.", "To give the other party their copy: select it and press X.");
		break;
	}
	draw_dialog(ui);
}

static void import_key(ez_ui_t *ui, int ans)
{
	ez_core_t *c = ui->env.core;
	switch (ui->step) {
	case 0: {
		if (!card_present(ui)) { info(ui, "Import", "Insert the card with the key first.", NULL); return; }
		dlg_open(ui, DLG_PICK, "Import a key from the card");
		static char name[EZ_NAME_MAX];
		uint32_t size, i = 0;
		ui->f_n = 0;
		while (ui->f_n < 8 && c->ks->list(c->ks->ctx, 1, i++, name, &size) == EZ_OK) {
			size_t l = strlen(name);
			if (l != 12 || strcmp(name + 8, ".KEY")) continue;    /* "XXXXXXXX.KEY" only */
			uint32_t id = 0;
			for (size_t k = 0; k + 4 < l; k++) {
				char ch = name[k];
				id = id << 4 | (uint32_t)(ch >= 'A' ? ch - 'A' + 10 : ch - '0');
			}
			if (ez_meta_find_key_id(&c->meta, id) >= 0) continue;   /* already in use */
			memcpy(ui->f_files[ui->f_n], name, 13);
			ui->f_ids[ui->f_n] = id;
			OPT("%.12s  (%lu KiB)", name, (unsigned long)(size >> 10));
			ui->f_n++;
		}
		if (!ui->f_n) { info(ui, "Import", "No new key files on the card.", NULL); return; }
		ui->step = 1;
		break;
	}
	case 1:
		ui->f_id = ui->f_ids[ans];
		memmove(ui->f_files[0], ui->f_files[ans], sizeof ui->f_files[0]);   /* may be the same entry */
		dlg_open(ui, DLG_INPUT, "Import: label");
		MSG(0, "A short name for the other party.");
		ui->step = 2;
		break;
	case 2:
		if (!label_ok(ui, ui->dlg_in)) break;
		snprintf(ui->f_label, sizeof ui->f_label, "%s", ui->dlg_in);
		dlg_open(ui, DLG_PICK, "Import: your role");
		OPT("bob    (the other party generated the key)");
		OPT("alice  (you generated it)");
		ui->step = 3;
		break;
	case 3: {
		ui->f_role = ans == 0 ? EZ_ROLE_BOB : EZ_ROLE_ALICE;
		ui->step = 4;
		ui->f_pend = 3;
		wait_dlg(ui, "Importing", "Checking the key and creating the session...");
		pend_start(ui);
		break;
	}
	case 4:
		if (ui->f_result != EZ_OK) { info(ui, "Import", "Import failed:", ez_status_name(ui->f_result)); return; }
		info(ui, "Import", "The key is imported and ready.", NULL);
		break;
	}
	draw_dialog(ui);
}

/* Export: a key leaves the device only on a card (UI-S1). With one slot,
 * the key is held on drive 0 while the cards are swapped. */
static void export_key(ez_ui_t *ui, int ans)
{
	ez_core_t *c = ui->env.core;
	switch (ui->step) {
	case 0:
		if (ui->f_drive != 0 && !(c->meta.drive0_enabled && ez_core_drive_usable(c, 0) == EZ_OK)) {
			info(ui, "Export", "Internal storage is needed to hold the key while the cards are swapped.", NULL);
			return;
		}
		dlg_open(ui, DLG_YN, "Export to a transfer card");
		MSG(0, "Copy '%s' to a card for the other party:", ui->f_label);
		MSG(1, "you will swap your card for a FAT-formatted transfer card,");
		MSG(2, "the key is copied and verified, and you put your card back.");
		MSG(3, "Continue?");
		ui->step = 1;
		break;
	case 1: {
		if (ans != 1) { flow_end(ui); return; }
		ui->step = 2;
		if (ui->f_drive != 0) {                   /* hold it on drive 0 for the swap */
			uint8_t q[6];
			ez_put_le32(q, ui->f_id); q[4] = 1; q[5] = 0;
			ui->f_tmp0 = !(ui->f_flags & EZ_SESS_CRITICAL);
			start_job(ui, EZ_CMD_KEY_COPY, q, 6, "Holding the key in internal storage");
			break;
		}
		flow_next(ui, ANS_JOB);
		return;
	}
	case 2:
		if (ui->f_job == false && ui->f_result != EZ_OK && ui->f_result != EZ_ERR_EXISTS && ui->f_drive != 0) {
			info(ui, "Export", "Could not hold the key in internal storage:", ez_status_name(ui->f_result));
			return;
		}
		wait_dlg(ui, "Export: swap the cards", "Remove your card now.");
		ui->f_card = 1;
		ui->step = 3;
		break;
	case 3:
		wait_dlg(ui, "Export: swap the cards", "Insert the transfer card.");
		ui->f_card = 2;
		ui->step = 4;
		break;
	case 4: {
		uint8_t q[6];
		ez_put_le32(q, ui->f_id); q[4] = 0; q[5] = 1;
		ui->step = 5;
		start_job(ui, EZ_CMD_KEY_COPY, q, 6, "Copying to the transfer card");
		break;
	}
	case 5: {
		ez_status_t st = ui->f_result;
		snprintf(ui->dlg_err, sizeof ui->dlg_err, "%s", st == EZ_OK ? "" : ez_status_name(st));
		wait_dlg(ui, "Export: swap the cards", st == EZ_OK ? "Copied and verified. Remove the transfer card." :
		                                                     "Copying FAILED. Remove the transfer card.");
		ui->f_force = st != EZ_OK;                /* remember the failure */
		ui->f_card = 1;
		ui->step = 6;
		break;
	}
	case 6:
		wait_dlg(ui, "Export: swap the cards", "Insert your own card again.");
		ui->f_card = 2;
		ui->step = 7;
		break;
	case 7:
		ui->step = 8;
		if (ui->f_tmp0) {
			uint8_t q[5];
			ez_put_le32(q, ui->f_id); q[4] = 0;
			start_job(ui, EZ_CMD_KEY_DELETE, q, 5, "Erasing the copy held in internal storage");
			break;
		}
		flow_next(ui, ANS_JOB);
		return;
	case 8:
		ez_dispatch_want_sync(ui->env.disp);     /* your card is back: check it fully */
		if (ui->f_force) info(ui, "Export", "The transfer card was NOT written.", "Try another card.");
		else info(ui, "Export", "Done. Give the transfer card to the other party;", "they import it as 'bob' (Keys, I).");
		return;
	}
	draw_dialog(ui);
}

static void delete_key(ez_ui_t *ui, int ans)
{
	switch (ui->step) {
	case 0:
		dlg_open(ui, DLG_TYPE, "Delete a key");
		MSG(0, "This erases '%s' and its key file for good.", ui->f_label);
		MSG(1, "Type the label to confirm.");
		snprintf(ui->dlg_expect, sizeof ui->dlg_expect, "%s", ui->f_label);
		ui->step = 1;
		break;
	case 1: {
		uint8_t q[6] = { (uint8_t)ui->f_slot };
		ez_put_le32(q + 1, ui->f_id);
		q[5] = ui->f_force ? 1 : 0;
		ui->step = 2;
		start_job(ui, EZ_CMD_SESSION_DELETE, q, 6, "Deleting");
		return;
	}
	case 2: {
		ez_status_t st = ui->f_result;
		if (st == EZ_OK) { info(ui, "Delete", "The key is erased.", NULL); return; }
		if (!ui->f_force) {
			dlg_open(ui, DLG_YN, "Delete");
			MSG(0, "The key file could not be erased (%s).", ez_status_name(st));
			MSG(1, "Delete the key's record anyway? Its file stays where it is.");
			ui->step = 3;
			break;
		}
		info(ui, "Delete", "Deleting failed:", ez_status_name(st));
		return;
	}
	case 3:
		if (ans != 1) { flow_end(ui); return; }
		ui->f_force = true;
		ui->step = 1;
		flow_next(ui, 0);
		return;
	}
	draw_dialog(ui);
}

static void skip_resolve(ez_ui_t *ui, int ans)
{
	ez_core_t *c = ui->env.core;
	bool skip = ui->flow == FL_SKIP;
	if (ui->step == 0) {
		dlg_open(ui, DLG_YN, skip ? "Skip damaged key data" : "Resolve");
		if (skip) { MSG(0, "Move '%s' past damaged key units?", ui->f_label); MSG(1, "That part of the key is never used."); }
		else MSG(0, "Check '%s' and return it to use if its key is intact?", ui->f_label);
		ui->step = 1;
		draw_dialog(ui);
		return;
	}
	if (ans != 1) { flow_end(ui); return; }
	ez_status_t st;
	if (skip) { uint32_t n = 0; st = ez_session_skip(c, ui->f_slot, &n); }
	else st = ez_session_resolve(c, ui->f_slot);
	info(ui, skip ? "Skip" : "Resolve", st == EZ_OK ? "Done." : "Not possible:", st == EZ_OK ? NULL : ez_status_name(st));
}

static void backup_key(ez_ui_t *ui, int ans)
{
	bool on = !(ui->f_flags & EZ_SESS_CRITICAL);
	switch (ui->step) {
	case 0:
		if (ui->f_drive == 0) { info(ui, "Spare copy", "This key is in internal storage already.", NULL); return; }
		dlg_open(ui, DLG_YN, on ? "Spare copy" : "Remove the spare copy");
		if (on) { MSG(0, "Keep a spare copy of '%s' in internal storage?", ui->f_label); MSG(1, "If the card is lost or fails, the key is not lost."); }
		else MSG(0, "Remove the spare copy of '%s' from internal storage?", ui->f_label);
		ui->step = 1;
		break;
	case 1: {
		if (ans != 1) { flow_end(ui); return; }
		uint8_t q[6] = { (uint8_t)ui->f_slot };
		ez_put_le32(q + 1, ui->f_id);
		q[5] = on ? 1 : 0;
		ui->step = 2;
		start_job(ui, EZ_CMD_SESSION_CRITICAL, q, 6, on ? "Making the spare copy" : "Removing the spare copy");
		return;
	}
	case 2: {
		ez_status_t st = ui->f_result;
		if (st == EZ_OK) info(ui, "Spare copy", on ? "The spare copy is made." : "The spare copy is removed.", NULL);
		else info(ui, "Spare copy", st == EZ_ERR_DRIVE_DISABLED || st == EZ_ERR_PROTECTION ?
		          "Internal storage is off; no spare copy possible." : "Not possible:", st == EZ_ERR_DRIVE_DISABLED || st == EZ_ERR_PROTECTION ? NULL : ez_status_name(st));
		return;
	}
	}
	draw_dialog(ui);
}

static void flow_next(ez_ui_t *ui, int ans)
{
	if (ans == ANS_CANCEL && ui->dlg != DLG_WAIT) { flow_end(ui); return; }
	if (ui->step == 99) {
		int f = ui->flow;
		flow_end(ui);
		if (f == 101) receive_open(ui);                  /* after a failed receive: ready for the next paste */
		return;
	}
	switch (ui->flow) {
	case FL_NEW:     new_key(ui, ans); break;
	case FL_IMPORT:  import_key(ui, ans); break;
	case FL_EXPORT:  export_key(ui, ans); break;
	case FL_DELETE:  delete_key(ui, ans); break;
	case FL_SKIP: case FL_RESOLVE: skip_resolve(ui, ans); break;
	case FL_BACKUP:  backup_key(ui, ans); break;
	case 102: upload_encrypt(ui, ans); break;         /* Send: an uploaded file, confirmed */
	case 100:                                          /* Send: the key picked */
		ui->flow = FL_NONE;
		dlg_close(ui);
		send_open(ui, (int)ui->f_ids[ans]);
		break;
	default: flow_end(ui); break;
	}
}

static void dlg_key(ez_ui_t *ui, int k);
enum { K_UP = 0x100, K_DOWN, K_LEFT, K_RIGHT, K_ESC, K_ENTER, K_BS, K_PGUP, K_PGDN };

static void dlg_key(ez_ui_t *ui, int k)
{
	switch (ui->dlg) {
	case DLG_INFO:
		dlg_close(ui);
		flow_next(ui, ANS_OK);
		return;
	case DLG_WAIT:
		if (ui->flow == FL_NEW && ui->f_job) {
			if (k == K_ESC) {                        /* carry on in the background */
				ui->f_detached = true;
				dlg_close(ui);
				ez_ui_redraw(ui);
			} else if ((k == 'c' || k == 'C') && ui->env.disp->job == 1) {
				ui->env.disp->cancel = true;
			}
		}
		return;                                      /* the job or the card moves it on */
	case DLG_YN:
		if (k == 'y' || k == 'Y') flow_next(ui, 1);
		else if (k == 'n' || k == 'N') flow_next(ui, 0);
		else if (k == K_ESC) flow_next(ui, ANS_CANCEL);
		return;
	case DLG_PICK:
		if (k == K_UP && ui->dlg_at > 0) ui->dlg_at--;
		else if (k == K_DOWN && ui->dlg_at + 1 < ui->dlg_nopt) ui->dlg_at++;
		else if (k == K_ENTER) { flow_next(ui, ui->dlg_at); return; }
		else if (k == K_ESC) { flow_next(ui, ANS_CANCEL); return; }
		draw_dialog(ui);
		return;
	case DLG_INPUT: case DLG_TYPE:
		if (k == K_ESC) { flow_next(ui, ANS_CANCEL); return; }
		if (k == K_ENTER) {
			if (ui->dlg == DLG_TYPE && strcmp(ui->dlg_in, ui->dlg_expect)) {
				snprintf(ui->dlg_err, sizeof ui->dlg_err, "that is not '%s'", ui->dlg_expect);
				draw_dialog(ui);
				return;
			}
			ui->dlg_err[0] = 0;
			flow_next(ui, ANS_OK);
			return;
		}
		if (k == K_BS && ui->dlg_ilen) ui->dlg_in[--ui->dlg_ilen] = 0;
		else if (k >= 32 && k < 127 && ui->dlg_ilen < (int)EZ_LABEL_MAX) { ui->dlg_in[ui->dlg_ilen++] = (char)k; ui->dlg_in[ui->dlg_ilen] = 0; }
		draw_dialog(ui);
		return;
	default:
		return;
	}
}

/* ---- Send and Receive (round 19, EZ-UI-001 §5-§7) ------------------------------- */

enum { ACT_ENCRYPT = 1, ACT_CANCEL = 2, ACT_UPLOAD = 3 };
enum { TAG_ENC = 1, TAG_DISCARD = 2, TAG_UPLOAD = 3 };
enum { VIEW_NONE, VIEW_CIPHER, VIEW_PLAIN };
#define IDLE_WIPE_MS (10u * 60u * 1000u)              /* §10: wipe open messages after 10 minutes */
#define B64_PER_LINE 57u                              /* 76 characters of base64 */

static void ed_write(void *ctx, const char *b, uint32_t n) { ez_ui_t *ui = ctx; ui->env.write(ui->env.ctx, b, n); }
static void xm_start(ez_ui_t *ui, int mode);
static void xm_start_seen(ez_ui_t *ui, int mode, const uint8_t *seen, uint32_t seen_n);
static void view_open(ez_ui_t *ui, int kind, const uint8_t *b, uint32_t n, const char *from);

static void home_now(ez_ui_t *ui);

/* Everything a message screen held is wiped: the editor's text and state,
 * the core's stage, and the terminal's screen and scrollback. */
static void wipe_messages(ez_ui_t *ui)
{
	if (ui->env.text) ez_secure_zero(ui->env.text, ui->env.text_cap);
	ez_secure_zero(&ui->ed, sizeof ui->ed);
	ez_release(ui->env.core);
	ez_secure_zero(&ui->b64, sizeof ui->b64);
	ui->editing = ui->capture = ui->view_dump = ui->view_bare = false;
	ui->view = VIEW_NONE;
	ui->vbuf = NULL;
	ui->vlen = ui->cap_n = ui->cap_need = ui->dec_pending = 0;
	out(ui, "\033[r\033[2J\033[3J");
}

static const char *why_words(ez_status_t st)
{
	switch (st) {
	case EZ_ERR_INTEGRITY:     return "Changed or damaged in transit: nothing is shown.";
	case EZ_ERR_REPLAY:        return "This message was already received.";
	case EZ_ERR_NO_SESSION:
	case EZ_ERR_KEY_ID:        return "There is no key for this message on this device.";
	case EZ_ERR_QUARANTINED:   return "The key for this message needs attention (see Keys).";
	case EZ_ERR_RANGE:         return "The message does not fit its key's range.";
	case EZ_ERR_CAPACITY:      return "Not enough key left.";
	case EZ_ERR_MEDIA_REMOVED: return "Insert the card that holds the key.";
	case EZ_ERR_KEY_DAMAGED:   return "The key data is damaged (Keys: check).";
	case EZ_ERR_BUSY:          return "The device is busy for a moment; try again.";
	default:                   return ez_status_name(st);
	}
}

/* ---- the message view ---- */

static uint32_t plain_line(const ez_ui_t *ui, uint32_t from, uint32_t *next)
{
	uint32_t w = (uint32_t)ui->cols - 1, i = from, n = 0;
	while (i < ui->vlen && ui->vbuf[i] != '\n' && n < w) { i++; n++; }
	*next = i < ui->vlen && ui->vbuf[i] == '\n' ? i + 1 : i;
	return n;
}

static int view_lines(const ez_ui_t *ui)
{
	if (ui->view == VIEW_CIPHER) return (int)((ui->vlen + B64_PER_LINE - 1) / B64_PER_LINE);
	int n = 0;
	for (uint32_t i = 0, nx; i < ui->vlen; i = nx, n++) plain_line(ui, i, &nx);
	return n ? n : 1;
}

/* Line k of the view, as text, into o. */
static void view_line(const ez_ui_t *ui, int k, char *o, size_t cap)
{
	o[0] = 0;
	if (ui->view == VIEW_CIPHER) {
		uint32_t a = (uint32_t)k * B64_PER_LINE;
		if (a >= ui->vlen) return;
		uint32_t n = ui->vlen - a < B64_PER_LINE ? ui->vlen - a : B64_PER_LINE;
		if (cap > 80) o[ez_b64_encode(ui->vbuf + a, n, o)] = 0;
		return;
	}
	uint32_t i = 0, nx;
	for (int j = 0; j < k && i < ui->vlen; j++) { plain_line(ui, i, &nx); i = nx; }
	uint32_t n = plain_line(ui, i, &nx);
	size_t m = 0;
	for (uint32_t j = 0; j < n && m + 1 < cap; j++) {
		uint8_t ch = ui->vbuf[i + j];
		o[m++] = ch >= 32 || ch >= 0x80 ? (char)ch : '.';
	}
	o[m] = 0;
}

static void draw_view(ez_ui_t *ui)
{
	char l[200];
	int rows = ui->view_bare ? ui->rows : ui->rows - 1, n = view_lines(ui);
	out(ui, "\033[r" NORM "\033[2J");
	for (int r = 0; r < rows && ui->vtop + r < n; r++) {
		at(ui, 1 + r, 1);
		view_line(ui, ui->vtop + r, l, sizeof l);
		out(ui, l);
	}
	if (ui->view_bare) return;
	at(ui, ui->rows, 1);
	char f[160];
	if (ui->view == VIEW_CIPHER)
		snprintf(f, sizeof f, " For '%s', %lu bytes. Arrows/PgUp/PgDn  C copy  D download  Enter done",
		         ui->view_from, (unsigned long)ui->vlen);
	else
		snprintf(f, sizeof f, " From '%s', %lu B, verified. Arrows/PgUp/PgDn  C copy  D download  Enter done",
		         ui->view_from, (unsigned long)ui->vlen);
	outf(ui, INV "%-*.*s" NORM, ui->cols - 1, ui->cols - 1, f);
}

static void view_open(ez_ui_t *ui, int kind, const uint8_t *b, uint32_t n, const char *from)
{
	ui->view = kind;
	ui->vbuf = b;
	ui->vlen = n;
	ui->vtop = 0;
	ui->view_dump = ui->view_bare = false;
	ui->view_opened_ms = ui->now_ms;
	snprintf(ui->view_from, sizeof ui->view_from, "%s", from);
	draw_view(ui);
}

/* C: the whole text, plainly, for selecting and copying in the terminal
 * (its scrollback holds it all); any key returns, clearing the scrollback. */
static void view_dump(ez_ui_t *ui)
{
	char l[200];
	out(ui, "\033[r" NORM "\033[2J\033[H");
	int n = view_lines(ui);
	for (int k = 0; k < n; k++) { view_line(ui, k, l, sizeof l); out(ui, l); out(ui, "\r\n"); }
	out(ui, "\r\n-- end: press any key to return --");
	ui->view_dump = true;
}

static void view_key(ez_ui_t *ui, int k);

/* ---- Send ---- */

static void send_open(ez_ui_t *ui, int slot)
{
	const ez_session_t *s = &ui->env.core->meta.s[slot];
	ui->send_slot = slot;
	zetta_cfg_t cfg;
	memset(&cfg, 0, sizeof cfg);
	cfg.rows = ui->rows;
	cfg.cols = ui->cols;
	snprintf(ui->ed_title, sizeof ui->ed_title, "Send to '%s' (%lu bytes of key left)", s->label,
	         (unsigned long)ez_meta_tx_remaining(s));
	cfg.title = ui->ed_title;
	cfg.actions[0] = (zetta_action_t){ ZK_CTRL('E'), "Encrypt", ACT_ENCRYPT };
	cfg.actions[1] = (zetta_action_t){ ZK_CTRL('O'), "Upload a file", ACT_UPLOAD };
	cfg.actions[2] = (zetta_action_t){ 0, "Cancel", ACT_CANCEL };
	cfg.nactions = 3;
	cfg.main_action = ACT_ENCRYPT;
	cfg.write = ed_write;
	cfg.ctx = ui;
	ez_secure_zero(ui->env.text, ui->env.text_cap);
	out(ui, "\033[r" NORM "\033[2J");
	zetta_init(&ui->ed, &cfg, ui->env.text, ui->env.text_cap);
	ui->editing = true;
}

static void send_encrypt(ez_ui_t *ui)
{
	ez_core_t *c = ui->env.core;
	ez_dispatch_t *d = ui->env.disp;
	if (d->job_running) {                                 /* never in parallel with a job */
		if (d->job == 4) d->yield = true;
		zetta_error(&ui->ed, "The device is busy for a moment; press Ctrl-E again.");
		return;
	}
	uint32_t n = ui->ed.len;
	uint8_t *p = ez_stage_plaintext(c, n);
	if (!p) { zetta_error(&ui->ed, "The message is too long."); return; }
	memcpy(p, ui->env.text, n);
	const uint8_t *o;
	uint32_t on;
	ez_status_t st = ez_encrypt_buffered(c, ui->send_slot, n, &o, &on);
	if (st != EZ_OK) { ez_release(c); zetta_error(&ui->ed, why_words(st)); return; }
	/* The plaintext is gone from the device as soon as it is encrypted. */
	ez_secure_zero(ui->env.text, ui->env.text_cap);
	ez_secure_zero(&ui->ed, sizeof ui->ed);
	ui->editing = false;
	view_open(ui, VIEW_CIPHER, o, on, c->meta.s[ui->send_slot].label);
}

static void ed_event(ez_ui_t *ui, int ev)
{
	const ez_session_t *s = &ui->env.core->meta.s[ui->send_slot];
	if (ev == ZE_ACTION && ui->ed.action == ACT_ENCRYPT) {
		uint32_t n = ui->ed.len, left = ez_meta_tx_remaining(s);
		char q[80];
		if (!n) { zetta_error(&ui->ed, "Nothing to send yet."); return; }
		if (n > EZ_BUFFERED_MAX) { zetta_error(&ui->ed, "Over 64 KiB: send it with 'ez' on a computer."); return; }
		if (n > left) { zetta_error(&ui->ed, "Not enough key left for this message."); return; }
		snprintf(q, sizeof q, "Encrypt %lu bytes for '%s'? %lu bytes of key will remain.",
		         (unsigned long)n, s->label, (unsigned long)(left - n));
		zetta_confirm(&ui->ed, q, TAG_ENC);
		return;
	}
	if (ev == ZE_ACTION && ui->ed.action == ACT_UPLOAD) {
		if (ui->ed.len) { zetta_confirm(&ui->ed, "Replace this message with an uploaded file?", TAG_UPLOAD); return; }
		ez_secure_zero(ui->env.text, ui->env.text_cap);
		ez_secure_zero(&ui->ed, sizeof ui->ed);
		ui->editing = false;
		xm_start(ui, 1);
		return;
	}
	if (ev == ZE_EXIT || (ev == ZE_ACTION && ui->ed.action == ACT_CANCEL)) {
		if (ui->ed.len) { zetta_confirm(&ui->ed, "Discard this message?", TAG_DISCARD); return; }
		wipe_messages(ui);
		home_now(ui);
		return;
	}
	if (ev == ZE_ANSWER && ui->ed.answer == 'y') {
		if (ui->ed.answer_tag == TAG_ENC) send_encrypt(ui);
		else if (ui->ed.answer_tag == TAG_UPLOAD) {
			ez_secure_zero(ui->env.text, ui->env.text_cap);
			ez_secure_zero(&ui->ed, sizeof ui->ed);
			ui->editing = false;
			xm_start(ui, 1);
		}
		else if (ui->ed.answer_tag == TAG_DISCARD) { wipe_messages(ui); home_now(ui); }
	}
}

static bool busy_screen(ez_ui_t *ui, const char *title)
{
	const ez_dispatch_t *d = ui->env.disp;
	if (!d->job_running || d->job == 4) return false;    /* a sync makes way by itself */
	char l2[80];
	snprintf(l2, sizeof l2, "The device is %s; this is possible again when it's done.",
	         d->job == 1 ? "generating a key" : "busy with another task");
	draw_text(ui, (const char *const[]){ title, "", l2, "Meanwhile the menus, Keys, Device and Help still work.", NULL });
	return true;
}

static void send_start(ez_ui_t *ui)
{
	if (busy_screen(ui, "Send")) return;
	int cand[EZ_META_SESSIONS], n = 0;
	for (int i = 0; i < EZ_META_SESSIONS; i++) {
		const ez_session_t *s = &ui->env.core->meta.s[i];
		if (s->state == EZ_SS_VALID && s->identity && s->offsets && ez_meta_tx_remaining(s) > 0) cand[n++] = i;
	}
	if (!n) { draw_text(ui, (const char *const[]){ "Send", "", "No key can send: make one in Keys (N), or import one (I).", NULL }); return; }
	if (n == 1) { send_open(ui, cand[0]); return; }
	ui->flow = 100;                                     /* the key pick */
	ui->step = 0;
	dlg_open(ui, DLG_PICK, "Send with which key?");
	ui->f_n = 0;
	for (int i = 0; i < n && i < 8; i++) {
		const ez_session_t *s = &ui->env.core->meta.s[cand[i]];
		OPT("%-16s %lu bytes left", s->label, (unsigned long)ez_meta_tx_remaining(s));
		ui->f_ids[ui->f_n++] = (uint32_t)cand[i];
	}
	draw_dialog(ui);
}

/* ---- Receive ---- */

static void draw_capture(ez_ui_t *ui, bool full)
{
	if (full) {
		out(ui, "\033[r" NORM "\033[2J");
		draw_menu(ui);
		draw_text(ui, (const char *const[]){ "Receive", "",
		    "Paste the message now (base64). It finishes by itself when complete.",
		    "Messages up to 64 KiB; larger ones with 'ez decrypt' on a computer.",
		    "A message file: start a ZMODEM upload, or press Ctrl-R (ZMODEM or XMODEM).",
		    "Esc cancels.", NULL });
		draw_status(ui, true);
	}
	at(ui, 10, 3);
	if (ui->cap_need) outf(ui, "%lu of %lu bytes received" EOL, (unsigned long)ui->cap_n, (unsigned long)ui->cap_need);
	else outf(ui, "%lu bytes received" EOL, (unsigned long)ui->cap_n);
}

static void receive_done(ez_ui_t *ui, const char *why)
{
	wipe_messages(ui);
	ui->screen = EZ_UI_RECEIVE;
	ui->menu_focus = false;
	ez_ui_redraw(ui);
	ui->flow = 101;
	info(ui, "Receive", why, "Press a key, then paste the next message (or Esc).");
}

static void receive_decrypt(ez_ui_t *ui)
{
	ez_core_t *c = ui->env.core;
	ez_dispatch_t *d = ui->env.disp;
	if (d->job_running) {                                 /* wait for the job; a sync makes way */
		if (d->job == 4) d->yield = true;
		ui->dec_pending = ui->cap_need;
		return;
	}
	ui->dec_pending = 0;
	ez_msg_hdr_t h;
	ez_msg_hdr_decode(c->stage, &h);
	int slot = ez_meta_find_key_id(&c->meta, h.key_id);
	const uint8_t *pt;
	uint32_t n;
	ez_status_t st = ez_decrypt_buffered(c, -1, ui->cap_need, &pt, &n);
	if (st != EZ_OK) { receive_done(ui, why_words(st)); return; }
	ui->capture = false;
	view_open(ui, VIEW_PLAIN, pt, n, slot >= 0 ? c->meta.s[slot].label : "?");
}

static void receive_open(ez_ui_t *ui)
{
	if (busy_screen(ui, "Receive")) return;
	ez_b64_dec_init(&ui->b64);
	ui->cap_n = ui->cap_need = 0;
	ui->cap_prev = 0;
	ui->capture = true;
	draw_capture(ui, true);
}

/* One byte of a message, pasted or uploaded: base64 decoded (or, for an
 * uploaded raw message, copied) straight into the core's stage. Returns 0
 * to go on, 1 when the message is complete, -1 on an error (shown). */
static int cap_push(ez_ui_t *ui, uint8_t byte, bool quiet)
{
	ez_core_t *c = ui->env.core;
	if (ui->cap_need && ui->cap_n >= ui->cap_need) return 1;        /* complete: the rest is padding */
	char ch = (char)byte;
	size_t got = 0;
	if (ui->cap_n + 3 > EZ_STAGE_SIZE) { if (!quiet) receive_done(ui, "The message is larger than 64 KiB: use 'ez decrypt'."); return -1; }
	/* Until the header is in, decode into a small buffer; then stage the
	 * whole message once (staging wipes the stage) and decode into it. */
	uint8_t *dst = ui->cap_need ? c->stage : ui->cap_tmp;
	if (ui->cap_raw) {
		dst[ui->cap_n] = byte;
		got = 1;
	} else {
		bool b64 = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
		           ch == '+' || ch == '/' || ch == '=';
		if (!b64) return 0;                                   /* line breaks, spaces, frames, ^Z */
		if (ez_b64_dec_update(&ui->b64, &ch, 1, dst + ui->cap_n, &got) != EZ_OK) {
			if (!quiet) receive_done(ui, "That is not an Einszeit message (not base64).");
			return -1;
		}
	}
	ui->cap_n += (uint32_t)got;
	if (!ui->cap_need && ui->cap_n >= 3 &&
	    (ui->cap_tmp[0] != 0x5A || ui->cap_tmp[1] != 0x45 || ui->cap_tmp[2] != EZ_MSG_VERSION)) {
		if (!quiet) receive_done(ui, "That is not an Einszeit message.");
		return -1;
	}
	if (!ui->cap_need && ui->cap_n >= EZ_MSG_HDR) {
		ez_msg_hdr_t h;
		if (ez_msg_hdr_decode(ui->cap_tmp, &h) != EZ_OK) { if (!quiet) receive_done(ui, "That is not an Einszeit message."); return -1; }
		if (h.length > EZ_BUFFERED_MAX) { if (!quiet) receive_done(ui, "The message is larger than 64 KiB: use 'ez decrypt'."); return -1; }
		ui->cap_need = EZ_MSG_OVERHEAD + h.length;
		uint8_t *stage = ez_stage_message(c, ui->cap_need);
		if (!stage) { if (!quiet) receive_done(ui, "That is not an Einszeit message."); return -1; }
		memcpy(stage, ui->cap_tmp, ui->cap_n);
		ez_secure_zero(ui->cap_tmp, sizeof ui->cap_tmp);
	}
	return ui->cap_need && ui->cap_n >= ui->cap_need ? 1 : 0;
}

/* Pasted bytes. */
static void capture_bytes(ez_ui_t *ui, const uint8_t *b, uint32_t n)
{
	for (uint32_t i = 0; i < n && ui->capture && !ui->dec_pending; i++) {
		if (b[i] == 0x1B) { wipe_messages(ui); home_now(ui); return; }  /* Esc cancels */
		if (b[i] == 0x12) { xm_start(ui, 3); return; }                  /* Ctrl-R: a file instead */
		/* A ZMODEM upload started from the terminal: ZPAD ZDLE. (Neither
		 * byte is base64, so a paste never contains them.) */
		if (ui->cap_prev == '*' && b[i] == 0x18) {
			uint8_t seen[64] = { '*', 0x18 };
			uint32_t k = 2;
			for (uint32_t j = i + 1; j < n && k < sizeof seen; j++) seen[k++] = b[j];
			xm_start_seen(ui, 3, seen, k);
			return;
		}
		ui->cap_prev = b[i];
		int r = cap_push(ui, b[i], false);
		if (r < 0) return;
		if (r > 0) { draw_capture(ui, false); receive_decrypt(ui); return; }
	}
	if (ui->capture) draw_capture(ui, false);
}


static void view_key(ez_ui_t *ui, int k)
{
	if (ui->view_dump) { ui->view_dump = false; out(ui, "\033[2J\033[3J"); draw_view(ui); return; }
	int n = view_lines(ui), page = ui->rows - 2;
	if (k == K_UP && ui->vtop > 0) ui->vtop--;
	else if (k == K_DOWN && ui->vtop + 1 < n) ui->vtop++;
	else if (k == K_PGUP) ui->vtop = ui->vtop > page ? ui->vtop - page : 0;
	else if (k == K_PGDN) { ui->vtop += page; if (ui->vtop >= n) ui->vtop = n ? n - 1 : 0; }
	else if (k == 'c' || k == 'C') { view_dump(ui); return; }
	else if (k == 'd' || k == 'D') { xm_start(ui, 2); return; }
	else if (k == K_ENTER && ui->now_ms - ui->view_opened_ms < 700u) return;   /* the tail of a paste */
	else if (k == K_ENTER || k == K_ESC || k == 'q' || k == 'Q') { wipe_messages(ui); home_now(ui); return; }
	else return;
	draw_view(ui);
}

/* ---- file transfers: XMODEM and ZMODEM (rounds 21-22) ----------------------------- */

static void xm_out(void *ctx, const uint8_t *b, uint32_t n) { ez_ui_t *ui = ctx; ui->env.write(ui->env.ctx, (const char *)b, n); }

static bool xm_sink_send(void *ctx, const uint8_t *b, uint32_t n)
{
	ez_ui_t *ui = ctx;
	if (ui->xm_n + n > ui->env.text_cap) return false;
	memcpy(ui->env.text + ui->xm_n, b, n);
	ui->xm_n += n;
	return true;
}

static bool xm_sink_receive(void *ctx, const uint8_t *b, uint32_t n)
{
	ez_ui_t *ui = ctx;
	if (!ui->cap_kind_known && n >= 3) {             /* a raw message, or its base64 */
		ui->cap_raw = b[0] == 0x5A && b[1] == 0x45 && b[2] == EZ_MSG_VERSION;
		ui->cap_kind_known = true;
	}
	for (uint32_t i = 0; i < n; i++) {
		int r = cap_push(ui, b[i], true);
		if (r < 0) { snprintf(ui->xm_msg, sizeof ui->xm_msg, "That is not an Einszeit message."); return false; }
		if (r > 0) break;                                /* complete: the rest is padding */
	}
	return true;
}

/* seen: a ZMODEM sender already recognised on the Receive screen (its
 * first bytes); NULL to detect the protocol. */
static void xm_start_seen(ez_ui_t *ui, int mode, const uint8_t *seen, uint32_t seen_n)
{
	ui->xm_mode = mode;
	ui->xm_n = 0;
	ui->xm_redraw_at = 0;
	ui->xm_msg[0] = 0;
	ui->xf_result = EZ_XF_RUNNING;
	const char *what = mode == 2 ? "Start a ZMODEM or XMODEM download (receive) in your terminal now." :
	                               "Start a ZMODEM or XMODEM upload (send) in your terminal now.";
	/* A transfer the terminal already started reads everything we send:
	 * not one byte of screen output (sz took the 'C' of "Ctrl-X" for an
	 * XMODEM receiver and fell back to YMODEM). */
	if (!seen) out(ui, "\033[r" NORM "\033[2J\033[H");
	if (!seen) outf(ui, "%s\r\n%s\r\nTo cancel: Ctrl-X a few times.\r\n", what,
	     mode == 2 ? "Many terminals start a ZMODEM download by themselves." :
	     mode == 1 ? "The file is encrypted, not shown: at most 64 KiB." :
	                 "A message file: base64 or raw, at most 64 KiB of plaintext.");
	if (mode == 2) {
		const uint8_t *data = ui->vbuf;
		uint32_t len = ui->vlen;
		if (ui->view == VIEW_CIPHER) {                       /* the base64, in lines */
			uint32_t k = 0;
			for (uint32_t a = 0; a < ui->vlen && k + 80 < ui->env.text_cap; a += B64_PER_LINE) {
				uint32_t m = ui->vlen - a < B64_PER_LINE ? ui->vlen - a : B64_PER_LINE;
				k += (uint32_t)ez_b64_encode(ui->vbuf + a, m, ui->env.text + k);
				ui->env.text[k++] = '\n';
			}
			data = (const uint8_t *)ui->env.text;
			len = k;
		}
		ez_xf_send(&ui->xf, data, len, ui->view == VIEW_CIPHER ? "message.ez" : "message.txt", xm_out, ui, ui->now_ms);
	} else {
		if (mode == 3) { ez_b64_dec_init(&ui->b64); ui->cap_n = ui->cap_need = 0; ui->cap_kind_known = ui->cap_raw = false; }
		ez_xf_sink_fn sink = mode == 1 ? xm_sink_send : xm_sink_receive;
		/* An upload holds at most the editor's buffer, a message file its base64. */
		if (seen) ez_xf_recv_zmodem(&ui->xf, sink, ui->env.text_cap, xm_out, ui, seen, seen_n, ui->now_ms);
		else ez_xf_recv(&ui->xf, sink, ui->env.text_cap, xm_out, ui, ui->now_ms);
	}
}

static void xm_start(ez_ui_t *ui, int mode) { xm_start_seen(ui, mode, NULL, 0); }

/* The transfer ended a second ago (the terminal's own transfer screen has
 * closed): show the outcome. */
static void xm_finish(ez_ui_t *ui)
{
	int mode = ui->xm_mode;
	bool ok = ui->xf_result == EZ_XF_DONE;
	const char *why = ui->xm_msg[0] ? ui->xm_msg : ez_xf_error(&ui->xf);
	ui->xm_mode = 0;
	ui->xm_redraw_at = 0;
	if (mode == 2) {                                   /* back to the view */
		if (ui->view == VIEW_CIPHER) ez_secure_zero(ui->env.text, ui->env.text_cap);
		draw_view(ui);
		at(ui, ui->rows, 1);
		char m[80];
		snprintf(m, sizeof m, ok ? "Downloaded by %s%s. Enter: done" : "The download did not complete. Enter: done",
		         ez_xf_proto_name(&ui->xf), ui->xf.proto == EZ_XF_XMODEM ? " (padded with ^Z)" : "");
		outf(ui, INV " %-*.*s" NORM, ui->cols - 2, ui->cols - 2, m);
		if (!ok) { at(ui, ui->rows - 1, 1); outf(ui, "%s" EOL, why); }
		return;
	}
	if (mode == 3) {
		if (ok && ui->cap_need && ui->cap_n >= ui->cap_need) { ui->capture = true; receive_decrypt(ui); return; }
		receive_done(ui, ok ? "The file ended before the message was complete." : why);
		return;
	}
	/* mode 1: an upload to Send */
	uint32_t n = ui->xm_n;
	if (ez_xf_padded(&ui->xf))                                          /* XMODEM's padding; ZMODEM is exact */
		while (n && (uint8_t)ui->env.text[n - 1] == EZ_XM_SUB) n--;
	ui->xm_n = n;
	ui->screen = EZ_UI_SEND;
	ui->menu_focus = false;
	ez_ui_redraw(ui);
	const ez_session_t *s = &ui->env.core->meta.s[ui->send_slot];
	if (!ok || !n || n > EZ_BUFFERED_MAX || n > ez_meta_tx_remaining(s)) {
		const char *m = !ok ? why : !n ? "The file is empty." : n > EZ_BUFFERED_MAX ? "Over 64 KiB: send it with 'ez' on a computer." :
		                "Not enough key left for this file.";
		ez_secure_zero(ui->env.text, ui->env.text_cap);
		ui->flow = 99;
		info(ui, "Upload", m, NULL);
		return;
	}
	ui->flow = 102;
	ui->step = 0;
	dlg_open(ui, DLG_YN, "Encrypt the uploaded file");
	MSG(0, "Encrypt the uploaded file (%lu bytes) for '%s'?", (unsigned long)n, s->label);
	MSG(1, "%lu bytes of key will remain.", (unsigned long)(ez_meta_tx_remaining(s) - n));
	draw_dialog(ui);
}

/* The uploaded file, confirmed: encrypt it as Send does a typed message. */
static void upload_encrypt(ez_ui_t *ui, int ans)
{
	ez_core_t *c = ui->env.core;
	ui->flow = FL_NONE;
	ui->step = 0;
	dlg_close(ui);
	if (ans != 1 || (ui->env.disp->job_running && ui->env.disp->job != 4)) {
		ez_secure_zero(ui->env.text, ui->env.text_cap);
		if (ans == 1) { ui->flow = 99; info(ui, "Upload", "The device is busy; nothing was encrypted.", NULL); return; }
		home_now(ui);
		return;
	}
	if (ui->env.disp->job_running) ui->env.disp->yield = true;
	uint8_t *p = ez_stage_plaintext(c, ui->xm_n);
	ez_status_t st = EZ_ERR_BAD_REQUEST;
	const uint8_t *o = NULL;
	uint32_t on = 0;
	if (p && !ui->env.disp->job_running) {
		memcpy(p, ui->env.text, ui->xm_n);
		st = ez_encrypt_buffered(c, ui->send_slot, ui->xm_n, &o, &on);
	} else if (ui->env.disp->job_running) st = EZ_ERR_BUSY;
	ez_secure_zero(ui->env.text, ui->env.text_cap);           /* the plaintext is gone either way */
	if (st != EZ_OK) { ez_release(c); ui->flow = 99; info(ui, "Upload", why_words(st), NULL); return; }
	view_open(ui, VIEW_CIPHER, o, on, c->meta.s[ui->send_slot].label);
}

static void home_now(ez_ui_t *ui)
{
	ui->screen = EZ_UI_HOME;
	ui->menu_at = 0;
	ui->menu_focus = true;
	ui->flow = FL_NONE;
	ui->step = 0;
	dlg_close(ui);
	ez_ui_redraw(ui);
}

/* ---- screens ------------------------------------------------------------------- */

static void draw_screen(ez_ui_t *ui)
{
	if (ui->editing) { zetta_redraw(&ui->ed); return; }
	if (ui->view) { if (ui->view_dump) view_dump(ui); else draw_view(ui); return; }
	if (ui->capture) { draw_capture(ui, true); return; }
	out(ui, "\033[r" NORM "\033[2J");            /* full screen, cleared */
	draw_menu(ui);
	switch (ui->screen) {
	case EZ_UI_HOME:    draw_home(ui, true); break;
	case EZ_UI_SEND:    break;                   /* opened by open_screen() */
	case EZ_UI_RECEIVE: break;
	case EZ_UI_KEYS:    draw_keys(ui); break;
	case EZ_UI_DEVICE:  draw_device(ui); break;
	case EZ_UI_HELP:    draw_text(ui, help_text); break;
	case EZ_UI_CLI:
		outf(ui, "\033[3;%dr", ui->rows - 1);       /* output scrolls between the bars */
		at(ui, ui->rows - 1, 1);
		P("Einszeit CLI -- 'help' for commands, Esc for the menu\n");
		break;
	}
	draw_status(ui, true);
	if (ui->dlg) draw_dialog(ui);
	if (ui->screen == EZ_UI_CLI && !ui->menu_focus) cli_prompt(ui);
	else at(ui, 1, 1);
}

void ez_ui_reset(ez_ui_t *ui)
{
	out(ui, "\033c\033[2J\033[3J\033[H");               /* reset: screen and scrollback */
	ez_ui_redraw(ui);
}

void ez_ui_redraw(ez_ui_t *ui)
{
	memset(ui->panel_shown, 0, sizeof ui->panel_shown);
	draw_screen(ui);
}

static void open_screen(ez_ui_t *ui, int s)
{
	ui->screen = s;
	ui->menu_at = s;
	/* Screens with nothing to operate (Home, Device, Help) keep the menu
	 * bar's focus, so Left/Right carry on at once (TR-09 feedback). */
	ui->menu_focus = s == EZ_UI_HOME || s == EZ_UI_DEVICE || s == EZ_UI_HELP;
	ui->key_detail = false;
	ez_ui_redraw(ui);
	if (s == EZ_UI_SEND) send_start(ui);
	else if (s == EZ_UI_RECEIVE) receive_open(ui);
}

void ez_ui_init(ez_ui_t *ui, const ez_ui_env_t *env)
{
	memset(ui, 0, sizeof *ui);
	ui->env = *env;
	ui->rows = 24;
	ui->cols = 80;
	ui->screen = EZ_UI_HOME;
	ui->menu_focus = true;
}

/* ---- input ------------------------------------------------------------------------ */

static void key(ez_ui_t *ui, int k)
{
	if (k == 12) { ez_ui_redraw(ui); return; }                 /* Ctrl-L */
	if (ui->view) { view_key(ui, k); return; }                  /* a message on screen */
	if (ui->dlg) { dlg_key(ui, k); return; }                    /* a dialog has the keys */
	if (ui->menu_focus) {
		if (k == K_LEFT) ui->menu_at = (ui->menu_at + EZ_UI_SCREENS - 1) % EZ_UI_SCREENS;
		else if (k == K_RIGHT) ui->menu_at = (ui->menu_at + 1) % EZ_UI_SCREENS;
		else if (k == K_ENTER || k == K_DOWN) { open_screen(ui, ui->menu_at); return; }
		else {
			for (int i = 0; i < EZ_UI_SCREENS; i++)
				if (k == menu_keys[i] || k == menu_keys[i] - 32) { open_screen(ui, i); return; }
		}
		draw_menu(ui);
		return;
	}
	/* Left/Right on any other screen go back to the menu bar, one step along
	 * (except in the CLI while a line is being typed). */
	if ((k == K_LEFT || k == K_RIGHT) && !(ui->screen == EZ_UI_KEYS && ui->key_detail) &&
	    !(ui->screen == EZ_UI_CLI && (ui->line_len || ui->wait_job))) {
		if (ui->screen == EZ_UI_CLI) out(ui, "\033[r");
		ui->menu_focus = true;
		ui->menu_at = (ui->screen + (k == K_LEFT ? EZ_UI_SCREENS - 1 : 1)) % EZ_UI_SCREENS;
		draw_menu(ui);
		return;
	}
	if (k == K_ESC) {
		if (ui->screen == EZ_UI_KEYS && ui->key_detail) { ui->key_detail = false; ez_ui_redraw(ui); return; }
		if (ui->screen == EZ_UI_CLI) out(ui, "\033[r");
		ui->menu_focus = true;
		ui->menu_at = ui->screen;
		draw_menu(ui);
		return;
	}
	switch (ui->screen) {
	case EZ_UI_KEYS: {
		int n = key_count(ui, NULL);
		if (k == K_UP && ui->key_at > 0) ui->key_at--;
		else if (k == K_DOWN && ui->key_at + 1 < n) ui->key_at++;
		else if (k == K_ENTER && n) { ui->key_detail = true; ez_ui_redraw(ui); return; }
		else if (k == 'n' || k == 'N') { flow_start(ui, FL_NEW); return; }
		else if (k == 'i' || k == 'I') { flow_start(ui, FL_IMPORT); return; }
		else if (n && (k == 'x' || k == 'X')) { flow_start(ui, FL_EXPORT); return; }
		else if (n && (k == 'd' || k == 'D')) { flow_start(ui, FL_DELETE); return; }
		else if (n && (k == 's' || k == 'S')) { flow_start(ui, FL_SKIP); return; }
		else if (n && (k == 'q' || k == 'Q')) { flow_start(ui, FL_RESOLVE); return; }
		else if (n && (k == 'p' || k == 'P')) { flow_start(ui, FL_BACKUP); return; }
		else if ((k == 'c' || k == 'C') && ui->env.disp->job_running && ui->env.disp->job == 1) { ui->env.disp->cancel = true; return; }
		else return;
		draw_keys(ui);
		return;
	}
	case EZ_UI_CLI:
		if (ui->wait_job) return;                          /* the job's result comes first */
		if (k == K_ENTER) {
			char l[EZ_UI_LINE];
			memcpy(l, ui->line, (size_t)ui->line_len);
			l[ui->line_len] = 0;
			ui->line_len = 0;
			out(ui, "\r\n");
			cli_exec(ui, l);
			ez_secure_zero(l, sizeof l);
			if (ui->screen == EZ_UI_CLI && !ui->menu_focus && !ui->wait_job) cli_prompt(ui);
		} else if (k == K_BS) {
			if (ui->line_len) { ui->line_len--; out(ui, "\b \b"); }
		} else if (k >= 32 && k < 127 && ui->line_len < EZ_UI_LINE - 1) {
			ui->line[ui->line_len++] = (char)k;
			char ch[2] = { (char)k, 0 };
			out(ui, ch);
		}
		return;
	default:
		return;
	}
}

static void decode(ez_ui_t *ui, uint8_t b)
{
	if (ui->esc_len) {
		ui->esc[ui->esc_len++] = b;
		if (ui->esc_len == 2 && b != '[' && b != 'O') { ui->esc_len = 0; key(ui, K_ESC); decode(ui, b); return; }
		if (ui->esc_len >= 3 && (b >= 0x40 && b <= 0x7E)) {
			int k = 0;
			switch (b) { case 'A': k = K_UP; break; case 'B': k = K_DOWN; break; case 'C': k = K_RIGHT; break; case 'D': k = K_LEFT; break;
			             case '~': k = ui->esc[2] == '5' ? K_PGUP : ui->esc[2] == '6' ? K_PGDN : 0; break; }
			ui->esc_len = 0;
			if (k) key(ui, k);
			return;
		}
		if (ui->esc_len >= (int)sizeof ui->esc) ui->esc_len = 0;
		return;
	}
	if (b == 0x1B) { ui->esc[0] = b; ui->esc_len = 1; ui->esc_ms = ui->now_ms; return; }
	if (b == '\r') { key(ui, K_ENTER); return; }
	if (b == '\n') return;                                 /* CR LF from some terminals */
	if (b == 0x7F || b == 0x08) { key(ui, K_BS); return; }
	key(ui, b);
}

void ez_ui_input(ez_ui_t *ui, const uint8_t *b, uint32_t n, uint32_t now_ms)
{
	ui->now_ms = now_ms;
	ui->last_input_ms = now_ms;
	if (ui->xm_mode) {                                  /* a transfer has the line */
		if (!ui->xm_redraw_at && (ui->xf_result = ez_xf_input(&ui->xf, b, n, now_ms)) != EZ_XF_RUNNING) ui->xm_redraw_at = now_ms + 1000u;
		return;
	}
	if (ui->editing) {                                  /* the editor decodes its own keys */
		int ev = zetta_key(&ui->ed, b, n, now_ms);
		while (ev != ZE_NONE && ui->editing) {
			ed_event(ui, ev);
			if (!ui->editing) break;
			static const uint8_t none[1];
			ev = zetta_key(&ui->ed, none, 0, now_ms);  /* input held after an event (not NULL: zetta memcpy()s it) */
		}
		return;
	}
	if (ui->capture && !ui->dec_pending) { capture_bytes(ui, b, n); return; }
	for (uint32_t i = 0; i < n; i++) decode(ui, b[i]);
}

void ez_ui_tick(ez_ui_t *ui, uint32_t now_ms)
{
	ui->now_ms = now_ms;
	if (ui->xm_mode) {                                  /* nothing else may be written meanwhile */
		if (!ui->xm_redraw_at) { if ((ui->xf_result = ez_xf_tick(&ui->xf, now_ms)) != EZ_XF_RUNNING) ui->xm_redraw_at = now_ms + 1000u; }
		else if ((int32_t)(now_ms - ui->xm_redraw_at) >= 0) xm_finish(ui);
		return;
	}
	if (ui->editing) {
		int ev = zetta_tick(&ui->ed, now_ms);
		if (ev != ZE_NONE) ed_event(ui, ev);
	}
	if (ui->dec_pending && !ui->env.disp->job_running) receive_decrypt(ui);
	/* §10: an open message is wiped after 10 minutes without input. */
	if ((ui->editing || ui->view || ui->capture) && now_ms - ui->last_input_ms > IDLE_WIPE_MS) {
		wipe_messages(ui);
		home_now(ui);
	}
	if (ui->editing || ui->view) return;               /* they own the screen */
	if (ui->esc_len == 1 && now_ms - ui->esc_ms > 60u) { ui->esc_len = 0; key(ui, K_ESC); }   /* a lone Esc */
	if (ui->wait_job && ez_dispatch_ticket_done(ui->env.disp, ui->f_ticket, &ui->f_result)) {
		cli_job_done(ui);
		if (ui->screen == EZ_UI_CLI && !ui->menu_focus) cli_prompt(ui);
	}
	/* A flow waiting for its job, or for the card to go or come. */
	if (ui->flow && ui->f_pend) pend_start(ui);
	if (ui->flow && ui->f_job && ez_dispatch_ticket_done(ui->env.disp, ui->f_ticket, &ui->f_result)) {
		ui->f_job = false;
		flow_next(ui, ANS_JOB);
	}
	if (ui->flow && ui->f_card) {
		bool p = card_present(ui);
		if ((ui->f_card == 1 && !p) || (ui->f_card == 2 && p)) { ui->f_card = 0; flow_next(ui, ANS_CARD); }
	}
	if (now_ms - ui->last_tick_ms < 1000u) return;
	ui->last_tick_ms = now_ms;
	if (ui->dlg == DLG_WAIT && ui->f_job) {
		const ez_dispatch_t *d = ui->env.disp;
		unsigned pm = d->job == 1 ? (unsigned)ez_keygen_progress(&d->kg) : ui->env.core->progress;
		MSG(1, "%u%%", pm / 10u);
		draw_dialog(ui);
	}
	draw_status(ui, false);
	if (ui->screen == EZ_UI_HOME) draw_home(ui, false);
	if (ui->screen == EZ_UI_KEYS && !ui->dlg && !ui->key_detail && ui->env.disp->job == 1) draw_keys(ui);
}
