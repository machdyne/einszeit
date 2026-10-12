/*
 * ez_ui.h -- the terminal user interface (EZ-UI-001).
 *
 * Pure VT100 on an 80x24 (or larger) terminal: a menu bar on row 1, the
 * content area, a status line on the last row, updated about once a
 * second. Portable C11, no heap: the firmware runs it over USB CDC, the
 * virtual device over a socket, and tests drive it with a VT100 emulator.
 *
 * The platform calls:
 *   ez_ui_init()     once
 *   ez_ui_input()    with bytes typed, and a millisecond clock
 *   ez_ui_tick()     regularly (status refresh, a lone Esc)
 *   ez_ui_redraw()   when a terminal (re)connects
 * Long work is submitted to the dispatcher as a job (second core on the
 * device); the interface never blocks waiting for it.
 */
#ifndef EZ_UI_H
#define EZ_UI_H

#include <stdbool.h>
#include <stdint.h>
#include "ez_core.h"
#include "ez_dispatch.h"
#include "ez_base64.h"
#include "zetta.h"
#include "ez_xfer.h"

typedef struct {
	void (*write)(void *ctx, const char *s, uint32_t n);
	void *ctx;
	ez_core_t     *core;
	ez_dispatch_t *disp;
	const char *fw_version;
	const char *board_id;
	bool  development;                          /* a development image */
	/* Platform facts for the status displays (may be NULL). */
	void (*card_info)(void *ctx, char *out, uint32_t cap);   /* "31.7 GB, 2 copies" */
	/* Development commands (NULL in production): true if handled. */
	bool (*cli_ext)(void *ctx, int argc, char **argv);
	/* The editor's text (Send), also used for an upload and for a download's
	 * base64: EZ_UI_TEXT_CAP bytes, wiped after use. */
	char    *text;
	uint32_t text_cap;
} ez_ui_env_t;

enum { EZ_UI_HOME, EZ_UI_SEND, EZ_UI_RECEIVE, EZ_UI_KEYS, EZ_UI_DEVICE, EZ_UI_CLI, EZ_UI_HELP, EZ_UI_SCREENS };

#define EZ_UI_LINE 128
/* Base64 of the largest message, in lines, fits: 4/3 x 64 KiB + line breaks. */
#define EZ_UI_TEXT_CAP (92u * 1024u)

typedef struct {
	ez_ui_env_t env;
	int  rows, cols;
	int  screen;                 /* EZ_UI_* */
	int  menu_at;                /* highlighted menu item */
	bool menu_focus;             /* keys go to the menu bar */
	/* input decoding */
	uint8_t esc[8];
	int  esc_len;
	uint32_t esc_ms, now_ms, last_tick_ms;
	/* what was drawn, to redraw only changes */
	char status_shown[160];
	char panel_shown[12][EZ_UI_LINE];
	/* keys screen */
	int  key_at;
	bool key_detail;
	/* CLI */
	char line[EZ_UI_LINE];
	int  line_len;
	int  confirm;                /* a command waiting for YES: 0 none */
	char confirm_arg[16];
	int  wait_job;               /* a CLI command waiting for its job: the command, 0 none */
	/* dialogs and multi-step actions (round 18: the key manager) */
	int  dlg;                    /* 0 none, else the dialog kind */
	char dlg_title[64];
	char dlg_msg[5][80];
	char dlg_opt[8][56];
	int  dlg_nopt, dlg_at, dlg_rows;
	char dlg_in[EZ_LABEL_MAX + 1];
	int  dlg_ilen;
	char dlg_expect[EZ_LABEL_MAX + 1];
	char dlg_err[72];
	int  flow, step;
	bool f_job;                  /* waiting for a job */
	int  f_card;                 /* waiting for the card: 1 to go, 2 to come */
	uint32_t f_len, f_id;
	uint8_t  f_drive, f_flags, f_role;
	bool f_staged, f_tmp0, f_force;
	int  f_slot;
	char f_label[EZ_LABEL_MAX + 1];
	char f_files[8][16];          /* "XXXXXXXX.KEY" */
	uint32_t f_ids[8];
	int  f_n;
	/* Send and Receive (round 19) */
	zetta_t  ed;                 /* the editor */
	bool     editing;
	char     ed_title[80];
	int      send_slot;
	int      view;               /* 0 none, 1 a message (base64), 2 a plaintext */
	bool     view_dump, view_bare;
	const uint8_t *vbuf;
	uint32_t vlen;
	int      vtop;
	char     view_from[EZ_LABEL_MAX + 1];
	bool     capture;            /* Receive: decoding a pasted message */
	ez_b64_dec_t b64;
	uint32_t cap_n, cap_need, dec_pending;
	uint8_t  cap_tmp[24];        /* the first bytes, until the header gives the length */
	uint32_t last_input_ms, view_opened_ms;
	bool     f_detached;         /* a new key generating in the background */
	uint32_t f_ticket;           /* the job the flow or the CLI waits for */
	ez_status_t f_result;        /* ... and its result */
	uint8_t  f_pend;             /* a job to start once the device is free: 1 command, 2 keygen, 3 import */
	uint8_t  f_pend_cmd;
	uint8_t  f_pend_req[40];
	uint32_t f_pend_n;
	char     notice[80];         /* shown on Home: how a background action ended */
	/* file transfers (rounds 21-22): XMODEM or ZMODEM, detected */
	ez_xf_t  xf;
	ez_xf_result_t xf_result;
	uint8_t  cap_prev;           /* Receive: the byte before, to spot a ZMODEM upload */
	int      xm_mode;            /* 0 none, 1 upload to Send, 2 download, 3 upload to Receive */
	uint32_t xm_n, xm_redraw_at;
	char     xm_msg[80];
	bool     cap_raw, cap_kind_known;
} ez_ui_t;

void ez_ui_init(ez_ui_t *ui, const ez_ui_env_t *env);
void ez_ui_input(ez_ui_t *ui, const uint8_t *b, uint32_t n, uint32_t now_ms);
void ez_ui_tick(ez_ui_t *ui, uint32_t now_ms);
void ez_ui_redraw(ez_ui_t *ui);
/* A terminal (re)connected: reset it (screen and scrollback), then draw. */
void ez_ui_reset(ez_ui_t *ui);
/* For the platform's development commands: print in the CLI's area. */
void ez_ui_printf(ez_ui_t *ui, const char *fmt, ...);

#endif
