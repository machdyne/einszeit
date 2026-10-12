/* ez_test.c -- runner for ez_test.h */
#include "ez_test.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static jmp_buf g_jmp;
static unsigned long g_checks;

void ez_test_count(void) { g_checks++; }

void ez_test_fail(const char *file, int line, const char *expr, const char *msg)
{
	fprintf(stderr, "    FAILED %s:%d: %s%s%s\n", file, line, expr,
	        msg ? "  -- " : "", msg ? msg : "");
	longjmp(g_jmp, 1);
}

void ez_test_note(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("    note: ", stdout);
	vprintf(fmt, ap);
	fputc('\n', stdout);
	va_end(ap);
}

int ez_test_run(const char *suite, const ez_test_case_t *cases, int n, int argc, char **argv)
{
	static const char *base;
	static int failed, run, i;
	static volatile int ok;
	const char *only = argc > 1 ? argv[1] : NULL;
	base = strrchr(suite, '/');
	base = base ? base + 1 : suite;
	failed = 0; run = 0;
	printf("== %s\n", base);
	for (i = 0; i < n; i++) {
		if (only && strcmp(only, cases[i].name) != 0) continue;
		g_checks = 0;
		run++;
		fflush(stdout);
		ok = 1;
		if (setjmp(g_jmp) == 0)
			cases[i].fn();
		else
			ok = 0;
		printf("[%s] %-40s %8lu checks  (%s)\n", ok ? "PASS" : "FAIL",
		       cases[i].name, g_checks, cases[i].reqs);
		if (!ok) failed++;
	}
	printf("== %s: %d run, %d failed\n", base, run, failed);
	return failed ? 1 : 0;
}
