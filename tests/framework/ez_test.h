/*
 * ez_test.h -- minimal test framework for the Einszeit host suite
 *
 * Every test case declares the requirement IDs it demonstrates; the runner
 * prints them with the result so the output can be cited directly in the
 * traceability matrix (EZ-SEC-001 §11). No external dependencies.
 *
 *   static void t_example(void) { EZ_CHECK(1 + 1 == 2); }
 *   static const ez_test_case_t cases[] = {
 *       { "example", "SEC-TEST-ENC-001", t_example },
 *   };
 *   EZ_TEST_MAIN(cases)
 *
 * A failed EZ_CHECK aborts the current test case (longjmp), so checks may
 * be used inside helper functions.
 */
#ifndef EZ_TEST_H
#define EZ_TEST_H

#include <stdint.h>

typedef struct {
	const char *name;
	const char *reqs;     /* comma-separated requirement IDs */
	void (*fn)(void);
} ez_test_case_t;

void ez_test_fail(const char *file, int line, const char *expr, const char *msg);
void ez_test_count(void);
void ez_test_note(const char *fmt, ...);
int  ez_test_run(const char *suite, const ez_test_case_t *cases, int n, int argc, char **argv);

#define EZ_CHECK(c) do { ez_test_count(); \
	if (!(c)) ez_test_fail(__FILE__, __LINE__, #c, 0); } while (0)
#define EZ_CHECK_MSG(c, msg) do { ez_test_count(); \
	if (!(c)) ez_test_fail(__FILE__, __LINE__, #c, msg); } while (0)
#define EZ_CHECK_EQ(a, b) do { ez_test_count(); \
	long long _a = (long long)(a), _b = (long long)(b); \
	if (_a != _b) { char _m[96]; \
		snprintf(_m, sizeof _m, "%lld != %lld", _a, _b); \
		ez_test_fail(__FILE__, __LINE__, #a " == " #b, _m); } } while (0)

#define EZ_TEST_MAIN(cases) \
	int main(int argc, char **argv) { \
		return ez_test_run(__FILE__, cases, (int)(sizeof(cases) / sizeof(cases[0])), argc, argv); }

#include <stdio.h>

#endif /* EZ_TEST_H */
