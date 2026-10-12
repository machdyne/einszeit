#ifndef SELFTEST_H
#define SELFTEST_H
#include <stdbool.h>
#include "ez_core.h"
/* SEC-TEST-ENC-001 on target. Uses (and clears) the given core and stage;
 * the caller re-initialises its own core afterwards. */
bool selftest_kat(ez_core_t *c, uint8_t *stage);
#endif
