/*
 * tr05.h -- TR-05, storage reliability under power loss (development
 * images only). Procedure: fw/einszeit/README.md.
 */
#ifndef TR05_H
#define TR05_H
#include <stdbool.h>
bool tr05_armed(void);
/* Armed: runs at boot instead of the normal application, never returns
 * (q disarms and reboots). */
void tr05_mode(void);
/* Shell: tr05 prep | status | disarm | wp */
void tr05_cmd(int argc, char **argv);
#endif
