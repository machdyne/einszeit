#ifndef EZ_TRANSPORT_H
#define EZ_TRANSPORT_H
#include <stddef.h>
#include "ez_client.h"
/* The virtual device (ez-vdev) over its Unix socket; waits up to 2 s for it. */
int  transport_vdev_open(const char *path, ez_transport_t *t);
/* A device over USB HID; serial NULL = the only one connected. */
int  transport_hid_open(const char *serial, ez_transport_t *t, char *err, size_t errcap);
void transport_hid_list(void);
#endif
