/* transport_vdev.c -- ez_transport_t over the virtual device's Unix socket. */
#define _POSIX_C_SOURCE 200809L
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "transport.h"

static int w(void *ctx, const uint8_t f[EZ_FRAME_SIZE])
{
	int fd = *(int *)ctx;
	return write(fd, f, EZ_FRAME_SIZE) == EZ_FRAME_SIZE ? 0 : -1;
}

static int r(void *ctx, uint8_t f[EZ_FRAME_SIZE], int timeout_ms)
{
	int fd = *(int *)ctx;
	size_t got = 0;
	while (got < EZ_FRAME_SIZE) {
		struct pollfd p = { fd, POLLIN, 0 };
		int k = poll(&p, 1, got ? 5000 : timeout_ms);
		if (k == 0) return got ? -1 : 0;
		if (k < 0) return -1;
		ssize_t n = read(fd, f + got, EZ_FRAME_SIZE - got);
		if (n <= 0) return -1;
		got += (size_t)n;
	}
	return 1;
}

int transport_vdev_open(const char *path, ez_transport_t *t)
{
	static int fd;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof a.sun_path) return -1;
	strcpy(a.sun_path, path);
	/* A device started a moment ago may not have its socket yet: wait up
	 * to 2 s for it. */
	for (int tries = 0;; tries++) {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) return -1;
		if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) break;
		close(fd);
		if (tries >= 20) return -1;
		struct timespec ts = { 0, 100 * 1000000L };
		nanosleep(&ts, NULL);
	}
	t->ctx = &fd;
	t->write = w;
	t->read = r;
	return 0;
}
