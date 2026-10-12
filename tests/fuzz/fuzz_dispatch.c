/*
 * fuzz_dispatch.c -- libFuzzer: arbitrary frame streams into the device
 * dispatcher (closes fw/test gap G-03 for the production protocol). The input is split into 64-byte frames; jobs are
 * advanced between frames. ASan/UBSan report any memory error.
 */
#include <string.h>

#include "core_fixture.h"
#include "ez_dispatch.h"

static ezdev_t *dev;
static ez_dispatch_t disp;
static const ez_devinfo_t info = { "fuzz", 0xEE, 0 };
static void sink(void *ctx, const uint8_t f[EZ_FRAME_SIZE]) { (void)ctx; (void)f; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
	if (!dev) {
		dev = dev_new(1);
		dev_put_key(dev, 1, 0x1234, 16384, 2);
		int s;
		ez_session_create(&dev->c, 0x1234, 1, EZ_ROLE_ALICE, "x", &s);
		ez_dispatch_init(&disp, &dev->c, sink, NULL, &info);
	}
	uint8_t f[EZ_FRAME_SIZE];
	for (size_t o = 0; o < n; o += EZ_FRAME_SIZE) {
		memset(f, 0, sizeof f);
		memcpy(f, data + o, n - o < EZ_FRAME_SIZE ? n - o : EZ_FRAME_SIZE);
		ez_dispatch_frame(&disp, f);
		ez_dispatch_poll(&disp, 1);
	}
	ez_dispatch_reset(&disp);
	return 0;
}
