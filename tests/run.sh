#!/bin/sh
# Build and run the host test suite with sanitizers; prints every test
# case with the requirement IDs it demonstrates.
set -e
here=$(cd "$(dirname "$0")" && pwd)
build="${BUILD_DIR:-$here/../build/tests}"
cmake -S "$here" -B "$build" -DCMAKE_BUILD_TYPE=Debug "$@" >/dev/null
cmake --build "$build" -j >/dev/null
status=0
for t in test_primitives test_meta test_meta_rollback test_meta_powercut test_meta_bitflip \
         test_codec test_entropy test_core test_keygen test_engine test_media \
         test_keystore test_sum test_chaos test_store0 test_proto test_mirror test_sdcard test_xmodem test_zmodem test_xfer; do
    "$build/$t" || status=1
done
# End to end: ez and two virtual devices (built above, with sanitizers).
ASAN_OPTIONS=detect_leaks=0 "$here/e2e/e2e.sh" "$build" || status=1
# Transfer protocols against an independent implementation (lrzsz).
python3 "$here/xfer/test_interop.py" "$build" || status=1
# Screen tests of the terminal interface (EZ-UI-001); need python3-pyte.
if python3 -c "import pyte" 2>/dev/null; then
	python3 "$here/ui/test_ui.py" "$build" || status=1
else
	echo "ui: SKIPPED (pip install pyte)"
fi
[ $status -eq 0 ] && echo "ALL HOST TESTS PASSED" || echo "HOST TESTS FAILED"
exit $status
