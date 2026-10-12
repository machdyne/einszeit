#!/bin/sh
# tests/fuzz/run.sh <build dir> [seconds per fuzzer, default 60]
set -e
B=$1; S=${2:-60}
for f in fuzz_dispatch fuzz_message fuzz_fatfs fuzz_store0 fuzz_xfer; do
    mkdir -p "$B/corpus/$f"
    echo "== $f ($S s)"
    "$B/$f" -max_total_time="$S" -max_len=8192 -print_final_stats=1 "$B/corpus/$f" 2>&1 \
        | grep -E "stat::number_of_executed_units|stat::new_units_added|ERROR|SUMMARY|Test unit written" || true
done
