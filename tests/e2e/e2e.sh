#!/bin/sh
#
# tests/e2e/e2e.sh -- end to end through the real CLI and protocol:
# two virtual devices (ez-vdev), driven by ez, exchanging messages.
#
#   tests/e2e/e2e.sh <dir containing ez and ez-vdev>
#
# EZ-SEC-001 / EZ-IMPL-001: SEC-ENC-001, SEC-DEC-001..004 end to end,
# SEC-UI-003 / IMPL-CLI-001 (no confirmation without a terminal),
# IMPL-CLI-003 (no plaintext on failure), IMPL-CLI-006, SEC-STORE-004/005,
# SEC-PTR-004, IMPL-DRV-002.
#
set -u
BIN=$(cd "$1" && pwd)
EZ="$BIN/ez"
TMP=$(mktemp -d)
cd "$TMP"
FAILS=0; PASSES=0
cleanup() { kill $PA $PB 2>/dev/null; wait 2>/dev/null; rm -rf "$TMP"; }
ok()   { PASSES=$((PASSES+1)); echo "[PASS] $1"; }
bad()  { FAILS=$((FAILS+1)); echo "[FAIL] $1"; }
check() { if eval "$1" >/dev/null 2>&1; then ok "$2"; else bad "$2"; fi; }

"$BIN/ez-vdev" A 2>/dev/null & PA=$!
"$BIN/ez-vdev" B 2>/dev/null & PB=$!
trap cleanup EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S A/ez.sock ] && [ -S B/ez.sock ] && break; sleep 0.2; done
a() { "$EZ" --virtual A/ez.sock "$@"; }
b() { "$EZ" --virtual B/ez.sock "$@"; }
send_left() { "$EZ" --virtual "$1"/ez.sock session info "$2" | sed -n 's/.*send: \([0-9]*\) of.*/\1/p'; }

check "a device info | grep -q UNINITIALISED" "a new virtual device reads as uninitialised"
check "a device erase --yes && b device erase --yes" "device erase"

# --- key generated on A, handed over with its .SUM
ID=$(a key generate 262144 | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
check "[ -n '$ID' ] && [ -f A/drive1/$ID.KEY ] && [ -f A/drive1/$ID.SUM ]" "generate writes the key and its .SUM"
cp A/drive1/$ID.KEY A/drive1/$ID.SUM B/drive1/
check "a session create bob --key-id $ID" "create session from a generated key"
check "b session import alice $ID.KEY --key-id $ID --role bob 2>err && ! grep -q warning err" \
      "import with .SUM: verified, no warning"

# --- exchange at the full buffered size, both ways
head -c 65536 /dev/urandom > pt1
a encrypt bob --yes -i pt1 -o m1 2>/dev/null
check "b decrypt -i m1 -o out1 && cmp -s pt1 out1" "65536 bytes A -> B"
echo "padded" | a encrypt bob --yes -o mpad 2>/dev/null; printf '\032\032\032' >> mpad
check "b decrypt -i mpad | grep -q padded" "ez decrypt accepts an XMODEM-padded file (trailing ^Z)"
head -c 20000 /dev/urandom > ptb
check "a encrypt bob --yes --stream -i ptb -o mb 2>/dev/null && b decrypt --stream -i mb -o outb && cmp -s ptb outb" "20,000 bytes A -> B, streamed over the protocol (--stream)"
check "! b decrypt -i mb -o outb2 && [ ! -e outb2 ]" "streamed message: replay refused, no output"
printf 'reply\n' > pt2
check "b encrypt --yes -i pt2 | a decrypt > out2 && cmp -s pt2 out2" "B -> A, session chosen automatically"
check "! b decrypt -i m1 -o out3 && [ ! -e out3 ]" "replay refused, no output file written (IMPL-CLI-003)"
sed 's/A/B/' m1 > m1bad
check "! b decrypt -i m1bad -o out4 && [ ! -e out4 ]" "damaged message refused, no output"

# --- SEC-UI-003: no controlling terminal and no --yes: refused, key unspent
L0=$(send_left A bob)
check "! echo secret | setsid -w '$EZ' --virtual A/ez.sock encrypt bob" "encrypt without terminal or --yes refused"
check "[ '$(send_left A bob)' = '$L0' ]" "  ... and no key spent"

# --- a key without .SUM: warned, checked, accepted
ID2=$(a key generate 16384 | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
cp A/drive1/$ID2.KEY "B/drive1/from alice.bin"
check "b session import a2 'from alice.bin' --key-id $ID2 --role bob 2>err && grep -q 'no integrity file' err" \
      "import without .SUM warns (IMPL-CLI-006) and succeeds"
check "[ -f B/drive1/$ID2.KEY ] && [ -f B/drive1/$ID2.SUM ] && [ ! -e 'B/drive1/from alice.bin' ]" \
      "  ... renamed to its Key ID, .SUM created"

# --- transfer damage caught by the .SUM
ID3=$(a key generate 65536 | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
cp A/drive1/$ID3.KEY A/drive1/$ID3.SUM B/drive1/
printf '\001' | dd of=B/drive1/$ID3.KEY bs=1 seek=40000 conv=notrunc 2>/dev/null
check "! b session import a3 $ID3.KEY --key-id $ID3 --role bob 2>err && grep -q 'do not match' err" \
      "damage in transfer refused (SEC-STORE-004)"

# --- deletion erases the key and its .SUM
check "b session delete a2 --yes && [ ! -e B/drive1/$ID2.KEY ] && [ ! -e B/drive1/$ID2.SUM ]" \
      "session delete erases key and .SUM (SEC-PTR-004)"
check "! b session delete alice 2>/dev/null </dev/null && b session list | grep -q alice" \
      "delete without terminal or --yes refused"

# --- drive 0
check "! a key generate 8192 --drive 0 2>/dev/null" "drive 0 disabled by default (IMPL-DRV-001)"
check "a drive enable 0 --yes && a key generate 8192 --drive 0 && a drive list 0 | grep -q SUM" \
      "drive 0 enabled, key generated on it"
check "a drive disable 0 --yes && ! a drive list 0 2>/dev/null" "drive 0 erased and disabled"
check "a log | grep -q 'drive 0 off'" "log records it"

# --- a mirrored device (SEC-AVAIL-003): two copies, failover, check, repair
"$BIN/ez-vdev" M --mirror 2>/dev/null & PM=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S M/ez.sock ] && break; sleep 0.2; done
m() { "$EZ" --virtual M/ez.sock "$@"; }
m device erase --yes >/dev/null 2>&1
IDM=$(m key generate 64K 2>/dev/null | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
check "m session create peer --key-id $IDM 2>&1 | grep -q 'Writing key storage'" "maintenance warning before writing (SEC-AVAIL-002)"
check "cmp -s M/drive1/$IDM.KEY M/drive2/$IDM.KEY && cmp -s M/drive1/$IDM.SUM M/drive2/$IDM.SUM" "session create replicates the key to the second copy"
printf '\377' | dd of=M/drive1/$IDM.KEY bs=1 seek=100 conv=notrunc 2>/dev/null
check "echo hi | m encrypt peer --yes >/dev/null" "encryption works with copy 0 damaged (failover)"
check "m session check peer | grep -q 'copy 0: DAMAGED'" "check reports the damaged copy"
check "m session repair peer --yes && m session check peer | grep -q 'copy 0: ok'" "repair rewrites it"
check "m session delete peer --yes && [ ! -e M/drive1/$IDM.KEY ] && [ ! -e M/drive2/$IDM.KEY ]" "deletion erases both copies"
check "m drive info 1 | grep -q '2 copies'" "drive info shows two copies"
# --- round 16: the mirror maintains itself
IDR=$(m key generate 16K --direct 2>/dev/null | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
m session create self16 --key-id $IDR >/dev/null 2>&1
# The virtual device checks its mirror every 2 s after a quiet second, so a
# change is noticed within about 3 s: wait up to 10 s, not a fixed time.
until_ok() { for _ in $(seq 1 20); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
rm -f M/drive2/$IDR.KEY
until_ok "cmp -s M/drive1/$IDR.KEY M/drive2/$IDR.KEY"
check "cmp -s M/drive1/$IDR.KEY M/drive2/$IDR.KEY" "background sync restores a deleted copy by itself"
mv M/drive2 M/drive2.away
until_ok "m device info | grep -q 'mirror     DEGRADED'"
check "m device info | grep -q 'mirror     DEGRADED'" "a missing copy volume: device reports DEGRADED"
check "! m key generate 16K --direct 2>&1 | grep -q generated" "  ... writing to the card is refused without --force"
check "m key generate 16K --direct --force 2>/dev/null | grep -q generated" "  ... and allowed with --force"
check "echo hi | m encrypt self16 --yes 2>&1 | grep -q 'recommend waiting for nominal state'" "  ... encryption works, with the warning"
mv M/drive2.away M/drive2
until_ok "m device info | grep -q 'mirror     ok'"
check "m device info | grep -q 'mirror     ok'" "volume back: the device returns to ok by itself"
m session delete self16 --yes >/dev/null 2>&1
m drive enable 0 --yes >/dev/null 2>&1
IDS=$(m key generate 32K 2>/dev/null | sed -n 's/key \([0-9A-F]*\) on drive 1.*/\1/p')
check "[ -n '$IDS' ] && [ -f M/drive1/$IDS.KEY ] && [ ! -e M/drive1/$IDS.TMP ]" "generation staged on drive 0, then copied to the card (IMPL-AV-006)"
check "! m drive list 0 | grep -q $IDS" "  ... and erased from drive 0"
check "m session create crit --key-id $IDS --spare | grep -q 'spare copy made in internal storage'" "a spare copy in internal storage, drive 0 (IMPL-AV-005)"
check "cmp -s M/drive1/$IDS.KEY M/drive2/$IDS.KEY && m drive list 0 | grep -q $IDS.KEY" "  ... three copies: two on the card, one on drive 0"
check "m session check crit | grep -q 'spare copy (internal): ok'" "  ... and check reports it"
check "m session delete crit --yes && ! m drive list 0 | grep -q $IDS" "deleting the session erases its spare copy"
m drive disable 0 --yes >/dev/null 2>&1
IDF=$(m key generate 16K 2>/dev/null | sed -n 's/key \([0-9A-F]*\) generated/\1/p')
m session create f --key-id $IDF >/dev/null 2>&1
check "! m drive format 1 --yes 2>/dev/null" "format refused while a session uses the card (IMPL-AV-007)"
m session delete f --yes >/dev/null 2>&1
m key generate 16K >/dev/null 2>&1
check "m drive format 1 --yes && [ \$(ls M/drive1 M/drive2 | grep -c -e KEY -e SUM) -eq 0 ]" "format erases every key file on both copies"
kill $PM 2>/dev/null

echo "== e2e: $((PASSES+FAILS)) run, $FAILS failed"
[ $FAILS -eq 0 ]
