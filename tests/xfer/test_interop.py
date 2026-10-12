#!/usr/bin/env python3
"""test_interop.py -- the XMODEM module against lrzsz (sx, rx), an
independent implementation, over pipes. Usage: test_interop.py <build dir>.
Skipped when lrzsz is not installed (apt install lrzsz)."""
import os, random, select, shutil, subprocess, sys, tempfile, time

build = sys.argv[1] if len(sys.argv) > 1 else "build/tests"
peer = os.path.join(build, "xm_peer")
if not shutil.which("sx") or not shutil.which("rx"):
    print("== xmodem interop: SKIPPED (apt install lrzsz)"); sys.exit(0)

passes = fails = 0
def check(c, what):
    global passes, fails
    if c: passes += 1; print(f"[PASS] {what}")
    else: fails += 1; print(f"[FAIL] {what}")

def relay(a, b, secs=60):
    """Connect two processes: a's stdout to b's stdin and back."""
    end = time.time() + secs
    fa, fb = a.stdout.fileno(), b.stdout.fileno()
    live = {fa: b.stdin, fb: a.stdin}
    while live and time.time() < end:
        if a.poll() is not None and b.poll() is not None: break
        r, _, _ = select.select(list(live), [], [], 0.2)
        for fd in r:
            d = os.read(fd, 65536)
            if not d: live.pop(fd); continue
            try: live[fd].write(d); live[fd].flush()
            except (BrokenPipeError, ValueError): live.pop(fd, None)
    for p in (a, b):
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill()
        for f in (p.stdin, p.stdout):
            try: f.close()
            except (BrokenPipeError, OSError): pass
    return a.returncode, b.returncode

def run(ours, theirs, cwd, later=0.0):
    """later: start theirs this long after ours, as a person starts an upload
    after the device has asked for it."""
    a = subprocess.Popen(ours, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=cwd)
    if later:
        time.sleep(later)
        a_early = b""
        while select.select([a.stdout], [], [], 0)[0]:
            chunk = os.read(a.stdout.fileno(), 65536)    # what a terminal shows before the upload starts
            if not chunk: break
            a_early += chunk
    b = subprocess.Popen(theirs, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=cwd)
    return relay(a, b)

def intact(got, want):
    return got[:len(want)] == want and set(got[len(want):]) <= {0x1A} and len(got) - len(want) < 1024

d = tempfile.mkdtemp(prefix="xmi")
random.seed(5)
for size in (1, 128, 1000, 4096, 50000):
    data = bytes(random.randrange(256) for _ in range(size))
    src = os.path.join(d, "src.bin"); open(src, "wb").write(data)
    # our receiver, their sender (128-byte and 1K blocks)
    for opt in ([], ["-k"]):
        dst = os.path.join(d, "ours.bin")
        rc = run([os.path.abspath(peer), "recv", dst], ["sx"] + opt + ["src.bin"], d)
        check(rc == (0, 0) and intact(open(dst, "rb").read(), data), f"sx{' -k' if opt else ''} -> ours: {size} bytes")
    # our sender, their receiver (CRC and checksum mode; 1K allowed or not)
    for mode, k1 in ((["-c"], "1k"), (["-c"], "128"), ([], "128")):
        dst = os.path.join(d, "theirs.bin")
        if os.path.exists(dst): os.unlink(dst)
        rc = run([os.path.abspath(peer), "send", src, k1], ["rx"] + mode + ["theirs.bin"], d)
        got = open(dst, "rb").read() if os.path.exists(dst) else b""
        check(rc == (0, 0) and intact(got, data), f"ours ({k1}) -> rx{' -c' if mode else ' (checksum)'}: {size} bytes")

# ---- ZMODEM against sz / rz: exact lengths, both CRCs, escaping ----
zpeer = os.path.join(build, "zm_peer")
if shutil.which("sz") and shutil.which("rz"):
    for size in (0, 1, 1024, 4097, 50000, 200000):
        data = bytes(random.randrange(256) for _ in range(size))
        src = os.path.join(d, "src.bin"); open(src, "wb").write(data)
        # their sender, our receiver: default, escaping all control characters, 8 KiB blocks
        for opt in ([], ["-e"], ["-8"]):
            if size > 100000 and opt: continue
            dst = os.path.join(d, "ours.bin")
            if os.path.exists(dst): os.unlink(dst)
            rc = run([os.path.abspath(zpeer), "recv", dst], ["sz", "-q"] + opt + ["src.bin"], d)
            got = open(dst, "rb").read() if os.path.exists(dst) else b"?"
            check(rc == (0, 0) and got == data, f"sz {' '.join(opt)} -> ours: {size} bytes")
        # our sender, their receiver (rz writes the file under the name we give)
        for opt in ([], ["-e"]):
            if size > 100000 and opt: continue
            dst = os.path.join(d, "msg.ez")
            if os.path.exists(dst): os.unlink(dst)
            rc = run([os.path.abspath(zpeer), "send", src, "msg.ez"], ["rz", "-q", "-y"] + opt, d)
            got = open(dst, "rb").read() if os.path.exists(dst) else b"?"
            check(rc == (0, 0) and got == data, f"ours -> rz {' '.join(opt)}: {size} bytes")
else:
    print("zmodem interop: SKIPPED (apt install lrzsz)")


# ---- automatic detection against lrzsz: whatever the terminal starts ----
fpeer = os.path.abspath(os.path.join(build, "xf_peer"))
if shutil.which("sz"):
    for size in (100, 20000):
        data = bytes(random.randrange(256) for _ in range(size))
        src = os.path.join(d, "src.bin"); open(src, "wb").write(data)
        for prog, padded in ((["sx", "src.bin"], True), (["sx", "-k", "src.bin"], True), (["sz", "-q", "src.bin"], False)):
            dst = os.path.join(d, "ours.bin")
            if os.path.exists(dst): os.unlink(dst)
            # the device asks first (its one ZRINIT shows on the terminal), then the person starts the upload
            rc = run([fpeer, "recv", dst], prog, d, later=1.0)
            got = open(dst, "rb").read() if os.path.exists(dst) else b"?"
            ok = intact(got, data) if padded else got == data
            check(rc == (0, 0) and ok, f"{' '.join(prog[:-1])} -> auto receiver: {size} bytes")
        for prog, out in ((["rx", "-c", "x.out"], "x.out"), (["rx", "x.out"], "x.out"), (["rz", "-q", "-y"], "msg.ez")):
            dst = os.path.join(d, out)
            if os.path.exists(dst): os.unlink(dst)
            rc = run([fpeer, "send", src, "msg.ez"], prog, d)
            got = open(dst, "rb").read() if os.path.exists(dst) else b"?"
            ok = intact(got, data) if prog[0] == "rx" else got == data
            check(rc == (0, 0) and ok, f"auto sender -> {' '.join(prog[:-1] if prog[0] == 'rx' else prog[:1])}: {size} bytes")

shutil.rmtree(d, ignore_errors=True)
print(f"== xmodem/zmodem interop: {passes + fails} run, {fails} failed")
sys.exit(1 if fails else 0)
