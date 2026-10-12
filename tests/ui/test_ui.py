#!/usr/bin/env python3
"""test_ui.py -- screen tests for the terminal interface (EZ-UI-001), driven
through ez-vdev's terminal socket with a VT100 emulator. Usage:
    tests/ui/test_ui.py <build dir with ez and ez-vdev>"""
import os, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(__file__))
from termlib import Term, UP, DOWN, RIGHT, LEFT, ESC, ENTER

passes = fails = 0
CURRENT = None
def check(cond, what):
    global passes, fails
    if cond: passes += 1; print(f"[PASS] {what}")
    else:
        fails += 1; print(f"[FAIL] {what}")
        if CURRENT is not None:                   # what the terminal showed
            print("\n".join("    | " + l for l in CURRENT.screen.display))

def wait_for(t, pred, secs=4.0):
    end = time.time() + secs
    while time.time() < end:
        t.pump(0.2)
        if pred(): return True
    return pred()

bindir = sys.argv[1] if len(sys.argv) > 1 else "build/tests"
t = Term(bindir, mirror=True)
CURRENT = t
try:
    t.ez("device", "erase", "--yes")
    t.connect()
    # 1. Home
    check(t.line(0).startswith(" Home  Send  Receive  Keys  Device  CLI  Help"), "menu bar: Home, Send, Receive, Keys, Device, CLI, Help")
    check(t.line(1).strip() == "-" * 80, "a plain ASCII separator under the menu bar")
    check("one-time pad" not in t.text(), "Home: just the logo, no tagline")
    check("|  _|   |   |  _|_  |  _|  |_   _|" in t.text(), "Home shows the logo")
    check(wait_for(t, lambda: "Mirror   ok" in t.text()), "Home: the mirror reaches ok by itself")
    check(t.line(23).startswith(" Keys 0 | Mirror"), "status line on the last row")
    check(all(len(l.rstrip()) <= 80 for l in t.screen.display), "nothing wider than 80 columns")
    # 2. live updates, without a key press
    kid = t.ez("key", "generate", "64K", "--direct").stdout.split()[1]
    t.ez("session", "create", "alice", "--key-id", kid)
    check(wait_for(t, lambda: t.line(23).startswith(" Keys 1 |")), "status line updates by itself (Keys 1)")
    check(wait_for(t, lambda: "Keys     1" in t.text()), "Home panel updates by itself")
    # 3. navigation
    t.keys(RIGHT * 3 + ENTER)
    check("Label        Key ID" in t.text(), "Right x3 and Enter open Keys")
    t.keys(ESC, 0.3)
    t.keys("h")
    check("|___|___|_|_|___|___|___|___|___|" in t.text(), "Esc then H returns to Home")
    t.keys("d")
    check("Maintenance is in the CLI" in t.text(), "D opens Device")
    t.keys(LEFT + ENTER)
    check("Label        Key ID" in t.text(), "on Device, the arrows still move along the menu (Left, Enter: Keys)")
    t.keys(RIGHT + ENTER)
    check("Maintenance is in the CLI" in t.text(), "and on Keys, Right leaves for the menu (Right, Enter: Device)")
    t.keys(ESC, 0.3); t.keys("?")
    check("Ctrl-L redraws" in t.text(), "? opens Help")
    # 4. keys: list and details
    t.keys(ESC, 0.3); t.keys("k")
    row = t.line(3)
    check(row.startswith("> alice") and kid in row and "[########]" in row, "Keys lists the key with its bars")
    check(t.line(4).strip() == "", "the key's row fits on one line")
    t.keys(ENTER)
    check("Key 'alice'" in t.text() and "Send left" in t.text(), "Enter shows the key's details")
    t.keys(ESC, 0.3)
    check("Label        Key ID" in t.text(), "Esc returns to the list")
    # 5. CLI
    t.keys(ESC, 0.3); t.keys("c")
    check("ez>" in t.text(), "C opens the CLI")
    t.keys("help\r")
    check("card format [1|2] [erase]" in t.text(), "help lists the commands")
    t.keys("keys\r")
    check("alice" in t.text() and "send 32768, receive 32768 left" in t.text(), "keys")
    t.keys("ls a\r")
    check(f"{kid}.KEY" in t.text(), "ls a lists copy volume A")
    t.keys("ls internal\r")
    check("internal storage is off" in t.text(), "ls internal on a device with internal storage off")
    t.keys("frobnicate\r")
    check("unknown command 'frobnicate'" in t.text(), "an unknown command")
    t.keys("key alice check\r", 0.3)
    check(wait_for(t, lambda: "copy 1: ok" in t.text()), "key check runs as a job and reports every copy")
    t.keys("erase\r")
    check("Type YES to continue" in t.text(), "erase asks for YES")
    t.keys("no\r")
    check("cancelled" in t.text(), "anything but YES cancels")
    check(t.line(0).startswith(" Home") and t.line(23).startswith(" Keys 1"), "the bars survive the CLI's scrolling")
    # 6. degraded shows on Home and the status line by itself
    t.keys(ESC, 0.3); t.keys("h")
    os.rename(os.path.join(t.dir, "drive2"), os.path.join(t.dir, "drive2.away"))
    check(wait_for(t, lambda: "Mirror DEGRADED" in t.line(23), 8), "status line: Mirror DEGRADED")
    check("! DEGRADED: one of the card's two copies is unavailable" in t.text(), "Home shows the degraded reason")
    os.rename(os.path.join(t.dir, "drive2.away"), os.path.join(t.dir, "drive2"))
    check(wait_for(t, lambda: "Mirror ok" in t.line(23), 8), "and returns to ok by itself")
finally:
    t.close()
    shutil.rmtree(t.dir, ignore_errors=True)

# 7..10: the key manager (round 18), on a device with one card copy and drive 0
t = Term(bindir)
CURRENT = t
try:
    t.ez("device", "erase", "--yes")
    t.ez("drive", "enable", "0", "--yes")
    t.connect()
    t.keys("k")
    check("N makes a new one" in t.text(), "Keys with no keys says how to make one")
    # 7. new key
    t.keys("n")
    check("New key: size" in t.text() and "64 KiB    send up to 32 KiB" in t.text() and "Each side" not in t.text(),
          "N asks for the size, saying what each can send (64 KiB included)")
    t.keys(UP + ENTER)
    check("New key: label" in t.text(), "then for a label")
    t.keys("carol" + ENTER)
    check("New key: where to keep it" in t.text() and "On the card, with a spare copy" in t.text()
          and "Internal storage only" in t.text() and "drive 0" not in t.text(), "then where, in plain words")
    t.keys(ENTER)
    check("Generate 128 KiB for 'carol'" in t.text(), "then a confirmation")
    t.keys("y")
    check(wait_for(t, lambda: "The key is ready." in t.text(), 15), "the key is generated, copied, and its session created")
    t.keys(" ")
    check(t.line(3).startswith("> carol") and "card" in t.line(3), "carol is in the list, on the card")
    files0 = os.listdir(os.path.join(t.dir, "drive0")) if os.path.isdir(os.path.join(t.dir, "drive0")) else []
    check(not any(f.endswith(".KEY") for f in t.ez("drive", "list", "0").stdout.split()), "nothing left on drive 0 after the staged generation")
    # a duplicate label is refused in the dialog
    t.keys("n"); t.keys(ENTER); t.keys("carol" + ENTER)
    check("'carol' is already a key" in t.text(), "a duplicate label is refused")
    t.keys(ESC, 0.3)
    # 8. import
    kid = t.ez("key", "generate", "64K", "--direct").stdout.split()[1]
    t.keys("i")
    check("Import a key from the card" in t.text() and f"{kid}.KEY" in t.text(), "I lists the new key file on the card")
    t.keys(ENTER); t.keys("dave" + ENTER); t.keys(ENTER)
    check(wait_for(t, lambda: "The key is imported and ready." in t.text(), 10), "the key is imported")
    t.keys(" ")
    check(any(l.startswith("  dave") for l in t.screen.display) and "bob" in t.text(), "dave is listed, as bob")
    # 9. export to a transfer card (the swap simulated by renaming directories)
    t.keys(UP * 4)
    t.keys("x")
    check("Export to a transfer card" in t.text() and "'carol'" in t.text(), "X explains the export")
    t.keys("y")
    check(wait_for(t, lambda: "Remove your card now." in t.text(), 10), "the key is held on drive 0, then: remove your card")
    d1 = os.path.join(t.dir, "drive1")
    os.rename(d1, d1 + ".mine")
    check(wait_for(t, lambda: "Insert the transfer card." in t.text(), 5), "the removal is noticed: insert the transfer card")
    os.mkdir(d1)
    check(wait_for(t, lambda: "Copied and verified. Remove the transfer card." in t.text(), 10), "copied to the transfer card and verified")
    os.rename(d1, d1 + ".transfer")
    check(wait_for(t, lambda: "Insert your own card again." in t.text(), 5), "then: put your own card back")
    os.rename(d1 + ".mine", d1)
    check(wait_for(t, lambda: "Give the transfer card to the other party" in t.text(), 10), "the export finishes")
    tf = os.listdir(d1 + ".transfer")
    check(any(f.endswith(".KEY") for f in tf) and any(f.endswith(".SUM") for f in tf), "the transfer card holds the key and its .SUM")
    check(not any(f.endswith(".KEY") for f in t.ez("drive", "list", "0").stdout.split()), "the copy held on drive 0 is erased afterwards")
    t.keys(" ")
    # 10. delete, with the label typed
    t.keys(UP * 4)
    t.keys("d")
    check("Type the label to confirm." in t.text(), "D asks for the label")
    t.keys("carl" + ENTER)
    check("that is not 'carol'" in t.text(), "a wrong label is refused")
    t.keys("\x7fol" + ENTER)
    check(wait_for(t, lambda: "The key is erased." in t.text(), 10), "the right label deletes it")
    t.keys(" ")
    check(not any(l.startswith("> carol") or l.startswith("  carol") for l in t.screen.display), "carol is gone from the list")
finally:
    t.close()
    shutil.rmtree(t.dir, ignore_errors=True)
# 11..14: Send and Receive (round 19), between two devices sharing a key
a = Term(bindir); b = Term(bindir)
try:
    for t in (a, b): t.ez("device", "erase", "--yes")
    kid = a.ez("key", "generate", "64K", "--direct").stdout.split()[1]
    for f in os.listdir(os.path.join(a.dir, "drive1")):
        shutil.copy(os.path.join(a.dir, "drive1", f), os.path.join(b.dir, "drive1"))
    a.ez("session", "create", "bob", "--key-id", kid, "--role", "alice")
    b.ez("session", "create", "alice", "--key-id", kid, "--role", "bob")
    a.connect(); b.connect(); a.pump(1.0)
    CURRENT = a
    # 11. send
    a.keys("s", 0.5)
    check("Send to 'bob' (32768 bytes of key left)" in a.text(), "Send with one key opens the editor for it")
    a.keys("\x05", 0.4)
    check("Nothing to send yet." in a.text(), "an empty message is refused")
    a.keys("Hello Bob,\rthe meeting is at noon.\r", 0.3)
    a.keys("\x05", 0.4)
    check("Encrypt 35 bytes for 'bob'? 32733 bytes of key will remain." in a.text(), "Ctrl-E asks, with the bytes it will use")
    a.keys("n", 0.4)
    check("the meeting is at noon." in a.text(), "n returns to the text, unchanged")
    a.keys("\x05", 0.4); a.keys("y", 0.6)
    check("For 'bob', 55 bytes." in a.line(23), "y encrypts and shows the message")
    check(a.line(0).startswith("WkUB"), "as base64, starting with the header")
    a.keys("c", 0.5)
    ct = [l.strip() for l in a.screen.display if l.strip() and not l.startswith("--")]
    check(len(ct) == 1 and "end: press any key" in a.text(), "C shows it plainly for copying")
    a.keys(" ", 0.4)
    check("For 'bob'" in a.line(23), "any key returns to the view")
    a.keys(ENTER, 0.5)
    check(a.line(0).startswith(" Home"), "Enter returns to Home")
    a.keys("s", 0.5); a.keys("second", 0.3); a.keys("\x05", 0.4); a.keys("y", 0.6); a.keys("c", 0.5)
    ct2 = [l.strip() for l in a.screen.display if l.strip() and not l.startswith("--")]
    a.keys(" ", 0.3); a.keys(ENTER, 0.5)
    # 12. discard asks first
    a.keys("s", 0.5); a.keys("draft", 0.3); a.keys("\x18", 0.4)
    check("Discard this message?" in a.text(), "Ctrl-X on a message asks first")
    a.keys("y", 0.5)
    check(a.line(0).startswith(" Home"), "y discards it")
    # 13. receive
    CURRENT = b
    b.keys("r", 0.5)
    check("Paste the message now" in b.text(), "Receive asks for the message")
    b.keys("\r\n".join(ct) + "\r\n", 1.0)
    check(b.line(0).startswith("Hello Bob,") and b.line(1).startswith("the meeting is at noon."), "the pasted message decrypts")
    check("From 'alice', 35 B, verified." in b.line(23), "shown as verified, from alice")
    b.keys(ENTER, 0.5)
    check(b.line(0).startswith(" Home"), "Enter closes it (and wipes it)")
    b.keys("r", 0.5); b.keys("\r\n".join(ct) + "\r\n", 1.0)
    check("already received" in b.text(), "the same message again: a replay, refused")
    b.keys(" ", 0.4)
    check("Paste the message now" in b.text(), "after an error: ready for the next paste")
    bad = ct2[0][:30] + ("A" if ct2[0][30] != "A" else "B") + ct2[0][31:]
    b.keys(bad + "\r\n", 1.0)
    check("Changed or damaged in transit: nothing is shown." in b.text(), "a tampered message: refused, nothing shown")
    b.keys(" ", 0.4)
    b.keys("\r\n".join(ct2) + "\r\n", 1.0)
    check(b.line(0).startswith("second"), "the untampered message still decrypts: a rejection consumes no key")
    b.keys(ENTER, 0.5); b.keys("r", 0.5)
    b.keys("$$$ this is not a message $$$\r\n", 1.0)
    check("not an Einszeit message" in b.text(), "garbage is recognised")
    b.keys(" ", 0.4); b.keys(ESC, 0.4)
    check(b.line(0).startswith(" Home"), "Esc leaves Receive")
    # 14. two keys: Send asks which
    CURRENT = a
    k2 = a.ez("key", "generate", "64K", "--direct").stdout.split()[1]
    a.ez("session", "create", "carol", "--key-id", k2, "--role", "alice")
    a.pump(1.0)
    a.keys("s", 0.5)
    check("Send with which key?" in a.text() and "carol" in a.text(), "with two keys, Send asks which")
    a.keys(DOWN + ENTER, 0.5)
    check("Send to 'carol'" in a.text(), "and opens the editor for the one picked")
    a.keys("\x18", 0.4)
finally:
    a.close(); b.close()
    shutil.rmtree(a.dir, ignore_errors=True); shutil.rmtree(b.dir, ignore_errors=True)

# 15. generating in the background; cancel; spare copy on/off (round 20), with a
# worker thread like the device's second core and a slowed TRNG
t = Term(bindir, extra=("--worker", "--trng-rate", "40000"))
CURRENT = t
try:
    t.ez("device", "erase", "--yes"); t.ez("drive", "enable", "0", "--yes")
    t.connect()
    check(t.line(0).startswith(" Home"), "a fresh connection shows a clean Home")
    t.keys("k"); t.keys("n"); t.keys(ENTER)              # 256 KiB: about 6 s at 40 kB/s
    t.keys("erin" + ENTER); t.keys(ENTER); t.keys("y", 0.6)
    check("Esc: continue in the background    C: cancel" in t.text(), "the generation dialog offers background and cancel")
    t.keys(ESC, 0.6)
    check("erin: generating" in t.text(), "Esc: the list shows erin as generating")
    t.keys(ESC, 0.3); t.keys("s", 0.5)
    check("The device is generating a key" in t.text(), "Send says plainly that it must wait")
    t.keys(ESC, 0.3); t.keys("h", 0.3)
    check(wait_for(t, lambda: "* New key: Key 'erin' is ready." in t.text() or "Key 'erin' is ready." in t.text(), 20),
          "Home notes when the background generation is done")
    t.keys("k", 0.4)
    check(any(l.startswith("> erin") or l.startswith("  erin") for l in t.screen.display), "erin is in the list")
    # cancel
    t.keys("n"); t.keys(ENTER); t.keys("finn" + ENTER); t.keys(ENTER); t.keys("y", 0.6)
    t.keys("c", 0.2)
    check(wait_for(t, lambda: "Generating was cancelled; nothing was kept." in t.text(), 10), "C cancels the generation")
    t.keys(" ", 0.4)
    check(not any("finn" in l for l in t.screen.display[3:20]), "nothing of finn is kept")
    # spare copy on, then off
    t.keys("p", 0.4)
    check("Keep a spare copy of 'erin' in internal storage?" in t.text(), "P offers a spare copy")
    t.keys("y")
    check(wait_for(t, lambda: "The spare copy is made." in t.text(), 10), "the spare copy is made")
    t.keys(" ", 0.4)
    check("card+spare" in t.text(), "the list shows card+spare")
    t.keys(ESC, 0.3); t.keys("h", 0.4)
    check("(1 with a spare copy)" in t.text() and "Internal " in t.text(), "Home: 'with a spare copy', internal storage")
    t.keys("?", 0.4)
    check("Spare copy An extra copy of a card key in internal storage" in t.text(), "Help explains card, internal, spare copy")
    t.keys("k", 0.4)
    t.keys("p", 0.4); t.keys("y")
    check(wait_for(t, lambda: "The spare copy is removed." in t.text(), 10), "and removed again")
    t.keys(" ", 0.4)
    check("card+spare" not in t.text(), "the list shows card only")
    # TR-09 feedback: after an info box, the Send key pick still opens the editor
    r = t.ez("key", "generate", "64K", "--direct")
    k3 = r.stdout.split()[1]
    t.ez("session", "create", "gwen", "--key-id", k3, "--role", "alice")
    t.pump(1.0)
    t.keys(ESC, 0.3); t.keys("s", 0.5)
    check("Send with which key?" in t.text(), "two keys: Send asks which")
    t.keys(DOWN + ENTER, 0.5)
    check("Send to 'gwen'" in t.text(), "after an info box, the key picked opens the editor")
    t.keys("\x18", 0.4)
finally:
    t.close()
    shutil.rmtree(t.dir, ignore_errors=True)

# 16. XMODEM through the interface, against lrzsz (round 21)
import select, subprocess
def xfer(term, cmd, cwd, secs=60):
    """Relay the terminal's line to an XMODEM program, as a terminal does."""
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=cwd)
    end = time.time() + secs
    fs, fp = term.s.fileno(), p.stdout.fileno()
    while time.time() < end and p.poll() is None:
        r, _, _ = select.select([fs, fp], [], [], 0.2)
        if fs in r:
            d = os.read(fs, 65536)
            if d: p.stdin.write(d); p.stdin.flush()
        if fp in r:
            d = os.read(fp, 65536)
            if d: term.s.sendall(d)
    try: p.wait(timeout=5)
    except subprocess.TimeoutExpired: p.kill()
    term.screen.reset()                                # what the transfer wrote is not a screen
    return p.returncode

if shutil.which("sx") and shutil.which("rx"):
    a = Term(bindir); b = Term(bindir)
    w = tempfile.mkdtemp(prefix="ezxm")
    try:
        for t in (a, b): t.ez("device", "erase", "--yes")
        kid = a.ez("key", "generate", "64K", "--direct").stdout.split()[1]
        for f in os.listdir(os.path.join(a.dir, "drive1")):
            shutil.copy(os.path.join(a.dir, "drive1", f), os.path.join(b.dir, "drive1"))
        a.ez("session", "create", "bob", "--key-id", kid, "--role", "alice")
        b.ez("session", "create", "alice", "--key-id", kid, "--role", "bob")
        a.connect(); b.connect(); a.pump(1.0)
        CURRENT = a
        plain = ("Meet at the old mill at six.\nBring the second key.\n" * 40).encode()
        open(os.path.join(w, "letter.txt"), "wb").write(plain)
        a.keys("s", 0.5); a.keys("\x0f", 0.6)
        rc = xfer(a, ["sx", "-k", "letter.txt"], w)
        check(rc == 0, "Send: Ctrl-O, then sx uploads a file")
        a.pump(1.5)
        check(f"Encrypt the uploaded file ({len(plain)} bytes) for 'bob'?" in a.text(), "the upload is confirmed with its size")
        a.keys("y", 0.6)
        check(f"For 'bob', {len(plain) + 20} bytes." in a.line(23), "and encrypted")
        a.keys("d", 0.6)
        rc = xfer(a, ["rx", "-c", "letter.ez"], w)
        check(rc == 0, "D, then rx downloads the message")
        a.pump(1.5)
        check("Downloaded by XMODEM" in a.text(), "the view says it was downloaded")
        got = open(os.path.join(w, "letter.ez"), "rb").read().rstrip(b"\x1a")
        check(got.startswith(b"WkUB") and got.endswith(b"\n"), "the file is the message's base64, in lines")
        CURRENT = b
        b.pump(0.5); b.keys("r", 0.5); b.keys("\x12", 0.6)
        rc = xfer(b, ["sx", "letter.ez"], w)
        check(rc == 0, "Receive: Ctrl-R, then sx uploads the message file (^Z padding and all)")
        b.pump(1.5)
        check(b.line(0).startswith("Meet at the old mill at six.") and "verified" in b.line(23), "it decrypts, verified")
        b.keys("d", 0.6)
        rc = xfer(b, ["rx", "-c", "letter.out"], w)
        out = open(os.path.join(w, "letter.out"), "rb").read() if os.path.exists(os.path.join(w, "letter.out")) else b""
        check(rc == 0 and out.rstrip(b"\x1a") == plain, "D on the plaintext: rx gets the original file")
    finally:
        a.close(); b.close()
        for d_ in (a.dir, b.dir, w): shutil.rmtree(d_, ignore_errors=True)
else:
    print("xmodem screen tests: SKIPPED (apt install lrzsz)")

# 17. ZMODEM through the interface (round 22): the same round trip with sz
# and rz, exact lengths, and a ZMODEM upload recognised on Receive with no
# key pressed (a terminal that starts its upload by itself)
if shutil.which("sz") and shutil.which("rz"):
    a = Term(bindir); b = Term(bindir)
    w = tempfile.mkdtemp(prefix="ezzm")
    try:
        for t in (a, b): t.ez("device", "erase", "--yes")
        kid = a.ez("key", "generate", "64K", "--direct").stdout.split()[1]
        for f in os.listdir(os.path.join(a.dir, "drive1")):
            shutil.copy(os.path.join(a.dir, "drive1", f), os.path.join(b.dir, "drive1"))
        a.ez("session", "create", "bob", "--key-id", kid, "--role", "alice")
        b.ez("session", "create", "alice", "--key-id", kid, "--role", "bob")
        a.connect(); b.connect(); a.pump(1.0)
        CURRENT = a
        plain = bytes(range(256)) * 20 + b"\x1a\x1a"                 # binary, ending in ^Z: exact by ZMODEM
        open(os.path.join(w, "data.bin"), "wb").write(plain)
        a.keys("s", 0.5); a.keys("\x0f", 0.6)
        rc = xfer(a, ["sz", "-q", "data.bin"], w)
        check(rc == 0, "Send: Ctrl-O, then sz uploads a file")
        a.pump(1.5)
        check(f"Encrypt the uploaded file ({len(plain)} bytes) for 'bob'?" in a.text(),
              "exact length by ZMODEM: a trailing ^Z is kept")
        a.keys("y", 0.6)
        a.keys("d", 0.6)
        rc = xfer(a, ["rz", "-q", "-y"], w)
        check(rc == 0 and os.path.exists(os.path.join(w, "message.ez")), "D, then rz downloads message.ez")
        a.pump(1.5)
        check("Downloaded by ZMODEM." in a.text(), "the view says it was downloaded by ZMODEM")
        CURRENT = b
        b.pump(0.5); b.keys("r", 0.5)
        rc = xfer(b, ["sz", "-q", "message.ez"], w)
        check(rc == 0, "Receive: sz started without a key press is recognised")
        b.pump(1.5)
        check("verified" in b.line(23) and f"{len(plain)} B" in b.line(23), "it decrypts, verified")
        b.keys("d", 0.6)
        rc = xfer(b, ["rz", "-q", "-y"], w)
        out = open(os.path.join(w, "message.txt"), "rb").read() if os.path.exists(os.path.join(w, "message.txt")) else b""
        check(rc == 0 and out == plain, "D on the plaintext: rz gets the original file, byte for byte")
    finally:
        a.close(); b.close()
        for d_ in (a.dir, b.dir, w): shutil.rmtree(d_, ignore_errors=True)
else:
    print("zmodem screen tests: SKIPPED (apt install lrzsz)")

print(f"== ui: {passes + fails} run, {fails} failed")
sys.exit(1 if fails else 0)
