"""termlib.py -- drive the terminal interface (EZ-UI-001) of ez-vdev with a
VT100 emulator (pyte), for screen tests."""
import os, socket, subprocess, tempfile, time, select
import pyte

class Term:
    def __init__(self, bindir, mirror=False, extra=()):
        self.dir = tempfile.mkdtemp(prefix="ezui")
        self.sock = os.path.join(self.dir, "ez.sock")
        self.tsock = os.path.join(self.dir, "term.sock")
        args = [os.path.join(bindir, "ez-vdev"), self.dir, "--socket", self.sock, "--term", self.tsock]
        if mirror: args.append("--mirror")
        args += list(extra)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        self.p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        self.ez_bin = os.path.join(bindir, "ez")
        for _ in range(100):
            if os.path.exists(self.tsock) and os.path.exists(self.sock): break
            time.sleep(0.02)
        self.screen = pyte.Screen(80, 24)
        self.stream = pyte.ByteStream(self.screen)
        self.s = None

    def ez(self, *args):
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        return subprocess.run([self.ez_bin, "--virtual", self.sock] + list(args),
                              capture_output=True, text=True, env=env)

    def connect(self):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(self.tsock)
        self.pump(0.3)

    def pump(self, secs=0.2):
        end = time.time() + secs
        while True:
            left = end - time.time()
            if left <= 0: break
            r, _, _ = select.select([self.s], [], [], left)
            if r:
                b = self.s.recv(65536)
                if not b: break
                self.stream.feed(b)

    def keys(self, data, secs=0.3):
        if isinstance(data, str): data = data.encode()
        self.s.sendall(data)
        self.pump(secs)

    def text(self):
        return "\n".join(self.screen.display)

    def line(self, n):
        return self.screen.display[n]

    def close(self):
        if self.s: self.s.close()
        self.p.terminate()
        self.p.wait()

UP, DOWN, RIGHT, LEFT, ESC, ENTER = "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b", "\r"
