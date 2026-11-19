#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""Integration test of `forgeext run`, the daemon, as root.

In network and mount namespaces of its own: the image's deny rules loaded, a
peer namespace on a veth pair, a stand-in for forgectrl's read-only routes on
loopback whose answers the test changes, and four real packages installed
through the command line: a heartbeat, a dialer that declares one destination
by name, one that ends at once, and one the operator let run through a job.
The host's machine token is a file of the test's (FORGEEXT_HOST_TOKEN_FILE),
and the stand-in takes a claim on the Grbl sender only with that token and
serves the host's event stream. As it starts, the host names that file's
variable and the FFLOG_* ones set, in one notice, names only, and its list
of them is held to the sources.

Nothing starts while extensions are off or the machine is not ready. Then
services start one at a time, each as its pool account in its own cgroup, with
its output in the log under its name. The dialer reaches its declared
destination and not the machine. An armed window freezes every service but the
one with the grant, which gets job-time limits; disarming thaws them; a
forgectrl that stops answering freezes them again. That same package names
programs to run: the file that is really in its data directory gets as far as
the machine, and a symbolic link out of the directory and a name with a
directory in it are refused in words before anything does. A killed service
comes back. The one that keeps ending is quarantined, and state.json
remembers it. One that holds more than its storage capability asks for, a
file it unlinked while it holds it open included, or whose data directory
the host cannot measure, is set aside, in words that
say why, and runs again once its data is cleared and the operator enables
it; a quarantine the host could not write holds all the same, across a
restart of the host too, and is written as soon as it can be. A
destination the operator names in the
meantime does not lift it. The operator's enable lifts it, and the host
does not write the quarantine over that enable, nor over one that comes
inside the host's turn, between its read of the state and its write. An
enable that comes just before the measurement that sets the service
aside lifts nothing. One whose manifest cannot be read is set aside too,
with the way out that fits it: remove the package and install it again;
one enabled with no manifest to read when a host starts is held out by
that host, never started, in words that name the manifest.
A package the operator removes inside the
turn that measures it, after the host has read the state and before it
measures, is not set aside by the measurement its removal breaks. A
package granted sender.keep_out that asks to keep the Grbl sender out has
its claim kept fresh beside the holds, until it is disabled.
A package that holds events has the host hold one stream from forgectrl: a
poll at the head comes back empty at its deadline, a waiting one as soon as
the stream carries an event, and with the package disabled the stream is let
go. A package removed and installed again while the host is not
looking is started again from the new install, never left running from the
old one. A fifth package asks for destinations of the operator's: it
reaches nothing until the operator names the peer, is started again with
it, reaches it, and loses it again when the operator takes it away. A sixth,
holding events and the job_time.run grant, reads the host's ext.will_freeze
as the armed window opens, running on, and ext.thawed as it closes. A
seventh, holding events and no grant, reads the host's ext.shutdown before
safe mode stops it, unfrozen through that last second.
Safe mode stops everything and leaves no group and no chain. SIGTERM does the
same and the daemon exits 0.
Last, the host runs under the init script's own wrapper (init/forgeext.init,
lifted from the script and expanded as the script expands it): a SIGKILL of
the host takes its services with it at once, and the wrapper starts the host
again, which starts the service again under a new pid. This needs Landlock's
network rules (ABI 4 or newer), which the host is not told to do without.
A stray TERM of the host is no stop: the wrapper starts it again.

Besides: a package's data directory is root's and its account's group's,
0770, which the package cannot open to another account; its data kept
across a removal and installed again into another account is handed to that
account entry by entry, a link left in it not followed. The dialer's second
destination has the stand-in forgectrl's port, so landlock lets it dial
that port at 127.0.0.1 and the image's table is what refuses it. One
package's five silent connections to its socket: the fifth is closed at
once, and another package is answered meanwhile. A service that closes its
output costs the host no CPU. A command that holds the root's lock holds up
nothing of the host's turn. Inside the shutdown grace (4 s here, 1 s on the
machine) an armed window, or one that cannot be read, freezes what is left
running before it is stopped; the host's own stop waits the machine's 1 s
whatever its grace, and --shutdown-grace takes nothing below 1 s or past
30 s. The M-code of the one with the grant is listed while it runs, and not
while it is frozen in place of job-time limits that cannot be set. A stop
whose process outlives its group's kill holds up nothing of the turn. A
predecessor's removal that the root's lock put off is taken up once the
lock is let go. A root
mount that is not shared (this namespace's, as unshare leaves it) is a
machine not ready, until the test makes it shared. A start whose name is
being looked up is put off, the turn going on, and a name the resolver
never answers is then a start the machine is not ready for, never
counted; so is a full /data; a LAN name in a manifest is refused, and the
same name the operator types is taken; a tree changed by hand is a start
that fails for the package's own reason, and is counted. A listener opens
only while the operator's grant is in the record, read at each start. The
init script itself (its four paths moved under the test, a stand-in for
the host) finds a running wrapper at a second start, has a stray TERM of
the host answered by a respawn, and sends TERM to a host whose wrapper is
gone; the relay of that wrapper, which outlives it, is ended by the test.

Needs root, cgroup v2, nft, ip, nsenter, unshare, fwup (FWUP), the built
forgeext (FORGEEXT), and the rule file (FFX_RULES). Exits 77 without them.
"""
import ctypes
import errno
import fcntl
import http.server
import json
import os
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
FWUP = os.environ.get("FWUP") or shutil.which("fwup")
NFT = os.environ.get("NFT") or shutil.which("nft") or "/usr/sbin/nft"
RULES = os.environ.get("FFX_RULES") or os.path.join(HERE, "..", "..", "forgefirm", "meta-forgefirm", "recipes-forgefirm",
                                                    "forgefirm-sandbox", "files", "ffx.nft")
MKFFX = os.path.join(HERE, "..", "tools", "mkffx.sh")
CG_PARENT = "/sys/fs/cgroup/forgeext-run-test"
# Two documentation networks, routed to each other over the veth pair: the peer is on no subnet of the host's own,
# which a destination named by DNS must not lead into.
HERE_ADDR, PEER_ADDR = "203.0.113.1", "198.51.100.2"
SKIP = 77

PEER = r'''
import socket, sys, threading
print("pid", flush=True)
sys.stdin.readline()
s = socket.socket()
s.bind(("%s", 0))
s.listen(128)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("%s", 53))          # the namespace's resolver: it takes every query and answers none
def take():
    while True:
        c, _ = s.accept()
        c.close()
threading.Thread(target=take, daemon=True).start()
print(s.getsockname()[1], flush=True)
sys.stdin.readline()
''' % (PEER_ADDR, PEER_ADDR)

# What a service needs to talk to the host: one request per connection to the socket named in FFX_API.
API_CLIENT = r'''
import json, os, socket
def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else b""
    head = "%s %s HTTP/1.1\r\nHost: forgeext\r\n" % (method, path)
    if body is not None:
        head += "Content-Type: application/json\r\nContent-Length: %d\r\n" % len(data)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(os.environ["FFX_API"])
        s.sendall(head.encode() + b"\r\n" + data)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
        top, _, payload = buf.partition(b"\r\n\r\n")
        return int(top.split()[1]), json.loads(payload or b"null")
    except (OSError, ValueError, IndexError) as e:
        return 599, {"error": str(e)}
    finally:
        s.close()
'''

# The one the operator lets run through a job: it may read the machine and has a hold.
JOBTIME = API_CLIENT + r'''
import sys, time
code, me = api("GET", "/v0/self")
print("api self %d %s %s %s" % (code, me.get("id"), me.get("api"), ",".join(sorted(me.get("capabilities", [])))), flush=True)
code, mode = api("GET", "/v0/machine/mode")
print("api mode %d %s %s" % (code, mode.get("mode"), mode.get("motion")), flush=True)
print("api nowhere %d" % api("GET", "/v0/nowhere")[0], flush=True)
print("api bad hold %d" % api("POST", "/v0/hold", {"raised": "yes"})[0], flush=True)
code, h = api("POST", "/v0/hold", {"raised": True, "reason": "through the job"})
print("api raise %d %s" % (code, h), flush=True)
codes = [api("GET", "/v0/self")[0] for _ in range(60)]
print("api burst %d ok %d limited" % (codes.count(200), codes.count(429)), flush=True)
# motion.job names a file of this package's own data. The host opens it
# through a descriptor for that directory, so a name with a directory in
# it and a symbolic link out of it are both refused before anything
# reaches the machine; the file that is really there is not.
time.sleep(1.5)                                 # the burst above spent this package's rate; let it refill
d = os.environ["FFX_DATA"]
with open(os.path.join(d, "job.gcode"), "w") as f:
    for g in ("G21", "G90", "G0 X1"):
        print(g, file=f)
os.symlink("/etc/passwd", os.path.join(d, "elsewhere.gcode"))
for what, name in (("real", "job.gcode"), ("link", "elsewhere.gcode"), ("dir", "../../state.json")):
    code, ans = api("POST", "/v0/motion/job", {"program": name})
    print("api job %s %d %s" % (what, code, (ans or {}).get("error", "")), flush=True)
cleared = False
while True:
    if not cleared and os.path.exists(os.path.join(os.environ["FFX_DATA"], "clear")):
        time.sleep(1.5)
        print("api clear %d" % api("POST", "/v0/hold", {"raised": False})[0], flush=True)
        cleared = True
    print("through the job", flush=True)
    time.sleep(1)
'''

DIAL = API_CLIENT + r'''
import socket, sys, time
name, port, local = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
print("api without the capabilities: mode %d hold %d raise %d" % (api("GET", "/v0/machine/mode")[0], api("GET", "/v0/hold")[0],
      api("POST", "/v0/hold", {"raised": True})[0]), flush=True)
def dial(host, p):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, p))
        return "ok"
    except OSError as e:
        return "errno %s" % e.errno
    finally:
        s.close()
while True:
    print("dial peer %s, machine %s" % (dial(name, port), dial("127.0.0.1", local)), flush=True)
    time.sleep(1)
'''

# The one the operator gives its destinations: what it may reach, and whether it does.
OPDIAL = API_CLIENT + r'''
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
code, me = api("GET", "/v0/self")
print("opdial self %d [%s]" % (code, ",".join(me.get("destinations", []))), flush=True)
def dial():
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, port))
        return "ok"
    except OSError as e:
        return "errno %s" % e.errno
    finally:
        s.close()
while True:
    print("opdial dial %s" % dial(), flush=True)
    time.sleep(1)
'''

# One that follows the feed and keeps every host event it reads.
LIFE = API_CLIENT + r'''
import json, os, time
code, ans = api("POST", "/v0/events", {})
place = ans.get("next", 0)
open(os.path.join(os.environ["FFX_DATA"], "ready"), "w").close()
got = []
while True:
    code, ans = api("POST", "/v0/events", {"since": place, "wait": 20})
    for e in (ans or {}).get("events") or []:
        if e.get("event", "").startswith("ext."):
            got.append(e)
            with open(os.path.join(os.environ["FFX_DATA"], "host.json.new"), "w") as f:
                json.dump(got, f)
            os.rename(os.path.join(os.environ["FFX_DATA"], "host.json.new"), os.path.join(os.environ["FFX_DATA"], "host.json"))
    place = (ans or {}).get("next", place)
'''

# The one that unlinks a file while it holds it open: no name for the walk to find, and 2 MiB held all the same.
UNLINKED = r'''
import os, time
d = os.environ["FFX_DATA"]
f = open(os.path.join(d, "gone"), "wb")
os.unlink(os.path.join(d, "gone"))
f.write(b"x" * (2 << 20))
f.flush()
print("holding 2 MiB unlinked", flush=True)
while True:
    time.sleep(1)
'''
# One that keeps the Grbl sender out as it starts.
KEEPOUT = API_CLIENT + r'''
import time
code, ans = api("POST", "/v0/sender", {"out": True})
print("keepout %d %s" % (code, ans), flush=True)
while True:
    time.sleep(1)
'''

# One that polls the host's events when the test says so, and writes down what it was told and when.
EVPOLL = API_CLIENT + r'''
import json, os, time
d = os.environ["FFX_DATA"]
def put(name, v):
    with open(os.path.join(d, name + ".new"), "w") as f:
        json.dump(v, f)
    os.rename(os.path.join(d, name + ".new"), os.path.join(d, name))
def after(name):
    while not os.path.exists(os.path.join(d, name)):
        time.sleep(0.1)
after("go1")
head = api("POST", "/v0/events", {})[1].get("next")
t0 = time.monotonic()
code, ans = api("POST", "/v0/events", {"since": head, "wait": 1})
put("poll1.json", {"code": code, "head": head, "next": ans.get("next"), "events": ans.get("events"),
                   "took": time.monotonic() - t0})
after("go2")
head = api("POST", "/v0/events", {})[1].get("next")
put("polling", {})
code, ans = api("POST", "/v0/events", {"since": head, "wait": 4})
put("poll2.json", {"code": code, "events": ans.get("events"), "at": time.monotonic()})
while True:
    time.sleep(1)
'''

TOKEN = "0123456789abcdef0123456789abcdef"
failures = []
facts = {"armed": False, "controller": "running", "motion": "unverified", "mode": "grbl", "diag": False, "updating": False,
         "down": False, "sender": [], "on_mode": None}
streams = []                                    # each /events stream the stand-in holds: the events it has yet to write
streams_mu = threading.Lock()
asked_mode = []                                 # when each GET /mode came (time.monotonic()): one a turn


def open_streams():
    with streams_mu:
        return len(streams)


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


class Forgectrl(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/events" and not facts["down"] and self.headers.get("X-ForgeFIRM-Client") == "extension-host":
            return self.stream()
        if self.path == "/mode":
            asked_mode.append(time.monotonic())
        if self.path == "/mode" and facts["on_mode"]:
            facts["on_mode"]()                      # the host asks this between its read of the state and its measurement
        body = {"/cool/status": {"armed": facts["armed"]},
                "/mode": {"mode": facts["mode"], "controller": facts["controller"], "motion": facts["motion"]},
                "/status": {"diag": facts["diag"]},
                "/update/status": {"running": facts["updating"]}}.get(self.path)
        if facts["down"] or body is None:
            self.send_error(503 if facts["down"] else 404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def stream(self):
        """The host's slot in forgectrl's event stream: a greeting, then what the test writes, until the host lets go."""
        q = []
        with streams_mu:
            streams.append(q)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"event: hello\ndata: {}\n\n")
            self.wfile.flush()
            while True:
                with streams_mu:
                    out, q[:] = q[:], []
                for name, data in out:
                    self.wfile.write(("event: %s\ndata: %s\n\n" % (name, json.dumps(data))).encode())
                    self.wfile.flush()
                if select.select([self.connection], [], [], 0.1)[0] and not self.connection.recv(1):
                    return
        except OSError:
            return
        finally:
            with streams_mu:
                streams.remove(q)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.split("?")[0] == "/motion/sender" and not facts["down"]:
            ok = self.headers.get("X-ForgeFIRM-Token") == TOKEN
            facts["sender"].append((self.path, ok))
            body, code = ({}, 200) if ok else ({"error": "not the extension host's token"}, 403)
        else:
            body, code = {"error": "the stand-in has no such route"}, 404
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def relays(under):
    """The pids whose standard input is a file under `under`: the init wrapper's logger relays, which hold the
    wrapper's fifo open for reading and writing and so never see its end."""
    pids = []
    for d in os.listdir("/proc"):
        try:
            if d.isdigit() and os.readlink("/proc/%s/fd/0" % d).startswith(under + "/"):
                pids.append(int(d))
        except OSError:
            pass
    return pids


def kill_relays(under):
    for pid in relays(under):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return True


def wait_for(cond, seconds, poll=0.25):
    end = time.time() + seconds
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(poll)
    return None


def opens_of(path):
    """The times (time.monotonic()) at which the directory at path is itself opened, from inotify, kept as they come.
    The host's measurement opens each running service's data directory once a measuring turn, and nothing else opens
    the data directory of a service that does not use it, so these are the host's measurements."""
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    if fd < 0 or libc.inotify_add_watch(fd, os.fsencode(path), 0x20) < 0:     # IN_OPEN
        return None
    times = []

    def read():
        while True:
            data = os.read(fd, 4096)
            now, off = time.monotonic(), 0
            while off + 16 <= len(data):
                mask, length = struct.unpack_from("iIII", data, off)[1::2]
                if mask & 0x20 and length == 0:     # the directory itself, not an entry of it
                    times.append(now)
                off += 16 + length
    threading.Thread(target=read, daemon=True).start()
    return times


def main():
    # Before the namespace and the root gate, so that it runs anywhere: the
    # host's list of environment variables, held to every getenv in the sources.
    print("the start notice's list of environment variables, held to the sources")
    src = os.path.join(HERE, "..", "src")
    names, indirect = set(), set()
    for name in sorted(os.listdir(src)):
        if name.endswith((".c", ".h")):
            text = open(os.path.join(src, name)).read()
            # A read through getenv or secure_getenv names its variable as one string literal, with or without
            # white space around it, in any case. Any other use of either name is a read the list cannot be held
            # to, and fails: a call with any other argument, and the name with no call after it (a macro, a
            # pointer, the name in parentheses). A walk of environ is outside these patterns.
            names.update(re.findall(r'\b(?:secure_)?getenv\s*\(\s*"([^"]+)"\s*\)', text))
            indirect.update(re.findall(r'\b(?:secure_)?getenv\s*\((?!\s*"[^"]+"\s*\)|\s*ENV_OVERRIDES\[)[^)]*\)', text))
            indirect.update(re.findall(r'\b(?:secure_)?getenv\b(?!\s*\()', text))
    table = re.search(r'ENV_OVERRIDES\[\] = \{(.*?)\};', open(os.path.join(src, "run.c")).read(), re.S)
    env_vars = re.findall(r'"([^"]+)"', table.group(1)) if table else []
    check(table is not None, "run.c carries the list")
    check(sorted(env_vars) == sorted(names) and len(env_vars) == len(set(env_vars)),
          "the list is the sources' reads: %s", sorted(names))
    check(not indirect, "every getenv names its variable: %s", sorted(indirect))
    if failures:
        print("FAIL: run_test, the list is not the sources'")
        return 1

    if os.environ.get("FFX_RUN_NS") != "1":
        missing = [t for t in ("unshare", "nsenter", "ip", "mount") if not shutil.which(t)]
        need = {"forgeext": os.path.isfile(FORGEEXT), "fwup": bool(FWUP), "nft": os.path.isfile(NFT), "rules": os.path.isfile(RULES),
                "cgroup v2": os.path.isfile("/sys/fs/cgroup/cgroup.controllers")}
        if os.geteuid() != 0 or missing or not all(need.values()):
            print("skipped: needs root and %s; tools missing: %s" % ([k for k, v in need.items() if not v], missing))
            return SKIP
        os.execvpe("unshare", ["unshare", "-n", "-m", sys.executable, os.path.abspath(__file__)], dict(os.environ, FFX_RUN_NS="1"))

    top = tempfile.mkdtemp(prefix="forgeext-run.")
    os.chmod(top, 0o755)
    root, run_dir, conf, safe = (os.path.join(top, n) for n in ("root", "run", "forgefirm.conf", "ext-safe"))
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    hosts = os.path.join(top, "hosts")
    with open(hosts, "w") as f:
        f.write("127.0.0.1 localhost\n%s peer.test\n192.168.1.20 broker.lan\n" % PEER_ADDR)
    subprocess.run(["mount", "--bind", hosts, "/etc/hosts"], check=True)
    # The peer is the namespace's one resolver, and answers nothing: a name not in hosts is never answered.
    resolv = os.path.join(top, "resolv.conf")
    with open(resolv, "w") as f:
        f.write("nameserver %s\n" % PEER_ADDR)
    subprocess.run(["mount", "--bind", resolv, os.path.realpath("/etc/resolv.conf")], check=True)
    peer = subprocess.Popen(["unshare", "-n", sys.executable, "-u", "-c", PEER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    peer.stdout.readline()
    ns = ["nsenter", "-t", str(peer.pid), "-n"]
    for cmd in (["ip", "link", "add", "ffxr0", "type", "veth", "peer", "name", "ffxr1"], ["ip", "link", "set", "ffxr1", "netns", str(peer.pid)],
                ["ip", "addr", "add", HERE_ADDR + "/24", "dev", "ffxr0"], ["ip", "link", "set", "ffxr0", "up"],
                ns + ["ip", "addr", "add", PEER_ADDR + "/24", "dev", "ffxr1"], ns + ["ip", "link", "set", "ffxr1", "up"],
                ["ip", "route", "add", PEER_ADDR.rsplit(".", 1)[0] + ".0/24", "dev", "ffxr0"],
                ns + ["ip", "route", "add", HERE_ADDR.rsplit(".", 1)[0] + ".0/24", "dev", "ffxr1"]):
        subprocess.run(cmd, check=True, capture_output=True)
    peer.stdin.write("go\n")
    peer.stdin.flush()
    pport = int(peer.stdout.readline())
    subprocess.run([NFT, "-f", RULES], check=True)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Forgectrl)
    fport = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    os.makedirs(CG_PARENT, exist_ok=True)
    with open(CG_PARENT + "/cgroup.subtree_control", "w") as f:
        f.write("+cpu +memory +pids")
    with open(CG_PARENT + "/cpu.idle", "w") as f:       # an idle group, as the image's ffx is
        f.write("1")

    def fx(*args):
        p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "--no-reserve"] + list(args),
                           capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": None, "error": p.stdout[:200] + p.stderr[:200]}

    def package(id_, runtime, files, caps=(), grants=(), args=(), version="1.0.0"):
        d = os.path.join(top, "src-" + id_)
        os.makedirs(os.path.join(d, "bin"), exist_ok=True)
        exe = "bin/run.py" if runtime == "python" else "bin/run.sh"
        m = {"manifest": 1, "id": id_, "name": id_, "version": version, "author": "Test", "license": "MIT", "api": "0.1",
             "runtime": runtime, "service": {"exec": exe, "args": list(args)}, "capabilities": list(caps)}
        with open(os.path.join(d, "manifest.json"), "w") as f:
            f.write(json.dumps(m, indent=1) + "\n")
        with open(os.path.join(d, exe), "w") as f:
            f.write(files)
        os.chmod(os.path.join(d, exe), 0o755)
        out = os.path.join(top, id_ + ".ffx")
        subprocess.run(["sh", MKFFX, d, out], check=True, capture_output=True, env=dict(os.environ, FWUP=FWUP))
        r = fx("install", out, "--consent-unverified", *[a for g in grants for a in ("--grant", g)])
        check(r.get("ok") is True, "installed %s: %s", id_, r.get("error", ""))

    print("four packages")
    package("org.example.beat", "shell", "#!/bin/sh\nwhile true; do echo beat; sleep 1; done\n", caps=["hold"], grants=["hold"])
    # Its second destination has the stand-in forgectrl's port: landlock lets it dial that port anywhere, 127.0.0.1
    # included, and the image's table is what refuses the machine.
    package("org.example.dial", "python", DIAL, caps=["net.outbound:peer.test:%d" % pport, "net.outbound:peer.test:%d" % fport],
            args=["peer.test", str(pport), str(fport)])
    package("org.example.jobtime", "python", JOBTIME, caps=["job_time.run", "machine.read", "hold", "motion.job", "mcode:170"],
            grants=["job_time.run", "hold", "motion.job"])
    package("org.example.crash", "shell", "#!/bin/sh\necho about to end\nexit 3\n", caps=["hold"], grants=["hold"])

    print("the shutdown grace a host test may hold open: never below the machine's 1 s, never past 30 s")
    for v, refused in (("0.5", True), ("30.5", True), ("nan", True), ("4x", True), ("1", False), ("30", False)):
        # A value taken gets as far as the daemon, which stops at once: there is no cgroup parent under this root.
        rc_ = subprocess.run([FORGEEXT, "--root", os.path.join(top, "grace-root"), "run", "--cg-parent",
                              os.path.join(top, "no-cgroup"), "--run-dir", os.path.join(top, "grace-run"),
                              "--shutdown-grace", v], capture_output=True).returncode
        check((rc_ == 2) == refused, "--shutdown-grace %s -> exit %d (2 is the usage's)", v, rc_)

    print("a package's data directory is root's and its group's, 0770, and kept data follows it to another account")

    def slot_of(id_):
        return json.load(open(os.path.join(root, "state.json")))["packages"][id_]["slot"]

    def as_account(uid, fn):
        """fn() run as a pool account: 'ok', or the errno's name."""
        r, w_ = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            word = "ok"
            try:
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
                fn()
            except OSError as e:
                word = errno.errorcode.get(e.errno, str(e.errno))
            os.write(w_, word.encode())
            os._exit(0)
        os.close(w_)
        word = os.read(r, 64).decode()
        os.close(r)
        os.waitpid(pid, 0)
        return word

    kid, taker = "org.example.kept", "org.example.taker"
    package(kid, "shell", "#!/bin/sh\nexit 0\n")
    kdata, k1 = os.path.join(root, "data", kid), 800 + slot_of(kid)
    st_ = os.stat(kdata)
    check((st_.st_uid, st_.st_gid, stat.S_IMODE(st_.st_mode)) == (0, k1, 0o770),
          "installed: root's, its account's group, 0770: %d:%d %o", st_.st_uid, st_.st_gid, stat.S_IMODE(st_.st_mode))
    check(as_account(k1, lambda: os.chmod(kdata, 0o711)) == "EPERM" and as_account(k1 + 1, lambda: os.listdir(kdata)) == "EACCES",
          "the package cannot open its directory to another account, and another account cannot walk into it")
    # What its service would leave: a file, a directory, and a link to a file of the machine's.
    as_account(k1, lambda: (os.makedirs(os.path.join(kdata, "sub")), open(os.path.join(kdata, "sub", "f"), "w").close(),
                            os.symlink("/etc/hostname", os.path.join(kdata, "link"))))
    check(fx("remove", kid, "--keep-data").get("ok") is True and os.path.isdir(kdata), "removed, its data kept")
    package(taker, "shell", "#!/bin/sh\nexit 0\n")
    package(kid, "shell", "#!/bin/sh\nexit 0\n")
    k2 = 800 + slot_of(kid)
    owners = {os.path.relpath(os.path.join(d, n), kdata): (os.lstat(os.path.join(d, n)).st_uid, os.lstat(os.path.join(d, n)).st_gid)
              for d, ds, fs in os.walk(kdata) for n in ds + fs if os.path.join(d, n) != os.path.join(kdata, "tmp")}
    check(slot_of(taker) + 800 == k1 and k2 != k1 and owners and set(owners.values()) == {(k2, k2)}
          and os.stat(kdata).st_gid == k2 and os.stat("/etc/hostname").st_uid == 0,
          "installed again in another account (%d, its old one %d taken): every entry is the new account's, and the link "
          "was not followed: %s", k2, k1, owners)
    for id_ in (kid, taker):
        check(fx("remove", id_).get("ok") is True, "%s removed", id_)

    print("a hold is the operator's to mark, and only where there is one")
    holds_dir, marks, api_dir = os.path.join(top, "holds"), os.path.join(root, "required-holds"), os.path.join(top, "api")
    call_dir = os.path.join(top, "call")
    r = fx("hold", "org.example.dial", "required")
    check(r.get("ok") is False and "has no hold" in r.get("error", ""), "no grant, no hold to mark: %s", r.get("error"))
    r = fx("hold", "org.example.crash", "required")
    check(r.get("ok") is True and os.listdir(marks) == ["org.example.crash"], "marked required, and named for forgectrl: %s %s",
          r.get("error", ""), os.listdir(marks))
    # What each package may use, as the list reports it. The panel's bridge
    # decides on this and the service sees the same answer at GET /v0/self,
    # so the two are checked against each other below.
    eff = {x["id"]: sorted(x.get("effective") or []) for x in fx("list").get("packages", [])}
    check(eff.get("org.example.jobtime") == ["hold", "job_time.run", "machine.read", "mcode:170", "motion.job"],
          "what jobtime may use: %s", eff.get("org.example.jobtime"))
    check(eff.get("org.example.dial") == sorted(["net.outbound:peer.test:%d" % pport, "net.outbound:peer.test:%d" % fport]),
          "what dial may use: %s", eff.get("org.example.dial"))
    listed = {x["id"]: x.get("hold") for x in fx("list").get("packages", [])}
    check(listed == {"org.example.beat": "advisory", "org.example.dial": None, "org.example.jobtime": "advisory",
                     "org.example.crash": "required"}, "the list says which hold is which: %s", listed)

    def held(id_, where=holds_dir):
        """The hold file of a package (or its claim on the sender, in that directory): None, or its fields with the age
        of its timestamp."""
        try:
            with open(os.path.join(where, id_ + ".json")) as f:
                h = json.load(f)
        except (OSError, ValueError):
            return None
        h["age"] = time.monotonic() - h["ts_mono"]
        return h

    abi = int(subprocess.run([sys.executable, "-c", "import ctypes;print(ctypes.CDLL(None).syscall(444,None,0,1))"],
                             capture_output=True, text=True).stdout.strip() or 0)
    with open(conf, "w") as f:
        f.write("ext_enabled=0\n")
    log_path = os.path.join(top, "daemon.log")
    log = open(log_path, "w")
    token_file = os.path.join(top, "host.token")
    with open(token_file, "w") as f:
        f.write(TOKEN + "\n")
    os.chmod(token_file, 0o600)

    daemon_env = dict(os.environ, FFLOG_STDERR="1", FFLOG_SOCK="/nonexistent", FORGEEXT_HOST_TOKEN_FILE=token_file)

    def start_daemon(grace=False):
        """The host; with grace, its shutdown grace held open 4 s for the cases that look inside it, and for the
        host's own stop, which must not take it (the machine's grace is 1 s, which the first daemon keeps)."""
        return subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "run", "--conf", conf, "--safe-file", safe,
                                 "--forgectrl", "127.0.0.1:%d" % fport, "--cg-parent", CG_PARENT, "--run-dir", run_dir,
                                 "--holds-dir", holds_dir, "--api-dir", api_dir, "--call-dir", call_dir]
                                + (["--shutdown-grace", "4"] if grace else []) + (["--landlock-fs-only"] if abi < 4 else []),
                                stderr=log, stdout=log, env=daemon_env)

    daemon = start_daemon()
    wrapper = None

    def status():
        try:
            with open(os.path.join(run_dir, "status.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def svc(id_):
        return next((s for s in status().get("services", []) if s["id"] == id_), {})

    def running():
        return sorted(s["id"] for s in status().get("services", []) if s["state"] == "running")

    def logged(text):
        log.flush()
        return text in open(log_path).read()

    def cg(id_, name):
        try:
            return open("%s/%s/%s" % (CG_PARENT, id_, name)).read()
        except OSError:
            return ""

    try:
        print("off, then not ready")
        check(wait_for(lambda: status().get("pid") == daemon.pid, 10), "the status file names the host that wrote it")
        want = sorted(n for n in env_vars if n in daemon_env)
        check(wait_for(lambda: logged("environment overrides in force: "), 10), "the host names its overrides as it starts")
        line = next((l for l in open(log_path).read().splitlines() if "environment overrides in force: " in l), "")
        named = line.split("environment overrides in force: ", 1)[1].split() if line else []
        check(sorted(named) == want, "names only, the ones set and no other: %s", named)
        check(wait_for(lambda: status().get("off_reason"), 10) and not running(), "off: %s", status().get("off_reason"))
        check(sorted(os.listdir(root)) == ["data", "keys", "lock", "pkg", "required-holds", "settings",
                                           "state.json", "tmp"],
              "the extension root holds what it should and nothing else: %s", sorted(os.listdir(root)))
        check(os.path.isdir(holds_dir) and not os.listdir(holds_dir), "extensions off: no hold has a file: %s",
              os.path.isdir(holds_dir) and os.listdir(holds_dir))
        with open(conf, "w") as f:
            f.write("log_forgeext_disk=info\next_enabled = 1\n")
        check(wait_for(lambda: "motion is unverified" in status().get("not_ready", ""), 10) and not running(),
              "enabled and not ready: %s", status().get("not_ready"))

        print("a root no package account can walk to: the machine is not ready, and nobody is quarantined for it")
        os.chmod(top, 0o700)                            # as an installer under a strict umask leaves a data directory
        facts["motion"] = "verified"
        check(wait_for(lambda: "does not let a package's account through" in status().get("not_ready", ""), 10),
              "the host names the directory: %s", status().get("not_ready"))
        time.sleep(8)
        check(not running() and not any(s_["state"] == "quarantined" for s_ in status().get("services", []))
              and logged("no service can start: " + top), "nothing started, nothing is quarantined, and the log says why once")
        check(open(log_path).read().count("no service can start") == 1, "it is said once, not every second")
        facts["motion"] = "unverified"
        os.chmod(top, 0o755)
        check(wait_for(lambda: "motion is unverified" in status().get("not_ready", ""), 10), "walkable again: %s",
              status().get("not_ready"))

        print("a root mount that is not shared: the machine is not ready")
        # This namespace's mounts are private, as unshare leaves them: a service's namespace would keep a copy of
        # every one of them after it is unmounted. The image makes its root shared before any service starts.
        facts["motion"] = "verified"
        check(wait_for(lambda: "root mount is not shared" in status().get("not_ready", ""), 10) and not running(),
              "this namespace's root is private: %s", status().get("not_ready"))
        subprocess.run(["mount", "--make-rshared", "/"], check=True)
        facts["motion"] = "unverified"
        check(wait_for(lambda: "motion is unverified" in status().get("not_ready", ""), 10), "shared: %s",
              status().get("not_ready"))

        print("ready: one at a time, each in its own account and group")
        t0 = time.time()
        facts["motion"] = "verified"
        stay = ["org.example.beat", "org.example.dial", "org.example.jobtime"]
        first = wait_for(lambda: len(running()) >= 1 and time.time(), 15)
        three = wait_for(lambda: all(s in running() for s in stay) and time.time(), 40)
        check(first and three and 8 <= three - first <= 22,
              "the three that stay up are running, the last %.1f s after the first (the stagger is 5 s, and the one that "
              "keeps ending does not take their turns)", (three or 0) - (first or 0))
        for id_ in ("org.example.beat", "org.example.dial", "org.example.jobtime"):
            s = svc(id_)
            pid = s.get("pid", 0)
            st = open("/proc/%d/status" % pid).read() if pid else ""
            uid = 800 + int(s.get("account", "ffx-800")[3:])
            check(s.get("state") == "running" and ("Uid:\t%d\t%d" % (uid, uid)) in st and "NoNewPrivs:\t1" in st
                  and "Seccomp:\t2" in st and ("/%s" % id_) in open("/proc/%d/cgroup" % pid).read(),
                  "%s runs as %s, confined, in its group", id_, s.get("account"))
        check(wait_for(lambda: logged("ext org.example.beat: beat"), 10), "the heartbeat's output is in the log under its name")
        check(wait_for(lambda: logged("ext org.example.dial: dial peer ok, machine errno %d" % errno.ECONNREFUSED), 15),
              "the dialer reaches its declared destination and not the machine")
        check(cg("org.example.beat", "cpu.max").split() == ["25000", "100000"] and cg("org.example.beat", "pids.max").strip() == "32"
              and cg("org.example.beat", "memory.max").strip() == str(48 << 20),
              "its limits: cpu.max %s pids.max %s memory.max %s", cg("org.example.beat", "cpu.max").strip(),
              cg("org.example.beat", "pids.max").strip(), cg("org.example.beat", "memory.max").strip())

        print("a stop whose process outlives its group's kill holds up nothing of the turn")
        # The heartbeat's main process moved out of its group, as a task the kill does not reach would be: the
        # disable stops the service, its group goes, and the turn goes on without waiting for the process to end.
        bpid = svc("org.example.beat").get("pid", 0)
        side = CG_PARENT + "-side"
        os.makedirs(side, exist_ok=True)
        with open(side + "/cgroup.procs", "w") as f:
            f.write(str(bpid))
        os.kill(bpid, signal.SIGSTOP)                   # asleep, it writes nothing that its closed pipe could end it for
        check(fx("disable", "org.example.beat").get("ok") is True, "the heartbeat disabled")
        went = wait_for(lambda: svc("org.example.beat").get("state") not in (None, "running"), 20)
        lived = os.path.exists("/proc/%d" % bpid)
        try:
            os.kill(bpid, signal.SIGKILL)
        except OSError:
            pass
        # Reaped by the host's loop, with nothing left to match it; the side group goes once the kill has emptied it.
        wait_for(lambda: not open(side + "/cgroup.procs").read().strip(), 10, poll=0.1)
        try:
            os.rmdir(side)
        except OSError:
            pass
        check(went and lived, "the turn went on past a stop whose process outlived its group: %s (alive then: %s)",
              svc("org.example.beat"), lived)
        check(fx("enable", "org.example.beat").get("ok") is True and wait_for(
              lambda: svc("org.example.beat").get("state") == "running", 40), "enabled, the heartbeat runs again")

        print("the API socket: a package's one way to the machine, and the broker behind it")
        jid = "ext org.example.jobtime: "
        check(wait_for(lambda: logged(jid + "api burst"), 40), "the service with the API's use has been through its calls")
        # Its share of the broker: one package holds at most 4 of the 16 connections. Five opened from the heartbeat's
        # account and left silent: the fifth is closed at once, and another package is answered meanwhile.
        buid, duid = (800 + int(svc(i)["account"][3:]) for i in ("org.example.beat", "org.example.dial"))
        r_, w_ = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(r_)
            os.setgroups([])
            os.setgid(buid)
            os.setuid(buid)
            conns = []
            for _ in range(5):
                c = socket.socket(socket.AF_UNIX)
                c.connect(os.path.join(api_dir, "org.example.beat.sock"))
                conns.append(c)
            conns[4].settimeout(2)
            try:
                closed = conns[4].recv(1) == b""
            except OSError:
                closed = False
            os.write(w_, b"1" if closed else b"0")
            time.sleep(3)                               # the four stay open, silent, while the other package is asked
            os._exit(0)
        os.close(w_)
        fifth = os.read(r_, 1)
        os.close(r_)

        def self_of_dial():
            # The dialer's own rate is untouched here, where jobtime's burst has just spent jobtime's.
            c = socket.socket(socket.AF_UNIX)
            c.settimeout(3)
            c.connect(os.path.join(api_dir, "org.example.dial.sock"))
            c.sendall(b"GET /v0/self HTTP/1.1\r\nHost: forgeext\r\n\r\n")
            if not c.recv(64).startswith(b"HTTP/1.1 200"):
                raise OSError(errno.EPROTO, "not answered")

        other = as_account(duid, self_of_dial)
        os.waitpid(child, 0)
        check(fifth == b"1" and other == "ok", "five silent connections from one package: the fifth closed at once (%s), "
              "and another package answered meanwhile (%s)", fifth, other)
        check(",".join(eff["org.example.jobtime"]) == "hold,job_time.run,machine.read,mcode:170,motion.job",
              "the list and the socket must answer alike, and the list says %s", eff["org.example.jobtime"])
        check(logged(jid + "api self 200 org.example.jobtime 0.1 hold,job_time.run,machine.read,mcode:170,motion.job"),
              "GET /v0/self: who it is, the API's version, and what it may use (the grants it got, the capabilities that need none)")
        check(logged(jid + "api mode 200 grbl verified"), "GET /v0/machine/mode: forgectrl's answer, relayed")
        check(logged(jid + "api nowhere 404") and logged(jid + "api bad hold 400"), "a path the API does not have, and a hold in no form")
        check(logged(jid + "api raise 200 {'raised': True, 'reason': 'through the job'}"), "POST /v0/hold: raised, in its words")
        j = wait_for(lambda: (held("org.example.jobtime") or {}).get("raised") and held("org.example.jobtime"), 5)
        check(j and j["required"] is False and j["reason"] == "through the job" and j["age"] < 1.5,
              "and the host keeps it for forgectrl: %s", j)
        check(logged("org.example.jobtime: it raised its hold: through the job"), "the host's log says who raised what")
        burst = [l for l in open(log_path).read().splitlines() if jid + "api burst" in l]
        ok, limited = (int(burst[0].split("api burst ")[1].split()[0]), int(burst[0].split(" ok ")[1].split()[0])) if burst else (0, 0)
        check(ok + limited == 60 and 1 <= limited and ok <= 30, "sixty requests in a row: %d answered, %d told to slow down", ok, limited)
        check(logged("ext org.example.dial: api without the capabilities: mode 403 hold 403 raise 403"),
              "a package that holds neither capability gets 403 three times")

        # motion.job: the program is a file of the package's own data, and
        # the host opens it through a descriptor for that directory. The
        # one that is really there gets as far as the machine (which this
        # stand-in does not serve, so 502); a symbolic link out of the
        # directory and a name with a directory in it never do.
        def job_lines():
            log.flush()
            out = {}
            for line in open(log_path).read().splitlines():
                if jid + "api job " not in line:
                    continue
                rest = line.split("api job ", 1)[1].split(" ", 2)
                out[rest[0]] = (int(rest[1]), rest[2] if len(rest) > 2 else "")
            return out if len(out) == 3 else None

        job = wait_for(job_lines, 15) or {}
        check(set(job) == {"real", "link", "dir"}, "the package did not try all three programs: %s", job)
        check(job.get("real", (0,))[0] != 400, "the file that is there was refused as a program: %s", job.get("real"))
        for what in ("link", "dir"):
            code, words = job.get(what, (0, ""))
            check(code == 400 and "this package's data" in words, "the %s program was not refused in words: %s %s",
                  what, code, words)
        sock = os.path.join(api_dir, "org.example.jobtime.sock")
        st = os.stat(sock)
        juid = 800 + int(svc("org.example.jobtime")["account"][3:])
        check(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660 and (st.st_uid, st.st_gid) == (0, juid),
              "its socket is root's and its account's, 0660: %o %d:%d", stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        check(sorted(os.listdir(api_dir)) == ["org.example.beat.sock", "org.example.dial.sock", "org.example.jobtime.sock"],
              "one socket per running service: %s", sorted(os.listdir(api_dir)))
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(3)
        c.connect(sock)
        try:                                            # the host may close it before the request is even sent
            c.sendall(b"GET /v0/self HTTP/1.1\r\n\r\n")
            got = c.recv(4096)
        except OSError:
            got = b""
        c.close()
        check(got == b"" and wait_for(lambda: logged("a connection to its API socket that is not its account's"), 3),
              "a caller that is not the package's account gets no answer (root here): %r", got[:60])
        open(os.path.join(root, "data", "org.example.jobtime", "clear"), "w").close()
        check(wait_for(lambda: logged(jid + "api clear 200"), 10) and
              wait_for(lambda: (held("org.example.jobtime") or {"raised": True})["raised"] is False, 5),
              "POST /v0/hold with raised false clears it: %s", held("org.example.jobtime"))

        print("the holds: kept by the host, fresh, and failing closed for the one marked required")
        b, c = held("org.example.beat"), None
        check(b and b["required"] is False and b["raised"] is False and b["age"] < 1.5,
              "a running package's advisory hold: clear and fresh: %s", b)
        check(wait_for(lambda: (held("org.example.crash") or {}).get("raised"), 10), "the package that keeps ending has its hold raised")
        c = held("org.example.crash")
        check(c and c["required"] is True and c["age"] < 1.5
              and c["reason"] in ("the extension is not running", "the extension has only just started"),
              "required and not running: raised by the host, in the host's words: %s", c)
        check(sorted(os.listdir(holds_dir)) == ["org.example.beat.json", "org.example.crash.json", "org.example.jobtime.json"],
              "a package without the grant has no file: %s", sorted(os.listdir(holds_dir)))
        ages, clear = [], 0
        for _ in range(8):
            time.sleep(0.4)
            ages.append((held("org.example.beat") or {"age": 99})["age"])
            clear += not (held("org.example.crash") or {}).get("raised")
        check(max(ages) < 1.5, "kept fresh between the host's turns: the oldest of eight looks was %.2f s", max(ages))
        check(clear == 0, "the required hold of the package that ends at every start never reads clear: %d of 8 looks did", clear)
        check(svc("org.example.crash").get("hold") == "required" and svc("org.example.beat").get("hold") == "advisory"
              and "hold" not in svc("org.example.dial"), "the status file says which hold is which")

        print("the armed window")
        facts["armed"] = True
        check(wait_for(lambda: svc("org.example.beat").get("frozen") and svc("org.example.dial").get("frozen"), 6),
              "armed: the services are frozen")
        check("frozen 1" in cg("org.example.beat", "cgroup.events") and "frozen 0" in cg("org.example.jobtime", "cgroup.events")
              and svc("org.example.jobtime").get("job_limited") and cg("org.example.jobtime", "cpu.max").split() == ["3000", "100000"],
              "the kernel agrees, and the one with the grant runs on under job-time limits (cpu.max %s)",
              cg("org.example.jobtime", "cpu.max").strip())
        before = len(running())
        time.sleep(3)
        facts["armed"] = False
        check(wait_for(lambda: not svc("org.example.beat").get("frozen") and "frozen 0" in cg("org.example.beat", "cgroup.events"), 6)
              and cg("org.example.jobtime", "cpu.max").split() == ["25000", "100000"] and len(running()) >= before,
              "disarmed: thawed, and the grant's limits lifted")
        # status.json names an M-code only for a service that answers it: running, with the grant, and not frozen.
        # Its group's cpu.max read-only for one window: the grant's job-time limits cannot be set, the freeze stands
        # in their place, and its code leaves the list until the window closes.
        listed = any(c.get("code") == 170 and c.get("id") == "org.example.jobtime" for c in status().get("mcodes", []))
        jcpu, ro = os.path.join(CG_PARENT, "org.example.jobtime", "cpu.max"), os.path.join(top, "cpu.max.ro")
        with open(ro, "w") as f:
            f.write(open(jcpu).read())
        subprocess.run(["mount", "--bind", ro, jcpu], check=True)
        subprocess.run(["mount", "-o", "remount,bind,ro", jcpu], check=True)
        facts["armed"] = True
        unlisted = wait_for(lambda: svc("org.example.jobtime").get("frozen") and status().get("mcodes") == [], 8)
        facts["armed"] = False
        thawed = wait_for(lambda: not svc("org.example.jobtime").get("frozen"), 8)
        subprocess.run(["umount", jcpu], check=True)
        check(listed and unlisted and thawed and wait_for(lambda: any(c.get("code") == 170 for c in status().get("mcodes", [])), 5),
              "the M-code of the one with the grant is listed, not while it is frozen in place of its limits, and again "
              "after: %s", status().get("mcodes"))
        facts["down"] = True
        check(wait_for(lambda: svc("org.example.beat").get("frozen"), 8) and status().get("armed") is None,
              "forgectrl stops answering: frozen, the window unknown")
        facts["down"] = False
        check(wait_for(lambda: not svc("org.example.beat").get("frozen"), 8), "and thawed when it answers again")

        print("a package keeps the Grbl sender out, by the operator's grant")
        kid, senders_dir = "org.example.keepout", os.path.join(top, "sender-out")     # beside the holds directory
        package(kid, "python", KEEPOUT, caps=["sender.keep_out"], grants=["sender.keep_out"])
        k = wait_for(lambda: (held(kid, senders_dir) or {}).get("raised") and held(kid, senders_dir), 40)
        time.sleep(1.0)
        k2 = held(kid, senders_dir)
        check(k and k["reason"] == "keeps the Grbl sender out" and k["age"] < 1.5 and k2 and k2["raised"] and k2["age"] < 1.5,
              "its claim is kept beside the holds, raised, in the host's words, and fresh a second later: %s %s "
              "(the stand-in was asked %s)", k, k2, facts["sender"])
        r = fx("disable", kid)
        check(r.get("ok") is True and wait_for(lambda: held(kid, senders_dir) is None, 5),
              "disabled, its claim is gone: %s %s", r.get("error", ""), os.listdir(senders_dir))
        check(fx("remove", kid).get("ok") is True, "and it goes")

        print("the machine's events: one stream from forgectrl, held while a package wants it")
        eid = "org.example.events"
        edata = os.path.join(root, "data", eid)

        def jload(name):
            try:
                with open(os.path.join(edata, name)) as f:
                    return json.load(f)
            except (OSError, ValueError):
                return None
        package(eid, "python", EVPOLL, caps=["events"])
        check(wait_for(lambda: (status().get("events") or {}).get("connected") is True
                       and status()["events"].get("wanted", 0) >= 1 and open_streams() == 1, 40),
              "a package wants events: the host holds the stream (%s), and the stand-in has %d open",
              status().get("events"), open_streams())
        open(os.path.join(edata, "go1"), "w").close()
        p1 = wait_for(lambda: jload("poll1.json"), 10) or {}
        check(p1.get("code") == 200 and p1.get("events") == [] and p1.get("next") == p1.get("head")
              and 1.0 <= p1.get("took", 0) < 3, "a poll at the head with wait 1: nothing, and not before that second: %s", p1)
        open(os.path.join(edata, "go2"), "w").close()
        check(wait_for(lambda: jload("polling") is not None, 10), "the package asks again, with a longer wait")
        time.sleep(0.5)
        with streams_mu:
            for q in streams:
                q.append(("lid", {"open": True}))
        wrote = time.monotonic()
        p2 = wait_for(lambda: jload("poll2.json"), 10) or {}
        check(p2.get("code") == 200 and [e.get("event") for e in p2.get("events") or []] == ["lid"]
              and p2.get("at", wrote + 99) - wrote < 1.0,
              "a poll with wait 4 is answered %.2f s after the stand-in writes one event: %s", p2.get("at", wrote) - wrote, p2)
        r = fx("disable", eid)
        check(r.get("ok") is True and wait_for(lambda: status().get("events") == {"connected": False, "wanted": 0}
                                               and open_streams() == 0, 10),
              "disabled, nobody wants events: %s, and the stand-in has %d open", status().get("events"), open_streams())
        check(fx("remove", eid).get("ok") is True, "and it goes")

        print("a killed service comes back; one that keeps ending is quarantined")
        walks = opens_of(os.path.join(root, "data", "org.example.beat"))   # the host's measurements, from here on
        old = svc("org.example.beat")["pid"]
        os.kill(old, signal.SIGKILL)
        check(wait_for(lambda: svc("org.example.beat").get("state") == "running" and svc("org.example.beat")["pid"] != old, 20),
              "the heartbeat is running again with a new pid")
        check(wait_for(lambda: svc("org.example.crash").get("state") == "quarantined", 120, poll=1),
              "the crasher is quarantined: %s", svc("org.example.crash").get("reason"))
        st = json.load(open(os.path.join(root, "state.json")))["packages"]
        check(st["org.example.crash"]["quarantined"] is True and st["org.example.beat"]["quarantined"] is False,
              "state.json remembers it")
        check(logged("ext org.example.crash: about to end"), "its last words are in the log")
        check(not os.path.isdir(CG_PARENT + "/org.example.crash"), "and its group is gone")

        def since(mark, text):
            log.flush()
            return text in open(log_path).read()[mark:]

        def mark():
            log.flush()
            return len(open(log_path).read())

        def pause_clear_of_lock():
            """SIGSTOP the host at a moment it does not hold the root's lock, which it takes every turn to write a
            quarantine it could not write before: the command line can then take the lock while the host is stopped."""
            for _ in range(100):
                os.kill(daemon.pid, signal.SIGSTOP)
                wait_for(lambda: open("/proc/%d/stat" % daemon.pid).read().rsplit(")", 1)[1].split()[0] == "T", 2, poll=0.01)
                with open(os.path.join(root, "lock"), "a") as lf:
                    try:
                        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(lf, fcntl.LOCK_UN)
                        return True
                    except OSError:
                        pass
                os.kill(daemon.pid, signal.SIGCONT)
                time.sleep(0.05)
            return False

        def measuring_turn_hook(act, done):
            """A hook for the stand-in's GET /mode that runs act() inside the turn that measures next, after the host
            has read the state and before it measures. The host's turns are a second apart and it measures every
            10 s: the first question 9.3 s or more after the last measurement comes in one of the turns around 10 s
            after it, and the answer waits until 10.1 s after it, so the turn that asked measures once it has the
            answer. act's result and the time of the answer go into done."""
            once = threading.Lock()

            def hook():
                if not walks or time.monotonic() < walks[-1] + 9.3 or not once.acquire(blocking=False):
                    return
                facts["on_mode"] = None
                due = walks[-1] + 10.1
                done["result"] = act()
                time.sleep(max(0.0, due - time.monotonic()))
                done["at"] = time.monotonic()
            return hook

        print("over its storage quota: set aside, and back once its data is cleared and it is enabled")
        sid = "org.example.store"
        # It closes its standard output and error at once and runs on: the host lets the pipe go at its end rather
        # than waking at every poll on the hang-up, and its own CPU time shows which.
        package(sid, "shell", "#!/bin/sh\nprintf 'its last words, no newline\\007'\nexec >/dev/null 2>&1\n"
                "while true; do sleep 1; done\n", caps=["storage:1", "net.outbound.operator"])
        check(wait_for(lambda: svc(sid).get("state") == "running", 40), "it runs: %s", svc(sid))
        spid = svc(sid).get("pid", 0)

        def cpu_s(pid):
            f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
            return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")

        c0 = cpu_s(daemon.pid)
        time.sleep(3)
        check(cpu_s(daemon.pid) - c0 < 0.5 and logged("ext %s: its last words, no newline?" % sid),
              "a service with its output closed: its last words logged as text, and the host spent %.2f s of CPU in 3 s",
              cpu_s(daemon.pid) - c0)
        # Just after a measurement, so that the next one, 10 s on, comes after the 2 MiB is there.
        check(wait_for(lambda: walks and time.monotonic() < walks[-1] + 5, 15, poll=0.1), "the host measures")
        blocker = os.path.join(root, "state.json.new")
        os.mkdir(blocker)                               # state.json cannot be written while this is there: a full /data, in effect
        big = os.path.join(root, "data", sid, "toobig")
        with open(big, "wb") as f:
            f.write(b"x" * (2 << 20))
        # The operator enables it inside the turn that measures it, after the host has read the state and before the
        # measurement: the quarantine comes after that enable, so the enable does not lift it.
        def enable_unblocked():
            os.rmdir(blocker)                           # for the enable's own write of the state
            r = fx("enable", sid)
            os.mkdir(blocker)
            return r

        enabled = {}
        at = mark()
        facts["on_mode"] = measuring_turn_hook(enable_unblocked, enabled)
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)  # the host measures every 10 s
        facts["on_mode"] = None
        check(q and "may hold" in q.get("reason", "") and not os.path.exists("/proc/%d" % spid),
              "2 MiB where it declares storage:1: stopped and set aside, in words that say what it may hold: %s", q or svc(sid))
        after = wait_for(lambda: next((t for t in walks if t > enabled.get("at", 1e18)), None), 5, poll=0.1)
        between = [t for t in asked_mode if enabled.get("at", 1e18) < t < (after or 0)]
        check((enabled.get("result") or {}).get("ok") is True and after and not between,
              "the operator's enable came inside the turn that set it aside, before its measurement (%.2f s after the "
              "stand-in's answer, and the host asked the mode %d time%s between): %s", (after or 0) - enabled.get("at", 0),
              len(between), "" if len(between) == 1 else "s", enabled.get("result"))

        print("a quarantine the host could not write stays in force, and is written as soon as it can be")

        def remembered(id_=sid):
            return json.load(open(os.path.join(root, "state.json")))["packages"][id_]["quarantined"]

        check(wait_for(lambda: logged("the quarantine could not be written"), 5), "the host says the write failed")
        check(wait_for(lambda: svc(sid).get("state") != "quarantined" or svc(sid).get("pid"), 12, poll=0.5) is None
              and not remembered() and not since(at, "lifted its quarantine"),
              "unwritten for 12 s: still set aside with no process, state.json does not say so, and the enable that came "
              "before the measurement lifted nothing: %s", svc(sid))
        # The way clears, and the operator names a destination for it before the host's next turn: a destination
        # lifts no quarantine, so the host's write lands all the same.
        at = mark()
        paused = pause_clear_of_lock()
        try:
            os.rmdir(blocker)
            r = fx("dest", sid, "add", "%s:41741" % PEER_ADDR) if paused else {"error": "the host held the lock"}
        finally:
            os.kill(daemon.pid, signal.SIGCONT)
        check(r.get("ok") is True and wait_for(remembered, 5) and since(at, "its quarantine is written now")
              and not since(at, "%s: started as" % sid),
              "the way clear and a destination named, the write lands at the next turn and the host says so: %s",
              r.get("error", ""))
        os.unlink(big)
        r = fx("enable", sid)
        check(r.get("ok") is True and wait_for(lambda: svc(sid).get("state") == "running" and svc(sid)["pid"] != spid, 20),
              "its data cleared and enabled again, it runs again: %s %s", r.get("error", ""), svc(sid))

        print("a data directory the host cannot measure is set aside too, and back once it can be; a command holding "
              "the root's lock meanwhile holds up nothing of the host's turn")
        at = mark()
        held_lock = open(os.path.join(root, "lock"), "a")
        fcntl.flock(held_lock, fcntl.LOCK_EX)           # as an install holds it, through fwup, for as long as it takes
        os.makedirs(os.path.join(root, "data", sid, *["d"] * 18))  # deeper than the 16 directories the host walks
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)
        check(q and "could not be measured" in q.get("reason", "") and wait_for(lambda: since(at, "could not be written"), 5),
              "18 directories deep, the root's lock held by another: set aside, in words that say why, and unwritten, "
              "the host's turn not waiting on the lock: %s", q or svc(sid))
        # The operator clears it, then enables it, before the host's next turn: the enable lifts the quarantine the
        # host has not written, and the host does not write it over the enable.
        at = mark()
        held_lock.close()
        paused = pause_clear_of_lock()
        try:
            shutil.rmtree(os.path.join(root, "data", sid, "d"))
            r = fx("enable", sid) if paused else {"error": "the host held the lock"}
        finally:
            os.kill(daemon.pid, signal.SIGCONT)
        looks = []
        ran = wait_for(lambda: looks.append(remembered()) or svc(sid).get("state") == "running", 20, poll=0.2)
        check(r.get("ok") is True and ran and not any(looks) and not since(at, "its quarantine is written now"),
              "cleared and enabled before the host's turn: it runs, and state.json never said quarantined: %s %s %s",
              r.get("error", ""), svc(sid), looks.count(True))

        print("a manifest the host cannot read is set aside too, with the way out that fits it")
        mf, kept = os.path.join(root, "pkg", sid, "current", "manifest.json"), os.path.join(top, "store-manifest.json")
        at = mark()
        os.mkdir(blocker)
        os.rename(mf, kept)
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)
        why = (q or {}).get("reason", "")
        check("manifest could not be read" in why and "remove the package and install it again" in why
              and "clear its data" not in why and wait_for(lambda: since(at, "could not be written"), 5),
              "its manifest gone: set aside, unwritten, and told to remove the package and install it again: %s",
              q or svc(sid))
        os.rename(kept, mf)
        # The operator enables it inside the host's turn, after the host has read the state and before it asks for
        # the quarantine's write again: the write, asked again, finds the enable under the lock and writes nothing.
        lifted, lifting = {}, threading.Lock()

        def enable_before_the_write():
            if not lifting.acquire(blocking=False):
                return
            facts["on_mode"] = None
            os.rmdir(blocker)
            lifted["result"] = fx("enable", sid)

        at = mark()
        facts["on_mode"] = enable_before_the_write
        looks = []
        ran = wait_for(lambda: looks.append(remembered()) or svc(sid).get("state") == "running", 20, poll=0.2)
        facts["on_mode"] = None
        check((lifted.get("result") or {}).get("ok") is True and ran and not any(looks)
              and since(at, "%s: the operator lifted its quarantine before it could be written" % sid)
              and not since(at, "its quarantine is written now"),
              "its manifest back and enabled inside the host's turn, between its read of the state and its write: it "
              "runs, and state.json never said quarantined: %s %s %s", lifted.get("result"), svc(sid), looks.count(True))
        if os.path.isdir(blocker):
            os.rmdir(blocker)

        print("removed inside the turn that measures it: not set aside by the measurement its removal breaks")
        removal = {}
        at = mark()
        facts["on_mode"] = measuring_turn_hook(lambda: fx("remove", sid), removal)
        check(walks is not None and wait_for(lambda: removal.get("at"), 70, poll=0.5),
              "the operator's removal was made inside the host's question: %s", removal)
        facts["on_mode"] = None
        # The host asks the mode once a turn, before it measures: no question between the answer and the
        # measurement puts the two in one turn, the turn whose state was read before the removal.
        after = wait_for(lambda: next((t for t in walks or [] if t > removal.get("at", 1e18)), None), 5, poll=0.1)
        between = [t for t in asked_mode if removal.get("at", 1e18) < t < (after or 0)]
        check(after and not between and (removal.get("result") or {}).get("ok") is True,
              "removed (%s), in a turn that measures, before its measurement (%.2f s after the stand-in's answer, "
              "and the host asked the mode %d time%s between)", removal.get("result"), (after or 0) - removal.get("at", 0),
              len(between), "" if len(between) == 1 else "s")
        gone = wait_for(lambda: not svc(sid), 10)
        log.flush()
        aside = re.findall(r"%s: .*: set aside" % re.escape(sid), open(log_path).read()[at:])
        check(gone and not aside, "it goes, and it was not set aside: %s %s", svc(sid), aside)

        print("a file the service unlinked while it holds it open counts: set aside all the same")
        uid_, at = "org.example.unlinked", mark()
        package(uid_, "python", UNLINKED, caps=["storage:1"])
        check(wait_for(lambda: svc(uid_).get("state") == "running", 40), "it runs: %s", svc(uid_))
        upid = svc(uid_).get("pid", 0)
        os.mkdir(blocker)                               # its quarantine's write fails: the restart below takes it from there
        q = wait_for(lambda: svc(uid_).get("state") == "quarantined" and svc(uid_), 45, poll=1)
        named = [n for n in os.listdir(os.path.join(root, "data", uid_)) if n != "tmp"]   # tmp is the host's, made at every start
        check(q and "may hold" in q.get("reason", "") and not os.path.exists("/proc/%d" % upid) and not named
              and logged("ext %s: holding 2 MiB unlinked" % uid_),
              "2 MiB unlinked and held open where it declares storage:1, nothing named in its data directory (%s): "
              "stopped (pid %d %s) and set aside, in words that say what it may hold: %s", named, upid,
              "gone" if not os.path.exists("/proc/%d" % upid) else "there", q or svc(uid_))
        print("a quarantine the host could not write outlives the host: set aside still after a restart")
        kept = os.path.join(run_dir, "aside", uid_)

        def kept_ones():
            return sorted(os.listdir(os.path.dirname(kept))) if os.path.isdir(os.path.dirname(kept)) else None
        check(wait_for(lambda: since(at, "%s: the quarantine could not be written" % uid_), 10) and not remembered(uid_),
              "the write of the aside fails, and state.json does not say quarantined: %s", svc(uid_))
        check(os.path.isfile(kept) and open(kept).read().split("\n")[1] == svc(uid_).get("reason"),
              "the host keeps the unwritten quarantine under its run directory, with the reason: %s", kept_ones())
        # A second record, for a package that runs, kept under lifts that match no state: the next host takes it up,
        # finds at its first turn that the operator lifted it since, and the record goes with the lift.
        lifted = os.path.join(run_dir, "aside", "org.example.jobtime")
        with open(lifted, "w") as f:
            f.write("ffffffffffffffff\nset aside under lifts that match no state\n")
        daemon.kill()                                   # SIGKILL: no chance to write anything on the way out
        daemon.wait(timeout=10)
        # The state unreadable as the host starts: nothing is taken up, and the kept records wait for the first turn
        # the state reads, where they are taken up ahead of any start.
        state_path, state_kept = os.path.join(root, "state.json"), os.path.join(top, "state.json.kept")
        os.rename(state_path, state_kept)
        with open(state_path, "w") as f:
            f.write("not a state\n")
        at = mark()
        daemon = start_daemon(grace=True)               # it runs through the cases inside the shutdown grace below
        check(wait_for(lambda: status().get("pid") == daemon.pid, 15)
              and wait_for(lambda: since(at, "nothing is changed until it reads"), 10)
              and not since(at, "set aside before the host last stopped") and os.path.isfile(kept) and os.path.isfile(lifted),
              "started on a state it cannot read, the host takes nothing up and leaves the records: %s", kept_ones())
        os.rename(state_kept, state_path)
        check(wait_for(lambda: since(at, "%s: set aside before the host last stopped, and not written" % uid_), 10)
              and not since(at, "%s: started as" % uid_),
              "the state readable, the kept quarantine is taken up at the next turn, ahead of any start")
        check(wait_for(lambda: status().get("pid") == daemon.pid, 15) and since(at, "%s: set aside before the host last "
              "stopped, and not written" % uid_), "the host started again says it took the kept quarantine up")
        check(wait_for(lambda: since(at, "org.example.jobtime: the operator lifted its quarantine before it could be "
                                         "written"), 10)
              and since(at, "org.example.jobtime: set aside before the host last stopped")
              and wait_for(lambda: not os.path.exists(lifted), 5),
              "a kept record the operator lifted since is taken up, let go at the first turn, and dropped with the lift: %s",
              kept_ones())
        # The status the host writes at the end of a turn whose sync could not read the state lists no service at all:
        # the 12 s are counted from a status that lists this one, set aside.
        listed = wait_for(lambda: svc(uid_).get("state") == "quarantined", 10)
        check(listed and wait_for(lambda: svc(uid_).get("state") != "quarantined" or svc(uid_).get("pid"), 12, poll=0.5) is None
              and not remembered(uid_) and not since(at, "%s: started as" % uid_) and "may hold" in svc(uid_).get("reason", ""),
              "unwritten for 12 s under the new host: still set aside with no process and never started, state.json "
              "does not say so, and the reason is the one it was set aside for: %s", svc(uid_))
        os.rmdir(blocker)
        check(wait_for(lambda: remembered(uid_), 5) and since(at, "%s: its quarantine is written now" % uid_)
              and wait_for(lambda: not os.path.exists(kept), 2),
              "the way clear, the write lands at the next turn, the host says so, and the kept copy goes: %s",
              kept_ones())
        check(wait_for(lambda: all(s_ in running() for s_ in ("org.example.beat", "org.example.dial", "org.example.jobtime")), 40),
              "the services the killed host left run again under the new one: %s", running())
        check(fx("remove", uid_).get("ok") is True and wait_for(lambda: not svc(uid_), 10), "and it goes")
        print("removed and installed again inside one turn of the host: started again from the new install")
        old = svc("org.example.beat")["pid"]
        os.kill(daemon.pid, signal.SIGSTOP)             # the host sees neither step alone, only where the two end
        try:
            r1 = fx("remove", "org.example.beat")
            r2 = fx("install", os.path.join(top, "org.example.beat.ffx"), "--consent-unverified", "--grant", "hold")
        finally:
            os.kill(daemon.pid, signal.SIGCONT)
        check(r1.get("ok") is True and r2.get("ok") is True, "removed and installed again: %s %s",
              r1.get("error", ""), r2.get("error", ""))
        check(wait_for(lambda: logged("org.example.beat: stopping (started again: it was installed again, or its "
                                      "destinations changed)"), 10),
              "the host stops the service still running from the install that was removed")
        check(wait_for(lambda: not os.path.exists("/proc/%d" % old), 10), "and it is gone: pid %d", old)
        check(wait_for(lambda: svc("org.example.beat").get("state") == "running"
                       and svc("org.example.beat")["pid"] not in (0, old), 20),
              "the heartbeat runs again, from the new install")

        print("the host's own word on the armed window, to a service with the grant")
        wid = "org.example.watch"
        package(wid, "python", LIFE, caps=["events", "job_time.run"], grants=["job_time.run"])
        check(wait_for(lambda: svc(wid).get("state") == "running" and os.path.exists(os.path.join(root, "data", wid, "ready")),
                       40), "it runs and follows its feed: %s", svc(wid))

        def read(id_):
            try:
                return [e.get("event") for e in json.load(open(os.path.join(root, "data", id_, "host.json")))]
            except (OSError, ValueError):
                return []
        facts["armed"] = True
        check(wait_for(lambda: read(wid) == ["ext.will_freeze"], 10) and svc(wid).get("job_limited") and not svc(wid).get("frozen"),
              "the window opens: it runs on under the grant and reads ext.will_freeze at once: %s %s", read(wid), svc(wid))
        facts["armed"] = False
        check(wait_for(lambda: read(wid) == ["ext.will_freeze", "ext.thawed"], 10), "the window closes: ext.thawed: %s", read(wid))
        check(fx("remove", wid).get("ok") is True and wait_for(lambda: wid not in running(), 10), "and it goes")

        print("the host's own word before it stops a service")
        # The others are out of the way for this one's restarts out of safe mode: started alone, it starts at once.
        for id_ in ("org.example.beat", "org.example.dial", "org.example.jobtime"):
            check(fx("disable", id_).get("ok") is True, "%s disabled for the cases below", id_)
        lid_ = "org.example.life"
        package(lid_, "python", LIFE, caps=["events"])
        check(wait_for(lambda: svc(lid_).get("state") == "running" and os.path.exists(os.path.join(root, "data", lid_, "ready")),
                       40), "it runs and follows its feed: %s", svc(lid_))
        time.sleep(1.0)
        at = mark()
        open(safe, "w").close()
        check(wait_for(lambda: svc(lid_).get("state") != "running", 15), "safe mode stops it: %s", svc(lid_))
        try:
            host = json.load(open(os.path.join(root, "data", lid_, "host.json")))
        except (OSError, ValueError):
            host = []
        check(host and host[0].get("event") == "ext.shutdown"
              and str((host[0].get("data") or {}).get("reason", "")).startswith("safe mode"),
              "it read ext.shutdown, with the reason, before it was stopped: %s", host)
        check(not since(at, "%s: frozen for the armed window" % lid_),
              "nobody is frozen in that last second for a window that is not open")
        os.unlink(safe)
        # Inside the grace (held open here for 4 s, where the machine's is 1 s) an armed window still freezes what is
        # left running, and so does a window that cannot be read: the stand-in not answering. The grace asks for the
        # window on its own (machine_armed), so this is the one case of that question unanswered.
        for what, key in (("an armed window", "armed"), ("a machine that does not answer", "down")):
            check(wait_for(lambda: svc(lid_).get("state") == "running", 40), "out of safe mode it runs again: %s", svc(lid_))
            open(safe, "w").close()
            facts[key] = True
            frozen = wait_for(lambda: "frozen 1" in cg(lid_, "cgroup.events") and svc(lid_).get("state") == "running", 3,
                              poll=0.1)
            check(frozen, "safe mode and %s inside the grace: the service is frozen before it is stopped: %s", what,
                  svc(lid_))
            check(wait_for(lambda: svc(lid_).get("state") != "running", 10), "and stopped at the grace's end: %s", svc(lid_))
            facts[key] = False
            os.unlink(safe)
        check(fx("remove", lid_).get("ok") is True, "and it goes")
        for id_ in ("org.example.beat", "org.example.dial", "org.example.jobtime"):
            check(fx("enable", id_).get("ok") is True, "%s enabled again", id_)

        print("the operator's switch for one package")
        r = fx("disable", "org.example.crash")
        check(r.get("ok") is True and wait_for(lambda: held("org.example.crash") is None, 5) and not os.listdir(marks),
              "disabled: its hold file and its name among the required holds are gone: %s %s", r.get("error", ""), os.listdir(marks))
        check(svc("org.example.crash").get("state") in ("quarantined", "stopped") and not running().count("org.example.crash"),
              "and it does not run: %s", svc("org.example.crash").get("state"))
        r = fx("enable", "org.example.crash")
        st = json.load(open(os.path.join(root, "state.json")))["packages"]["org.example.crash"]
        check(r.get("ok") is True and st["enabled"] is True and st["quarantined"] is False and os.listdir(marks) == ["org.example.crash"],
              "enabled again: out of quarantine, and named among the required holds again: %s", st)
        check(wait_for(lambda: logged("org.example.crash: started as") and
                       open(log_path).read().count("org.example.crash: started as") >= 6, 20),
              "and the host tries it again")
        check(wait_for(lambda: (held("org.example.crash") or {}).get("raised"), 10), "with its required hold raised while it does")
        check(fx("enable", "org.example.nothere").get("ok") is False, "a package that is not installed cannot be enabled")

        print("a package whose current cannot be turned stops its package, not the host")
        # The operator's hand, or a damaged /data: no code path takes a package's tree from under its record. The
        # host's start prepares the root, and its repair of current says so and leaves that package; the host starts
        # and runs the others. Installed disabled here, so that nothing of it is started before its tree goes.
        notree = "org.example.notree"
        package(notree, "shell", "#!/bin/sh\nwhile true; do sleep 1; done\n")
        r = fx("disable", notree)
        shutil.rmtree(os.path.join(root, "pkg", notree))
        check(r.get("ok") is True and wait_for(lambda: svc(notree).get("state") != "running", 10),
              "installed, disabled, and its tree taken by hand: %s %s", r.get("error", ""), svc(notree))
        # A second one the same way, enabled again once the host that would start it is killed below: the next
        # host finds it enabled with no manifest to read, and holds it out in words that say so.
        notree2 = "org.example.notree2"
        package(notree2, "shell", "#!/bin/sh\nwhile true; do sleep 1; done\n")
        r = fx("disable", notree2)
        shutil.rmtree(os.path.join(root, "pkg", notree2))
        check(r.get("ok") is True and wait_for(lambda: svc(notree2).get("state") != "running", 10),
              "a second one, installed, disabled, and its tree taken by hand: %s %s", r.get("error", ""), svc(notree2))

        print("one daemon at a time; a killed daemon's services do not outlive the next one's start")
        check(wait_for(lambda: len(running()) >= 2, 30), "services are running before the daemon is killed: %s", running())
        # not the one that ends at every start: it is out of quarantine again, and its pid is gone before it is looked at
        mine = {s_["id"]: s_["pid"] for s_ in status().get("services", [])
                if s_["state"] == "running" and s_["id"] != "org.example.crash"}
        second = start_daemon()
        rc2 = second.wait(timeout=20)
        check(rc2 == 1 and logged("another extension host holds"), "a second daemon is refused (exit %s)", rc2)
        check(all(os.path.exists("/proc/%d" % pid) for pid in mine.values()) and running(),
              "and the first one's services are untouched by it")
        daemon.kill()
        daemon.wait(timeout=10)
        r = fx("enable", notree2)
        check(r.get("ok") is True, "the second one enabled with no tree, with no host running: %s", r.get("error", ""))
        time.sleep(2.6)
        stale = held("org.example.crash")
        check(stale and stale["age"] > 2.0 and stale["required"], "a killed host's required hold stays and goes stale, which "
              "is what forgectrl holds on: %s", stale)
        alive = [i for i, pid in mine.items() if os.path.exists("/proc/%d" % pid)]
        groups = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "chains", "inet"], capture_output=True, text=True).stdout
        # A service that writes to its log ends at its next line once the host that read the pipe is gone (SIGPIPE, as
        # any program started anew has it); one that writes nothing runs on. Either way its group and its chain stay.
        check(groups and "chain u8" in chains, "a killed daemon leaves its services' groups and their chains in place "
              "(what the sweep is for): groups %s, still running %s", groups, alive)
        with open(conf, "w") as f:
            f.write("ext_enabled=0\n")                    # the next daemon starts nothing: what ends them is the sweep
        at = mark()
        daemon = start_daemon(grace=True)               # its own stop, at the end, waits the machine's second all the same
        check(wait_for(lambda: since(at, "a previous extension host left"), 15), "the next daemon says what it found")
        check(wait_for(lambda: status().get("pid") == daemon.pid, 10), "and the status file is the new host's word")
        check(since(at, "%s: current cannot be turned to 1.0.0" % notree) and daemon.poll() is None
              and svc(notree).get("state") != "running",
              "the package with no tree is said as the host prepares the root, and the host starts without it: %s",
              svc(notree))
        r = fx("remove", notree)
        check(r.get("ok") is True and wait_for(lambda: not svc(notree), 10), "and it goes: %s", r.get("error", ""))
        gone = wait_for(lambda: not any(os.path.exists("/proc/%d" % pid) for pid in mine.values()), 10)
        left = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "chains", "inet"], capture_output=True, text=True).stdout
        check(gone and not left and "chain u8" not in chains, "and what it found is gone: processes %s, groups %s",
              "gone" if gone else "alive", left)
        check(wait_for(lambda: not os.listdir(holds_dir), 5), "extensions off under the new host: every hold file is gone: %s",
              os.listdir(holds_dir))
        with open(conf, "w") as f:
            f.write("ext_enabled=1\n")
        check(wait_for(lambda: len(running()) >= 1, 30), "turned on again, the services start under the new daemon")
        check(wait_for(lambda: svc(notree2).get("reason", "").startswith("its manifest could not be read"), 10)
              and svc(notree2).get("state") == "stopped" and not svc(notree2).get("pid")
              and not since(at, "%s: started as" % notree2) and since(at, "%s: its manifest could not be read" % notree2),
              "the enabled package with no tree is held out, in words that name its manifest, and never started: %s",
              svc(notree2))
        r = fx("remove", notree2)
        check(r.get("ok") is True and wait_for(lambda: not svc(notree2), 10), "and it goes: %s", r.get("error", ""))

        check(wait_for(lambda: held("org.example.crash") is not None, 10), "on again: the required hold has its file again")

        # Room for the starts below, under the cap of four running.
        for id_ in ("org.example.crash", "org.example.dial", "org.example.beat", "org.example.jobtime"):
            check(fx("disable", id_).get("ok") is True, "%s disabled for the cases below", id_)

        print("a predecessor's removal put off by the root's lock is taken up once the lock is let go")
        # Version 2 of a package turns healthy, 60 s after its start, while the test holds the root's lock: the
        # removal of version 1 is put off, and it goes at the first turn after the lock is let go. (That the
        # removal takes only the predecessor of the install it was put off for is super_test's.) The cases below
        # run while it waits; the lock is taken once the unanswered-name case has installed its package, whose own
        # waits need no lock, and 56 s on at the latest.
        loop = "#!/bin/sh\nwhile true; do sleep 1; done\n"
        upd2 = "org.example.updated2"
        package(upd2, "shell", loop, version="1.0.0")
        package(upd2, "shell", loop, version="2.0.0")
        upd2pkg = os.path.join(root, "pkg", upd2)
        # Running before the cases below take the starts.
        check(wait_for(lambda: svc(upd2).get("state") == "running", 30), "version 2 runs: %s", svc(upd2))
        upd_started = time.monotonic()
        upd_result = {}
        lock_free = threading.Event()

        def hold_across_healthy():
            lock_free.wait(max(0.0, upd_started + 56 - time.monotonic()))
            with open(os.path.join(root, "lock"), "a") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX)
                upd_result["held_at"] = time.monotonic() - upd_started
                upd_result["healthy"] = wait_for(lambda: svc(upd2).get("healthy"), 40)
                time.sleep(1.5)                     # past the turn that put the removal off
                upd_result["v1_kept_meanwhile"] = os.path.isdir(os.path.join(upd2pkg, "1.0.0"))
                fcntl.flock(lf, fcntl.LOCK_UN)

        holder = threading.Thread(target=hold_across_healthy, daemon=True)
        holder.start()

        print("destinations the operator names")
        # While the predecessor case waits for its healthy mark (its own thread), with room under the cap.
        oid, where = "org.example.opdial", "%s:%d" % (PEER_ADDR, pport)
        at = mark()
        package(oid, "python", OPDIAL, caps=["net.outbound.operator"], args=[PEER_ADDR, str(pport)])
        check(wait_for(lambda: since(at, "ext %s: opdial self 200 []" % oid), 30),
              "it runs, and may reach nothing: no destination is named")
        check(wait_for(lambda: since(at, "ext %s: opdial dial errno" % oid), 10) and not since(at, "opdial dial ok"),
              "and it does not reach the peer")
        first = svc(oid).get("pid")
        for args, words in (((oid, "add", "127.0.0.1:80"), "is this machine"),
                            ((oid, "add", "peer.test"), "a destination is host:port"),
                            ((oid, "remove", where), "is not one of the destinations"),
                            (("org.example.dial", "add", where), "does not ask for destinations"),
                            (("org.example.nothere", "add", where), "is not installed")):
            r = fx("dest", *args)
            check(r.get("ok") is False and words in r.get("error", ""), "dest %s -> %s", " ".join(args), r.get("error"))
        at = mark()
        r = fx("dest", oid, "add", where)
        check(r.get("ok") is True and r.get("destinations") == [where], "the operator names the peer: %s", r)
        check(fx("dest", oid, "add", where).get("ok") is False, "the same destination twice is refused")
        listed = {x["id"]: x.get("destinations") for x in fx("list").get("packages", [])}
        check(listed.get(oid) == [where] and listed.get("org.example.dial") == [], "the list names them: %s", listed)
        check(wait_for(lambda: since(at, "ext %s: opdial self 200 [%s]" % (oid, where)), 30),
              "it is started again with its new way out, and its own answer names it")
        check(wait_for(lambda: since(at, "ext %s: opdial dial ok" % oid), 10), "and it reaches the peer")
        s = svc(oid)
        check(s.get("state") == "running" and s.get("pid") != first
              and since(at, "%s: stopping (started again: it was installed again, or its destinations changed)" % oid),
              "a new process, said in the log, and no crash: %s", s)
        at = mark()
        r = fx("dest", oid, "remove", where)
        check(r.get("ok") is True and r.get("destinations") == [], "the operator takes it away: %s", r)
        check(wait_for(lambda: since(at, "ext %s: opdial self 200 []" % oid), 30)
              and wait_for(lambda: since(at, "ext %s: opdial dial errno" % oid), 10),
              "started again, it reaches nothing again")
        st = json.load(open(os.path.join(root, "state.json")))["packages"][oid]
        check(st.get("destinations") == [] and not st.get("quarantined"), "state.json: %s", st)
        # A name the operator types may lead into the machine's own network: the operator chose that host.
        at = mark()
        check(fx("dest", oid, "add", "broker.lan:1883").get("ok") is True, "the operator names broker.lan:1883")
        ouid = 800 + int(svc(oid).get("account", "ffx0")[3:])
        check(wait_for(lambda: since(at, "ext %s: opdial self 200 [broker.lan:1883]" % oid), 30)
              and "ip daddr 192.168.1.20 tcp dport 1883 accept" in subprocess.run(
                  [NFT, "list", "chain", "inet", "ffx", "u%d" % ouid], capture_output=True, text=True).stdout,
              "a LAN name the operator typed is taken: started with it, as the address it answers (192.168.1.20)")
        check(fx("remove", oid).get("ok") is True and wait_for(lambda: oid not in running(), 10), "and it goes")

        print("a listener opens only with the operator's grant, read at each start")
        lis = "org.example.listen"
        package(lis, "python", "import json, os, socket, time\ns = socket.socket()\ntry:\n    s.bind(('0.0.0.0', 18765))\n"
                "    word = 'ok'\nexcept OSError as e:\n    word = e.errno\nopen(os.path.join(os.environ['FFX_DATA'], 'bound.%d' % "
                "os.getpid()), 'w').write(json.dumps(word))\nwhile True:\n    time.sleep(1)\n",
                caps=["net.listen:18765"], grants=["net.listen:18765"])

        def bound():
            pid_ = svc(lis).get("pid") or 0
            try:
                return json.load(open(os.path.join(root, "data", lis, "bound.%d" % pid_)))
            except (OSError, ValueError):
                return None

        def listen_rule():
            luid = 800 + int(svc(lis).get("account", "ffx0")[3:])
            return "sport 18765" in subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % luid], capture_output=True,
                                                   text=True).stdout

        check(wait_for(lambda: bound() == "ok", 40) and listen_rule(), "granted: it binds its port, and the table answers "
              "from it: %s", bound())
        check(fx("disable", lis).get("ok") is True and wait_for(lambda: svc(lis).get("state") != "running", 10), "disabled")
        with open(os.path.join(root, "lock"), "a") as lf:  # the record as an install made before the grant existed
            fcntl.flock(lf, fcntl.LOCK_EX)
            sp = os.path.join(root, "state.json")
            state_ = json.load(open(sp))
            state_["packages"][lis]["grants"] = [g for g in state_["packages"][lis]["grants"] if not g.startswith("net.listen")]
            with open(sp + ".test", "w") as f:
                json.dump(state_, f)
            os.rename(sp + ".test", sp)
        check(fx("enable", lis).get("ok") is True, "enabled again, with no grant")
        check(wait_for(lambda: bound() == errno.EACCES, 40) and not listen_rule(),
              "with no grant: its bind is refused (%s) and the table has no rule for the port", bound())
        check(fx("remove", lis).get("ok") is True, "and it goes")

        print("a start the machine is not ready for counts against nobody; one its own files fail is counted")
        tam = "org.example.tampered"
        package(tam, "shell", loop)
        check(wait_for(lambda: svc(tam).get("state") == "running", 40), "it runs: %s", svc(tam))
        check(fx("disable", tam).get("ok") is True and wait_for(lambda: svc(tam).get("state") != "running", 10), "disabled")
        # Its data directory on a full file system (a tmpfs with no inode to spare): the machine's to put right.
        tdata = os.path.join(root, "data", tam)
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64k,nr_inodes=1", "ffx-full", tdata], check=True)
        at = mark()
        check(fx("enable", tam).get("ok") is True, "enabled on a full /data")
        full = wait_for(lambda: since(at, "%s: not started: the machine is not ready for it" % tam), 20)
        check(full and since(at, "No space left on device") and not since(at, "%s: it did not start" % tam),
              "a full /data: not ready, and not counted: %s", svc(tam))
        check(fx("disable", tam).get("ok") is True, "disabled again")
        subprocess.run(["umount", tdata], check=True)
        with open(os.path.join(root, "pkg", tam, "1.0.0", "bin", "run.sh"), "a") as f:
            f.write("# changed by hand\n")
        check(fx("enable", tam).get("ok") is True, "enabled again")
        bad = wait_for(lambda: "did not start" in svc(tam).get("reason", "") and dict(svc(tam)), 20)
        check(bad and "changed since it was installed" in bad.get("reason", "") and "not ready" not in bad.get("reason", ""),
              "its tree changed by hand: a start that fails for the package's own reason, counted toward its quarantine: %s",
              bad or svc(tam))
        check(fx("remove", tam).get("ok") is True, "and it goes")
        # The same LAN name the operator may type, named in a manifest: refused, the machine's to put right.
        lan = "org.example.lanname"
        at = mark()
        package(lan, "python", "import time\nwhile True:\n    time.sleep(1)\n", caps=["net.outbound:broker.lan:1883"])
        check(wait_for(lambda: since(at, "%s: not started: the machine is not ready for it (broker.lan answers "
                                         "192.168.1.20, a private or local address" % lan), 30),
              "a LAN name in a manifest is refused: %s", svc(lan))
        check(fx("remove", lan).get("ok") is True, "and it goes")
        # The namespace's resolver takes every query and answers none. The start is put off while the name is looked
        # up (the turn goes on), and not ready once the lookup has had its 5 s; never counted. Once the package is
        # installed these waits need no lock, so the predecessor case's hold of the root's lock runs over them.
        una = "org.example.unanswered"
        at = mark()
        package(una, "python", "import time\nwhile True:\n    time.sleep(1)\n", caps=["net.outbound:nowhere.test:443"])
        lock_free.set()
        looking = wait_for(lambda: "not started yet: looking up nowhere.test" in svc(una).get("reason", ""), 30, poll=0.1)
        unanswered = wait_for(lambda: since(at, "%s: not started: the machine is not ready for it (cannot resolve "
                                                "nowhere.test: the resolver did not answer in 5 s)" % una), 30)
        state_ = svc(una)
        check(looking and unanswered and state_.get("state") == "waiting" and not since(at, "%s: it did not start" % una)
              and json.load(open(os.path.join(root, "state.json")))["packages"][una]["quarantined"] is False,
              "a name the resolver never answers: put off while it is looked up, then not ready, never counted: %s, %s, %s",
              looking, unanswered, state_)

        holder.join(timeout=100)
        check(not holder.is_alive() and upd_result.get("healthy") and upd_result.get("v1_kept_meanwhile"),
              "version 2 healthy under the held lock, its predecessor's removal put off: %s", upd_result)
        check(wait_for(lambda: not os.path.isdir(os.path.join(upd2pkg, "1.0.0")), 5)
              and os.path.isdir(os.path.join(upd2pkg, "2.0.0")),
              "the lock let go, the removal put off is taken up: version 1 goes, version 2 stays: %s",
              sorted(os.listdir(upd2pkg)))
        check(fx("remove", una).get("ok") is True and fx("remove", upd2).get("ok") is True, "and they go")
        for id_ in ("org.example.crash", "org.example.dial", "org.example.beat", "org.example.jobtime"):
            check(fx("enable", id_).get("ok") is True, "%s enabled again", id_)

        print("safe mode, and the end")
        open(safe, "w").close()
        check(wait_for(lambda: not running() and "safe mode" in status().get("off_reason", ""), 10), "safe mode stops everything")
        check(wait_for(lambda: not os.listdir(holds_dir), 5), "and ends every hold: %s", os.listdir(holds_dir))
        left = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "table", "inet", "ffx"], capture_output=True, text=True).stdout
        check(not left and "chain u8" not in chains, "no group and no chain stays behind: %s", left)
        os.unlink(safe)
        check(wait_for(lambda: len(running()) >= 1, 20), "out of safe mode they start again")
        t_term = time.monotonic()
        daemon.send_signal(signal.SIGTERM)
        rc = daemon.wait(timeout=30)
        took = time.monotonic() - t_term
        left = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "table", "inet", "ffx"], capture_output=True, text=True).stdout
        check(rc == 0 and not left and "chain u8" not in chains and not running(),
              "SIGTERM: exit %s, groups left %s, the status says nothing runs", rc, left)
        # No turn runs in the host's own last wait, so it is the machine's second, whatever its grace (4 s here) says.
        check(1.0 <= took < 3.0, "its own stop waited the machine's second, not its grace: %.1f s", took)
        check(not os.listdir(api_dir), "and no API socket: %s", os.listdir(api_dir))
        check(os.listdir(holds_dir) == ["org.example.crash.json"], "a clean stop takes the advisory hold's file and leaves the "
              "required one to go stale: %s", os.listdir(holds_dir))
        r = fx("remove", "org.example.crash")
        check(r.get("ok") is True and not os.listdir(marks), "removing the package takes its name out of the required holds: %s",
              os.listdir(marks))

        print("under the init script's wrapper: a killed host takes its services with it, and the wrapper starts it again")
        # The wrapper's own text, from the init script: the -c body, expanded with this run's daemon, fifo and pool the way
        # the script's double quotes expand it. The daemon is a launcher that execs forgeext with this run's options and
        # the wrapper's own "run"; the host is told nothing about Landlock, as on the machine.
        with open(os.path.join(HERE, "..", "init", "forgeext.init")) as f:
            body = re.search(r'-x /bin/sh -- -c "((?:[^"\\]|\\.)*)"', f.read(), re.S)
        check(body, "the init script carries its wrapper")
        launcher, fifo, script = (os.path.join(top, n) for n in ("forgeext-run", "forgeext.stderr", "wrapper.sh"))
        with open(launcher, "w") as f:
            f.write("#!/bin/sh\nexec env FFLOG_STDERR=1 FFLOG_SOCK=/nonexistent FORGEEXT_HOST_TOKEN_FILE=%s %s --root %s "
                    "--fwup %s --nft %s \"$@\" --conf %s --safe-file %s --forgectrl 127.0.0.1:%d --cg-parent %s "
                    "--run-dir %s --holds-dir %s --api-dir %s --call-dir %s\n"
                    % (shlex.quote(token_file), shlex.quote(FORGEEXT), shlex.quote(root), shlex.quote(FWUP),
                       shlex.quote(NFT), shlex.quote(conf), shlex.quote(safe), fport, shlex.quote(CG_PARENT),
                       shlex.quote(run_dir), shlex.quote(holds_dir), shlex.quote(api_dir), shlex.quote(call_dir)))
        os.chmod(launcher, 0o755)
        os.mkfifo(fifo, 0o600)
        with open(script, "w") as f:
            f.write("DAEMON=%s\nFIFO=%s\nPOOL=%s\nexec /bin/sh -c \"%s\"\n"
                    % (shlex.quote(launcher), shlex.quote(fifo), shlex.quote(CG_PARENT), body.group(1) if body else ""))
        wrapper = subprocess.Popen(["/bin/sh", script], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        beat = "org.example.beat"
        check(wait_for(lambda: svc(beat).get("state") == "running" and os.path.exists("/proc/%d" % status().get("pid", 0)), 40),
              "the host under the wrapper runs the heartbeat: %s", svc(beat))
        host1, beat1 = status().get("pid", 0), svc(beat).get("pid", 0)
        os.kill(host1, signal.SIGKILL)
        check(beat1 > 0 and wait_for(lambda: not os.path.exists("/proc/%d" % beat1), 2, poll=0.05),
              "the host killed (pid %d), its service (pid %d) is gone at once", host1, beat1)
        check(wait_for(lambda: status().get("pid") not in (None, host1) and os.path.exists("/proc/%d" % status()["pid"]), 20),
              "the wrapper starts the host again: pid %s, was %d", status().get("pid"), host1)
        check(wait_for(lambda: svc(beat).get("state") == "running" and svc(beat).get("pid") not in (None, beat1), 40),
              "and the heartbeat runs again under a new pid: %s, was %d", svc(beat).get("pid"), beat1)
        host2 = status().get("pid", 0)
        os.kill(host2, signal.SIGTERM)                  # a stray TERM of the host, not of its wrapper: it ends with 0
        check(wait_for(lambda: status().get("pid") not in (None, host2) and os.path.exists("/proc/%d" % status()["pid"]), 30),
              "a host ended by a TERM of its own (pid %d) is started again by the wrapper: pid %s", host2, status().get("pid"))
        host2 = status().get("pid", 0)
        wrapper.send_signal(signal.SIGTERM)
        wrapper.wait(timeout=10)
        check(wait_for(lambda: not os.path.exists("/proc/%d" % host2), 30)
              and wait_for(lambda: not [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))], 10),
              "stopping the wrapper stops the host (pid %d) and its services: groups %s", host2,
              [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))])
        print("the init script itself: a second start, a stray TERM of the host, a stop with the wrapper gone")
        # The script with its four paths moved under this run, and a stand-in for the host that sleeps until a TERM.
        idir = os.path.join(top, "init")
        os.makedirs(os.path.join(idir, "pool"))
        with open(os.path.join(idir, "host.c"), "w") as f:
            f.write("#include <signal.h>\n#include <unistd.h>\nstatic void done(int s) { (void)s; _exit(0); }\n"
                    "int main(void) { signal(SIGTERM, done); for (;;) pause(); }\n")
        stand_in = os.path.join(idir, "forgeext")
        built = subprocess.run(["cc", "-o", stand_in, os.path.join(idir, "host.c")], capture_output=True).returncode == 0
        script_ = open(os.path.join(HERE, "..", "init", "forgeext.init")).read()
        for name, value in (("DAEMON", stand_in), ("PIDFILE", os.path.join(idir, "forgeext.pid")),
                            ("FIFO", os.path.join(idir, "forgeext.stderr")), ("POOL", os.path.join(idir, "pool"))):
            script_ = re.sub(r"(?m)^%s=.*$" % name, "%s=%s" % (name, value), script_)
        init_sh = os.path.join(idir, "forgeext.init")
        with open(init_sh, "w") as f:
            f.write(script_)

        def stand_ins():
            pids = []
            for d in os.listdir("/proc"):
                try:
                    if d.isdigit() and os.readlink("/proc/%s/exe" % d) == stand_in:
                        pids.append(int(d))
                except OSError:
                    pass
            return pids

        def fifo_inode():
            try:
                return os.stat(os.path.join(idir, "forgeext.stderr")).st_ino
            except OSError:
                return None

        def init(*args):
            return subprocess.run(["sh", init_sh] + list(args), capture_output=True, text=True, timeout=40).stdout

        init("start")
        h1 = wait_for(lambda: stand_ins(), 10) or []
        ino1 = fifo_inode()
        said = init("start")
        check(built and h1 and "already running" in said and fifo_inode() == ino1 and stand_ins() == h1,
              "a second start finds the wrapper and touches nothing: %r, fifo %s then %s, host %s then %s", said.strip(),
              ino1, fifo_inode(), h1, stand_ins())
        if h1:
            os.kill(h1[0], signal.SIGTERM)
        h2 = wait_for(lambda: [p for p in stand_ins() if p not in h1], 15) or []
        check(h2, "a stray TERM of the host: the wrapper starts it again: %s", stand_ins())
        try:
            os.kill(int(open(os.path.join(idir, "forgeext.pid")).read()), signal.SIGKILL)  # the wrapper gone, its host left
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
        t_stop = time.monotonic()
        init("stop")
        check(not stand_ins() and time.monotonic() - t_stop < 10, "a stop with the wrapper gone sends the host its TERM: "
              "%s left after %.1f s", stand_ins(), time.monotonic() - t_stop)
        for p_ in stand_ins():
            os.kill(p_, signal.SIGKILL)
        # The killed wrapper's logger relay holds its fifo open and so outlives it: the test ends it.
        kill_relays(idir)
        check(wait_for(lambda: not relays(idir), 5), "the killed wrapper's relay is ended: %s", relays(idir))
        print("the whole run took %.0f s" % (time.time() - t0))
    finally:
        kill_relays(top)                                # a logger relay a wrapper left, on any path out
        if daemon.poll() is None:
            daemon.kill()
        if wrapper is not None and wrapper.poll() is None:
            wrapper.send_signal(signal.SIGTERM)
            try:
                wrapper.wait(timeout=10)
            except subprocess.TimeoutExpired:
                wrapper.kill()
        log.close()
        if failures:
            print("---- the daemon's log, its end ----")
            print("".join(open(log_path).readlines()[-40:]))
        for d in os.listdir(CG_PARENT) if os.path.isdir(CG_PARENT) else []:
            p = os.path.join(CG_PARENT, d)
            if os.path.isdir(p):
                try:
                    open(p + "/cgroup.kill", "w").write("1")
                    time.sleep(0.3)
                    os.rmdir(p)
                except OSError:
                    pass
        for g in (CG_PARENT + "-side", CG_PARENT):
            try:
                if g.endswith("-side") and os.path.isdir(g):
                    open(g + "/cgroup.kill", "w").write("1")
                    time.sleep(0.3)
                os.rmdir(g)
            except OSError:
                pass
        peer.stdin.close()
        server.shutdown()
        shutil.rmtree(top, ignore_errors=True)
    print("%s: run_test, %d failure%s" % ("FAIL" if failures else "PASS", len(failures), "" if len(failures) == 1 else "s"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
