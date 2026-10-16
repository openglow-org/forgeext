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
remembers it. One that holds more than its storage capability asks for, or
whose data directory the host cannot measure, is set aside, in words that
say why, and runs again once its data is cleared and the operator enables
it; a quarantine the host could not write holds all the same, and is
written as soon as it can be. One whose manifest cannot be read is set
aside too, with the way out that fits it: remove the package and install
it again. A package the operator removes inside the turn that measures
it, after the host has read the state and before it measures, is not set
aside by the measurement its removal breaks. A package granted
sender.keep_out that asks to keep the Grbl sender out has its claim kept
fresh beside the holds, until it is disabled.
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

Needs root, cgroup v2, nft, ip, nsenter, unshare, fwup (FWUP), the built
forgeext (FORGEEXT), and the rule file (FFX_RULES). Exits 77 without them.
"""
import ctypes
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
HERE_ADDR, PEER_ADDR = "10.99.2.1", "10.99.2.2"
SKIP = 77

PEER = r'''
import socket, sys, threading
print("pid", flush=True)
sys.stdin.readline()
s = socket.socket()
s.bind(("%s", 0))
s.listen(128)
def take():
    while True:
        c, _ = s.accept()
        c.close()
threading.Thread(target=take, daemon=True).start()
print(s.getsockname()[1], flush=True)
sys.stdin.readline()
''' % PEER_ADDR

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
            names.update(re.findall(r'\bgetenv\(\s*"([A-Z][A-Z0-9_]*)"\s*\)', text))
            indirect.update(re.findall(r'\bgetenv\(\s*(?!"|ENV_OVERRIDES\[)[^)]*\)', text))
    table = re.search(r'ENV_OVERRIDES\[\] = \{(.*?)\};', open(os.path.join(src, "run.c")).read(), re.S)
    env_vars = re.findall(r'"([A-Z][A-Z0-9_]*)"', table.group(1)) if table else []
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
        f.write("127.0.0.1 localhost\n%s peer.test\n" % PEER_ADDR)
    subprocess.run(["mount", "--bind", hosts, "/etc/hosts"], check=True)
    peer = subprocess.Popen(["unshare", "-n", sys.executable, "-u", "-c", PEER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    peer.stdout.readline()
    ns = ["nsenter", "-t", str(peer.pid), "-n"]
    for cmd in (["ip", "link", "add", "ffxr0", "type", "veth", "peer", "name", "ffxr1"], ["ip", "link", "set", "ffxr1", "netns", str(peer.pid)],
                ["ip", "addr", "add", HERE_ADDR + "/24", "dev", "ffxr0"], ["ip", "link", "set", "ffxr0", "up"],
                ns + ["ip", "addr", "add", PEER_ADDR + "/24", "dev", "ffxr1"], ns + ["ip", "link", "set", "ffxr1", "up"]):
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

    def fx(*args):
        p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "--no-reserve"] + list(args),
                           capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": None, "error": p.stdout[:200] + p.stderr[:200]}

    def package(id_, runtime, files, caps=(), grants=(), args=()):
        d = os.path.join(top, "src-" + id_)
        os.makedirs(os.path.join(d, "bin"))
        exe = "bin/run.py" if runtime == "python" else "bin/run.sh"
        m = {"manifest": 1, "id": id_, "name": id_, "version": "1.0.0", "author": "Test", "license": "MIT", "api": "0.1",
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
    package("org.example.dial", "python", DIAL, caps=["net.outbound:peer.test:%d" % pport], args=["peer.test", str(pport), str(fport)])
    package("org.example.jobtime", "python", JOBTIME, caps=["job_time.run", "machine.read", "hold", "motion.job"],
            grants=["job_time.run", "hold", "motion.job"])
    package("org.example.crash", "shell", "#!/bin/sh\necho about to end\nexit 3\n", caps=["hold"], grants=["hold"])

    print("a hold is the operator's to mark, and only where there is one")
    holds_dir, marks, api_dir = os.path.join(top, "holds"), os.path.join(root, "required-holds"), os.path.join(top, "api")
    r = fx("hold", "org.example.dial", "required")
    check(r.get("ok") is False and "has no hold" in r.get("error", ""), "no grant, no hold to mark: %s", r.get("error"))
    r = fx("hold", "org.example.crash", "required")
    check(r.get("ok") is True and os.listdir(marks) == ["org.example.crash"], "marked required, and named for forgectrl: %s %s",
          r.get("error", ""), os.listdir(marks))
    # What each package may use, as the list reports it. The panel's bridge
    # decides on this and the service sees the same answer at GET /v0/self,
    # so the two are checked against each other below.
    eff = {x["id"]: sorted(x.get("effective") or []) for x in fx("list").get("packages", [])}
    check(eff.get("org.example.jobtime") == ["hold", "job_time.run", "machine.read", "motion.job"],
          "what jobtime may use: %s", eff.get("org.example.jobtime"))
    check(eff.get("org.example.dial") == ["net.outbound:peer.test:%d" % pport],
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

    def start_daemon():
        return subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "run", "--conf", conf, "--safe-file", safe,
                                 "--forgectrl", "127.0.0.1:%d" % fport, "--cg-parent", CG_PARENT, "--run-dir", run_dir,
                                 "--holds-dir", holds_dir, "--api-dir", api_dir]
                                + (["--landlock-fs-only"] if abi < 4 else []),
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
        check(sorted(named) == want and all(re.fullmatch(r"[A-Z][A-Z0-9_]*", n) for n in named),
              "names only, the ones set and no other: %s", named)
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
        check(wait_for(lambda: logged("ext org.example.dial: dial peer ok, machine errno"), 15),
              "the dialer reaches its declared destination and not the machine")
        check(cg("org.example.beat", "cpu.max").split() == ["25000", "100000"] and cg("org.example.beat", "pids.max").strip() == "32"
              and cg("org.example.beat", "memory.max").strip() == str(48 << 20),
              "its limits: cpu.max %s pids.max %s memory.max %s", cg("org.example.beat", "cpu.max").strip(),
              cg("org.example.beat", "pids.max").strip(), cg("org.example.beat", "memory.max").strip())

        print("the API socket: a package's one way to the machine, and the broker behind it")
        jid = "ext org.example.jobtime: "
        check(wait_for(lambda: logged(jid + "api burst"), 40), "the service with the API's use has been through its calls")
        check(",".join(eff["org.example.jobtime"]) == "hold,job_time.run,machine.read,motion.job",
              "the list and the socket must answer alike, and the list says %s", eff["org.example.jobtime"])
        check(logged(jid + "api self 200 org.example.jobtime 0.1 hold,job_time.run,machine.read,motion.job"),
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
        check(ok + limited == 60 and 1 <= limited and ok <= 30, "sixty requests at once: %d answered, %d told to slow down", ok, limited)
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
        c.sendall(b"GET /v0/self HTTP/1.1\r\n\r\n")
        try:
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

        print("over its storage quota: set aside, and back once its data is cleared and it is enabled")
        sid = "org.example.store"
        package(sid, "shell", "#!/bin/sh\nwhile true; do sleep 1; done\n", caps=["storage:1"])
        check(wait_for(lambda: svc(sid).get("state") == "running", 40), "it runs: %s", svc(sid))
        spid = svc(sid).get("pid", 0)
        blocker = os.path.join(root, "state.json.new")
        os.mkdir(blocker)                               # state.json cannot be written while this is there: a full /data, in effect
        big = os.path.join(root, "data", sid, "toobig")
        with open(big, "wb") as f:
            f.write(b"x" * (2 << 20))
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)  # the host measures every 30 s
        check(q and "may hold" in q.get("reason", "") and not os.path.exists("/proc/%d" % spid),
              "2 MiB where it declares storage:1: stopped and set aside, in words that say what it may hold: %s", q or svc(sid))

        print("a quarantine the host could not write stays in force, and is written as soon as it can be")

        def remembered():
            return json.load(open(os.path.join(root, "state.json")))["packages"][sid]["quarantined"]

        check(wait_for(lambda: logged("the quarantine could not be written"), 5), "the host says the write failed")
        check(wait_for(lambda: svc(sid).get("state") != "quarantined" or svc(sid).get("pid"), 12, poll=0.5) is None
              and not remembered(), "unwritten for 12 s: still set aside with no process, and state.json does not say so: %s",
              svc(sid))
        os.rmdir(blocker)
        check(wait_for(remembered, 5) and logged("its quarantine is written now"),
              "the way clear, the write lands at the next turn and the host says so")
        os.unlink(big)
        r = fx("enable", sid)
        check(r.get("ok") is True and wait_for(lambda: svc(sid).get("state") == "running" and svc(sid)["pid"] != spid, 20),
              "its data cleared and enabled again, it runs again: %s %s", r.get("error", ""), svc(sid))

        print("a data directory the host cannot measure is set aside too, and back once it can be")
        os.makedirs(os.path.join(root, "data", sid, *["d"] * 18))  # deeper than the 16 directories the host walks
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)
        check(q and "could not be measured" in q.get("reason", ""),
              "18 directories deep: set aside, in words that say why: %s", q or svc(sid))
        shutil.rmtree(os.path.join(root, "data", sid, "d"))
        r = fx("enable", sid)
        check(r.get("ok") is True and wait_for(lambda: svc(sid).get("state") == "running", 20),
              "measurable again and enabled: it runs: %s %s", r.get("error", ""), svc(sid))

        print("a manifest the host cannot read is set aside too, with the way out that fits it")
        walks = opens_of(os.path.join(root, "data", "org.example.beat"))   # the host's measurements, from here on
        mf, kept = os.path.join(root, "pkg", sid, "current", "manifest.json"), os.path.join(top, "store-manifest.json")
        os.rename(mf, kept)
        q = wait_for(lambda: svc(sid).get("state") == "quarantined" and svc(sid), 45, poll=1)
        why = (q or {}).get("reason", "")
        check("manifest could not be read" in why and "remove the package and install it again" in why
              and "clear its data" not in why,
              "its manifest gone: set aside, and told to remove the package and install it again: %s", q or svc(sid))
        os.rename(kept, mf)
        r = fx("enable", sid)
        check(r.get("ok") is True and wait_for(lambda: svc(sid).get("state") == "running", 20),
              "its manifest back and enabled: it runs: %s %s", r.get("error", ""), svc(sid))

        print("removed inside the turn that measures it: not set aside by the measurement its removal breaks")
        removal, removing = {}, threading.Lock()

        def remove_in_measuring_turn():
            # The first question about the mode 29.3 s after a measurement is asked in the turn that measures
            # next, after the host has read the state; the measurement waits for the answer.
            if not walks or time.monotonic() < walks[-1] + 29.3 or not removing.acquire(blocking=False):
                return
            facts["on_mode"] = None
            removal["result"] = fx("remove", sid)
            time.sleep(0.5)
            removal["at"] = time.monotonic()

        at = mark()
        facts["on_mode"] = remove_in_measuring_turn
        check(walks is not None and wait_for(lambda: removal.get("at"), 70, poll=0.5),
              "the operator's removal was made inside the host's question: %s", removal)
        facts["on_mode"] = None
        after = wait_for(lambda: next((t for t in walks or [] if t > removal.get("at", 1e18)), None), 5, poll=0.1)
        check(after and after - removal["at"] < 0.9 and (removal.get("result") or {}).get("ok") is True,
              "removed (%s), in a turn that measures, before its measurement (%.2f s after the removal)",
              removal.get("result"), (after or 0) - removal.get("at", 0))
        check(wait_for(lambda: not svc(sid), 10) and not since(at, "%s: its manifest could not be read" % sid)
              and not since(at, "%s: its data directory could not be measured" % sid),
              "it goes, and it was not set aside: %s", svc(sid))

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

        print("destinations the operator names")
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
        check(fx("remove", oid).get("ok") is True and wait_for(lambda: oid not in running(), 10), "and it goes")

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
        check(fx("remove", lid_).get("ok") is True, "and it goes")
        check(wait_for(lambda: all(s_ in running() for s_ in ("org.example.beat", "org.example.dial", "org.example.jobtime")),
                       40), "out of safe mode the others run again: %s", running())

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
        time.sleep(2.6)
        stale = held("org.example.crash")
        check(stale and stale["age"] > 2.0 and stale["required"], "a killed host's required hold stays and goes stale, which "
              "is what forgectrl holds on: %s", stale)
        alive = [i for i, pid in mine.items() if os.path.exists("/proc/%d" % pid)]
        chains = subprocess.run([NFT, "list", "chains", "inet"], capture_output=True, text=True).stdout
        check(alive and "chain u8" in chains, "a killed daemon leaves its services running and their chains in place "
              "(what the sweep is for): alive %s", alive)
        with open(conf, "w") as f:
            f.write("ext_enabled=0\n")                    # the next daemon starts nothing: what ends them is the sweep
        daemon = start_daemon()
        check(wait_for(lambda: logged("a previous extension host left"), 15), "the next daemon says what it found")
        check(wait_for(lambda: status().get("pid") == daemon.pid, 10), "and the status file is the new host's word")
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

        check(wait_for(lambda: held("org.example.crash") is not None, 10), "on again: the required hold has its file again")

        print("safe mode, and the end")
        open(safe, "w").close()
        check(wait_for(lambda: not running() and "safe mode" in status().get("off_reason", ""), 10), "safe mode stops everything")
        check(wait_for(lambda: not os.listdir(holds_dir), 5), "and ends every hold: %s", os.listdir(holds_dir))
        left = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "table", "inet", "ffx"], capture_output=True, text=True).stdout
        check(not left and "chain u8" not in chains, "no group and no chain stays behind: %s", left)
        os.unlink(safe)
        check(wait_for(lambda: len(running()) >= 1, 20), "out of safe mode they start again")
        daemon.send_signal(signal.SIGTERM)
        rc = daemon.wait(timeout=30)
        left = [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))]
        chains = subprocess.run([NFT, "list", "table", "inet", "ffx"], capture_output=True, text=True).stdout
        check(rc == 0 and not left and "chain u8" not in chains and not running(),
              "SIGTERM: exit %s, groups left %s, the status says nothing runs", rc, left)
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
                    "--run-dir %s --holds-dir %s --api-dir %s\n"
                    % (shlex.quote(token_file), shlex.quote(FORGEEXT), shlex.quote(root), shlex.quote(FWUP),
                       shlex.quote(NFT), shlex.quote(conf), shlex.quote(safe), fport, shlex.quote(CG_PARENT),
                       shlex.quote(run_dir), shlex.quote(holds_dir), shlex.quote(api_dir)))
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
        wrapper.send_signal(signal.SIGTERM)
        wrapper.wait(timeout=10)
        check(wait_for(lambda: not os.path.exists("/proc/%d" % host2), 30)
              and wait_for(lambda: not [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))], 10),
              "stopping the wrapper stops the host (pid %d) and its services: groups %s", host2,
              [d for d in os.listdir(CG_PARENT) if os.path.isdir(os.path.join(CG_PARENT, d))])
        check(time.time() - t0 < 400, "the whole run took %.0f s", time.time() - t0)
    finally:
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
        try:
            os.rmdir(CG_PARENT)
        except OSError:
            pass
        peer.stdin.close()
        server.shutdown()
        shutil.rmtree(top, ignore_errors=True)
    print("%s: run_test, %d failure%s" % ("FAIL" if failures else "PASS", len(failures), "" if len(failures) == 1 else "s"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
