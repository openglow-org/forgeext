#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""Integration test of the author's kit (sdk/) against the real host, as root.

Each of the kit's service clients runs as a package's service under `forgeext
run`, in the sandbox a package gets on the image: sdk/python/ffx.py in a
Python package, sdk/sh/ffx.sh in a shell package (it speaks through the
image's curl), and sdk/c/ffx.h built static into a native package. Each asks
the host what a package asks - itself, its hold raised, read and cleared, a
machine route it holds and one it does not, a path there is none of, and (in
Python) its settings and the events poll - and writes what it was told into
its data directory, where the test reads it.

The Python and the C package also have a page, so their services answer the
page's calls (ffx.serve(), ffx_serve_one()): the test makes those calls the
way the panel relays them, with `forgeext call`, and holds the command to
its closed form, the refusals to their words, a frozen service to its own
answer, and the socket to being the host's and gone with the service.

In network and mount namespaces of its own, with the image's deny rules
loaded and a stand-in for forgectrl's read-only routes on loopback.

Needs root, cgroup v2, nft, ip, unshare, curl, a C compiler (CC, default cc),
fwup (FWUP), the built forgeext (FORGEEXT), and the rule file (FFX_RULES).
Exits 77 without them.
"""
import http.server
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.join(HERE, "..", "sdk")
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
FWUP = os.environ.get("FWUP") or shutil.which("fwup")
NFT = os.environ.get("NFT") or shutil.which("nft") or "/usr/sbin/nft"
CC = os.environ.get("CC") or "cc"
RULES = os.environ.get("FFX_RULES") or os.path.join(HERE, "..", "..", "forgefirm", "meta-forgefirm", "recipes-forgefirm",
                                                    "forgefirm-sandbox", "files", "ffx.nft")
MKFFX = os.path.join(HERE, "..", "tools", "mkffx.sh")
CG_PARENT = "/sys/fs/cgroup/forgeext-sdk-test"
SKIP = 77

PY_SERVICE = r'''
import json, os, socket, stat, sys, time
sys.path.insert(0, os.path.join(os.environ["FFX_PKG"], "lib"))
import ffx
out = {}
def handle(method, path, body):
    if path == "/echo":
        return {"method": method, "path": path, "body": body}
    if path == "/refuse":
        raise ffx.CallError(409, "not now")
    if path == "/big":
        return "x" * 70000
    if path == "/me":
        return ffx.me()["id"]
    raise ValueError("there is no " + path)
ffx.serve(handle, background=True)
def fds():
    r = {}
    for n in (3, 4, 5):
        try:
            r[str(n)] = "socket" if stat.S_ISSOCK(os.fstat(n).st_mode) else "other"
        except OSError:
            r[str(n)] = "closed"
    return r
def listening():
    s = socket.socket(fileno=os.dup(4))
    try:
        return s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
    finally:
        s.close()
out["call_env"] = os.environ.get("FFX_CALL_FD")
def note(name, fn):
    try:
        out[name] = ["ok", fn()]
    except ffx.ApiError as e:
        out[name] = ["refused", e.status, e.words]
    except Exception as e:
        out[name] = ["broke", repr(e)]
note("self", ffx.me)
note("mode", ffx.machine.mode)
note("settings", ffx.settings)
note("set", lambda: ffx.set_settings(threshold=7))
note("set_bad", lambda: ffx.set_settings(threshold=700))
note("raise", lambda: ffx.hold(True, "from ffx.py"))
note("hold", ffx.hold_state)
note("clear", lambda: ffx.hold(False))
note("events", ffx.events)
note("camera", lambda: len(ffx.camera("head")))
note("jog", lambda: ffx.jog(x=1))
note("nowhere", lambda: ffx.call("GET", "/v0/nowhere"))
note("program", lambda: ffx.write_program("p.gcode", "G21\n"))
note("program_dir", lambda: ffx.write_program("../p.gcode", "G21\n"))
note("fds", fds)
note("listening", listening)
d = os.environ["FFX_DATA"]
with open(os.path.join(d, "report.json.new"), "w") as f:
    json.dump(out, f)
os.rename(os.path.join(d, "report.json.new"), os.path.join(d, "report.json"))
while True:
    time.sleep(60)
'''

SH_SERVICE = r'''#!/bin/sh
. "$FFX_PKG/lib/ffx.sh"
r="$FFX_DATA/report.txt.new"
: > "$r"
ffx_get /v0/self > /dev/null; echo "self $? $FFX_STATUS $FFX_BODY" >> "$r"
ffx_hold 1 "from ffx.sh" > /dev/null; echo "raise $? $FFX_STATUS $FFX_BODY" >> "$r"
ffx_get /v0/hold > /dev/null; echo "hold $? $FFX_STATUS $FFX_BODY" >> "$r"
ffx_hold 0 > /dev/null; echo "clear $? $FFX_STATUS $FFX_BODY" >> "$r"
ffx_get /v0/machine/mode > /dev/null; echo "mode $? $FFX_STATUS $FFX_BODY" >> "$r"
ffx_get /v0/nowhere > /dev/null; echo "nowhere $? $FFX_STATUS $FFX_BODY" >> "$r"
mv "$r" "$FFX_DATA/report.txt"
while true; do sleep 60; done
'''

failures = []
facts = {"armed": False}


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


class Forgectrl(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/cool/status": {"armed": facts["armed"]},
                "/mode": {"mode": "grbl", "controller": "running", "motion": "verified"},
                "/status": {"diag": False, "state": "idle"},
                "/update/status": {"running": False}}.get(self.path)
        if body is None:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def cg_frozen(id_):
    try:
        with open(os.path.join(CG_PARENT, id_, "cgroup.events")) as f:
            return "frozen 1" in f.read()
    except OSError:
        return False


def wait_for(cond, seconds, poll=0.25):
    end = time.time() + seconds
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(poll)
    return None


def main():
    if os.environ.get("FFX_SDK_NS") != "1":
        missing = [t for t in ("unshare", "ip", "curl", CC) if not shutil.which(t)]
        need = {"forgeext": os.path.isfile(FORGEEXT), "fwup": bool(FWUP), "nft": os.path.isfile(NFT), "rules": os.path.isfile(RULES),
                "cgroup v2": os.path.isfile("/sys/fs/cgroup/cgroup.controllers")}
        if os.geteuid() != 0 or missing or not all(need.values()):
            print("skipped: needs root and %s; tools missing: %s" % ([k for k, v in need.items() if not v], missing))
            return SKIP
        os.execvpe("unshare", ["unshare", "-n", "-m", sys.executable, os.path.abspath(__file__)], dict(os.environ, FFX_SDK_NS="1"))

    top = tempfile.mkdtemp(prefix="forgeext-sdk.")
    os.chmod(top, 0o755)
    root, run_dir, conf, safe = (os.path.join(top, n) for n in ("root", "run", "forgefirm.conf", "ext-safe"))
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
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

    def package(id_, runtime, exe, files, caps, grants, settings=None):
        if "ui" in caps:
            files = dict(files, **{"ui/index.html": "<!doctype html><title>%s</title>\n" % id_})
        d = os.path.join(top, "src-" + id_)
        m = {"manifest": 1, "id": id_, "name": id_, "version": "1.0.0", "author": "Test", "license": "MIT", "api": "0.1",
             "runtime": runtime, "service": {"exec": exe}, "capabilities": list(caps)}
        if settings:
            m["settings"] = settings
        os.makedirs(d)
        with open(os.path.join(d, "manifest.json"), "w") as f:
            f.write(json.dumps(m, indent=1) + "\n")
        for rel, src in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if isinstance(src, bytes) or os.path.isfile(str(src)):
                shutil.copyfile(src, p) if not isinstance(src, bytes) else open(p, "wb").write(src)
            else:
                with open(p, "w") as f:
                    f.write(src)
            os.chmod(p, 0o755 if rel == exe else 0o644)
        out = os.path.join(top, id_ + ".ffx")
        subprocess.run(["sh", MKFFX, d, out], check=True, capture_output=True, env=dict(os.environ, FWUP=FWUP))
        r = fx("install", out, "--consent-unverified", *[a for g in grants for a in ("--grant", g)])
        check(r.get("ok") is True, "installed %s: %s", id_, r.get("error", ""))

    print("three packages, one for each of the kit's clients")
    native = os.path.join(top, "sdk-native")
    b = subprocess.run([CC, "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", native, os.path.join(HERE, "sdk_native.c")],
                       capture_output=True, text=True)
    check(b.returncode == 0, "ffx.h builds static with -Wall -Wextra -Werror: %s", b.stderr[-300:])
    package("org.example.sdkpy", "python", "bin/run.py", {"bin/run.py": PY_SERVICE, "lib/ffx.py": os.path.join(SDK, "python", "ffx.py")},
            caps=["hold", "machine.read", "settings.own", "events", "ui"], grants=["hold"],
            settings={"threshold": {"type": "number", "default": 40, "min": 0, "max": 100}})
    package("org.example.sdksh", "shell", "bin/run.sh", {"bin/run.sh": SH_SERVICE, "lib/ffx.sh": os.path.join(SDK, "sh", "ffx.sh")},
            caps=["hold"], grants=["hold"])
    package("org.example.sdkc", "native", "bin/run", {"bin/run": native}, caps=["hold", "machine.read", "ui"], grants=["hold"])

    abi = int(subprocess.run([sys.executable, "-c", "import ctypes;print(ctypes.CDLL(None).syscall(444,None,0,1))"],
                             capture_output=True, text=True).stdout.strip() or 0)
    with open(conf, "w") as f:
        f.write("ext_enabled=1\n")
    log = open(os.path.join(top, "daemon.log"), "w")
    call_dir = os.path.join(top, "call")
    daemon = subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "run", "--conf", conf, "--safe-file", safe,
                               "--forgectrl", "127.0.0.1:%d" % fport, "--cg-parent", CG_PARENT, "--run-dir", run_dir,
                               "--holds-dir", os.path.join(top, "holds"), "--api-dir", os.path.join(top, "api"),
                               "--call-dir", call_dir]
                              + (["--landlock-fs-only"] if abi < 4 else []),
                              stdout=log, stderr=subprocess.STDOUT)
    try:
        def report(id_, name):
            p = os.path.join(root, "data", id_, name)
            return p if os.path.exists(p) else None

        print("the Python client, ffx.py")
        p = wait_for(lambda: report("org.example.sdkpy", "report.json"), 60)
        check(p is not None, "it wrote its report")
        rep = json.load(open(p)) if p else {}
        me = (rep.get("self") or [None, {}])[1] or {}
        check(rep.get("self", [""])[0] == "ok" and me.get("id") == "org.example.sdkpy" and me.get("api") == "0.1",
              "self: %s", rep.get("self"))
        check(rep.get("mode") == ["ok", {"mode": "grbl", "controller": "running", "motion": "verified"}], "the machine's mode: %s",
              rep.get("mode"))
        check(rep.get("settings", [""])[0] == "ok" and rep["settings"][1]["settings"] == {"threshold": 40.0}, "settings: %s",
              rep.get("settings"))
        check(rep.get("set", [""])[0] == "ok" and rep["set"][1]["settings"] == {"threshold": 7}, "a patch: %s", rep.get("set"))
        check(rep.get("set_bad") == ["refused", 400, '"threshold" is at most 100'], "a value past its bound: %s", rep.get("set_bad"))
        check(rep.get("raise") == ["ok", {"raised": True, "reason": "from ffx.py"}], "a hold raised: %s", rep.get("raise"))
        check(rep.get("hold") == ["ok", {"raised": True, "reason": "from ffx.py"}], "and read: %s", rep.get("hold"))
        check(rep.get("clear", [""])[0] == "ok" and rep["clear"][1].get("raised") is False, "and cleared: %s", rep.get("clear"))
        ev = (rep.get("events") or [None, {}])[1] or {}
        check(rep.get("events", [""])[0] == "ok" and set(ev) >= {"next", "dropped", "connected", "events"}, "the events poll: %s",
              rep.get("events"))
        check(rep.get("camera", [""])[0] == "refused" and rep["camera"][1] == 403, "a camera it does not hold: %s", rep.get("camera"))
        check(rep.get("jog", [""])[0] == "refused" and rep["jog"][1] == 403, "a jog it does not hold: %s", rep.get("jog"))
        check(rep.get("nowhere", [""])[0] == "refused" and rep["nowhere"][1] == 404, "a path there is none of: %s", rep.get("nowhere"))
        check(rep.get("program") == ["ok", "p.gcode"] and os.path.isfile(os.path.join(root, "data", "org.example.sdkpy", "p.gcode")),
              "a program written into its own data: %s", rep.get("program"))
        check(rep.get("program_dir", [""])[0] == "broke" and "ValueError" in rep["program_dir"][1],
              "a program name with a directory in it: %s", rep.get("program_dir"))
        check(rep.get("call_env") == "4" and rep.get("fds") == ["ok", {"3": "closed", "4": "socket", "5": "closed"}]
              and rep.get("listening") == ["ok", 1],
              "its page's calls: FFX_CALL_FD=%s, descriptors %s, listening %s", rep.get("call_env"), rep.get("fds"),
              rep.get("listening"))

        def call(id_, method, path, *body):
            return fx("call", id_, method, path, *body, "--call-dir", call_dir, "--cg-parent", CG_PARENT)

        print("a page's calls to its own service (forgeext call, ffx.serve)")
        py = "org.example.sdkpy"
        st = os.lstat(os.path.join(call_dir, py + ".sock"))
        dst = os.lstat(call_dir)
        check(oct(dst.st_mode & 0o777) == "0o700" and dst.st_uid == 0 and st.st_uid == 0 and (st.st_mode & 0o777) == 0o600,
              "the socket is root's, 0600, in root's 0700 directory: %o %d, %o %d", dst.st_mode & 0o777, dst.st_uid,
              st.st_mode & 0o777, st.st_uid)
        r = call(py, "POST", "/echo", '{"a": 1, "b": "two"}')
        check(r.get("ok") is True and r.get("status") == 200
              and r.get("body") == {"method": "POST", "path": "/echo", "body": {"a": 1, "b": "two"}}, "a POST: %s", r)
        r = call(py, "POST", "/echo")
        check(r.get("ok") is True and r.get("body", {}).get("body") == {}, "a POST without a body sends {}: %s", r)
        r = call(py, "GET", "/echo")
        check(r.get("ok") is True and r.get("body") == {"method": "GET", "path": "/echo", "body": {}}, "a GET: %s", r)
        r = call(py, "GET", "/refuse")
        check(r.get("ok") is True and r.get("status") == 409 and r.get("body") == {"error": "not now"},
              "the service's own refusal is its status and words: %s", r)
        r = call(py, "GET", "/nothing")
        check(r.get("ok") is True and r.get("status") == 500 and "ValueError" in str(r.get("body")),
              "a handler that raised answers 500: %s", r)
        r = call(py, "GET", "/big")
        check(r.get("ok") is True and r.get("status") == 500 and "more than" in str(r.get("body")),
              "an answer past the limit is the SDK's 500: %s", r)
        r = call(py, "GET", "/me")
        check(r.get("ok") is True and r.get("body") == py, "a service asks the machine while it answers: %s", r)
        for args, words in (((py, "PUT", "/echo"), "a call is GET or POST"),
                            ((py, "GET", "/../etc"), "a call's path starts with"),
                            ((py, "GET", "/a?b"), "a call's path starts with"),
                            ((py, "GET", "echo"), "a call's path starts with"),
                            ((py, "GET", "/echo", "{}"), "a GET call has no body"),
                            ((py, "POST", "/echo", "[1]"), "a call's body is a JSON object"),
                            ((py, "POST", "/echo", '{"a": 1, "a": 2}'), "a call's body is a JSON object"),
                            ((py, "POST", "/echo", '{"a": "%s"}' % ("x" * 4100)), "a call's body is at most 4096 bytes"),
                            (("org.example.sdksh", "GET", "/echo"), "this package has no page that calls a service"),
                            (("org.example.nobody", "GET", "/echo"), "that package is not installed"),
                            (("Not.An.Id", "GET", "/echo"), "that is not a package id")):
            r = call(*args)
            check(r.get("ok") is False and str(r.get("error", "")).startswith(words), "%s %s -> %s", args[1], args[2], r.get("error"))

        def lines(id_):
            p = wait_for(lambda: report(id_, "report.txt"), 60)
            check(p is not None, "%s wrote its report", id_)
            out = {}
            for ln in open(p).read().splitlines() if p else []:
                k, _, rest = ln.partition(" ")
                out[k] = rest
            return out

        print("the shell client, ffx.sh (through the image's curl)")
        sh = lines("org.example.sdksh")
        check(sh.get("self", "").startswith("0 200 ") and '"org.example.sdksh"' in sh.get("self", ""), "self: %s", sh.get("self"))
        check(sh.get("raise", "").startswith("0 200 ") and '"from ffx.sh"' in sh.get("raise", ""), "a hold raised: %s", sh.get("raise"))
        check(sh.get("hold", "").startswith("0 200 ") and '"raised": true' in sh.get("hold", "").replace('":true', '": true'),
              "and read: %s", sh.get("hold"))
        check(sh.get("clear", "").startswith("0 200 "), "and cleared: %s", sh.get("clear"))
        check(sh.get("mode", "").startswith("1 403 "), "a machine route it does not hold: %s", sh.get("mode"))
        check(sh.get("nowhere", "").startswith("1 404 "), "a path there is none of: %s", sh.get("nowhere"))

        print("the C client, ffx.h (built static)")
        c = lines("org.example.sdkc")
        check(c.get("self", "").startswith("0 200 application/json ") and '"org.example.sdkc"' in c.get("self", ""), "self: %s",
              c.get("self"))
        check(c.get("escape") == r'"a \"b\" \\c\u000a"', "a string escaped for JSON: %s", c.get("escape"))
        check(c.get("escape_small") == "-1", "and one that does not fit refused: %s", c.get("escape_small"))
        check(c.get("raise", "").startswith("0 200 ") and '"from ffx.h"' in c.get("raise", ""), "a hold raised: %s", c.get("raise"))
        check(c.get("hold", "").startswith("0 200 ") and '"from ffx.h"' in c.get("hold", ""), "and read: %s", c.get("hold"))
        check(c.get("clear", "").startswith("0 200 "), "and cleared: %s", c.get("clear"))
        check(c.get("mode", "").startswith("0 200 ") and '"grbl"' in c.get("mode", ""), "the machine's mode: %s", c.get("mode"))
        check(c.get("nowhere", "").startswith("0 404 "), "a path there is none of: %s", c.get("nowhere"))
        check(c.get("call_fd") == "4", "its page's calls, at descriptor %s", c.get("call_fd"))
        r = call("org.example.sdkc", "POST", "/echo", '{"x": [1, 2]}')
        check(r.get("ok") is True and r.get("status") == 200
              and r.get("body") == {"method": "POST", "path": "/echo", "body": {"x": [1, 2]}}, "ffx_serve_one answers: %s", r)
        r = call("org.example.sdkc", "GET", "/nothing")
        check(r.get("ok") is True and r.get("status") == 404 and r.get("body") == {"error": "there is no such thing"},
              "and refuses in its own words: %s", r)

        print("a frozen service, and a stopped one")
        facts["armed"] = True
        frozen = wait_for(lambda: cg_frozen(py), 15)
        check(frozen, "armed: the service froze")
        r = call(py, "GET", "/echo")
        check(r.get("ok") is False and r.get("error") == "its service is frozen while a job is armed", "a call to it: %s", r)
        facts["armed"] = False
        check(wait_for(lambda: not cg_frozen(py), 15), "disarmed: it thawed")
        r = call(py, "GET", "/echo")
        check(r.get("ok") is True and r.get("status") == 200, "and answers again: %s", r)
        daemon.send_signal(signal.SIGTERM)
        daemon.wait(20)
        check(not os.path.exists(os.path.join(call_dir, py + ".sock")), "the host stopped: the socket's name is gone")
        r = call(py, "GET", "/echo")
        check(r.get("ok") is False and r.get("error") == "its service is not running", "a call now: %s", r)
    finally:
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(20)
        except subprocess.TimeoutExpired:
            daemon.kill()
        log.close()
        server.shutdown()
        if failures:
            print("--- the daemon's log")
            print(open(os.path.join(top, "daemon.log")).read()[-4000:])
        shutil.rmtree(top, ignore_errors=True)
        try:
            os.rmdir(CG_PARENT)
        except OSError:
            pass

    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
