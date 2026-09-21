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

Nothing starts while extensions are off or the machine is not ready. Then
services start one at a time, each as its pool account in its own cgroup, with
its output in the log under its name. The dialer reaches its declared
destination and not the machine. An armed window freezes every service but the
one with the grant, which gets job-time limits; disarming thaws them; a
forgectrl that stops answering freezes them again. A killed service comes
back. The one that keeps ending is quarantined, and state.json remembers it.
Safe mode stops everything and leaves no group and no chain. SIGTERM does the
same and the daemon exits 0.

Needs root, cgroup v2, nft, ip, nsenter, unshare, fwup (FWUP), the built
forgeext (FORGEEXT), and the rule file (FFX_RULES). Exits 77 without them.
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
import socket, sys
print("pid", flush=True)
sys.stdin.readline()
s = socket.socket()
s.bind(("%s", 0))
s.listen(128)
print(s.getsockname()[1], flush=True)
sys.stdin.readline()
''' % PEER_ADDR

DIAL = r'''
import socket, sys, time
name, port, local = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
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

failures = []
facts = {"armed": False, "controller": "running", "motion": "unverified", "mode": "grbl", "diag": False, "updating": False,
         "down": False}


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


class Forgectrl(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
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


def main():
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
    package("org.example.beat", "shell", "#!/bin/sh\nwhile true; do echo beat; sleep 1; done\n")
    package("org.example.dial", "python", DIAL, caps=["net.outbound:peer.test:%d" % pport], args=["peer.test", str(pport), str(fport)])
    package("org.example.jobtime", "shell", "#!/bin/sh\nwhile true; do echo through the job; sleep 1; done\n",
            caps=["job_time.run"], grants=["job_time.run"])
    package("org.example.crash", "shell", "#!/bin/sh\necho about to end\nexit 3\n")

    abi = int(subprocess.run([sys.executable, "-c", "import ctypes;print(ctypes.CDLL(None).syscall(444,None,0,1))"],
                             capture_output=True, text=True).stdout.strip() or 0)
    with open(conf, "w") as f:
        f.write("ext_enabled=0\n")
    log_path = os.path.join(top, "daemon.log")
    log = open(log_path, "w")

    def start_daemon():
        return subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "run", "--conf", conf, "--safe-file", safe,
                                 "--forgectrl", "127.0.0.1:%d" % fport, "--cg-parent", CG_PARENT, "--run-dir", run_dir]
                                + (["--landlock-fs-only"] if abi < 4 else []),
                                stderr=log, stdout=log, env=dict(os.environ, FFLOG_STDERR="1", FFLOG_SOCK="/nonexistent"))

    daemon = start_daemon()

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
        check(wait_for(lambda: status().get("off_reason"), 10) and not running(), "off: %s", status().get("off_reason"))
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
        check(cg("org.example.beat", "cpu.max").split() == ["25000", "100000"] and cg("org.example.beat", "pids.max").strip() == "32",
              "its limits: cpu.max %s pids.max %s", cg("org.example.beat", "cpu.max").strip(), cg("org.example.beat", "pids.max").strip())

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

        print("one daemon at a time; a killed daemon's services do not outlive the next one's start")
        check(wait_for(lambda: len(running()) >= 2, 30), "services are running before the daemon is killed: %s", running())
        mine = {s_["id"]: s_["pid"] for s_ in status().get("services", []) if s_["state"] == "running"}
        second = start_daemon()
        rc2 = second.wait(timeout=20)
        check(rc2 == 1 and logged("another extension host holds"), "a second daemon is refused (exit %s)", rc2)
        check(all(os.path.exists("/proc/%d" % pid) for pid in mine.values()) and running(),
              "and the first one's services are untouched by it")
        daemon.kill()
        daemon.wait(timeout=10)
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
        with open(conf, "w") as f:
            f.write("ext_enabled=1\n")
        check(wait_for(lambda: len(running()) >= 1, 30), "turned on again, the services start under the new daemon")

        print("safe mode, and the end")
        open(safe, "w").close()
        check(wait_for(lambda: not running() and "safe mode" in status().get("off_reason", ""), 10), "safe mode stops everything")
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
        check(time.time() - t0 < 400, "the whole run took %.0f s", time.time() - t0)
    finally:
        if daemon.poll() is None:
            daemon.kill()
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
