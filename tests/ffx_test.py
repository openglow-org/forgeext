#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""tools/ffx held to the host it mirrors.

Every fixture is a package directory. `ffx lint` judges it, and the same
directory, packed unsigned by tools/mkffx.sh, is judged by the built
`forgeext inspect`: the two must agree on every verdict, and where the host
refuses a manifest the words must be the host's. Then `ffx pack` builds an
archive the host takes, the same bytes twice over; `ffx new` makes a package
for each runtime that lints as its template says; `ffx keygen` refuses to
overwrite a key; `ffx index record` writes a listed version's record only
for an archive its signer's key verifies; `ffx index build` makes an index
of a catalog directory that the host keeps, the same bytes twice over,
and refuses a catalog out of form; and ffx's index form is the host's,
document by document.

Needs fwup (FWUP) and the built forgeext (FORGEEXT). Exits 77 without them.
"""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
FWUP = os.environ.get("FWUP") or shutil.which("fwup")
SKIP = 77
failures = []


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


def load_ffx():
    loader = importlib.machinery.SourceFileLoader("ffx_tool", os.path.join(TOOLS, "ffx"))
    spec = importlib.util.spec_from_loader("ffx_tool", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


BASE = {"manifest": 1, "id": "org.example.fixture", "name": "Fixture", "version": "1.0.0", "author": "Test",
        "license": "MIT", "api": "0.1", "runtime": "python", "service": {"exec": "bin/run.py"},
        "capabilities": ["machine.read"]}


def with_(**kw):
    m = json.loads(json.dumps(BASE))
    for k, v in kw.items():
        if v is None:
            m.pop(k, None)
        else:
            m[k] = v
    return m


# (name, manifest (dict, or raw bytes), extra files {path: text}); a ui package gets its page, a service its entry
FIXTURES = [
    ("a python service", with_(), {}),
    ("a ui package", with_(runtime="ui", service=None, capabilities=["ui", "machine.read", "camera.head"]), {}),
    ("a data package", with_(runtime="data", service=None, capabilities=[]), {}),
    ("a shell service", with_(runtime="shell", service={"exec": "bin/run.sh"}, capabilities=["hold"]), {}),
    ("every setting type", with_(capabilities=["settings.own"], settings={
        "a": {"type": "string", "default": "x", "max": 8, "label": "A"}, "b": {"type": "number", "default": 2, "min": 0, "max": 5},
        "c": {"type": "bool", "default": True}, "d": {"type": "choice", "default": "y", "choices": ["x", "y"]}}), {}),
    ("an outbound destination by name and by address", with_(capabilities=["net.outbound:mqtt.example.org:8883",
                                                                            "net.outbound:10.1.2.3:80",
                                                                            "net.outbound:[fd00::1]:443"]), {}),
    ("the operator's destinations", with_(capabilities=["net.outbound.operator", "net.outbound:ntfy.sh:443"]), {}),
    ("the operator's destinations with an argument", with_(capabilities=["net.outbound.operator:plug.lan:80"]), {}),
    ("a core range", with_(core={"min": "0.0.1", "max": "9.0.0"}), {}),
    ("not JSON", b"{\"manifest\": 1,", {}),
    ("a key twice", b'{"manifest": 1, "manifest": 1}', {}),
    ("NaN", b'{"manifest": NaN}', {}),
    ("an unknown key", with_(colour="red"), {}),
    ("the wrong schema", with_(manifest=2), {}),
    ("a schema that is a string", with_(manifest="1"), {}),
    ("no id", with_(id=None), {}),
    ("an id with an upper-case letter", with_(id="org.Example.x"), {}),
    ("an id of one label", with_(id="fixture"), {}),
    ("an id ending in a dash", with_(id="org.example.x-"), {}),
    ("a name too long", with_(name="n" * 65), {}),
    ("a name with a control character", with_(name="a\tb"), {}),
    ("a version with a leading zero", with_(version="1.01.0"), {}),
    ("a version with a prerelease", with_(version="1.0.0-rc.1"), {}),
    ("a version with an empty prerelease", with_(version="1.0.0-"), {}),
    ("no author", with_(author=None), {}),
    ("an empty license", with_(license=""), {}),
    ("an api too new", with_(api="0.2"), {}),
    ("an api that is no version", with_(api="1"), {}),
    ("a core with an unknown key", with_(core={"least": "0.0.1"}), {}),
    ("a core min above its max", with_(core={"min": "2.0.0", "max": "1.0.0"}), {}),
    ("a runtime there is none of", with_(runtime="java"), {}),
    ("a ui package with a service", with_(runtime="ui", capabilities=["ui"]), {}),
    ("a service with no service", with_(service=None), {}),
    ("a service entry with ..", with_(service={"exec": "../run.py"}), {}),
    ("a service with an unknown key", with_(service={"exec": "bin/run.py", "user": "root"}), {}),
    ("seventeen args", with_(service={"exec": "bin/run.py", "args": ["a"] * 17}), {}),
    ("modes empty", with_(modes=[]), {}),
    ("a mode twice", with_(modes=["grbl", "grbl"]), {}),
    ("no capabilities", with_(capabilities=None), {}),
    ("a capability there is none of", with_(capabilities=["laser.fire"]), {}),
    ("a role", with_(capabilities=["role:homing"]), {}),
    ("an M-code", with_(capabilities=["mcode:160", "mcode:179", "job_time.run"]), {}),
    ("an M-code with no job_time.run", with_(capabilities=["mcode:160"]), {}),
    ("an M-code out of range", with_(capabilities=["mcode:180", "job_time.run"]), {}),
    ("an M-code below the range", with_(capabilities=["mcode:102", "job_time.run"]), {}),
    ("an M-code on a page", with_(runtime="ui", service=None, capabilities=["ui", "mcode:160"]), {}),
    ("a check of its own on the Setup page", with_(capabilities=["wizard"]), {}),
    ("a Setup check with no service", with_(runtime="ui", service=None, capabilities=["ui", "wizard"]), {}),
    ("a capability not offered", with_(capabilities=["motion.offsets"]), {}),
    ("an argument where none is taken", with_(capabilities=["hold:1"]), {}),
    ("an outbound to the machine", with_(capabilities=["net.outbound:127.0.0.1:80"]), {}),
    ("an outbound with an upper-case name", with_(capabilities=["net.outbound:MQTT.example.org:1883"]), {}),
    ("a listen on the firmware's port", with_(capabilities=["net.listen:8090"]), {}),
    ("a listen below 1024", with_(capabilities=["net.listen:80"]), {}),
    ("storage past its bound", with_(capabilities=["storage:300"]), {}),
    ("storage twice", with_(capabilities=["storage:4", "storage:8"]), {}),
    ("a capability twice", with_(capabilities=["hold", "hold"]), {}),
    ("a data package with a capability", with_(runtime="data", service=None, capabilities=["machine.read"]), {}),
    ("a ui package with a hold", with_(runtime="ui", service=None, capabilities=["ui", "hold"]), {}),
    ("a conflict with itself", with_(conflicts=["org.example.fixture"]), {}),
    ("a conflict twice", with_(conflicts=["org.example.a", "org.example.a"]), {}),
    ("seventeen settings", with_(capabilities=["settings.own"],
                                 settings={"s%d" % i: {"type": "bool", "default": False} for i in range(17)}), {}),
    ("a setting with no default", with_(settings={"a": {"type": "bool"}}), {}),
    ("a setting of no type", with_(settings={"a": {"type": "date", "default": "x"}}), {}),
    ("a setting named with a capital", with_(settings={"A": {"type": "bool", "default": False}}), {}),
    ("a number default out of bounds", with_(settings={"a": {"type": "number", "default": 9, "max": 5}}), {}),
    ("a number min above its max", with_(settings={"a": {"type": "number", "default": 1, "min": 5, "max": 1}}), {}),
    ("a number that is a bool", with_(settings={"a": {"type": "number", "default": True}}), {}),
    ("a string max that is not whole", with_(settings={"a": {"type": "string", "default": "", "max": 5.5}}), {}),
    ("a string max past 128", with_(settings={"a": {"type": "string", "default": "", "max": 129}}), {}),
    ("a string default past its max", with_(settings={"a": {"type": "string", "default": "abcdef", "max": 3}}), {}),
    ("a min on a string", with_(settings={"a": {"type": "string", "default": "", "min": 1}}), {}),
    ("choices on a string", with_(settings={"a": {"type": "string", "default": "", "choices": ["x", "y"]}}), {}),
    ("a choice with one choice", with_(settings={"a": {"type": "choice", "default": "x", "choices": ["x"]}}), {}),
    ("a choice named twice", with_(settings={"a": {"type": "choice", "default": "x", "choices": ["x", "x"]}}), {}),
    ("a choice default not a choice", with_(settings={"a": {"type": "choice", "default": "z", "choices": ["x", "y"]}}), {}),
    ("a label too long", with_(settings={"a": {"type": "bool", "default": False, "label": "l" * 49}}), {}),
    ("a setting with an unknown key", with_(settings={"a": {"type": "bool", "default": False, "unit": "mm"}}), {}),
    ("a ui package without its page", with_(runtime="ui", service=None, capabilities=["ui"]), {"__no_page__": ""}),
    ("a page without ui", with_(), {"ui/index.html": "<p>x</p>"}),
    ("an entry point that is not there", with_(service={"exec": "bin/other.py"}), {}),
]


def build(top, name, manifest, extra):
    d = os.path.join(top, "fx-%d" % abs(hash(name)))
    os.makedirs(d)
    raw = manifest if isinstance(manifest, bytes) else json.dumps(manifest, indent=1).encode()
    open(os.path.join(d, "manifest.json"), "wb").write(raw)
    m = manifest if isinstance(manifest, dict) else {}
    caps = m.get("capabilities") or []
    if "ui" in caps and "__no_page__" not in extra:
        os.makedirs(os.path.join(d, "ui"), exist_ok=True)
        open(os.path.join(d, "ui", "index.html"), "w").write("<!doctype html><p>page</p>")
    svc = m.get("service")
    if isinstance(svc, dict) and isinstance(svc.get("exec"), str) and m.get("runtime") in ("python", "shell", "native") \
            and svc["exec"] != "bin/other.py" and ".." not in svc["exec"]:
        p = os.path.join(d, svc["exec"])
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write("import os\n" if p.endswith(".py") else "#!/bin/sh\n")
        os.chmod(p, 0o755)
    for rel, text in extra.items():
        if rel.startswith("__"):
            continue
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    return d


TOKEN = "0123456789abcdef0123456789abcdef"


def machine_client(ffx, top, archive):
    """ffx install and ffx logs against a stand-in for forgectrl's HTTPS routes, answered as the daemon answers
    them (the login, the page that carries the token, the upload, the install, the log's tail), so what the tool
    sends is held to the contract: the cookie and the token on every write, an address-literal Host, the archive
    as the file part, the grants and the phrase."""
    import builtins
    import getpass
    import http.server
    import ssl
    import threading
    import urllib.parse
    if not shutil.which("openssl"):
        print("  (the machine client: skipped, no openssl to make the stand-in's certificate)")
        return
    cert, key = os.path.join(top, "cert.pem"), os.path.join(top, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-subj", "/CN=forgefirm", "-days", "1"], check=True, capture_output=True)
    seen = []

    class Forgectrl(http.server.BaseHTTPRequestHandler):
        def reply(self, code, body, headers=()):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if not isinstance(body, bytes) else "text/html")
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def authed(self):
            return self.headers.get("Cookie") == "session=s3" and self.headers.get("X-ForgeFIRM-Token") == TOKEN

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            seen.append(("GET", u.path, self.headers.get("Host")))
            if u.path == "/" and self.headers.get("Cookie") == "session=s3":
                return self.reply(200, ("<script>var TOK = '%s';</script>" % TOKEN).encode())
            if u.path == "/logs/tail" and self.authed():
                q = dict(urllib.parse.parse_qsl(u.query))
                return self.reply(200, {"name": q.get("name"), "exists": True, "offset": 99,
                                        "text": "a line of org.example.fixture\nsomebody else's line\n"})
            return self.reply(403, {"error": "authentication required"})

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append(("POST", u.path, self.headers.get("Host"), self.headers.get("Content-Type"), body))
            if u.path == "/login":
                f = dict(urllib.parse.parse_qsl(body.decode()))
                if f == {"name": "owner", "password": "pw"}:
                    return self.reply(200, {"ok": True}, [("Set-Cookie", "session=s3; Path=/; HttpOnly; Secure")])
                return self.reply(401, {"error": "wrong name or password"})
            if not self.authed():
                return self.reply(403, {"error": "authentication required"})
            if u.path == "/ext/upload":
                ok = b'name="file"' in body and open(archive, "rb").read() in body
                return self.reply(200 if ok else 400, {"tier": "community", "consent": "typed", "update": False,
                                                       "needs_grant": ["hold"], "new_capabilities": [],
                                                       "package": {"id": "org.example.fixture", "version": "1.0.0",
                                                                   "author": "Test", "capabilities": ["hold", "machine.read"]}})
            if u.path == "/ext/install":
                f = dict(urllib.parse.parse_qsl(body.decode()))
                ok = f == {"grants": "hold", "phrase": "I UNDERSTAND"}
                return self.reply(200 if ok else 400, {"enabled": True} if ok else {"error": "not the consent: %s" % f})
            if u.path == "/ext/upload/discard":
                return self.reply(200, {"discarded": True})
            return self.reply(404, {"error": "not found"})

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Forgectrl)
    cx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cx.load_cert_chain(cert, key)
    srv.socket = cx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr = "127.0.0.1:%d" % srv.server_address[1]
    answers = iter(["y", "I UNDERSTAND"])
    home = os.path.join(top, "home")
    saved = (builtins.input, getpass.getpass, os.environ.get("HOME"), os.environ.get("USERPROFILE"))
    builtins.input = lambda prompt="": next(answers)
    getpass.getpass = lambda prompt="": "pw"
    os.environ["HOME"] = os.environ["USERPROFILE"] = home
    out = io_capture()
    try:
        print("ffx install and logs, against a stand-in for forgectrl's routes")
        with out:
            rc = ffx.main(["install", archive, "--machine", addr, "--user", "owner", "--grant", "hold"])
        check(rc == 0 and "installed: org.example.fixture" in out.text, "installed: rc %s, %s", rc, out.text[-200:])
        posts = [s for s in seen if s[0] == "POST"]
        check([p[1] for p in posts] == ["/login", "/ext/upload", "/ext/install"], "login, upload, install: %s",
              [p[1] for p in posts])
        check(all(s[2] == addr for s in seen), "every request's Host is the address itself: %s", set(s[2] for s in seen))
        check(posts[1][3].startswith("multipart/form-data; boundary="), "the archive goes as a file part")
        known = json.load(open(os.path.join(home, ".ffx", "machines.json")))
        check(list(known) == [addr], "the certificate is remembered after the owner said yes")
        seen.clear()
        answers = iter([])
        with out:
            rc = ffx.main(["logs", "--machine", addr, "--user", "owner", "--id", "org.example.fixture"])
        check(rc == 0 and "a line of org.example.fixture" in out.text and "somebody else" not in out.text,
              "logs: a package's lines alone: %s", out.text.strip()[-120:])
        check(any(s[1] == "/logs/tail" for s in seen), "read through /logs/tail")
        # a certificate that changed is refused, not trusted again
        json.dump({addr: "00" * 32}, open(os.path.join(home, ".ffx", "machines.json"), "w"))
        with out:
            rc = ffx.main(["logs", "--machine", addr, "--user", "owner"])
        check(rc == 1 and "not the one it presented before" in out.err, "a changed certificate is refused: %s",
              out.err.strip()[-160:])
    finally:
        builtins.input, getpass.getpass = saved[0], saved[1]
        for k, v in (("HOME", saved[2]), ("USERPROFILE", saved[3])):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        srv.shutdown()


class io_capture:
    """stdout and stderr of a block, kept."""

    def __enter__(self):
        import io
        self._old = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        return self

    def __exit__(self, *exc):
        self.text, self.err = sys.stdout.getvalue(), sys.stderr.getvalue()
        sys.stdout, sys.stderr = self._old
        return False


def main():
    if not FWUP or not os.path.isfile(FORGEEXT):
        print("skipped: needs fwup and the built forgeext")
        return SKIP
    ffx = load_ffx()
    top = tempfile.mkdtemp(prefix="ffx-test.")
    root = os.path.join(top, "root")
    env = dict(os.environ, FWUP=FWUP)
    try:
        def inspect(archive):
            p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "inspect", archive],
                               capture_output=True, text=True)
            try:
                return json.loads(p.stdout)
            except ValueError:
                return {"ok": None, "error": p.stdout + p.stderr}

        print("ffx's capability list is the host's")
        p = subprocess.run([FORGEEXT, "caps"], capture_output=True, text=True)
        host = {c["name"]: (c["argument"], c["operator_grant"], c["offered"]) for c in json.loads(p.stdout)["capabilities"]}
        check(host == ffx.CAPS, "the same names, arguments, grants, and offers: only in the host %s, only in ffx %s, "
              "differing %s", sorted(set(host) - set(ffx.CAPS)), sorted(set(ffx.CAPS) - set(host)),
              sorted(k for k in set(host) & set(ffx.CAPS) if host[k] != ffx.CAPS[k]))
        svc = build(top, "a page asking for a service's capability",
                    with_(runtime="ui", service=None, capabilities=["ui", "net.outbound.operator"]), {})
        try:
            ffx.lint(svc)
            check(False, "a page with no service asking for net.outbound.operator is refused")
        except ffx.Refused as e:
            check("belongs to a service" in str(e), "a page asking for the operator's destinations: %s", e)

        print("a native service: what the machine's loader can run")
        nat = build(top, "a native service", with_(runtime="native", service={"exec": "bin/run"}, capabilities=[]), {})

        def native_says(path):
            shutil.copyfile(path, os.path.join(nat, "bin", "run"))
            os.chmod(os.path.join(nat, "bin", "run"), 0o755)
            try:
                ffx.lint(nat)
                return None
            except ffx.Refused as e:
                return str(e)
        script = os.path.join(top, "run.sh")
        open(script, "w").write("#!/bin/sh\n")
        check("not an ELF binary" in (native_says(script) or ""), "a script is no native service: %s", native_says(script))
        host_cc = shutil.which("cc")
        if host_cc:
            src = os.path.join(top, "hello.c")
            open(src, "w").write("#include <stdio.h>\nint main(void) { puts(\"hello\"); return 0; }\n")
            subprocess.run([host_cc, "-o", os.path.join(top, "hello-host"), src], check=True, capture_output=True)
            check("not a 32-bit ARM binary" in (native_says(os.path.join(top, "hello-host")) or ""),
                  "a binary for this computer is not the machine's: %s", native_says(os.path.join(top, "hello-host")))
        arm = shutil.which("arm-linux-gnueabihf-gcc")
        if arm:
            dyn, stat_ = os.path.join(top, "hello-arm"), os.path.join(top, "hello-arm-static")
            subprocess.run([arm, "-O2", "-o", dyn, src, "-lm"], check=True, capture_output=True)
            subprocess.run([arm, "-O2", "-static", "-o", stat_, src], check=True, capture_output=True)
            check(native_says(dyn) is None, "linked against the C library alone: taken (%s)", native_says(dyn))
            check(native_says(stat_) is None, "static: taken (%s)", native_says(stat_))
            b = bytearray(open(dyn, "rb").read())
            i = b.find(b"libc.so.6\0")
            b[i:i + 9] = b"libq.so.6"
            open(dyn + ".other", "wb").write(b)
            check("libq.so.6, which the machine does not promise" in (native_says(dyn + ".other") or ""),
                  "a library the machine does not promise: %s", native_says(dyn + ".other"))
            b = bytearray(open(dyn, "rb").read())
            i = b.find(b"GLIBC_2.")
            j = b.index(b"\0", i)
            b[i:j] = (b"GLIBC_9.9" + b"9" * 64)[:j - i]
            open(dyn + ".newer", "wb").write(b)
            check("and the machine carries 2.39" in (native_says(dyn + ".newer") or ""),
                  "a newer C library than the machine's: %s", native_says(dyn + ".newer"))
        else:
            print("  note: no arm-linux-gnueabihf-gcc here: the ARM binaries are not tried")

        print("ffx lint against forgeext inspect, fixture by fixture")
        for name, manifest, extra in FIXTURES:
            d = build(top, name, manifest, extra)
            try:
                ffx.lint(d)
                mine = None
            except ffx.Refused as e:
                mine = str(e)
            out = os.path.join(top, "fx.ffx")
            if os.path.exists(out):
                os.remove(out)
            subprocess.run(["sh", os.path.join(TOOLS, "mkffx.sh"), d, out], capture_output=True, env=env)
            if not os.path.exists(out):
                # mkffx.sh needs an id and a version it can read: the host never sees such a manifest at all
                check(mine is not None, "%s: packing fails, and lint refuses it too (%s)", name, mine)
                continue
            theirs = inspect(out)
            host_ok = theirs.get("ok") is True
            if host_ok or mine is None:
                check(host_ok == (mine is None), "%s: the host says %s, lint says %s", name,
                      "yes" if host_ok else theirs.get("error"), "yes" if mine is None else mine)
                continue
            words = theirs.get("error") or ""
            if mine.startswith("the manifest is not JSON"):
                check("not JSON" in words or "JSON" in words, "%s: both refuse it as JSON (%s / %s)", name, mine, words)
            else:
                check(mine in words, "%s: the host's words (%s) hold lint's (%s)", name, words, mine)

        print("ffx pack: an archive the host takes, the same bytes twice")
        d = build(top, "a packed one", with_(), {"lib/extra.py": "x = 1\n"})
        a1, a2 = os.path.join(top, "a1.ffx"), os.path.join(top, "a2.ffx")
        for out in (a1, a2):
            rc = ffx.main(["pack", d, "--out", out])
            check(rc == 0 and os.path.isfile(out), "packed %s: %s", os.path.basename(out), rc)
        check(open(a1, "rb").read() == open(a2, "rb").read(), "two packs of one directory are one archive")
        r = inspect(a1)
        check(r.get("ok") is True and r.get("tier") == "unverified" and r.get("files") == 3,
              "the host takes it: %s tier %s, %s files", r.get("error", "ok"), r.get("tier"), r.get("files"))
        key = os.path.join(top, "author")
        check(ffx.main(["keygen", key]) == 0 and os.path.isfile(key + ".priv") and os.path.isfile(key + ".pub"), "a key pair")
        check(ffx.main(["keygen", key]) == 1, "and a second keygen over it refused")
        signed = os.path.join(top, "signed.ffx")
        check(ffx.main(["pack", d, "--key", key + ".priv", "--out", signed]) == 0, "packed and signed")
        v = subprocess.run([FWUP, "-V", "-i", signed, "-p", key + ".pub"], capture_output=True)
        check(v.returncode == 0, "the signature checks under fwup: %s", v.stderr[-200:])
        os.makedirs(os.path.join(root, "keys"), exist_ok=True)
        shutil.copyfile(key + ".pub", os.path.join(root, "keys", "author.pub"))
        r = inspect(signed)
        check(r.get("ok") is True and r.get("tier") == "community", "with the key trusted, the host reads it community: %s",
              r.get("tier"))
        bad = build(top, "a bad one", with_(capabilities=["laser.fire"]), {})
        check(ffx.main(["pack", bad, "--out", os.path.join(top, "bad.ffx")]) == 1 and
              not os.path.exists(os.path.join(top, "bad.ffx")), "pack lints first, and packs nothing it refuses")
        imp = build(top, "an import", with_(), {"bin/run.py": "import requests\n"})
        try:
            ffx.lint(imp)
            check(False, "an import outside the release list is refused")
        except ffx.Refused as e:
            check("requests" in str(e) and "modules.txt" in str(e), "an import outside the release list: %s", e)
        vend = build(top, "a vendored import", with_(), {"bin/run.py": "import mylib\nimport json\n", "lib/mylib.py": ""})
        try:
            ffx.lint(vend)
            check(True, "a module the package carries is its own to import")
        except ffx.Refused as e:
            check(False, "a vendored import refused: %s", e)

        print("ffx new: a package's repository for each runtime")
        make = shutil.which("make")
        cross = shutil.which("arm-linux-gnueabihf-gcc")
        for runtime, lints in (("ui", True), ("python", True), ("shell", True), ("data", True), ("native", False)):
            d = os.path.join(top, "new-" + runtime)
            rc = ffx.main(["new", d, "--id", "org.example.new" + runtime, "--runtime", runtime, "--key", key + ".pub"])
            try:
                _m, warnings, _f = ffx.lint(d)
                ok, why = True, ""
            except ffx.Refused as e:
                ok, why, warnings = False, str(e), []
            check(rc == 0 and ok == lints, "%s: made, and %s%s", runtime, "lints" if lints else "wants its binary built",
                  (": " + why) if why else "")
            if lints:
                check(any("the package's repository, not the package as it ships" in w for w in warnings),
                      "%s: lint of the repository says to stage it: %s", runtime, warnings)
            wf = open(os.path.join(d, ".github", "workflows", "package.yml")).read()
            mk = open(os.path.join(d, "Makefile")).read()
            files = {n: os.path.exists(os.path.join(d, n)) for n in ("Makefile", ".gitignore", "README.md", "key.pub")}
            check(all(files.values()) and "uses: openglow-org/forgeext/.github/workflows/package.yml@main" in wf
                  and "secrets: inherit" in wf and ("apt: gcc-arm-linux-gnueabihf" in wf) == (runtime == "native")
                  and "\n\trm -rf build/pkg\n" in mk and ("bin/run:" in mk) == (runtime == "native")
                  and "@@" not in wf + mk + open(os.path.join(d, "README.md")).read()
                  and open(os.path.join(d, "key.pub")).read() == open(key + ".pub").read(),
                  "%s: the repository's files: %s", runtime, files)
            if make and (runtime != "native" or cross):
                p = subprocess.run([make, "-C", d, "stage"], capture_output=True, text=True)
                staged = sorted(os.listdir(os.path.join(d, "build", "pkg"))) if p.returncode == 0 else p.stderr[-300:]
                try:
                    _m, warnings, _f = ffx.lint(os.path.join(d, "build", "pkg"))
                    ok, why = True, ""
                except ffx.Refused as e:
                    ok, why, warnings = False, str(e), []
                check(p.returncode == 0 and ok and ".github" not in staged and "Makefile" not in staged
                      and not any("repository" in w for w in warnings),
                      "%s: make stage lays out what ships, and it lints: %s %s", runtime, staged, why)
            else:
                print("  note: no make%s here: %s is not staged" % ("" if make else "", runtime))
            if runtime == "ui":
                page = open(os.path.join(d, "ui", "index.html")).read()
                check("var ffx = (function" in page and "@@" not in page, "the page carries the bridge client")
            if runtime == "native":
                check("entry point, bin/run" in why or os.path.isfile(os.path.join(d, "bin", "run")),
                      "and wants its binary built, with ffx.h beside its source: %s", why)
                check(os.path.isfile(os.path.join(d, "src", "ffx.h")), "ffx.h is beside its source")
        clone = os.path.join(top, "clone")
        os.makedirs(os.path.join(clone, ".git"))
        check(ffx.main(["new", clone, "--id", "org.example.clone", "--runtime", "ui"]) == 0
              and os.path.isfile(os.path.join(clone, "manifest.json")) and os.path.isdir(os.path.join(clone, ".git")),
              "a fresh clone, .git alone, takes a new package")
        check(ffx.main(["new", clone, "--id", "org.example.clone", "--runtime", "ui"]) == 1,
              "and a directory that holds anything more is refused")

        print("ffx index record and build: a catalog directory, as the host keeps it")
        ogkey = os.path.join(top, "openglow")
        check(ffx.main(["keygen", ogkey]) == 0, "a stand-in for the OpenGlow extension key")
        off = build(top, "an official one", with_(id="org.openglow.fixture"), {})
        official = os.path.join(top, "official.ffx")
        check(ffx.main(["pack", off, "--key", ogkey + ".priv", "--out", official]) == 0, "OpenGlow's own, signed with it")
        cat = os.path.join(top, "catalog")
        fxdir, ogdir = os.path.join(cat, "packages", "org.example.fixture"), os.path.join(cat, "packages", "org.openglow.fixture")
        os.makedirs(fxdir)
        os.makedirs(ogdir)
        shutil.copyfile(key + ".pub", os.path.join(fxdir, "key.pub"))

        def ffx_run(*args):
            p = subprocess.run([sys.executable, "-B", os.path.join(TOOLS, "ffx")] + list(args), capture_output=True,
                               text=True, env=env)
            return p.returncode, (p.stdout + p.stderr).strip()

        url = "https://example.org/fixture-1.0.0.ffx"
        for args, words in ((["--url", url], "(--key)"),
                            (["--url", url, "--key", ogkey + ".pub"], "is not signed with"),
                            (["--url", "http://example.org/x.ffx", "--key", key + ".pub"], "https://"),
                            (["--url", "https://me:pw@example.org/x.ffx", "--key", key + ".pub"], "https://")):
            rc, said = ffx_run("index", "record", signed, *args)
            check(rc == 1 and words in said, "record refused: %s", said)
        rc, said = ffx_run("index", "record", official, "--url", url, "--key", key + ".pub")
        check(rc == 1 and "endorses no author key" in said, "an official one takes no author key: %s", said)
        rc, said = ffx_run("index", "record", a1, "--url", url, "--key", key + ".pub")
        check(rc == 1 and "is not signed with" in said, "an unsigned archive: %s", said)
        rc, said = ffx_run("index", "record", signed, "--url", url, "--key", key + ".pub", "--out",
                           os.path.join(fxdir, "1.0.0.json"))
        check(rc == 0, "the fixture's record: %s", said)
        rc, said = ffx_run("index", "record", official, "--url", "https://example.org/official.ffx", "--official-key",
                           ogkey + ".pub", "--out", os.path.join(ogdir, "1.0.0.json"))
        check(rc == 0, "OpenGlow's own record, checked against its key: %s", said)
        rec = json.load(open(os.path.join(fxdir, "1.0.0.json")))
        data = open(signed, "rb").read()
        check(rec.get("sha256") == hashlib.sha256(data).hexdigest() and rec.get("size") == len(data) and rec.get("url") == url
              and rec.get("name") == "Fixture" and rec.get("capabilities") == ["machine.read"] and rec.get("api") == "0.1",
              "the record is the archive's own: %s", rec)

        def index_build(out, signer=None, version="2026.923.1"):
            return ffx_run("index", "build", cat, "--version", version, "--out", out,
                           *(["--key", signer + ".priv"] if signer else []))

        def host(*args):
            p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "--official-key", ogkey + ".pub"]
                               + list(args), capture_output=True, text=True)
            try:
                return json.loads(p.stdout)
            except ValueError:
                return {"ok": None, "error": p.stdout + p.stderr}

        # A catalog out of form is refused, and nothing is written.
        out = os.path.join(top, "index.ffi")
        saved = json.load(open(os.path.join(fxdir, "1.0.0.json")))

        def put(path, obj):
            with open(path, "w") as f:
                f.write(obj if isinstance(obj, str) else json.dumps(obj))
        for what, act, undo, words in (
                ("no key.pub", lambda: os.rename(os.path.join(fxdir, "key.pub"), os.path.join(top, "k")),
                 lambda: os.rename(os.path.join(top, "k"), os.path.join(fxdir, "key.pub")), "key.pub is missing"),
                ("a key in OpenGlow's namespace", lambda: shutil.copyfile(key + ".pub", os.path.join(ogdir, "key.pub")),
                 lambda: os.remove(os.path.join(ogdir, "key.pub")), "names no key"),
                ("a record under another version's name", lambda: put(os.path.join(fxdir, "1.0.1.json"), saved),
                 lambda: os.remove(os.path.join(fxdir, "1.0.1.json")), "is not the record of"),
                ("a record holding more", lambda: put(os.path.join(fxdir, "1.0.0.json"), dict(saved, stars=5)),
                 lambda: put(os.path.join(fxdir, "1.0.0.json"), saved), "holds what a record does not: stars"),
                ("a withdrawal of both kinds", lambda: put(os.path.join(fxdir, "withdrawn.json"),
                                                          {"reason": "x", "versions": {"0.9.0": "y"}}),
                 lambda: os.remove(os.path.join(fxdir, "withdrawn.json")), "withdrawn.json is"),
                ("a withdrawal with no reason", lambda: put(os.path.join(fxdir, "withdrawn.json"), {"versions": {"0.9.0": " "}}),
                 lambda: os.remove(os.path.join(fxdir, "withdrawn.json")), "withdrawn.json is"),
                ("withdrawn whole and still listed", lambda: put(os.path.join(fxdir, "withdrawn.json"), {"reason": "x"}),
                 lambda: os.remove(os.path.join(fxdir, "withdrawn.json")), "withdrawn whole and still lists 1.0.0"),
                ("a version both listed and withdrawn", lambda: put(os.path.join(fxdir, "withdrawn.json"),
                                                                   {"versions": {"1.0.0": "y"}}),
                 lambda: os.remove(os.path.join(fxdir, "withdrawn.json")), "both lists and withdraws org.example.fixture 1.0.0"),
                ("a package that lists nothing", lambda: os.makedirs(os.path.join(cat, "packages", "org.openglow.empty")),
                 lambda: shutil.rmtree(os.path.join(cat, "packages", "org.openglow.empty")), "lists no version")):
            act()
            rc, said = index_build(out)
            undo()
            check(rc == 1 and words in said and not os.path.exists(out), "%s: refused, and nothing written: %s", what, said)
        rc, said = index_build(out, version="2026.9")
        check(rc == 1 and "YYYY.MMDD.N" in said, "an index version that is none: %s", said)

        i1, i2 = os.path.join(top, "i1.ffi"), os.path.join(top, "i2.ffi")
        for o in (i1, i2):
            rc, said = index_build(o, ogkey)
            check(rc == 0 and "2 packages, 2 versions" in said, "built and signed: %s", said)
        check(open(i1, "rb").read() == open(i2, "rb").read(), "two builds of one catalog are one index")
        r = host("index-verify", i1)
        check(r.get("ok") is True and r.get("packages") == 2 and r.get("version") == "2026.923.1", "the host keeps it: %s", r)
        kept = {p["id"]: p for p in (host("index").get("index") or {}).get("packages", [])}
        mine = kept.get("org.example.fixture", {})
        v0 = (mine.get("versions") or [{}])[0]
        check(v0.get("sha256") == hashlib.sha256(data).hexdigest() and v0.get("size") == len(data) and v0.get("api") == "0.1"
              and mine.get("key") == open(key + ".pub").read().strip() and mine.get("name") == "Fixture"
              and v0.get("capabilities") == ["machine.read"] and mine.get("offer") == "1.0.0",
              "the entry is the archive's own: %s", mine)
        check("key" not in kept.get("org.openglow.fixture", {"key": 1}), "the official entry names no key")
        rc, said = index_build(out)
        check(rc == 0 and "UNSIGNED" in said, "unsigned, it says so: %s", said)
        r = host("index-verify", out)
        check(r.get("ok") is False and "not signed" in (r.get("error") or ""), "and the host keeps none of it: %s",
              r.get("error"))

        # Versions, a narrowed range, and withdrawals, as the host keeps them. A newer version of the fixture is
        # recorded beside the first, its range narrowed by hand; an older one withdrawn; OpenGlow's withdrawn whole.
        d2 = build(top, "a second version", with_(version="1.1.0"), {})
        signed2 = os.path.join(top, "signed2.ffx")
        check(ffx.main(["pack", d2, "--key", key + ".priv", "--out", signed2]) == 0, "1.1.0, packed and signed")
        rc, said = ffx_run("index", "record", signed2, "--url", "https://example.org/fixture-1.1.0.ffx", "--key", key + ".pub",
                           "--out", os.path.join(fxdir, "1.1.0.json"))
        check(rc == 0, "its record: %s", said)
        rec = json.load(open(os.path.join(fxdir, "1.1.0.json")))
        put(os.path.join(fxdir, "1.1.0.json"), dict(rec, core={"min": "0.0.9"}))
        put(os.path.join(fxdir, "withdrawn.json"), {"versions": {"0.9.0": "a flaw"}})
        os.remove(os.path.join(ogdir, "1.0.0.json"))
        put(os.path.join(ogdir, "withdrawn.json"), {"reason": "replaced"})
        rc, said = index_build(i1, ogkey, version="2026.923.2")
        check(rc == 0 and "1 package, 2 versions, 1 withdrawn whole" in said, "the catalog of versions and withdrawals: %s", said)
        r = host("index-verify", i1)
        check(r.get("ok") is True and r.get("packages") == 1, "the host keeps it: %s", r)
        p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "--official-key", ogkey + ".pub",
                            "--core-version", "0.0.8", "index"], capture_output=True, text=True)
        doc = json.loads(p.stdout).get("index") or {}
        fx = (doc.get("packages") or [{}])[0]
        vs = [(v.get("version"), v.get("usable")) for v in fx.get("versions", [])]
        check(vs == [("1.1.0", False), ("1.0.0", True)] and fx.get("offer") == "1.0.0"
              and fx.get("withdrawn") == [{"version": "0.9.0", "reason": "a flaw"}]
              and doc.get("withdrawn") == [{"id": "org.openglow.fixture", "reason": "replaced"}],
              "newest first, judged, the narrowed range honored, the withdrawals named: %s %s %s", vs, fx.get("withdrawn"),
              doc.get("withdrawn"))
        r = host("index-verify", i2)
        check(r.get("ok") is False and "older than the one kept here (2026.923.2)" in (r.get("error") or ""),
              "and the first index, older, is refused now: %s", r.get("error"))

        print("ffx's index form is the host's, doc by doc")
        serial = [2]

        def host_says(doc):
            serial[0] += 1
            work = tempfile.mkdtemp(dir=top)
            idxjson = os.path.join(work, "index.json")
            with open(idxjson, "w") as f:
                json.dump(doc, f)
            pl = os.path.join(work, "payload.tar.gz")
            subprocess.run(["tar", "-C", work, "-czf", pl, "index.json"], check=True)
            conf = os.path.join(work, "fwup.conf")
            with open(conf, "w") as f:
                f.write('meta-product = "ForgeFIRM extension index"\nmeta-version = "2026.923.%d"\n'
                        'meta-platform = "forgefirm-ext"\nfile-resource payload.tar.gz {\n    host-path = "%s"\n}\n'
                        % (serial[0], pl))
            raw, sig = os.path.join(work, "i.raw"), os.path.join(work, "i.ffi")
            subprocess.run([FWUP, "-c", "-f", conf, "-o", raw], check=True, capture_output=True)
            subprocess.run([FWUP, "-S", "-s", ogkey + ".priv", "-i", raw, "-o", sig], check=True, capture_output=True)
            r = host("index-verify", sig)
            return None if r.get("ok") is True else (r.get("error") or "")
        k = open(key + ".pub").read().strip()
        v = {"version": "1.0.0", "url": "https://example.org/x.ffx", "sha256": "0f" * 32, "size": 9}
        pk = {"id": "org.example.a", "name": "A", "author": "T", "key": k, "versions": [v]}
        docs = [
            {"index": 1, "packages": [pk]},
            {"index": 1, "packages": [pk], "later": {"any": "thing"}},
            {"index": 1.0, "packages": []},
            {"index": 1, "packages": [pk, pk]},
            {"index": 1, "packages": [dict(pk, name="")]},
            {"index": 1, "packages": [dict(pk, homepage="ftp://x")]},
            {"index": 1, "packages": [dict(pk, homepage=None)]},
            {"index": 1, "packages": [dict(pk, key=None)]},
            {"index": 1, "packages": [dict(pk, id="org.forgefirm.a")]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, size=True)])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, size=-1)])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, url="https://a@b/")])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, url="https://b/@a")])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, capabilities=["x" * 256])])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, capabilities=["unheard.of"])])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, api=None)])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, core={"min": None})])]},
            {"index": 1, "packages": [dict(pk, versions=[dict(v, core={"later": "1"})])]},
            {"index": 1, "packages": [dict(pk, withdrawn=[{"version": "0.1.0"}, {"version": "0.1.0"}])]},
            {"index": 1, "packages": [dict(pk, withdrawn=[{"version": "0.1.0", "reason": 5}])]},
            {"index": 1, "packages": [], "withdrawn": None},
            {"index": 1, "packages": [], "withdrawn": [{"id": "org.example.b", "key": k}, {"id": "org.example.b", "key": k}]},
            {"index": 1, "packages": [], "withdrawn": [{"id": "org.openglow.b"}]},
        ]
        for doc in docs:
            try:
                ffx.index_check(doc)
                mine = None
            except ffx.Refused as e:
                mine = str(e)
            theirs = host_says(doc)
            check(mine == theirs, "%s: the host says %s, ffx says %s", json.dumps(doc)[:90], theirs, mine)

        machine_client(ffx, top, a1)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
