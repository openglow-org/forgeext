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
for each runtime that lints as its template says; and `ffx keygen` refuses to
overwrite a key.

Needs fwup (FWUP) and the built forgeext (FORGEEXT). Exits 77 without them.
"""
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

        print("ffx new: a package for each runtime")
        for runtime, lints in (("ui", True), ("python", True), ("shell", True), ("data", True), ("native", False)):
            d = os.path.join(top, "new-" + runtime)
            rc = ffx.main(["new", d, "--id", "org.example.new" + runtime, "--runtime", runtime])
            try:
                ffx.lint(d)
                ok, why = True, ""
            except ffx.Refused as e:
                ok, why = False, str(e)
            check(rc == 0 and ok == lints, "%s: made, and %s%s", runtime, "lints" if lints else "wants its binary built",
                  (": " + why) if why else "")
            if runtime == "ui":
                page = open(os.path.join(d, "ui", "index.html")).read()
                check("var ffx = (function" in page and "@@" not in page, "the page carries the bridge client")
            if runtime == "native":
                check("entry point, bin/run" in why and os.path.isfile(os.path.join(d, "src", "ffx.h")),
                      "and says so, with ffx.h beside its source: %s", why)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
