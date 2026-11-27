#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""End-to-end host test of forgeext's verify-and-install path.

Drives the built binary (FORGEEXT, default build/forgeext) against real
archives made with fwup (FWUP, default fwup on PATH) and throwaway keys:
the three tiers and what each needs from the operator, the product gate
in both of its directions, a firmware key on an extension, a payload that
is not the one the signed metadata names, payloads that try to leave the
package, the namespace, key pinning across an update, the capability diff,
conflicts, the budget, the integrity check, `current` left by a crash on
a version the state does not name and turned back at the next prepare
of the root, what a prepare sweeps and what it leaves (a staging still
held by its command, an entry under pkg/ that is no package id), the page
a package serves
(as it shipped, and none when it is not installed or disabled), removal,
the wipe a change of
owner takes (every package, everything under data/ and settings/, every
key the owner added), and the signed index (kept only under the OpenGlow index key, never the extension key,
held to its form, never older than the one kept, endorsing its author key
for one id and no other, judged version by version against the firmware
when read, and what it withdraws). After every refusal the root holds
nothing the refused archive brought.

    python3 tests/install_test.py [-v]

Exits 0 on a pass, 1 on a failure, 77 when fwup or the binary is missing.
"""
import fcntl
import io
import json
import os
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
FWUP = os.environ.get("FWUP") or shutil.which("fwup")
MKFFX = os.path.join(HERE, "..", "tools", "mkffx.sh")
VERBOSE = "-v" in sys.argv[1:]

failures = []
checks = 0


def check(ok, what):
    global checks
    checks += 1
    if VERBOSE or not ok:
        print("  %s  %s" % ("ok  " if ok else "FAIL", what), flush=True)
    if not ok:
        failures.append(what)


class World:
    """One extension root, five key pairs, and the forgeext command line over them."""

    def __init__(self, top):
        self.top = top
        self.root = os.path.join(top, "root")
        self.keys = {}
        for name in ("official", "index", "owner", "stranger", "firmware"):
            d = os.path.join(top, "key-" + name)
            os.mkdir(d)
            subprocess.run([FWUP, "-g"], cwd=d, check=True, capture_output=True)
            self.keys[name] = os.path.join(d, "fwup-key.priv")
        os.makedirs(os.path.join(self.root, "keys"))
        shutil.copy(self.pub("owner"), os.path.join(self.root, "keys", "a-friend.pub"))
        self.holds = os.path.join(top, "holds")       # the hold files a disable, a removal or an advisory mark takes away
        os.mkdir(self.holds)
        self.n = 0

    def pub(self, name):
        return self.keys[name][:-5] + ".pub"

    def run(self, *args, budget=None, core=None, pre=None, fwup=None):
        """forgeext's answer; pre runs in the child before the exec (limits), fwup is another fwup to use."""
        cmd = [FORGEEXT, "--root", self.root, "--fwup", fwup or FWUP, "--official-key", self.pub("official"),
               "--index-key", self.pub("index"), "--firmware-key", self.pub("firmware"), "--no-reserve",
               "--holds-dir", self.holds]
        cmd += (["--budget-mib", str(budget)] if budget else [])
        cmd += (["--core-version", core] if core else []) + list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, preexec_fn=pre)
        try:
            out = json.loads(p.stdout)
        except ValueError:
            out = {"ok": None, "error": "not JSON: %r %r" % (p.stdout[:200], p.stderr[:200])}
        if VERBOSE:
            print("    $ forgeext %s -> %s %s" % (" ".join(args)[:100], p.returncode, out.get("error", "")))
        check((p.returncode == 0) == (out.get("ok") is True), "the exit status agrees with \"ok\" (%s)" % " ".join(args)[:60])
        return out

    def path(self, name):
        self.n += 1
        return os.path.join(self.top, "%03d-%s" % (self.n, name))

    def tree(self, manifest, files=None):
        """A package directory: the manifest and files {path: (text, mode)}."""
        d = self.path("pkg")
        os.mkdir(d)
        with open(os.path.join(d, "manifest.json"), "w") as f:
            f.write(json.dumps(manifest, indent=1) + "\n")
        for rel, (text, mode) in (files or {}).items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
            os.chmod(p, mode)
        return d

    def pack(self, tree, key=None):
        out = self.path("pkg.ffx")
        cmd = ["sh", MKFFX, tree, out] + ([self.keys[key]] if key else [])
        subprocess.run(cmd, check=True, capture_output=True, env=dict(os.environ, FWUP=FWUP))
        return out

    def pack_raw(self, payload, version, key=None, product="ForgeFIRM extension", extra=""):
        """An archive made by hand, for what mkffx.sh will not make."""
        conf = self.path("fwup.conf")
        out = self.path("raw.ffx")
        with open(conf, "w") as f:
            f.write('meta-product = "%s"\nmeta-version = "%s"\nmeta-platform = "forgefirm-ext"\n'
                    'file-resource payload.tar.gz {\n    host-path = "%s"\n}\n%s' % (product, version, payload, extra))
        subprocess.run([FWUP, "-c", "-f", conf, "-o", out], check=True, capture_output=True)
        if key:
            signed = self.path("raw-signed.ffx")
            subprocess.run([FWUP, "-S", "-s", self.keys[key], "-i", out, "-o", signed], check=True, capture_output=True)
            return signed
        return out

    def tar(self, members):
        """payload.tar.gz from (TarInfo, bytes or None) pairs: whatever a hostile packer could write."""
        out = self.path("payload.tar.gz")
        with tarfile.open(out, "w:gz") as t:
            for info, data in members:
                t.addfile(info, io.BytesIO(data) if data is not None else None)
        return out

    def leftovers(self):
        tmp = os.path.join(self.root, "tmp")
        return os.listdir(tmp) if os.path.isdir(tmp) else []


def manifest(id_, version="1.0.0", runtime="shell", caps=(), **more):
    m = {"manifest": 1, "id": id_, "name": id_.split(".")[-1], "version": version, "author": "Test",
         "license": "MIT", "api": "0.1", "runtime": runtime, "capabilities": list(caps)}
    if runtime in ("shell", "native", "python"):
        m["service"] = {"exec": "bin/run.sh"}
    m.update(more)
    return m


RUN = {"bin/run.sh": ("#!/bin/sh\nexec sleep 3600\n", 0o755), "share/notes.txt": ("notes\n", 0o644)}


def member(name, data=b"x", type_=tarfile.REGTYPE, linkname="", mode=0o644, pax=None):
    info = tarfile.TarInfo(name)
    info.type = type_
    info.linkname = linkname
    info.mode = mode
    info.pax_headers = dict(pax or {})
    info.size = len(data) if type_ == tarfile.REGTYPE else 0
    return info, (data if type_ == tarfile.REGTYPE else None)


def manifest_member(m):
    return member("manifest.json", json.dumps(m).encode())


def core_range(t):
    """A package's "core" range against the firmware's own version. The
    version comes from the command line here, in the same form the machine
    reads from /etc/forgefirm-version: "v0.0.6" on a release image, and on
    a dev image a build stamp that is no version at all, and then there is
    nothing to compare and nothing is refused."""
    a = t.pack(t.tree(manifest("org.example.core", core={"min": "0.0.7"}), RUN), "owner")
    r = t.run("inspect", a, core="0.0.9")
    check(r.get("ok") is True and r.get("core_checked") is True,
          "core.min 0.0.7 on firmware 0.0.9 is taken: %s" % r.get("error"))
    r = t.run("inspect", a, core="0.0.5")
    check(r.get("ok") is False and "0.0.7 or newer" in (r.get("error") or ""),
          "core.min 0.0.7 on firmware 0.0.5 is refused: %s" % r.get("error"))
    r = t.run("inspect", a, core="0.0.7")
    check(r.get("ok") is True, "core.min is a floor the firmware may stand on: %s" % r.get("error"))

    b = t.pack(t.tree(manifest("org.example.core2", core={"max": "0.0.7"}), RUN), "owner")
    r = t.run("inspect", b, core="0.0.9")
    check(r.get("ok") is False and "0.0.7 or older" in (r.get("error") or ""),
          "core.max 0.0.7 on firmware 0.0.9 is refused: %s" % r.get("error"))
    r = t.run("inspect", b, core="0.0.5")
    check(r.get("ok") is True, "core.max 0.0.7 on firmware 0.0.5 is taken: %s" % r.get("error"))

    # The form a machine actually holds. /etc/forgefirm-version is written
    # "v<version>" by the image build, and a range judged only against a
    # bare version would be judged on no release image at all.
    r = t.run("inspect", a, core="v0.0.9")
    check(r.get("ok") is True and r.get("core_checked") is True,
          "a release image's own \"v0.0.9\" is a version: %s" % r)
    r = t.run("inspect", a, core="v0.0.5")
    check(r.get("ok") is False and "0.0.7 or newer" in (r.get("error") or ""),
          "and it is judged, not skipped: %s" % r.get("error"))

    # A build stamp is no version: nothing to compare against, and the
    # answer says so rather than leaving it to be guessed at.
    r = t.run("inspect", a, core="20260921190848")
    check(r.get("ok") is True and r.get("core_checked") is False,
          "a build stamp judges nothing, and says so: %s" % r)
    r = t.run("inspect", a, core="")
    check(r.get("ok") is True and r.get("core_checked") is False,
          "no firmware version judges nothing: %s" % r)

    # It is a gate on installing, not only on looking.
    r = t.run("install", a, core="0.0.5")
    check(r.get("ok") is False and "0.0.7 or newer" in (r.get("error") or ""),
          "the range is a gate on the install too: %s" % r.get("error"))
    check("org.example.core" not in [x.get("id") for x in t.run("list").get("packages", [])],
          "a package refused by its core range was installed anyway")


def operator_destinations(t):
    """The destinations the operator names for a package that asks for
    them: kept across an update that still asks, gone with one that does
    not, and never more than a service's ports hold."""
    D = "org.example.plugs"
    lists = lambda: {x["id"]: x.get("destinations") for x in t.run("list").get("packages", [])}  # noqa: E731
    page = t.tree(manifest("org.example.plugpage", runtime="ui", caps=["ui", "net.outbound.operator"]),
                  {"ui/index.html": ("<p>a page</p>\n", 0o644)})
    r = t.run("inspect", t.pack(page, "official"))
    check("belongs to a service" in (r.get("error") or ""), "a page with no service asking for them -> %s" % r.get("error"))
    v1 = t.pack(t.tree(manifest(D, caps=["net.outbound.operator", "net.outbound:api.example.org:443"]), RUN), "official")
    check(t.run("install", v1).get("ok") is True, "a package that asks for the operator's destinations installs")
    check(lists().get(D) == [], "and has none until the operator names one: %s" % lists().get(D))
    for dest in ("plug.lan:80", "192.0.2.7:1883"):
        r = t.run("dest", D, "add", dest)
        check(r.get("ok") is True and dest in r.get("destinations", []), "the operator names %s: %s" % (dest, r))
    for dest, words in (("[::1]:80", "is this machine"), ("127.0.0.5:80", "is this machine"), ("plug.lan", "host:port"),
                        ("Plug.LAN:80", "host:port"), ("plug.lan:0", "host:port"), ("plug.lan:80", "already")):
        r = t.run("dest", D, "add", dest)
        check(r.get("ok") is False and words in (r.get("error") or ""), "dest add %s -> %s" % (dest, r.get("error")))
    v2 = t.pack(t.tree(manifest(D, version="1.1.0", caps=["net.outbound.operator", "net.outbound:api.example.org:443"]), RUN),
                "official")
    check(t.run("install", v2).get("ok") is True and lists().get(D) == ["plug.lan:80", "192.0.2.7:1883"],
          "an update that still asks keeps them: %s" % lists().get(D))
    many = ["net.outbound:api%d.example.org:443" % i for i in range(14)]
    v3 = t.pack(t.tree(manifest(D, version="1.2.0", caps=["net.outbound.operator"] + many), RUN), "official")
    r = t.run("install", v3)
    check(r.get("ok") is False and "the operator named 2 destinations" in (r.get("error") or "")
          and lists().get(D) == ["plug.lan:80", "192.0.2.7:1883"],
          "an update whose own 14 and the operator's 2 are more than a service has -> %s" % r.get("error"))
    v4 = t.pack(t.tree(manifest(D, version="1.3.0", caps=["net.outbound:api.example.org:443"]), RUN), "official")
    check(t.run("install", v4).get("ok") is True and lists().get(D) == [],
          "an update that no longer asks keeps none of them: %s" % lists().get(D))
    r = t.run("dest", D, "add", "plug.lan:80")
    check(r.get("ok") is False and "does not ask for destinations" in (r.get("error") or ""), "and takes none -> %s" % r.get("error"))
    check(t.run("remove", D).get("ok") is True, "the package goes")


def mcodes(t):
    """An M-code is one package's, and it is answered during a job, which takes job_time.run."""
    r = t.run("inspect", t.pack(t.tree(manifest("org.example.mc0", runtime="python", caps=["mcode:170"]), RUN), "owner"))
    check(r.get("ok") is False and "which takes job_time.run" in (r.get("error") or ""),
          "mcode with no job_time.run -> %s" % r.get("error"))
    for cap in ("mcode:159", "mcode:180", "mcode:0170", "mcode", "mcode:17x"):
        r = t.run("inspect", t.pack(t.tree(manifest("org.example.mc1", caps=[cap, "job_time.run"]), RUN), "owner"))
        check(r.get("ok") is False and "mcode" in (r.get("error") or ""), "%s -> %s" % (cap, r.get("error")))
    a = t.pack(t.tree(manifest("org.example.mca", runtime="python", caps=["mcode:170", "mcode:171", "job_time.run"]), RUN), "owner")
    r = t.run("install", a, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is True, "a package answering M170 and M171 installs: %s" % r.get("error"))
    b = t.pack(t.tree(manifest("org.example.mcb", runtime="python", caps=["mcode:171", "job_time.run"]), RUN), "owner")
    r = t.run("install", b, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is False and "org.example.mca, which is installed, already answers M171" in (r.get("error") or ""),
          "a second package answering M171 -> %s" % r.get("error"))
    c = t.pack(t.tree(manifest("org.example.mcb", runtime="python", caps=["mcode:172", "job_time.run"]), RUN), "owner")
    r = t.run("install", c, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is True, "another number is its own: %s" % r.get("error"))
    for id_ in ("org.example.mca", "org.example.mcb"):
        check(t.run("remove", id_).get("ok") is True, "%s goes" % id_)


def background_page(t):
    """A page kept running while the panel shows another tab is the operator's to grant, and only a page's."""
    page = {"ui/index.html": ("<p>a page</p>\n", 0o644)}
    r = t.run("inspect", t.pack(t.tree(manifest("org.example.bg0", caps=["ui.background"]), RUN), "owner"))
    check(r.get("ok") is False and "which takes ui: ask for it too" in (r.get("error") or ""),
          "ui.background with no page -> %s" % r.get("error"))
    a = t.pack(t.tree(manifest("org.example.bg", runtime="ui", caps=["ui", "ui.background"]), page), "owner")
    r = t.run("inspect", a)
    check(r.get("ok") is True and r.get("needs_grant") == ["ui.background"], "inspect names the grant: %s" % r)
    r = t.run("install", a, "--consent-unverified")
    check(r.get("ok") is False and "only the operator grants: ui.background" in (r.get("error") or ""),
          "no grant -> %s" % r.get("error"))
    r = t.run("install", a, "--consent-unverified", "--grant", "ui.background")
    check(r.get("ok") is True, "installed with the grant: %s" % r.get("error"))
    b = t.pack(t.tree(manifest("org.example.fg", runtime="ui", caps=["ui"]), page), "owner")
    r = t.run("install", b, "--consent-unverified", "--grant", "ui.background")
    check(r.get("ok") is False and "does not ask for" in (r.get("error") or ""),
          "a grant for a page that does not ask -> %s" % r.get("error"))
    check(t.run("install", b, "--consent-unverified").get("ok") is True, "a page of its own installs with no grant")
    pk = {x["id"]: x for x in t.run("list").get("packages", [])}
    check("ui.background" in (pk.get("org.example.bg") or {}).get("effective", [])
          and (pk.get("org.example.bg") or {}).get("grants") == ["ui.background"],
          "granted, it holds it: %s" % pk.get("org.example.bg"))
    check("ui.background" not in (pk.get("org.example.fg") or {}).get("effective", ["ui.background"])
          and "ui" in (pk.get("org.example.fg") or {}).get("effective", []),
          "not asked for, it does not: %s" % pk.get("org.example.fg"))
    for id_ in ("org.example.bg", "org.example.fg"):
        check(t.run("remove", id_).get("ok") is True, "%s goes" % id_)


def the_page(t):
    """forgeext ui: the page an installed package shipped, byte for byte, and none for a package that is
    not installed or that the operator disabled. And the operator's enable, counted in state.json, which is
    how the host tells an enable that came after a quarantine it could not write."""
    P = "org.example.page"
    tree = t.tree(manifest(P, runtime="ui", caps=["ui"]),
                  {"ui/index.html": ("<!doctype html>\n<p class=\"a\">été \\ 'q'\t</p>\n<script>x = \"</p>\";</script>\n",
                                     0o644)})
    with open(os.path.join(tree, "ui", "index.html"), "rb") as f:
        shipped = f.read()
    check(t.run("install", t.pack(tree, "official")).get("ok") is True, "a package with a page installs")
    r = t.run("ui", P)
    check(r.get("ok") is True and (r.get("html") or "").encode() == shipped and r.get("bytes") == len(shipped),
          "its page, as it shipped (%d bytes): %s" % (len(shipped), {k: r.get(k) for k in ("ok", "bytes", "error")}))
    r = t.run("ui", "org.example.nothere")
    check(r.get("ok") is False and r.get("error") == "that package is not installed", "a package not installed -> %s" % r.get("error"))
    check(t.run("disable", P).get("ok") is True, "the operator disables it")
    r = t.run("ui", P)
    check(r.get("ok") is False and r.get("error") == "this package is disabled: its interface is not served" and "html" not in r,
          "disabled -> %s" % r.get("error"))

    def record():
        with open(os.path.join(t.root, "state.json")) as f:
            return json.load(f)["packages"][P]
    before = record().get("enables")
    check(t.run("enable", P).get("ok") is True and before == 0 and record().get("enables") == 1
          and t.run("enable", P).get("ok") is True and record().get("enables") == 2,
          "every enable is counted: %s, then %s" % (before, record()))
    check(t.run("remove", P).get("ok") is True, "the package goes")


def the_index(t):
    """The signed index: verified only under the OpenGlow extension key, held to its form, never older than the
    one kept, binding an id to an author key the owner never added - for that id and no other - and judged
    version by version against this firmware when it is read. And what it says was withdrawn."""
    ffx = os.path.join(HERE, "..", "tools", "ffx")
    adir = t.path("author")
    os.mkdir(adir)
    subprocess.run([FWUP, "-g"], cwd=adir, check=True, capture_output=True)
    t.keys["author"] = os.path.join(adir, "fwup-key.priv")
    author_pub = open(t.pub("author")).read().strip()
    owner_pub = open(t.pub("owner")).read().strip()
    listed = t.pack(t.tree(manifest("org.example.listed"), RUN), "author")
    other = t.pack(t.tree(manifest("org.example.other"), RUN), "author")
    r = t.run("inspect", listed)
    check(r.get("tier") == "unverified", "an author's key the owner never added: unverified (%s)" % r.get("tier"))
    check(t.run("index").get("index") is None, "no index is kept yet")
    serial = [0]

    def next_version():
        serial[0] += 1
        return "2026.901.%d" % serial[0]

    # Built the way OpenGlow builds it: a record per version from its signed archive, then the catalog.
    def build(entries, key="index", version=None):
        d = t.path("catalog")
        for e in entries:
            p = subprocess.run([sys.executable, "-B", ffx, "index", "record", e, "--url",
                                "https://example.org/" + os.path.basename(e), "--key", t.pub("author")],
                               capture_output=True, text=True, env=dict(os.environ, FWUP=FWUP))
            check(p.returncode == 0, "ffx index record: %s" % p.stderr.strip())
            m = json.loads(p.stdout)
            pdir = os.path.join(d, "packages", m["id"])
            os.makedirs(pdir, exist_ok=True)
            shutil.copy(t.pub("author"), os.path.join(pdir, "key.pub"))
            with open(os.path.join(pdir, m["version"] + ".json"), "w") as f:
                json.dump(m, f)
        os.makedirs(os.path.join(d, "packages"), exist_ok=True)
        out = os.path.join(d, "index.ffi")
        p = subprocess.run([sys.executable, "-B", ffx, "index", "build", d, "--version", version or next_version(),
                            "--out", out] + (["--key", t.keys[key]] if key else []),
                           capture_output=True, text=True, env=dict(os.environ, FWUP=FWUP))
        check(p.returncode == 0, "ffx index build: %s" % p.stderr.strip())
        return out

    idx = build([listed], version="2026.900.1")
    fresh = t.path("fresh-root")
    p = subprocess.run([FORGEEXT, "--root", fresh, "--fwup", FWUP, "--index-key", t.pub("index"), "--no-reserve",
                        "index-verify", idx], capture_output=True, text=True)
    check('"ok":true' in p.stdout.replace(" ", ""), "the catalog can be the first thing a root holds: %s" % p.stdout.strip())
    idx = build([listed])
    r = t.run("index-verify", idx)
    check(r.get("ok") is True and r.get("packages") == 1 and r.get("version") == "2026.901.1", "the index is kept: %s" % r)
    got = t.run("index")
    kept = (got.get("index") or {}).get("packages") or [{}]
    v0 = (kept[0].get("versions") or [{}])[0]
    check(kept[0].get("id") == "org.example.listed" and len(kept[0].get("key_id", "")) == 64 and v0.get("size", 0) > 0
          and v0.get("api") == "0.1" and v0.get("usable") is True and kept[0].get("offer") == "1.0.0",
          "and read back, with the endorsed key's id, judged usable here: %s" % kept[0])
    check(got.get("core_checked") is False, "no firmware version given: the ranges are not judged, and it says so: %s"
          % got.get("core_checked"))
    r = t.run("inspect", listed)
    check(r.get("tier") == "community" and r.get("endorsed") is True, "the listed package, signed by its endorsed key: "
          "community, endorsed (%s %s)" % (r.get("tier"), r.get("endorsed")))
    r = t.run("inspect", other)
    check(r.get("tier") == "unverified" and r.get("endorsed") is False,
          "the same key on another id counts for nothing: %s" % r.get("tier"))
    r = t.run("install", listed, "--consent-community")
    check(r.get("ok") is True and r.get("tier") == "community", "it installs as community: %s" % r.get("error", r.get("tier")))

    # An index the host does not keep, each refused in its words, the kept one left as it was.
    # The extension key that signs OpenGlow's packages signs no index.
    for key, words in (("official", "not signed with the OpenGlow index key"),
                       ("owner", "not signed with the OpenGlow index key"), (None, "not signed with the OpenGlow")):
        r = t.run("index-verify", build([listed], key=key))
        check(r.get("ok") is False and words in (r.get("error") or ""), "an index signed by %s -> %s" % (key or "nobody", r.get("error")))
    r = t.run("index-verify", listed)
    check(r.get("ok") is False and "product" in (r.get("error") or ""), "a package given as the index -> %s" % r.get("error"))

    def raw_index(doc, version=None, extra=None):
        members = [member("index.json", json.dumps(doc).encode())] + (extra or [])
        return t.pack_raw(t.tar(members), version or next_version(), "index", product="ForgeFIRM extension index")

    def ver(v, **more):
        e = {"version": v, "url": "https://example.org/x-%s.ffx" % v, "sha256": "ab" * 32, "size": 1000,
             "capabilities": [], "api": "0.1"}
        e.update(more)
        return e

    def pkg(id_, versions, key=author_pub, **more):
        e = {"id": id_, "name": id_.split(".")[-1], "author": "Test", "versions": versions}
        if key:
            e["key"] = key
        e.update(more)
        return e

    good = pkg("org.example.listed", [ver("1.0.0")])
    for doc, words in (({"index": 2, "packages": []}, "an index is"),
                       ({"index": 1, "packages": [good, good]}, "lists org.example.listed twice"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", url="http://example.org/x.ffx")])]},
                        "https://"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", url="https://u:pw@example.org/x")])]},
                        "no user or password"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", sha256="ABC")])]}, "sha256"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", size=0)])]}, "whole number"),
                       ({"index": 1, "packages": [pkg("org.openglow.fake", [ver("1.0.0")])]}, "OpenGlow's namespace"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0")], key=None)]}, "author's public key"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0")],
                                                      key="bm90IGEga2V5IGF0IGFsbCwgbm90IGFueSBvZiBpdCEhIQ==")]},
                        "no Ed25519 public key"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [])]}, "versions are a list of 1 to 16"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.%d" % i) for i in range(17)])]},
                        "versions are a list of 1 to 16"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0"), ver("1.0.0")])]},
                        "lists org.example.listed 1.0.0 twice"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("v1")])]}, "a listed version is not one"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", core={"min": "0.0.9", "max": "0.0.7"})])]},
                        "min is above its max"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", core={"min": "latest"})])]},
                        "core range is"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0", capabilities=["machine read"])])]},
                        "printable text with no space"),
                       ({"index": 1, "packages": [pkg("org.example.listed", [ver("1.0.0")],
                                                      withdrawn=[{"version": "1.0.0", "reason": "x"}])]},
                        "both lists and withdraws org.example.listed 1.0.0"),
                       ({"index": 1, "packages": [good], "withdrawn": [{"id": "org.example.listed", "key": author_pub}]},
                        "both lists and withdraws org.example.listed"),
                       ({"index": 1, "packages": [], "withdrawn": [{"id": "org.openglow.gone", "key": author_pub}]},
                        "OpenGlow's namespace"),
                       ({"index": 1, "packages": [pkg("org.example.p%d" % i, [ver("1.0.0")]) for i in range(513)]},
                        "at most 512")):
        r = t.run("index-verify", raw_index(doc))
        check(r.get("ok") is False and words in (r.get("error") or ""), "%s -> %s" % (words, r.get("error")))
    r = t.run("index-verify", raw_index({"index": 1, "packages": []}, extra=[member("extra.txt", b"x")]))
    check(r.get("ok") is False and "nothing else" in (r.get("error") or ""), "an index with a second file -> %s" % r.get("error"))
    r = t.run("index-verify", raw_index({"index": 1, "packages": [good]}, version="latest"))
    check(r.get("ok") is False and "not a version" in (r.get("error") or ""), "an index whose version is none -> %s" % r.get("error"))
    check(((t.run("index").get("index") or {}).get("packages") or [{}])[0].get("id") == "org.example.listed",
          "every refused index left the kept one as it was")

    # Never back: an older index is refused, however well signed; the same version again is kept.
    kept_version = t.run("index")["index"]["version"]
    r = t.run("index-verify", raw_index({"index": 1, "packages": []}, version="2026.831.9"))
    check(r.get("ok") is False and "older than the one kept here (%s)" % kept_version in (r.get("error") or ""),
          "an older index -> %s" % r.get("error"))
    r = t.run("index-verify", raw_index({"index": 1, "packages": [good]}, version=kept_version))
    check(r.get("ok") is True, "the same version again is kept: %s" % r.get("error"))

    # A field this host does not know is passed over, at every level: a newer catalog is still kept here.
    future = dict(good, future={"x": 1}, versions=[ver("1.0.0", future=[1, 2])])
    r = t.run("index-verify", raw_index({"index": 1, "packages": [future], "future": True}))
    check(r.get("ok") is True, "unknown fields are passed over: %s" % r.get("error"))

    # Judged when read, version by version, against this firmware. A version this firmware cannot run is kept,
    # and not offered; the newest one it can run is.
    span = pkg("org.example.span", [
        ver("3.0.0", core={"min": "0.0.9"}),
        ver("2.0.0", capabilities=["machine.read", "frobnicate"]),
        ver("1.5.0", api="0.2"),
        ver("1.4.0", size=33 * 1024 * 1024),
        ver("1.3.0", capabilities=["role:homing"]),
        ver("1.2.0", core={"max": "0.0.7"}),
        ver("1.1.0", capabilities=["machine.read"]),
        ver("1.0.0")])
    none_here = pkg("org.example.later", [ver("1.0.0", core={"min": "0.0.9"})])
    r = t.run("index-verify", raw_index({"index": 1, "packages": [good, span, none_here]}))
    check(r.get("ok") is True and r.get("packages") == 3, "an index of many versions is kept: %s" % r)

    def judged(core):
        got = t.run("index", core=core)
        pk = {p["id"]: p for p in (got.get("index") or {}).get("packages", [])}
        return got, pk, {v["version"]: v for v in pk.get("org.example.span", {}).get("versions", [])}
    got, pk, vs = judged("0.0.8")
    for v, words in (("3.0.0", "needs firmware 0.0.9 or newer, and this is 0.0.8"),
                     ("2.0.0", "frobnicate is not a capability"),
                     ("1.5.0", "built for extension API 0.2"),
                     ("1.4.0", "larger than this firmware takes"),
                     ("1.3.0", "role"),
                     ("1.2.0", "needs firmware 0.0.7 or older")):
        check(vs.get(v, {}).get("usable") is False and words in vs.get(v, {}).get("why", ""),
              "on 0.0.8, %s is not offered: %s" % (v, vs.get(v)))
    check(vs.get("1.1.0", {}).get("usable") is True and "why" not in vs.get("1.1.0", {}) and vs["1.0.0"].get("usable") is True,
          "and 1.1.0 and 1.0.0 are: %s %s" % (vs.get("1.1.0"), vs.get("1.0.0")))
    check(pk["org.example.span"].get("offer") == "1.1.0", "the offer is the newest it runs: %s" % pk["org.example.span"].get("offer"))
    check(pk["org.example.later"].get("offer") is None and got.get("core_checked") is True and got.get("core_version") == "0.0.8"
          and pk["org.example.later"].get("why") == "org.example.later 1.0.0 needs firmware 0.0.9 or newer, and this is 0.0.8",
          "a package with no version this firmware runs is offered none, and says why: %s" % pk["org.example.later"])
    check("why" not in pk["org.example.span"], "one that is offered a version has no why: %s" % pk["org.example.span"].get("why"))
    got, pk, vs = judged("v0.0.9")
    check(vs["3.0.0"].get("usable") is True and pk["org.example.span"].get("offer") == "3.0.0"
          and pk["org.example.later"].get("offer") == "1.0.0",
          "after a firmware update, the same kept index offers what it now runs: %s" % pk["org.example.span"].get("offer"))
    got, pk, vs = judged("20260925205500")
    check(got.get("core_checked") is False and vs["3.0.0"].get("usable") is True and vs["1.2.0"].get("usable") is True
          and vs["2.0.0"].get("usable") is False and pk["org.example.span"].get("offer") == "3.0.0",
          "a build stamp judges no range, and still judges the rest: %s" % pk["org.example.span"].get("offer"))
    check(t.run("index")["index"]["packages"][1]["versions"][0].get("why", "") == ""
          and "usable" not in open(os.path.join(t.root, "index", "index.json")).read(),
          "the judgment is the reading's, never written into the index kept")

    # Withdrawn: one version of a listed package, or a package whole. The key the catalog names for the id is
    # what makes an archive the listed package; the same id under another key is another package.
    wd = t.pack(t.tree(manifest("org.example.wd"), RUN), "author")
    wd11 = t.pack(t.tree(manifest("org.example.wd", version="1.1.0"), RUN), "author")
    wd_stranger = t.pack(t.tree(manifest("org.example.wd2"), RUN), "stranger")
    wd_owner = t.pack(t.tree(manifest("org.example.wd3"), RUN), "owner")
    og = t.pack(t.tree(manifest("org.openglow.wdprobe"), RUN), "official")
    lists = lambda: {x["id"]: x for x in t.run("list").get("packages", [])}  # noqa: E731
    r = t.run("index-verify", raw_index({"index": 1, "packages": [good, pkg("org.example.wd", [ver("1.0.0"), ver("1.1.0")])]}))
    check(r.get("ok") is True, "an index listing org.example.wd: %s" % r.get("error"))
    r = t.run("inspect", wd)
    check(r.get("tier") == "community" and r.get("endorsed") is True,
          "one author's key, endorsed for two ids, speaks for the second as well as the first: %s %s"
          % (r.get("tier"), r.get("error")))
    r = t.run("install", wd, "--consent-community")
    check(r.get("ok") is True, "org.example.wd 1.0.0 installs as community: %s" % r.get("error"))
    r = t.run("install", og)
    check(r.get("ok") is True, "org.openglow.wdprobe 1.0.0 installs as official: %s" % r.get("error"))
    check(lists()["org.example.wd"].get("withdrawn") is None, "and nothing is withdrawn yet: %s" % lists()["org.example.wd"])
    r = t.run("index-verify", raw_index({"index": 1, "packages": [
        good,
        pkg("org.example.wd", [ver("1.1.0")], withdrawn=[{"version": "1.0.0", "reason": "a flaw in 1.0.0"}]),
        pkg("org.example.wd2", [ver("2.0.0")], withdrawn=[{"version": "1.0.0", "reason": "x"}]),
        pkg("org.example.wd3", [ver("2.0.0")], key=owner_pub, withdrawn=[{"version": "1.0.0", "reason": "y"}]),
        pkg("org.openglow.wdprobe", [ver("1.1.0")], key=None, withdrawn=[{"version": "1.0.0", "reason": "z"}])]}))
    check(r.get("ok") is True, "an index withdrawing single versions: %s" % r.get("error"))
    have = lists()
    check(have["org.example.wd"].get("withdrawn") == {"scope": "version", "reason": "a flaw in 1.0.0"},
          "the installed copy of a withdrawn version stays, and says so: %s" % have["org.example.wd"].get("withdrawn"))
    check(have["org.openglow.wdprobe"].get("withdrawn") == {"scope": "version", "reason": "z"},
          "and so does OpenGlow's own: %s" % have["org.openglow.wdprobe"].get("withdrawn"))
    check(have["org.example.listed"].get("withdrawn") is None, "a package not withdrawn says nothing")
    t.run("remove", "org.example.wd")
    r = t.run("inspect", wd)
    check(r.get("ok") is False and "OpenGlow withdrew org.example.wd 1.0.0 from its catalog: a flaw in 1.0.0" in (r.get("error") or ""),
          "a withdrawn version does not install, from anywhere: %s" % r.get("error"))
    r = t.run("inspect", wd_owner)
    check(r.get("ok") is False and "withdrew org.example.wd3 1.0.0" in (r.get("error") or ""),
          "nor under the key the catalog endorses for it: %s" % r.get("error"))
    check(t.run("key-add", "wd3-author", t.pub("owner")).get("ok") is True, "the owner adds that author's key")
    r = t.run("inspect", wd_owner)
    check(r.get("ok") is False and "withdrew org.example.wd3 1.0.0" in (r.get("error") or ""),
          "nor under the owner's own copy of that key: %s" % r.get("error"))
    r = t.run("inspect", wd_stranger)
    check(r.get("ok") is True and r.get("tier") == "unverified" and r.get("withdrawn") is None,
          "the same id and version under another key is another package: %s %s" % (r.get("tier"), r.get("error")))
    check(t.run("remove", "org.openglow.wdprobe").get("ok") is True, "org.openglow.wdprobe goes")
    r = t.run("inspect", og)
    check(r.get("ok") is False and "withdrew org.openglow.wdprobe 1.0.0" in (r.get("error") or ""),
          "OpenGlow's own withdrawn version does not install: %s" % r.get("error"))
    r = t.run("install", wd11, "--consent-community")
    check(r.get("ok") is True and lists()["org.example.wd"].get("withdrawn") is None,
          "the version listed in its place installs, and is not withdrawn: %s" % r.get("error"))

    # A package withdrawn whole: its key endorses nothing any more, an installed copy stays and says so, and an
    # archive under the key the catalog named - here the owner's own copy of it - installs as the owner's key
    # says, with the withdrawal shown.
    r = t.run("index-verify", raw_index({"index": 1, "packages": [good], "withdrawn": [
        {"id": "org.example.wd", "key": author_pub, "reason": "its author asked"},
        {"id": "org.example.wd3", "key": owner_pub, "reason": "out of policy"}]}))
    check(r.get("ok") is True and r.get("packages") == 1, "an index withdrawing packages whole: %s" % r)
    check(lists()["org.example.wd"].get("withdrawn") == {"scope": "package", "reason": "its author asked"},
          "the installed copy of a withdrawn package stays, and says so: %s" % lists()["org.example.wd"].get("withdrawn"))
    check(not os.path.exists(os.path.join(t.root, "index", "keys", "org.example.wd.pub")), "and its key is endorsed for nothing")
    r = t.run("inspect", wd_owner)
    check(r.get("ok") is True and r.get("tier") == "community" and r.get("withdrawn") == {"scope": "package", "reason": "out of policy"},
          "the owner's own key still speaks for it, and the answer shows the withdrawal: %s %s"
          % (r.get("withdrawn"), {k: r.get(k) for k in ("ok", "tier", "error")}))
    check(t.run("key-remove", "wd3-author").get("ok") is True, "the owner takes that key away again")
    r = t.run("inspect", wd_owner)
    check(r.get("ok") is True and r.get("tier") == "unverified" and r.get("withdrawn") is None,
          "and with no key speaking for it, it is nobody's, and the withdrawal names another package: %s %s"
          % (r.get("tier"), r.get("withdrawn")))
    wd12 = t.pack(t.tree(manifest("org.example.wd", version="1.2.0"), RUN), "author")
    r = t.run("inspect", wd12)
    check(r.get("ok") is False and "signed by the key that signed the installed version" in (r.get("error") or ""),
          "an update of it reads as unverified, and the pinned key refuses it: %s" % r.get("error"))
    check(t.run("remove", "org.example.wd").get("ok") is True, "org.example.wd goes")

    # Withdrawn by leaving the catalog: the installed version stays, and an update no longer reads as community.
    r = t.run("index-verify", raw_index({"index": 1, "packages": []}))
    check(r.get("ok") is True and r.get("packages") == 0, "an index that lists nothing: %s" % r)
    update = t.pack(t.tree(manifest("org.example.listed", version="1.1.0"), RUN), "author")
    r = t.run("inspect", update)
    check(r.get("ok") is False and "signed by the key that signed the installed version" in (r.get("error") or ""),
          "delisted: the update is unverified now, and the pinned key refuses it -> %s" % r.get("error"))
    check("org.example.listed" in [p["id"] for p in t.run("list")["packages"]], "and the installed version stays")
    check(t.run("remove", "org.example.listed").get("ok") is True, "the package goes")


def main():
    if not FWUP or not os.path.isfile(FORGEEXT):
        print("skipped: needs fwup (FWUP) and the built forgeext (FORGEEXT)")
        return 77
    top = tempfile.mkdtemp(prefix="forgeext-install.")
    try:
        run_all(World(top), top)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    print("%s: install_test, %d checks, %d failure%s" % ("FAIL" if failures else "PASS", checks, len(failures),
                                                        "" if len(failures) == 1 else "s"))
    return 1 if failures else 0


def run_all(w, top):
    root = w.root
    A = "org.example.notify"

    print("an official package: inspect changes nothing, install needs the operator's grant")
    a1 = w.pack(w.tree(manifest(A, caps=["events", "hold", "storage:8"]), RUN), "official")
    r = w.run("inspect", a1)
    check(r.get("ok") and r["tier"] == "official" and r["needs_grant"] == ["hold"] and not r["update"]
          and sorted(r["new_capabilities"]) == ["events", "hold", "storage:8"] and r["files"] == 3, "inspect: %s" % r)
    check(not os.path.exists(os.path.join(root, "state.json")) and not os.listdir(os.path.join(root, "pkg"))
          and not w.leftovers(), "inspect left something behind")
    r = w.run("install", a1)
    check(r.get("ok") is False and "only the operator grants: hold" in r.get("error", ""), "no grant -> %s" % r.get("error"))
    r = w.run("install", a1, "--grant", "hold", "--grant", "motion.job")
    check(r.get("ok") is False and "does not ask for" in r.get("error", ""), "a grant too many -> %s" % r.get("error"))
    r = w.run("install", a1, "--grant", "hold")
    check(r.get("ok") is True, "install with the grant: %s" % r)
    pkg = os.path.join(root, "pkg", A)
    check(os.path.isfile(os.path.join(pkg, "1.0.0", "bin", "run.sh")) and os.readlink(os.path.join(pkg, "current")) == "1.0.0"
          and os.path.isfile(os.path.join(pkg, "1.0.0.files")) and os.path.isdir(os.path.join(root, "data", A))
          and stat.S_IMODE(os.stat(os.path.join(root, "data", A)).st_mode) == 0o770, "the installed layout")
    check(stat.S_IMODE(os.stat(os.path.join(pkg, "1.0.0", "bin", "run.sh")).st_mode) == 0o755
          and stat.S_IMODE(os.stat(os.path.join(pkg, "1.0.0", "share", "notes.txt")).st_mode) == 0o644, "the unpacked modes")
    # Installed by somebody whose umask is 077 (root at a console): every directory of the tree is 0755 all the same,
    # or the service's account could not read its own files.
    strict = w.pack(w.tree(manifest("org.example.umask", runtime="data"), {"share/deep/notes.txt": ("x", 0o644)}), "official")
    was = os.umask(0o077)
    try:
        r = w.run("install", strict)
    finally:
        os.umask(was)
    upkg = os.path.join(root, "pkg", "org.example.umask")
    modes = {p: stat.S_IMODE(os.stat(os.path.join(upkg, p)).st_mode) for p in ("", "1.0.0", "1.0.0/share", "1.0.0/share/deep")}
    check(r.get("ok") is True and set(modes.values()) == {0o755}, "installed under umask 077: %s" % modes)
    check(w.run("remove", "org.example.umask").get("ok") is True, "and removed")

    # What a process left that ended before it could take it away (forgectrl's kill, a power cut) goes at the next
    # command that prepares the root, and nothing under way does: a staging directory that nobody holds, a tree no
    # record names, a version of a recorded package that is neither its own nor its predecessor, and an index swap
    # cut between its two renames.
    # A version whose own name ends in ".files" keeps its tree.
    odd = "org.example.oddver"
    check(w.run("install", w.pack(w.tree(manifest(odd, version="1.0.0-a.files", runtime="data")), "official")).get("ok")
          is True, "a version named 1.0.0-a.files installs")
    tmp, old = os.path.join(root, "tmp"), time.time() - 60
    for name in ("in.stale1", "index.stale2", "in.live1", "in.young1"):
        os.makedirs(os.path.join(tmp, name, "tree"))
        if name != "in.young1":                         # made a moment ago, between its mkdtemp and its lock
            os.utime(os.path.join(tmp, name), (old, old))
    live = os.open(os.path.join(tmp, "in.live1"), os.O_RDONLY)
    fcntl.flock(live, fcntl.LOCK_EX)
    os.makedirs(os.path.join(root, "pkg", "org.example.ghost", "1.0.0"))
    os.makedirs(os.path.join(root, "pkg", "not_an_id", "kept"))    # no package id: no install made it
    os.makedirs(os.path.join(pkg, "9.9.9"))
    index, index_old = os.path.join(root, "index"), os.path.join(root, "index.old")
    if os.path.isdir(index):
        os.rename(index, index_old)
    else:
        os.makedirs(index_old)
        open(os.path.join(index_old, "kept"), "w").close()
    kept = sorted(os.listdir(index_old))
    r = w.run("inspect", w.pack(w.tree(manifest("org.example.sweep", runtime="data")), "official"))
    check(r.get("ok") is True and sorted(os.listdir(tmp)) == ["in.live1", "in.young1"], "a staging nobody holds goes, one "
          "under way stays, and so does one made a moment ago: %s" % sorted(os.listdir(tmp)))
    check(sorted(os.listdir(os.path.join(root, "pkg", odd))) == ["1.0.0-a.files", "1.0.0-a.files.files", "current"]
          and (w.run("check", odd).get("packages") or [{}])[0].get("intact") is True,
          "the version named 1.0.0-a.files keeps its tree and its list: %s"
          % sorted(os.listdir(os.path.join(root, "pkg", odd))))
    check(w.run("remove", odd).get("ok") is True, "and it goes")
    shutil.rmtree(os.path.join(tmp, "in.young1"))
    check(not os.path.exists(os.path.join(root, "pkg", "org.example.ghost")) and not os.path.exists(os.path.join(pkg, "9.9.9"))
          and os.path.isdir(os.path.join(pkg, "1.0.0")), "a tree no record names goes, and the recorded version stays")
    check(os.path.isdir(os.path.join(root, "pkg", "not_an_id", "kept")),
          "an entry under pkg/ whose name is no package id is nobody's install, and stays")
    shutil.rmtree(os.path.join(root, "pkg", "not_an_id"), ignore_errors=True)
    check(os.path.isdir(index) and sorted(os.listdir(index)) == kept and not os.path.exists(index_old),
          "the index this machine kept is put back")
    os.close(live)
    shutil.rmtree(os.path.join(tmp, "in.live1"))
    # A staging under way is locked by the command that made it: while an inspect is inside fwup (a stand-in that
    # waits there), its staging, made to look a minute old, outlives another command's prepare of the root.
    held_stub, held_seen = os.path.join(top, "fwup-held"), os.path.join(top, "fwup-held-seen")
    sweep2 = w.pack(w.tree(manifest("org.example.sweep2", runtime="data")), "official")
    other = " ".join(shlex.quote(x) for x in (FORGEEXT, "--root", root, "--fwup", FWUP, "--official-key", w.pub("official"),
                                              "--no-reserve", "inspect", sweep2))
    with open(held_stub, "w") as f:
        f.write('#!/bin/sh\nif [ "$1" = -V ] && [ ! -e %s ]; then\n  touch -d "1 minute ago" %s/in.*\n'
                '  ls %s > %s.before\n  %s > %s.other\n  ls %s > %s\nfi\nexec %s "$@"\n'
                % (shlex.quote(held_seen), shlex.quote(tmp), shlex.quote(tmp), shlex.quote(held_seen), other,
                   shlex.quote(held_seen), shlex.quote(tmp), shlex.quote(held_seen), shlex.quote(FWUP)))
    os.chmod(held_stub, 0o755)
    r = w.run("inspect", sweep2, fwup=held_stub)

    def read(path):
        return open(path).read() if os.path.exists(path) else ""

    before, after = read(held_seen + ".before").split(), read(held_seen).split()
    check(r.get("ok") is True and len(before) == 1 and after == before
          and json.loads(read(held_seen + ".other") or "{}").get("ok") is True,
          "an inspect's staging, a minute old and still held, outlives another command's prepare: %s, staged %s, after "
          "the other command %s" % (r.get("error") or "ok", before, after))
    check(not w.leftovers(), "and it is gone once its inspect ends: %s" % w.leftovers())

    # state.json has one writer at a time: a command that changes it waits while another holds the root's lock, and
    # goes on once it is let go.
    held = open(os.path.join(root, "lock"), "a")
    fcntl.flock(held, fcntl.LOCK_EX)
    p = subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "disable", A], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    time.sleep(1)
    waited = p.poll() is None
    fcntl.flock(held, fcntl.LOCK_UN)
    held.close()
    out = p.communicate(timeout=20)[0]
    check(waited and json.loads(out or "{}").get("ok") is True, "a state change waited for the root's lock (%s) and "
          "finished once it was let go: %s" % (waited, out.strip()))
    check(w.run("enable", A).get("ok") is True, "and enabled again")
    lst = w.run("list")["packages"]
    check(len(lst) == 1 and lst[0]["id"] == A and lst[0]["account"] == "ffx0" and lst[0]["grants"] == ["hold"]
          and lst[0]["enabled"] and lst[0]["tier"] == "official" and len(lst[0]["key"]) == 64, "list: %s" % lst)
    check(not w.leftovers(), "install left its staging behind")
    r = w.run("install", a1, "--grant", "hold")
    check("already installed" in r.get("error", ""), "the same version again -> %s" % r.get("error"))

    print("the integrity check")
    check(w.run("check").get("ok") is True, "an untouched package checks")
    notes = os.path.join(pkg, "1.0.0", "share", "notes.txt")
    with open(notes, "a") as f:
        f.write("more\n")
    r = w.run("check", A)
    check(r.get("ok") is False and "changed since" in r["packages"][0].get("why", ""), "a changed file -> %s" % r)
    with open(notes, "w") as f:
        f.write("notes\n")
    os.chmod(notes, 0o755)
    check("mode of a file" in w.run("check")["packages"][0].get("why", ""), "a changed mode")
    os.chmod(notes, 0o644)
    extra = os.path.join(pkg, "1.0.0", "bin", "extra")
    open(extra, "w").close()
    check("not installed with it" in w.run("check")["packages"][0].get("why", ""), "an added file")
    os.unlink(extra)
    os.symlink("/etc/passwd", extra)
    check(w.run("check").get("ok") is False, "an added symbolic link")
    os.unlink(extra)
    check(w.run("check").get("ok") is True, "restored, it checks again")

    print("an update: the capability diff, the pinned key, the predecessor kept once")
    a2 = w.pack(w.tree(manifest(A, "1.1.0", caps=["events", "hold", "storage:8", "motion.job"]), RUN), "official")
    r = w.run("inspect", a2)
    check(r.get("ok") and r["update"] and r["from_version"] == "1.0.0" and r["new_capabilities"] == ["motion.job"]
          and sorted(r["needs_grant"]) == ["hold", "motion.job"], "the update's diff: %s" % r)
    r = w.run("install", a2, "--grant", "hold")
    check("only the operator grants: motion.job" in r.get("error", ""), "the new capability ungranted -> %s" % r.get("error"))
    check(w.run("install", a2, "--grant", "hold", "--grant", "motion.job").get("ok") is True, "the update installs")
    p = w.run("list")["packages"][0]
    check(p["version"] == "1.1.0" and p["previous"] == "1.0.0" and p["account"] == "ffx0"
          and os.path.isdir(os.path.join(pkg, "1.0.0")) and os.readlink(os.path.join(pkg, "current")) == "1.1.0",
          "the predecessor stays until the new version has run: %s" % p)
    a3 = w.pack(w.tree(manifest(A, "1.2.0", caps=["events", "hold"]), RUN), "official")
    check(w.run("install", a3, "--grant", "hold").get("ok") is True, "a second update installs")
    p = w.run("list")["packages"][0]
    check(p["previous"] == "1.1.0" and not os.path.exists(os.path.join(pkg, "1.0.0"))
          and not os.path.exists(os.path.join(pkg, "1.0.0.files")) and p["grants"] == ["hold"], "the older predecessor went: %s" % p)
    r = w.run("inspect", w.pack(w.tree(manifest(A, "1.1.5", caps=["events"]), RUN), "official"))
    check(r.get("ok") and r["downgrade"], "a downgrade is named as one: %s" % r)
    for signer in ("owner", None):
        r = w.run("install", w.pack(w.tree(manifest(A, "2.0.0", caps=["events"]), RUN), signer),
                  "--consent-community", "--consent-unverified")
        check("signed by the key that signed the installed version" in r.get("error", ""),
              "an update by %s -> %s" % (signer or "nobody", r.get("error")))
    check(w.run("list")["packages"][0]["version"] == "1.2.0" and not w.leftovers(), "the refused updates changed nothing")
    # The kept predecessor installed again, as a rollback of an update that has not run healthy: current points at
    # its whole tree, and the version it replaces is kept in its place.
    r = w.run("install", a2, "--grant", "hold", "--grant", "motion.job")
    p = w.run("list")["packages"][0]
    check(r.get("ok") is True and r.get("downgrade") is True and p["version"] == "1.1.0" and p["previous"] == "1.2.0"
          and os.readlink(os.path.join(pkg, "current")) == "1.1.0"
          and os.path.isfile(os.path.join(pkg, "1.1.0", "manifest.json")) and os.path.isdir(os.path.join(pkg, "1.2.0")),
          "the kept predecessor installed again: current is its tree, and the replaced version is kept: %s %s" % (r, p))
    r = w.run("check", A)
    check(r.get("ok") is True, "and it checks: %s" % r)

    print("a required hold: its marker names its modes, and the operator's exits take its file and its marker at once")
    H = "org.example.holder"
    marks = os.path.join(root, "required-holds")

    def marker():
        try:
            return open(os.path.join(marks, H)).read()
        except OSError:
            return None

    def stopped_hosts_file():
        """The file a stopped host leaves for a required hold: stale, and standing on its own field."""
        p = os.path.join(w.holds, H + ".json")
        with open(p, "w") as f:
            f.write('{"id": "%s", "required": true, "raised": false, "reason": "", "ts_mono": 1.0}\n' % H)
        return p

    def hold_listed():
        return next((p.get("hold") for p in w.run("list")["packages"] if p["id"] == H), "gone")
    h1 = w.pack(w.tree(manifest(H, caps=["hold", "motion.job"], modes=["grbl"]), RUN), "official")
    check(w.run("install", h1, "--grant", "hold", "--grant", "motion.job").get("ok") is True
          and w.run("hold", H, "required").get("ok") is True and marker() == "grbl\n",
          "marked required: its marker names its one mode: %r" % marker())
    f_ = stopped_hosts_file()
    check(w.run("disable", H).get("ok") is True and not os.path.exists(f_) and marker() is None,
          "disabled: the file a stopped host left and the marker go: file %s, marker %r" % (os.path.exists(f_), marker()))
    check(w.run("enable", H).get("ok") is True and marker() == "grbl\n", "enabled: the marker is back")
    f_ = stopped_hosts_file()
    check(w.run("hold", H, "advisory").get("ok") is True and not os.path.exists(f_) and marker() is None,
          "made advisory: the file and the marker go: file %s, marker %r" % (os.path.exists(f_), marker()))
    check(w.run("hold", H, "required").get("ok") is True and marker() == "grbl\n", "required again")
    h15 = w.pack(w.tree(manifest(H, "1.0.1", caps=["hold", "motion.job"], modes=["grbl", "cloud"]), RUN), "official")
    check(w.run("install", h15, "--grant", "hold", "--grant", "motion.job").get("ok") is True
          and marker() == "grbl cloud\n",
          "an update that runs in both modes: its marker says so: %r" % marker())
    h2 = w.pack(w.tree(manifest(H, "1.1.0", caps=["motion.job"], modes=["grbl"]), RUN), "official")
    check(w.run("install", h2, "--grant", "motion.job").get("ok") is True and marker() is None and hold_listed() is None,
          "an update that drops the hold: its marker goes with the install: %r, %s" % (marker(), hold_listed()))
    h3 = w.pack(w.tree(manifest(H, "1.2.0", caps=["hold", "motion.job"], modes=["grbl"]), RUN), "official")
    check(w.run("install", h3, "--grant", "hold", "--grant", "motion.job").get("ok") is True and marker() is None
          and hold_listed() == "advisory",
          "a later version that asks for a hold again: advisory, not the mark set for an older one: %s" % hold_listed())
    # A removal whose write of state.json fails (a directory where its new copy goes): the package stays, and so
    # do its settings.
    kept_settings = os.path.join(root, "settings", H + ".json")
    os.makedirs(os.path.dirname(kept_settings), exist_ok=True)
    with open(kept_settings, "w") as f:
        f.write("{}\n")
    os.mkdir(os.path.join(root, "state.json.new"))
    r = w.run("remove", H)
    os.rmdir(os.path.join(root, "state.json.new"))
    check(r.get("ok") is False and hold_listed() == "advisory" and os.path.isfile(kept_settings),
          "a removal that could not write the state: still installed, its settings kept: %s %s"
          % (r.get("error"), os.path.isfile(kept_settings)))
    f_ = stopped_hosts_file()
    check(w.run("remove", H).get("ok") is True and not os.path.isfile(kept_settings) and not os.path.exists(f_)
          and hold_listed() == "gone", "removed: its settings and its hold file go")

    # An install that fails after current has turned, at the write of state.json (a directory where its new copy
    # goes): current turns back to the version the state names, and nothing the state names is deleted. The kept
    # predecessor installed again, an update, and a first install, each refused that way. current is read after the
    # kept predecessor's refusal, before the update's own turn back points it at the state's version again.
    blocker = os.path.join(root, "state.json.new")
    os.mkdir(blocker)
    a4 = w.pack(w.tree(manifest(A, "1.3.0", caps=["events", "hold"]), RUN), "official")
    F = "org.example.first"
    refused = [w.run("install", a3, "--grant", "hold")]
    cur, p = os.readlink(os.path.join(pkg, "current")), w.run("list")["packages"][0]
    read = (p.get("package") or {}).get("version")
    check(cur == "1.1.0" and p["version"] == "1.1.0" and read == "1.1.0" and "manifest_error" not in p,
          "the kept predecessor refused: current turns back to the version the state names: current %s, state %s, "
          "list reads %s" % (cur, p["version"], read or p.get("manifest_error")))
    refused += [w.run("install", a4, "--grant", "hold"),
                w.run("install", w.pack(w.tree(manifest(F, runtime="data")), "official"))]
    os.rmdir(blocker)
    p = w.run("list")["packages"][0]
    check(all(r.get("ok") is False and "state.json" in r.get("error", "") for r in refused),
          "the three installs are refused at the write of the state: %s" % [r.get("error") for r in refused])
    check(p["version"] == "1.1.0" and p["previous"] == "1.2.0" and os.readlink(os.path.join(pkg, "current")) == "1.1.0"
          and (p.get("package") or {}).get("version") == "1.1.0" and "manifest_error" not in p,
          "current names the version the state names, and its manifest is the one read: %s" % p)
    check(os.path.isfile(os.path.join(pkg, "1.2.0", "manifest.json")) and os.path.isfile(os.path.join(pkg, "1.2.0.files"))
          and not os.path.exists(os.path.join(pkg, "1.3.0")) and not os.path.exists(os.path.join(pkg, "1.3.0.files")),
          "the kept predecessor is whole, and the refused update's tree is gone: %s" % sorted(os.listdir(pkg)))
    check(not os.path.exists(os.path.join(root, "pkg", F)) and F not in [x["id"] for x in w.run("list")["packages"]]
          and not w.leftovers(), "the refused first install left nothing: %s" % os.listdir(os.path.join(root, "pkg")))
    check(w.run("check", A).get("ok") is True, "and the package checks")
    # A crash between the turn of current and the write of the state leaves current on a version the state does not
    # name. The next command to prepare the root (an inspect here) turns it back to the state's version: the kept
    # predecessor's tree stays, and a tree the state does not name goes with the turn.
    cur = os.path.join(pkg, "current")
    os.symlink("1.2.0", cur + ".new")
    os.rename(cur + ".new", cur)
    check(w.run("inspect", a4).get("ok") is True, "an inspect prepares the root")
    p = w.run("list")["packages"][0]
    check(os.readlink(cur) == "1.1.0" and p["version"] == "1.1.0" and (p.get("package") or {}).get("version") == "1.1.0"
          and os.path.isfile(os.path.join(pkg, "1.2.0", "manifest.json")),
          "current left on the kept predecessor by a crash: turned back to the state's version, the predecessor's "
          "tree kept: current %s, %s" % (os.readlink(cur), sorted(os.listdir(pkg))))
    os.mkdir(os.path.join(pkg, "9.9.9"))
    with open(os.path.join(pkg, "9.9.9", "manifest.json"), "w") as f:
        f.write("{}\n")
    os.symlink("9.9.9", cur + ".new")
    os.rename(cur + ".new", cur)
    check(w.run("inspect", a4).get("ok") is True, "an inspect prepares the root again")
    check(os.readlink(cur) == "1.1.0" and not os.path.exists(os.path.join(pkg, "9.9.9")) and w.run("check", A).get("ok") is True,
          "current left on a version the state does not name: turned back, and that tree goes: %s" % sorted(os.listdir(pkg)))
    # A version is all current may ever name, and only a tree named by one goes with the turn: current pointing at ..
    # (root's hand) is turned back and nothing else is touched, and a name too long to read whole is turned back and
    # the directory it named is left.
    pkgs = sorted(os.listdir(os.path.join(root, "pkg")))
    os.symlink("..", cur + ".new")
    os.rename(cur + ".new", cur)
    check(w.run("inspect", a4).get("ok") is True, "an inspect prepares the root with current pointing at ..")
    check(os.path.islink(cur) and os.readlink(cur) == "1.1.0" and sorted(os.listdir(os.path.join(root, "pkg"))) == pkgs
          and os.path.isfile(os.path.join(pkg, "1.1.0", "manifest.json")) and os.path.isfile(os.path.join(pkg, "1.2.0", "manifest.json"))
          and w.run("check", A).get("ok") is True,
          "current pointing at ..: turned back, and nothing else is removed: pkg holds %s, %s"
          % (sorted(os.listdir(os.path.join(root, "pkg"))), sorted(os.listdir(pkg)) if os.path.isdir(pkg) else "gone"))
    long = "9" * 70
    os.makedirs(os.path.join(pkg, long))
    os.symlink(long, cur + ".new")
    os.rename(cur + ".new", cur)
    check(w.run("inspect", a4).get("ok") is True, "an inspect prepares the root with current pointing at a long name")
    check(os.path.islink(cur) and os.readlink(cur) == "1.1.0" and os.path.isdir(os.path.join(pkg, long))
          and w.run("check", A).get("ok") is True,
          "current pointing at a name too long to read whole: turned back, and that directory is left: %s" % sorted(os.listdir(pkg)))
    os.rmdir(os.path.join(pkg, long))

    print("the other tiers, and the namespace")
    B, C, D = "org.example.community", "org.example.unsigned", "org.example.stranger"
    b = w.pack(w.tree(manifest(B, caps=["events"]), RUN), "owner")
    check("typed consent" in w.run("install", b).get("error", ""), "a community package with no consent")
    check(w.run("install", b, "--consent-unverified").get("ok") is False, "the button is not the typed consent")
    check(w.run("install", b, "--consent-community").get("ok") is True, "a community package with consent")
    c = w.pack(w.tree(manifest(C, runtime="data")))
    check("button held" in w.run("install", c).get("error", ""), "an unsigned package with no button")
    check(w.run("install", c, "--consent-community").get("ok") is False, "typed consent is not the button")
    check(w.run("install", c, "--consent-unverified").get("ok") is True, "an unsigned package with the button")
    d = w.pack(w.tree(manifest(D, runtime="data")), "stranger")
    r = w.run("inspect", d)
    check(r.get("ok") and r["tier"] == "unverified" and r["key"] == "", "a stranger's signature is nobody's: %s" % r)
    tiers = {p["id"]: (p["tier"], p.get("account")) for p in w.run("list")["packages"]}
    check(tiers.get(B) == ("community", "ffx1") and tiers.get(C) == ("unverified", None), "tiers and accounts: %s" % tiers)
    for signer in ("owner", "stranger", None):
        r = w.run("install", w.pack(w.tree(manifest("org.openglow.align", runtime="data")), signer),
                  "--consent-community", "--consent-unverified")
        check("OpenGlow's namespace" in r.get("error", ""), "org.openglow.* by %s -> %s" % (signer or "nobody", r.get("error")))
    check(w.run("install", w.pack(w.tree(manifest("org.openglow.align", runtime="data")), "official")).get("ok") is True,
          "org.openglow.* by the OpenGlow key")
    # The pin holds inside one tier too: a second author whose key the owner added does not replace the first one's
    # package, which would keep its data and its account.
    pinned = "org.example.pinned"
    check(w.run("install", w.pack(w.tree(manifest(pinned, runtime="data")), "owner"), "--consent-community").get("ok") is True,
          "a community package by the owner's first key")
    check(w.run("key-add", "second", w.pub("stranger")).get("ok") is True, "the owner adds a second author's key")
    r = w.run("install", w.pack(w.tree(manifest(pinned, version="2.0.0", runtime="data")), "stranger"), "--consent-community")
    check(r.get("ok") is False and "signed by the key that signed the installed version" in (r.get("error") or ""),
          "its version 2, community too but by the second key -> %s" % r.get("error"))
    check(w.run("key-remove", "second").get("ok") is True and w.run("remove", pinned).get("ok") is True, "both taken away")

    print("the product gate, and a firmware key")
    good_payload = w.tar([manifest_member(manifest("org.example.gate", runtime="data"))])
    r = w.run("inspect", w.pack_raw(good_payload, "1.0.0", "official"))
    check(r.get("ok") is True, "the hand-made archive is a good one to begin with: %s" % r)
    r = w.run("inspect", w.pack_raw(good_payload, "1.0.0", "official", product="ForgeFIRM firmware"))
    check("not \"ForgeFIRM extension\"" in r.get("error", ""), "firmware at the extension door -> %s" % r.get("error"))
    task = 'task upgrade.a {\n    on-resource payload.tar.gz { raw_write(0) }\n}\n'
    r = w.run("inspect", w.pack_raw(good_payload, "1.0.0", "official", extra=task))
    check("lists a task" in r.get("error", ""), "an extension archive with a task -> %s" % r.get("error"))
    other = w.path("other.bin")
    with open(other, "wb") as f:
        f.write(b"second resource")
    r = w.run("inspect", w.pack_raw(good_payload, "1.0.0", "official",
                                    extra='file-resource other.bin {\n    host-path = "%s"\n}\n' % other))
    check(r.get("ok") is False and ("does not" in r.get("error", "") or "holds" in r.get("error", "")),
          "a second resource -> %s" % r.get("error"))
    r = w.run("install", w.pack_raw(good_payload, "1.0.0", "firmware"), "--consent-unverified", "--consent-community")
    check("signed with a firmware key" in r.get("error", ""), "a firmware key on an extension -> %s" % r.get("error"))
    r = w.run("inspect", w.pack_raw(good_payload, "9.9.9", "official"))
    check("archive says version 9.9.9" in r.get("error", ""), "the archive's version against the manifest's -> %s" % r.get("error"))
    with open(w.path("not-an-archive.ffx"), "wb") as f:
        f.write(b"PK\x03\x04 this is not an archive")
        junk = f.name
    check(w.run("inspect", junk).get("ok") is False, "a file that is not an archive")
    check(w.run("inspect", os.path.join(top, "absent.ffx")).get("ok") is False, "a file that is not there")

    print("a payload that is not the one the signed metadata names")
    signed = w.pack(w.tree(manifest("org.example.tamper", runtime="data"),
                           {"data.txt": (os.urandom(3000).hex(), 0o644)}), "official")
    blob = bytearray(open(signed, "rb").read())
    at = blob.index(b"data/payload.tar.gz") + len(b"data/payload.tar.gz") + 400
    blob[at] ^= 0x55
    flipped = w.path("flipped.ffx")
    open(flipped, "wb").write(bytes(blob))
    r = w.run("inspect", flipped)
    check(r.get("ok") is False, "a byte flipped inside the payload -> %s" % r.get("error"))
    # The signed metadata of one archive over the payload of another: valid ZIP, valid CRCs, wrong hash.
    import zipfile
    swapped = w.path("swapped.ffx")
    other_payload = w.tar([manifest_member(manifest("org.example.tamper", runtime="data")), member("evil.txt", b"evil")])
    with zipfile.ZipFile(signed) as zin, zipfile.ZipFile(swapped, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in ("meta.conf.ed25519", "meta.conf"):
            zout.writestr(name, zin.read(name))
        zout.writestr("data/payload.tar.gz", open(other_payload, "rb").read())
    r = w.run("inspect", swapped)
    check("not the one the archive's metadata names" in r.get("error", ""), "another payload under a good signature -> %s" % r.get("error"))
    # The signed payload itself with one byte changed and zipped again: the same length and a good CRC, so only
    # this reader's hash against the signed metadata tells it from the one that was signed (fwup reads the file
    # again, and the installed tree is unpacked from this reader's own copy).
    with zipfile.ZipFile(signed) as zin:
        payload_bytes = bytearray(zin.read("data/payload.tar.gz"))
        heads = [(name, zin.read(name)) for name in ("meta.conf.ed25519", "meta.conf")]
    payload_bytes[len(payload_bytes) // 2] ^= 0x01
    onebyte = w.path("onebyte.ffx")
    with zipfile.ZipFile(onebyte, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in heads:
            zout.writestr(name, data)
        zout.writestr("data/payload.tar.gz", bytes(payload_bytes))
    r = w.run("inspect", onebyte)
    check("not the one the archive's metadata names" in r.get("error", ""), "one byte of the signed payload changed, "
          "same length, good CRC -> %s" % r.get("error"))
    # The other verifier, fwup, counts on its own: a stand-in that runs the real one except where a case changes its
    # answer, and notes how it was asked. Its -V refusing an archive this reader takes is a refusal; it is given the
    # key that verified the archive; the product it reads is compared; and where its -V takes anything, this reader
    # still refuses a metadata with a NUL in it, in its own words.
    stub = os.path.join(top, "fwup-stand-in")
    with open(stub, "w") as f:
        f.write('#!/bin/sh\necho "$*" >> "$FWUP_SEEN"\ncase "$FWUP_MODE:$1" in\n  pass:-V) exit 0 ;;\n'
                '  fail:-V) exit 1 ;;\n  product:-m) "$FWUP_REAL" "$@" | sed "s/^meta-product=.*/meta-product=\\"Another\\"/";'
                ' exit 0 ;;\nesac\nexec "$FWUP_REAL" "$@"\n')
    os.chmod(stub, 0o755)

    def with_fwup(mode, archive):
        seen = os.path.join(top, "fwup-seen")
        open(seen, "w").close()
        os.environ.update(FWUP_REAL=FWUP, FWUP_MODE=mode, FWUP_SEEN=seen)
        try:
            r = w.run("inspect", archive, fwup=stub)
        finally:
            for k in ("FWUP_REAL", "FWUP_MODE", "FWUP_SEEN"):
                os.environ.pop(k, None)
        return r, open(seen).read()

    r, seen = with_fwup("real", signed)
    check(r.get("ok") is True and ("-V -i %s -p %s" % (signed, w.pub("official"))) in seen,
          "fwup is asked to verify with the key that verified the archive: %s" % seen.strip().replace("\n", " | "))
    r, _ = with_fwup("fail", signed)
    check("fwup does not verify the archive" in (r.get("error") or ""), "fwup's own refusal -> %s" % r.get("error"))
    r, _ = with_fwup("product", signed)
    check("fwup reads another product" in (r.get("error") or ""), "fwup reading another product -> %s" % r.get("error"))
    with zipfile.ZipFile(signed) as zin:
        parts = {name: zin.read(name) for name in ("meta.conf.ed25519", "meta.conf", "data/payload.tar.gz")}
    nul = w.path("nul-meta.ffx")
    with zipfile.ZipFile(nul, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in ("meta.conf.ed25519", "meta.conf", "data/payload.tar.gz"):
            zout.writestr(name, parts[name] + (b"\0tail" if name == "meta.conf" else b""))
    r, _ = with_fwup("pass", nul)
    check("holds a NUL" in (r.get("error") or ""), "a metadata with a NUL, fwup taking anything -> %s" % r.get("error"))
    # The same, with the metadata rewritten to match and the old signature kept: the signature no longer holds.
    resigned = w.path("rewritten.ffx")
    import hashlib
    body = open(other_payload, "rb").read()
    with zipfile.ZipFile(signed) as zin, zipfile.ZipFile(resigned, "w", zipfile.ZIP_DEFLATED) as zout:
        meta = zin.read("meta.conf").decode()
        lines = []
        for line in meta.splitlines():
            if line.startswith("length="):
                line = "length=%d" % len(body)
            if line.startswith("blake2b-256="):
                line = "blake2b-256=" + hashlib.blake2b(body, digest_size=32).hexdigest()
            lines.append(line)
        zout.writestr("meta.conf.ed25519", zin.read("meta.conf.ed25519"))
        zout.writestr("meta.conf", "\n".join(lines) + "\n")
        zout.writestr("data/payload.tar.gz", body)
    r = w.run("inspect", resigned)
    check(r.get("ok") and r["tier"] == "unverified", "rewritten metadata under the old signature is nobody's: %s" % r)
    r = w.run("install", resigned)
    check("button held" in r.get("error", ""), "and installs only as an unverified package -> %s" % r.get("error"))

    print("payloads that try to leave the package")
    E = "org.example.escape"
    hostile = {
        "a parent path": [member("../evil.txt", b"evil")],
        "a deep parent path": [member("share/../../../evil.txt", b"evil")],
        "an absolute path": [member("/tmp/forgeext-evil.txt", b"evil")],
        "a symbolic link": [member("link", type_=tarfile.SYMTYPE, linkname="/etc/passwd")],
        "a link and a write through it": [member("out", type_=tarfile.SYMTYPE, linkname=top), member("out/evil.txt", b"evil")],
        "a hard link": [member("hard", type_=tarfile.LNKTYPE, linkname="manifest.json")],
        "a fifo": [member("pipe", type_=tarfile.FIFOTYPE)],
        "a device": [member("null", type_=tarfile.CHRTYPE)],
        "a path listed twice": [member("twice.txt", b"1"), member("twice.txt", b"2")],
        "a control character in a name": [member("bad\x07name", b"x")],
        "a backslash in a name": [member("bad\\name", b"x")],
        "a path too deep": [member("/".join(["d"] * 17) + "/f", b"x")],
        "a path too long": [member("d/" + "n" * 200, b"x")],
        "too many files": [member("f/%04d" % i, b"") for i in range(4097)],
        "too many directories": [member("d/%04d" % i, type_=tarfile.DIRTYPE) for i in range(4097)],
        "one directory over and over": [member("/".join(["d"] * 16), type_=tarfile.DIRTYPE)] * 4097,
        # 63 MiB of files, under the 64 the files may hold, and then 10.5 MiB of headers: past the stream's 72
        "headers past the stream's bound": [member("big%d" % i, b"\0" * (63 << 19)) for i in range(2)]
                                           + [member("p%02d" % i, b"x", pax={"comment": "x" * (900 << 10)}) for i in range(12)],
    }
    # The caps that are this reader's own, each refused in its own words (the others are refused on the way in).
    said = {"too many directories": "directory entries", "one directory over and over": "directory entries",
            "headers past the stream's bound": "tar stream is larger"}
    for what, members in hostile.items():
        payload = w.tar([manifest_member(manifest(E, runtime="data"))] + members)
        r = w.run("install", w.pack_raw(payload, "1.0.0", "official"))
        check(r.get("ok") is False and said.get(what, "") in (r.get("error") or ""), "%s -> %s" % (what, r.get("error")))
        check(not os.path.exists(os.path.join(root, "pkg", E)) and not w.leftovers()
              and not os.path.exists(os.path.join(top, "evil.txt")) and not os.path.exists(os.path.join(root, "evil.txt"))
              and not os.path.exists("/tmp/forgeext-evil.txt"), "%s left something behind" % what)
    setuid = w.tar([manifest_member(manifest(E, runtime="data")), member("tool", b"#!/bin/sh\n", mode=0o6777)])
    check(w.run("install", w.pack_raw(setuid, "1.0.0", "official")).get("ok") is True, "a setuid file installs")
    mode = stat.S_IMODE(os.stat(os.path.join(root, "pkg", E, "1.0.0", "tool")).st_mode)
    check(mode == 0o755, "and its mode is reduced to 0755, not %o" % mode)
    big = w.tar([manifest_member(manifest("org.example.big", runtime="data")), member("zeros", b"\0" * (33 << 20))])
    r = w.run("install", w.pack_raw(big, "1.0.0", "official"))
    check("MiB" in r.get("error", "") and not os.path.exists(os.path.join(root, "pkg", "org.example.big")) and not w.leftovers(),
          "a 33 MiB file out of a small archive -> %s" % r.get("error"))
    no_manifest = w.tar([member("readme.txt", b"hello")])
    check("no manifest.json" in w.run("inspect", w.pack_raw(no_manifest, "1.0.0", "official")).get("error", ""), "no manifest")

    page_unasked = w.pack(w.tree(manifest("org.example.pageless", runtime="data"), {"ui/index.html": ("<p>page</p>", 0o644)}),
                          "official")
    r = w.run("inspect", page_unasked)
    check("has a ui/index.html and does not ask for ui" in r.get("error", ""), "a page shipped without ui -> %s" % r.get("error"))
    pagenul = w.pack(w.tree(manifest("org.example.pagenul", runtime="ui", caps=["ui"]), {"ui/index.html": ("<p>a\0b</p>", 0o644)}),
                     "official")
    r = w.run("inspect", pagenul)
    check("ui/index.html holds a NUL" in r.get("error", ""), "a page that holds a NUL -> %s" % r.get("error"))

    many = manifest("org.example.many", runtime="python", caps=["net.outbound:h%d.example:443" % i for i in range(20)])
    check(w.run("install", w.pack(w.tree(many, RUN), "official")).get("ok") is True, "twenty destinations install")
    reach = next((x for x in w.run("list").get("packages", []) if x["id"] == "org.example.many"), {}).get("reach")
    check(reach == ["h%d.example:443" % i for i in range(15)], "what its service may reach, capped as its start caps it "
          "(the list GET /v0/self serves): %s" % reach)
    check(w.run("remove", "org.example.many").get("ok") is True, "and removed")

    print("the service's entry point, conflicts, the port, the budget")
    r = w.run("inspect", w.pack(w.tree(manifest("org.example.noexec", caps=[])), "official"))
    check("is not a file of the package" in r.get("error", ""), "an entry point that is not there -> %s" % r.get("error"))
    native = manifest("org.example.native", runtime="native", caps=[])
    r = w.run("inspect", w.pack(w.tree(native, {"bin/run.sh": ("\x7fELF", 0o644)}), "official"))
    check("is not executable" in r.get("error", ""), "a native entry point with no x bit -> %s" % r.get("error"))
    r = w.run("inspect", w.pack(w.tree(manifest("org.example.rival", runtime="data", conflicts=[A])), "official"))
    check("conflicts with %s, which is installed" % A in r.get("error", ""), "a conflict with an installed package -> %s" % r.get("error"))
    jealous = w.pack(w.tree(manifest("org.example.jealous", runtime="data", conflicts=["org.example.late"])), "official")
    check(w.run("install", jealous).get("ok") is True, "a package that names a future rival installs")
    r = w.run("inspect", w.pack(w.tree(manifest("org.example.late", runtime="data")), "official"))
    check("which is installed, conflicts with org.example.late" in r.get("error", ""), "the rival, later -> %s" % r.get("error"))
    web1 = w.pack(w.tree(manifest("org.example.web1", caps=["net.listen:8123"]), RUN), "official")
    r = w.run("install", web1)
    check(r.get("ok") is False and "only the operator grants: net.listen:8123" in (r.get("error") or ""),
          "a listener with no grant -> %s" % r.get("error"))
    check(w.run("install", web1, "--grant", "net.listen:8123").get("ok") is True, "a listener installs with the operator's grant")
    r = w.run("inspect", w.pack(w.tree(manifest("org.example.web2", caps=["net.listen:8123"]), RUN), "official"))
    check("already listens on port 8123" in r.get("error", ""), "the same port again -> %s" % r.get("error"))

    heavy = w.pack(w.tree(manifest("org.example.heavy", runtime="data"), {"blob.txt": (os.urandom(1 << 20).hex(), 0o644)}),
                   "official")
    r = w.run("install", heavy, budget=1)
    check("the limit is 1 MiB" in r.get("error", "") and not os.path.exists(os.path.join(root, "pkg", "org.example.heavy"))
          and not w.leftovers(), "2 MiB into a 1 MiB budget -> %s" % r.get("error"))
    check(w.run("install", heavy).get("ok") is True, "and into the default budget it installs")

    print("removal")
    check(w.run("remove", "org.example.nothere").get("ok") is False, "removing what is not installed")
    check(w.run("remove", "../../etc").get("ok") is False, "removing a path")
    with open(os.path.join(root, "data", B, "kept.txt"), "w") as f:
        f.write("the package's own data\n")
    check(w.run("remove", B, "--keep-data").get("ok") is True and not os.path.exists(os.path.join(root, "pkg", B))
          and os.path.isfile(os.path.join(root, "data", B, "kept.txt")), "remove --keep-data")
    check(w.run("remove", A).get("ok") is True and not os.path.exists(pkg) and not os.path.exists(os.path.join(root, "data", A)),
          "remove takes the files and the data")
    ids = [p["id"] for p in w.run("list")["packages"]]
    check(A not in ids and B not in ids, "the removed packages are forgotten: %s" % ids)
    again = w.run("install", a1, "--grant", "hold")
    check(again.get("ok") is True and [p for p in w.run("list")["packages"] if p["id"] == A][0]["account"] == "ffx0",
          "a removed package installs again, into the freed account")
    check(not w.leftovers(), "the staging directory is empty at the end: %s" % w.leftovers())

    print("the owner's keys, and what one makes of a package")
    keydir = os.path.join(root, "keys")
    for f in os.listdir(keydir):
        os.remove(os.path.join(keydir, f))
    check(w.run("keys").get("keys") == [], "a machine with no owner key lists one: %s" % w.run("keys"))
    pub = w.pub("owner")
    check(w.run("key-add", "a maker", pub).get("ok") is False, "a name with a space was taken")
    check(w.run("key-add", "../../etc/passwd", pub).get("ok") is False, "a name that is a path was taken")
    check(w.run("key-add", ".hidden", pub).get("ok") is False, "a name that starts with a dot was taken")
    check(w.run("key-add", "x" * 49, pub).get("ok") is False, "a name of 49 bytes was taken")
    check(os.listdir(keydir) == [], "a refused key left a file: %s" % os.listdir(keydir))
    notakey = os.path.join(w.top, "notakey.pub")
    with open(notakey, "w") as f:
        f.write("this is not a key\n")
    r = w.run("key-add", "maker", notakey)
    check(r.get("ok") is False and "public key" in r.get("error", ""), "what is no key was taken: %s" % r.get("error"))
    check(os.listdir(keydir) == [], "what is no key left a file: %s" % os.listdir(keydir))

    with open(pub) as f:
        keytext = f.read().strip()
    r = w.run("key-add", "maker", pub)
    keys = {k["name"]: k["key"] for k in r.get("keys", [])}
    check(r.get("ok") is True and list(keys) == ["maker"] and len(keys["maker"]) == 64,
          "the key is added and listed with its id: %s" % r)
    check(os.listdir(keydir) == ["maker.pub"] and open(os.path.join(keydir, "maker.pub")).read().strip() == keytext,
          "the key on disk is the key that was given: %s" % os.listdir(keydir))
    check(w.run("key-add", "maker", pub).get("ok") is False, "a second key of the same name was taken")

    # what the key makes of a package signed with its private half
    community = w.pack(w.tree(manifest("org.example.byakey"), RUN), "owner")
    r = w.run("inspect", community)
    check(r.get("tier") == "community" and r.get("key") == keys["maker"],
          "with the owner's key the package is community, by that key: %s" % {k: r.get(k) for k in ("tier", "key")})
    check(w.run("key-remove", "maker").get("keys") == [], "the key is removed")
    check(w.run("inspect", community).get("tier") == "unverified", "without it the same package is unverified")
    check(w.run("key-remove", "maker").get("ok") is False, "removing a key that is not there")
    check(w.run("key-remove", "../../etc/passwd").get("ok") is False, "removing a path")
    # The verifier reads 32 keys: a 33rd is refused at its add, never listed and trusted for nothing.
    for k in range(31):
        shutil.copy(pub, os.path.join(keydir, "k%02d.pub" % k))
    check(w.run("key-add", "k31", pub).get("ok") is True, "a 32nd key is taken")
    r = w.run("key-add", "k32", pub)
    check(r.get("ok") is False and "that is the limit" in (r.get("error") or ""), "a 33rd key -> %s" % r.get("error"))
    for k in range(32):
        os.remove(os.path.join(keydir, "k%02d.pub" % k))

    print("the firmware range a package says it needs")
    core_range(w)

    print("destinations the operator names")
    operator_destinations(w)

    print("the M-codes a package answers")
    mcodes(w)

    print("a page kept running off its tab")
    background_page(w)

    print("a package's page, served as it shipped")
    the_page(w)

    print("the signed index")
    the_index(w)

    print("a change of owner takes everything the last one left")
    wipe(w, root, keydir)


def wipe(w, root, keydir):
    """Every package, its data, and every key the owner added."""
    check(w.run("key-add", "maker", w.pub("owner")).get("ok") is True, "the key could not be added back")
    ids = []
    for n in range(3):
        id_ = "org.example.gone%d" % n
        ids.append(id_)
        arch = w.pack(w.tree(manifest(id_), RUN), "owner")
        check(w.run("install", arch, "--consent-community").get("ok") is True, "%s could not be installed" % id_)
        # Something of the owner's in each one's data, as a package's own
        # would be: this is what the wipe is for.
        d = os.path.join(root, "data", id_)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "token"), "w") as f:
            print("the last owner's", file=f)
    listed = sorted(x["id"] for x in w.run("list").get("packages", []))
    check(set(ids) <= set(listed), "the three packages are not installed: %s" % listed)
    # And what the owner typed into a package's settings.
    with open(os.path.join(root, "settings", ids[0] + ".json"), "w") as f:
        f.write('{"broker": "the last owner\'s"}\n')

    r = w.run("wipe")
    check(r.get("ok") is True and r.get("packages") == len(listed) and r.get("keys") == 1,
          "the wipe reports what it took (%d were installed): %s" % (len(listed), r))
    check(w.run("list").get("packages") == [], "a package is still listed: %s" % w.run("list"))
    check(w.run("keys").get("keys") == [], "an owner key is still there: %s" % w.run("keys"))
    for id_ in ids:
        for sub in ("pkg", "data"):
            left = os.path.join(root, sub, id_)
            check(not os.path.exists(left), "%s stayed behind" % left)
    # Everything under data/ goes, the leftovers of a package removed with
    # its data kept included: they hold what the wipe is for. So does every
    # package's settings file.
    for sub in ("pkg", "data", "keys", "settings"):
        here = os.path.join(root, sub)
        check(os.path.isdir(here) and os.listdir(here) == [], "%s is not an empty directory: %s"
              % (here, os.listdir(here) if os.path.isdir(here) else "gone"))
    marks = os.path.join(root, "required-holds")
    check(not os.path.isdir(marks) or os.listdir(marks) == [], "a required-hold marker stayed: %s" % marks)
    check(w.run("wipe").get("ok") is True, "a second wipe is not an error")
    # And the machine is usable again: the same package installs, now as
    # unverified, because the key that made it community went with the owner.
    arch = w.pack(w.tree(manifest("org.example.after"), RUN), "owner")
    check(w.run("inspect", arch).get("tier") == "unverified", "the owner's key outlived the wipe")
    r = w.run("install", arch, "--consent-unverified")
    check(r.get("ok") is True, "nothing installs after a wipe: %s" % r.get("error"))

    # A wipe that cannot take one thing takes everything else: a data tree 65 directories deep goes, a directory it
    # cannot empty is said (the first failure), and the owner's key and the other packages' data go all the same.
    check(w.run("key-add", "maker", w.pub("owner")).get("ok") is True, "the key could not be added back")
    for n in range(3):
        arch = w.pack(w.tree(manifest("org.example.left%d" % n), RUN), "owner")
        check(w.run("install", arch, "--consent-community").get("ok") is True, "left%d could not be installed" % n)
        os.makedirs(os.path.join(root, "data", "org.example.left%d" % n), exist_ok=True)
    deep = os.path.join(root, "data", "org.example.left0", *["d"] * 65)
    os.makedirs(deep)
    open(os.path.join(deep, "bottom"), "w").close()
    stuck = os.path.join(root, "data", "org.example.left1", "stuck")
    os.makedirs(stuck)
    open(os.path.join(stuck, "f"), "w").close()
    os.chmod(stuck, 0o500)                              # nothing in it can be unlinked, by anybody but root
    r = w.run("wipe")
    os.chmod(stuck, 0o700)
    if os.geteuid() != 0:
        check(r.get("ok") is False and "org.example.left1" in (r.get("error") or ""),
              "a directory the wipe cannot empty is said: %s" % r.get("error"))
    check(w.run("keys").get("keys") == [] and not os.path.exists(os.path.join(root, "data", "org.example.left0"))
          and not os.path.exists(os.path.join(root, "data", "org.example.left2")) and w.run("list").get("packages") == [],
          "past that failure, the owner's key, the deep tree and the other package's data are gone: %s" % os.listdir(
              os.path.join(root, "data")))
    check(w.run("wipe").get("ok") is True and os.listdir(os.path.join(root, "data")) == [], "a second wipe takes what is left")

    # A removal holds a constant number of descriptors however deep the tree: 100 levels under a limit of 64.
    arch = w.pack(w.tree(manifest("org.example.deep"), RUN), "official")
    check(w.run("install", arch).get("ok") is True, "deep could not be installed")
    os.makedirs(os.path.join(root, "data", "org.example.deep", *["d"] * 100))
    r = w.run("remove", "org.example.deep", pre=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64)))
    check(r.get("ok") is True and not os.path.exists(os.path.join(root, "data", "org.example.deep")),
          "a data tree 100 directories deep, removed by a command with 64 descriptors: %s" % r.get("error"))

    # A removal a running package races stays inside the package's tree: a directory moved up inside it or out of
    # it under the walk is found by its "..", and a directory swapped for a link between the walk's look and its open
    # is not followed. The hook makes each race once, inside the wipe; the directory beside the tree keeps all it had.
    hook = os.environ.get("RACE_HOOK") or os.path.join(HERE, "..", "build", "race_hook.so")
    check(os.path.isfile(hook), "the race hook is built: %s" % hook)
    for mode, words in (("up", "Stale file handle"), ("out", "Stale file handle"), ("symlink", "Not a directory")):
        rroot = os.path.join(w.top, "race-" + mode)
        tree_ = os.path.join(rroot, "data", "org.example.race")
        outside = os.path.join(rroot, "outside")
        for d in ("a/b/c", "z"):
            os.makedirs(os.path.join(tree_, d))
        os.makedirs(os.path.join(outside, "keepdir"))
        for f in ("a/b/c/trigger", "a/b/c/f1", "a/b/x", "a/t", "z/f"):
            with open(os.path.join(tree_, f), "w") as g:
                g.write("x")
        for f in ("precious", "keepdir/f"):
            with open(os.path.join(outside, f), "w") as g:
                g.write("kept")
        p = subprocess.run([FORGEEXT, "--root", rroot, "--no-reserve", "wipe"], capture_output=True, text=True,
                           env=dict(os.environ, LD_PRELOAD=hook, RACE_MODE=mode, RACE_TREE=tree_, RACE_OUT=outside))
        try:
            out = json.loads(p.stdout)
        except ValueError:
            out = {"ok": None, "error": "not JSON: %r" % p.stdout[:200]}
        kept = all(open(os.path.join(outside, f)).read() == "kept" for f in ("precious", "keepdir/f")
                   if os.path.exists(os.path.join(outside, f))) and os.path.isfile(os.path.join(outside, "keepdir", "f")) \
            and os.path.isfile(os.path.join(outside, "precious"))
        check("race_hook:" in p.stderr and out.get("ok") is False and words in (out.get("error") or "") and kept,
              "a wipe raced by a %s: %s, and beside the tree %s" % (mode, out.get("error") or out,
                                                                    "all is kept" if kept else "something went"))
        shutil.rmtree(rroot, ignore_errors=True)

    # A /data that takes no more writes: the empty state cannot be written and the wipe stops there, the owner's keys
    # gone all the same (removing one takes no space).
    check(w.run("key-add", "maker", w.pub("owner")).get("ok") is True, "the key could not be added back")

    def full():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    r = w.run("wipe", pre=full)
    check(r.get("ok") is False and "state.json" in (r.get("error") or "") and not [k for k in os.listdir(keydir) if k.endswith(".pub")],
          "a wipe whose state write fails still takes the owner's keys: %s, keys %s" % (r.get("error"), os.listdir(keydir)))
    check(w.run("wipe").get("ok") is True, "and the next wipe finishes")

    # A state that does not read names nothing, and the wipe takes everything all the same.
    check(w.run("key-add", "maker", w.pub("owner")).get("ok") is True, "the key could not be added back")
    arch = w.pack(w.tree(manifest("org.example.lost"), RUN), "owner")
    check(w.run("install", arch, "--consent-community").get("ok") is True, "lost could not be installed")
    for id_ in ("org.example.lost", "org.example.gone"):    # its settings, and those of a package no longer installed
        with open(os.path.join(root, "settings", id_ + ".json"), "w") as f:
            f.write('{"broker": "the last owner\'s"}\n')
    with open(os.path.join(root, "state.json"), "w") as f:
        f.write("{damaged")
    r = w.run("wipe")
    check(r.get("ok") is True and w.run("list").get("packages") == [] and w.run("keys").get("keys") == []
          and os.listdir(os.path.join(root, "pkg")) == [] and os.listdir(os.path.join(root, "data")) == []
          and os.listdir(os.path.join(root, "settings")) == [],
          "a wipe on a state that does not read takes every package, its data and every settings file: %s, settings %s"
          % (r, os.listdir(os.path.join(root, "settings"))))


if __name__ == "__main__":
    sys.exit(main())
