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
conflicts, the budget, the integrity check, removal, the wipe a change of
owner takes (every package, everything under data/, every key the owner
added), and the signed index (kept only under the OpenGlow extension key,
held to its form, never older than the one kept, endorsing its author key
for one id and no other, judged version by version against the firmware
when read, and what it withdraws). After every refusal the root holds
nothing the refused archive brought.

    python3 tests/install_test.py [-v]

Exits 0 on a pass, 1 on a failure, 77 when fwup or the binary is missing.
"""
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

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
    """One extension root, four key pairs, and the forgeext command line over them."""

    def __init__(self, top):
        self.top = top
        self.root = os.path.join(top, "root")
        self.keys = {}
        for name in ("official", "owner", "stranger", "firmware"):
            d = os.path.join(top, "key-" + name)
            os.mkdir(d)
            subprocess.run([FWUP, "-g"], cwd=d, check=True, capture_output=True)
            self.keys[name] = os.path.join(d, "fwup-key.priv")
        os.makedirs(os.path.join(self.root, "keys"))
        shutil.copy(self.pub("owner"), os.path.join(self.root, "keys", "a-friend.pub"))
        self.n = 0

    def pub(self, name):
        return self.keys[name][:-5] + ".pub"

    def run(self, *args, budget=None, core=None):
        cmd = [FORGEEXT, "--root", self.root, "--fwup", FWUP, "--official-key", self.pub("official"),
               "--firmware-key", self.pub("firmware"), "--no-reserve"]
        cmd += (["--budget-mib", str(budget)] if budget else [])
        cmd += (["--core-version", core] if core else []) + list(args)
        p = subprocess.run(cmd, capture_output=True, text=True)
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


def member(name, data=b"x", type_=tarfile.REGTYPE, linkname="", mode=0o644):
    info = tarfile.TarInfo(name)
    info.type = type_
    info.linkname = linkname
    info.mode = mode
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
    r = t.run("inspect", t.pack(t.tree(manifest("org.example.mc0", caps=["mcode:170"]), RUN), "owner"))
    check(r.get("ok") is False and "which takes job_time.run" in (r.get("error") or ""),
          "mcode with no job_time.run -> %s" % r.get("error"))
    for cap in ("mcode:159", "mcode:180", "mcode:0170", "mcode", "mcode:17x"):
        r = t.run("inspect", t.pack(t.tree(manifest("org.example.mc1", caps=[cap, "job_time.run"]), RUN), "owner"))
        check(r.get("ok") is False and "mcode" in (r.get("error") or ""), "%s -> %s" % (cap, r.get("error")))
    a = t.pack(t.tree(manifest("org.example.mca", caps=["mcode:170", "mcode:171", "job_time.run"]), RUN), "owner")
    r = t.run("install", a, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is True, "a package answering M170 and M171 installs: %s" % r.get("error"))
    b = t.pack(t.tree(manifest("org.example.mcb", caps=["mcode:171", "job_time.run"]), RUN), "owner")
    r = t.run("install", b, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is False and "org.example.mca, which is installed, already answers M171" in (r.get("error") or ""),
          "a second package answering M171 -> %s" % r.get("error"))
    c = t.pack(t.tree(manifest("org.example.mcb", caps=["mcode:172", "job_time.run"]), RUN), "owner")
    r = t.run("install", c, "--consent-unverified", "--grant", "job_time.run")
    check(r.get("ok") is True, "another number is its own: %s" % r.get("error"))
    for id_ in ("org.example.mca", "org.example.mcb"):
        check(t.run("remove", id_).get("ok") is True, "%s goes" % id_)


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
    def build(entries, key="official", version=None):
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
    p = subprocess.run([FORGEEXT, "--root", fresh, "--fwup", FWUP, "--official-key", t.pub("official"), "--no-reserve",
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
    for key, words in (("owner", "not signed with the OpenGlow extension key"), (None, "not signed with the OpenGlow")):
        r = t.run("index-verify", build([listed], key=key))
        check(r.get("ok") is False and words in (r.get("error") or ""), "an index signed by %s -> %s" % (key or "nobody", r.get("error")))
    r = t.run("index-verify", listed)
    check(r.get("ok") is False and "product" in (r.get("error") or ""), "a package given as the index -> %s" % r.get("error"))

    def raw_index(doc, version=None, extra=None):
        members = [member("index.json", json.dumps(doc).encode())] + (extra or [])
        return t.pack_raw(t.tar(members), version or next_version(), "official", product="ForgeFIRM extension index")

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
          and stat.S_IMODE(os.stat(os.path.join(root, "data", A)).st_mode) == 0o700, "the installed layout")
    check(stat.S_IMODE(os.stat(os.path.join(pkg, "1.0.0", "bin", "run.sh")).st_mode) == 0o755
          and stat.S_IMODE(os.stat(os.path.join(pkg, "1.0.0", "share", "notes.txt")).st_mode) == 0o644, "the unpacked modes")
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
    }
    for what, members in hostile.items():
        payload = w.tar([manifest_member(manifest(E, runtime="data"))] + members)
        r = w.run("install", w.pack_raw(payload, "1.0.0", "official"))
        check(r.get("ok") is False, "%s -> %s" % (what, r.get("error")))
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
    check(w.run("install", w.pack(w.tree(manifest("org.example.web1", caps=["net.listen:8123"]), RUN), "official")).get("ok") is True,
          "a listener installs")
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

    print("the firmware range a package says it needs")
    core_range(w)

    print("destinations the operator names")
    operator_destinations(w)

    print("the M-codes a package answers")
    mcodes(w)

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
    # its data kept included: they hold what the wipe is for.
    for sub in ("pkg", "data", "keys"):
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


if __name__ == "__main__":
    sys.exit(main())
