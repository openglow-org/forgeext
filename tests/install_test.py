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
conflicts, the budget, the integrity check, removal, and the wipe a change
of owner takes (every package, everything under data/, every key the owner
added). After every refusal the root holds nothing the refused archive
brought.

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
