#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""tools/ffx held to the host it mirrors.

Every fixture is a package directory. `ffx lint` judges it, and the same
directory, packed unsigned by tools/mkffx.sh, is judged by the built
`forgeext inspect`: the two must agree on every verdict, and where the host
refuses a manifest the words must be the host's. Then `ffx pack` builds an
archive the host takes, the same bytes twice over a second apart, signed or
not; `ffx new` makes a package
for each runtime that lints as its template says; `ffx keygen` refuses to
overwrite a key; `ffx index record` writes a listed version's record only
for an archive its signer's key verifies, and none for an archive that a
zip tool reads otherwise than the machine; `ffx install` and `ffx logs`
check the remembered certificate on every connection, before the password
goes, and `ffx install` names the archive it was answered for and takes an
unverified package's press through its consent; and `ffx index build` makes an
index of a catalog directory that the host keeps, the same bytes twice over
a second apart, and refuses a catalog out of form. The fixtures are one per
path of the manifest's judgment and of lint's file checks; the index's form
is install_test's.

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
import time

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


# (name, manifest (dict, or raw bytes), extra files {path: text}); a ui package gets its page, a service its entry;
# "__words__" in the extra files is the refusal both must give in those words
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
    ("not JSON", b"{\"manifest\": 1,", {}),
    ("a key twice", b'{"manifest": 1, "manifest": 1}', {}),
    ("an unknown key", with_(colour="red"), {}),
    ("the wrong schema", with_(manifest=2), {}),
    ("an id with an upper-case letter", with_(id="org.Example.x"), {}),
    ("a name with a control character", with_(name="a\tb"), {}),
    ("a version with a leading zero", with_(version="1.01.0"), {}),
    ("an api too new", with_(api="0.2"), {}),
    ("a core min above its max", with_(core={"min": "2.0.0", "max": "1.0.0"}), {}),
    ("a runtime there is none of", with_(runtime="java"), {}),
    ("a service entry with ..", with_(service={"exec": "../run.py"}), {}),
    ("a mode twice", with_(modes=["grbl", "grbl"]), {}),
    ("a capability there is none of", with_(capabilities=["laser.fire"]), {}),
    ("an M-code", with_(capabilities=["mcode:160", "mcode:179", "job_time.run"]), {}),
    ("an M-code with no job_time.run", with_(capabilities=["mcode:160"]), {}),
    ("an outbound to the machine", with_(capabilities=["net.outbound:127.0.0.1:80"]), {}),
    ("a capability twice", with_(capabilities=["hold", "hold"]), {}),
    ("a conflict with itself", with_(conflicts=["org.example.fixture"]), {}),
    ("a number default out of bounds", with_(settings={"a": {"type": "number", "default": 9, "max": 5}}), {}),
    ("a ui package without its page", with_(runtime="ui", service=None, capabilities=["ui"]), {"__no_page__": ""}),
    ("a page that asks for a press", with_(runtime="ui", service=None, capabilities=["ui", "button"]),
     {"__words__": 'capability "button" belongs to a service, and runtime ui has none'}),
    ("a page that does not ask for ui", with_(), {"ui/index.html": "<!doctype html><p>page</p>",
                                                  "__words__": "this package has a ui/index.html and does not ask for ui"}),
    ("an entry point that is not there", with_(service={"exec": "bin/other.py"}), {}),
    ("a page that holds a NUL", with_(runtime="ui", service=None, capabilities=["ui"]),
     {"ui/index.html": "<!doctype html><p>a\0b</p>", "__words__": "ui/index.html holds a NUL"}),
    ("a shell service that answers an M-code", with_(runtime="shell", service={"exec": "bin/run.sh"},
                                                     capabilities=["job_time.run", "mcode:160"]),
     {"__words__": 'capability "mcode:160" is asked on the call socket, which a shell service cannot answer: '
                   'runtime python or native'}),
    ("an outbound address in a form that is not the canonical dotted quad", with_(capabilities=["net.outbound:010.1.2.3:80"]),
     {}),
    ("more directories than a payload holds", with_(), {"__dirs__": "4097",
                                                         "__words__": "the payload holds more than 4096 directory entries"}),
]


def two_views(first, second):
    """first's entries and central directory as they are, then second's payload entry and a central directory
    that names first's metadata and second's payload: a streaming reader stops at first's directory, and a zip
    tool, which reads the last one, sees second's payload."""
    import struct

    def central(z):
        cd_size, cd_off = struct.unpack("<II", z[-10:-2])
        out, p = [], cd_off
        while p < cd_off + cd_size:
            nlen, xlen, klen = struct.unpack("<HHH", z[p + 28:p + 34])
            out.append((z[p + 46:p + 46 + nlen].decode(), p, z[p:p + 46 + nlen + xlen + klen]))
            p += 46 + nlen + xlen + klen
        return cd_off, out

    _, cd1 = central(first)
    off2, cd2 = central(second)
    local2 = struct.unpack("<I", cd2[-1][2][42:46])[0]
    tail = second[local2:off2]                          # second's payload entry, its data descriptor included
    at = len(first)
    entries = [e[2] for e in cd1 if e[0] != "data/payload.tar.gz"]
    entries.append(cd2[-1][2][:42] + struct.pack("<I", at) + cd2[-1][2][46:])
    cd = b"".join(entries)
    return (first + tail + cd + b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, len(entries), len(entries), len(cd),
                                                            at + len(tail), 0))


def zip_entries(z):
    """An archive as its entries, each with the fields of its local header and of its directory entry, so that a
    row of the archive table can change one thing and zip_join write it back."""
    import struct
    cd_size, cd_off = struct.unpack("<II", z[-10:-2])
    out, p = [], cd_off
    while p < cd_off + cd_size:
        (ver, need, flags, method, tm, dt, crc, csize, usize, nlen, xlen, klen, _d, _i, eattr, local) = \
            struct.unpack("<HHHHHHIIIHHHHHII", z[p + 4:p + 46])
        lf = struct.unpack("<HHHHHIIIHH", z[local + 4:local + 30])
        start = local + 30 + lf[8] + lf[9]
        e = {"ver": ver, "need": need, "flags": flags, "method": method, "tm": tm, "dt": dt, "crc": crc,
             "csize": csize, "usize": usize, "eattr": eattr, "name": z[p + 46:p + 46 + nlen],
             "cx": z[p + 46 + nlen:p + 46 + nlen + xlen], "lflags": lf[1], "lmethod": lf[2], "lsizes": lf[5:8],
             "lname": z[local + 30:local + 30 + lf[8]], "lx": z[local + 30 + lf[8]:start],
             "data": z[start:start + csize]}
        e["desc"] = z[start + csize:start + csize + 16] if flags & 8 else b""
        out.append(e)
        p += 46 + nlen + xlen + klen
    return out


def zip_join(entries, gap=b"", cd_size_delta=0, comment=b"", cd_tail=b"", disk=0, count_delta=0):
    """The archive of zip_entries' entries; a key "at" in an entry is the offset its directory entry gives, and
    "lsig" or "csig" the signature its local header or its directory entry carries. cd_tail is bytes after the
    directory's last entry that the end counts in the directory's size; disk the disk numbers the end gives;
    count_delta is added to the number of entries the end gives."""
    import struct
    body, cd = b"", b""
    for e in entries:
        at = len(body)
        body += struct.pack("<4sHHHHHIIIHH", e.get("lsig", b"PK\x03\x04"), e["need"], e["lflags"], e["lmethod"], e["tm"],
                            e["dt"], *e["lsizes"], len(e["lname"]), len(e["lx"])) + e["lname"] + e["lx"] + e["data"] + e["desc"]
        cd += struct.pack("<4sHHHHHHIIIHHHHHII", e.get("csig", b"PK\x01\x02"), e["ver"], e["need"], e["flags"], e["method"],
                          e["tm"], e["dt"], e["crc"], e["csize"], e["usize"], len(e["name"]), len(e["cx"]), 0, 0, 0,
                          e["eattr"], e.get("at", at)) + e["name"] + e["cx"]
    body += gap
    cd += cd_tail
    n = len(entries) + count_delta
    return body + cd + b"PK\x05\x06" + struct.pack("<HHHHIIH", disk, disk, n, n, len(cd) + cd_size_delta, len(body),
                                                   len(comment)) + comment


def local_header_cut_short():
    """An archive whose second local header starts 4 bytes before the end of the central directory, so that the
    file ends 26 bytes short of it. The first entry, stored, runs from its local header over the whole directory up
    to there; its CRC, which lies inside its own data, is solved for (CRC-32 is affine over GF(2) in the data's bits),
    so that the entry itself passes every rule."""
    import struct
    import zlib
    a, b = b"meta.conf", b"data/payload.tar.gz"
    xb = struct.pack("<HH", 0x5455, 5) + b"\x01PK\x03\x04"  # its last 4 bytes are the second local header's start
    cd_off = 30 + len(a)
    cd_size = 46 + len(a) + 46 + len(b) + len(xb)
    second = cd_off + cd_size - 4
    size = second - cd_off

    def cd(crc, tm):
        return (struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, tm, 0, crc, size, size, len(a), 0, 0, 0,
                            0, 0, 0) + a +
                struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0, len(b), len(xb), 0, 0,
                            0, 0, second) + b + xb)

    for tm in range(64):
        f0 = zlib.crc32(cd(0, tm)[:size])
        cols = [zlib.crc32(cd(1 << i, tm)[:size]) ^ f0 ^ (1 << i) for i in range(32)]
        # Solve (G + I) x = f0 over GF(2): rows are the 32 equations, each a 32-bit mask of x's bits and its value.
        rows = [(sum(((cols[i] >> r) & 1) << i for i in range(32)), (f0 >> r) & 1) for r in range(32)]
        x, piv = 0, []
        for col in range(32):
            k = next((j for j in range(len(rows)) if (rows[j][0] >> col) & 1), None)
            if k is None:
                break
            pr = rows.pop(k)
            rows = [(m ^ pr[0], v ^ pr[1]) if (m >> col) & 1 else (m, v) for m, v in rows]
            piv = [(m ^ pr[0], v ^ pr[1]) if (m >> col) & 1 else (m, v) for m, v in piv] + [pr]
        else:
            for m, v in piv:
                x |= v << (m.bit_length() - 1)
            d = cd(x, tm)
            assert zlib.crc32(d[:size]) == x
            return (struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, tm, 0, x, size, size, len(a), 0) + a + d +
                    b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 2, 2, cd_size, cd_off, 0))
    raise AssertionError("no CRC solves the archive")


def zip_rows(z):
    """The archive table: (what, archive), one row per rule of ffx's archive reader, each the signed fixture with
    one thing changed, which the reader must refuse. Two rules have no row. An entry that runs past the archive's
    end is refused by the size rule (stored), the deflated end (deflated) and the place rules too: the next entry,
    or the directory, is not where it ends. A compressed size of 0xFFFFFFFF runs past the end; a size of 0xFFFFFFFF
    is refused by the size rule too, except an entry that decompresses to exactly 4 GiB less one byte, which no
    test unpacks."""
    import copy
    import struct
    import zlib
    base = zip_entries(z)

    def row(change, **join):
        es = copy.deepcopy(base)
        change(es)
        return zip_join(es, **join)

    def entry(es, name):
        return next(e for e in es if e["name"] == name.encode())

    def put(e, body, method, flags=8):
        # body as the entry's data, stored (0) or deflated (8), its sizes after it as fwup writes them
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        e["data"] = body if method == 0 else c.compress(body) + c.flush()
        e["method"] = e["lmethod"] = method
        e["flags"] = e["lflags"] = flags
        e["crc"], e["csize"], e["usize"] = zlib.crc32(body) & 0xFFFFFFFF, len(e["data"]), len(body)
        redesc(e)

    def redesc(e):
        e["desc"] = b"PK\x07\x08" + struct.pack("<III", e["crc"], e["csize"], e["usize"])

    def meta_body(es):
        return zlib.decompress(entry(es, "meta.conf")["data"], -15)

    def stored_with_signature(es):
        put(entry(es, "meta.conf"), meta_body(es) + b"# PK\x07\x08\n", 0)

    def trailing(es):
        e = entry(es, "meta.conf")
        e["data"] += b"\0\0\0\0"
        e["csize"] += 4
        redesc(e)

    def unfinished(es):
        # meta.conf deflated with a sync flush and no final block: the whole body, but the stream does not end
        e, body = entry(es, "meta.conf"), meta_body(es)
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        e["data"] = c.compress(body) + c.flush(zlib.Z_SYNC_FLUSH)
        e["csize"] = len(e["data"])
        redesc(e)

    def longer(es):
        # the directory and the descriptor give meta.conf one byte more than its data, its CRC kept
        e = entry(es, "meta.conf")
        e["usize"] += 1
        redesc(e)

    def flip(es):
        e = entry(es, "meta.conf.ed25519")
        e["data"] = bytes([e["data"][0] ^ 1]) + e["data"][1:]

    def twice(es):
        es.insert(2, copy.deepcopy(entry(es, "meta.conf")))

    def other_name(e):
        n = b"data/payload.tar.xz"
        return struct.pack("<HHBI", 0x7075, 5 + len(n), 1, zlib.crc32(e["name"]) & 0xFFFFFFFF) + n

    return [
        ("the directory gives an entry another place than where it is", row(lambda es: es[0].update(at=1))),
        ("bytes between the last entry and the directory", row(lambda es: None, gap=b"\0" * 8)),
        ("a stored entry with its sizes after it holds a descriptor's signature", row(stored_with_signature)),
        ("a deflated entry with bytes after its end", row(trailing)),
        ("the directory's end gives the directory another size", row(lambda es: None, cd_size_delta=1)),
        ("a comment after the directory's end", row(lambda es: None, comment=b"note")),
        ("an entry of another name", row(lambda es: entry(es, "data/payload.tar.gz").update(
            name=b"data/payload.tar.xz", lname=b"data/payload.tar.xz"))),
        ("a local header that names another entry than the directory", row(lambda es: entry(es, "meta.conf").update(
            lname=b"meta.cong"))),
        ("a data descriptor that is not the directory's", row(lambda es: entry(es, "data/payload.tar.gz").update(
            desc=b"PK\x07\x08" + struct.pack("<III", entry(es, "data/payload.tar.gz")["crc"] ^ 1,
                                             entry(es, "data/payload.tar.gz")["csize"],
                                             entry(es, "data/payload.tar.gz")["usize"])))),
        ("an entry whose data is not the CRC the directory gives", row(flip)),
        ("an entry named twice", row(twice)),
        ("a zip64 field in a local header", row(lambda es: es[0].update(lx=struct.pack("<HH", 1, 16) + b"\0" * 16))),
        ("a second name in the directory's extra field", row(lambda es: entry(es, "data/payload.tar.gz").update(
            cx=other_name(entry(es, "data/payload.tar.gz"))))),
        ("an extra field that is not whole", row(lambda es: entry(es, "meta.conf").update(cx=b"\x01"))),
        ("an extra field of another type (Info-ZIP's Unix attributes, a link)", row(lambda es: entry(
            es, "data/payload.tar.gz").update(lx=struct.pack("<HHI", 0x6C78, 4, 0xA1FF0000)))),
        ("a deflated entry that does not decompress", row(lambda es: entry(es, "meta.conf").update(
            data=b"\0" + entry(es, "meta.conf")["data"][1:]))),
        ("an encrypted entry", row(lambda es: entry(es, "meta.conf.ed25519").update(
            flags=entry(es, "meta.conf.ed25519")["flags"] | 1, lflags=entry(es, "meta.conf.ed25519")["lflags"] | 1))),
        ("an entry compressed in another way than stored or deflated", row(lambda es: entry(
            es, "meta.conf.ed25519").update(method=12, lmethod=12))),
        ("an entry without its sizes after it whose local header gives other sizes", row(
            lambda es: without_descriptor(entry(es, "meta.conf.ed25519"), 1))),
        ("an entry without its sizes after it whose local header gives another CRC", row(
            lambda es: without_descriptor(entry(es, "meta.conf.ed25519"), crc_delta=1))),
        ("an entry without its sizes after it whose local header gives another compressed size", row(
            lambda es: without_descriptor(entry(es, "meta.conf.ed25519"), csize_delta=1))),
        ("a deflated entry that stops before its final block", row(unfinished)),
        ("an entry whose data is not the size the directory gives", row(longer)),
        ("a directory entry cut short by the directory's end", row(lambda es: None, cd_tail=b"PK\x01\x02" + b"\0" * 10,
                                                                   count_delta=1)),
        ("a local header that gives another method than the directory", row(lambda es: entry(
            es, "meta.conf.ed25519").update(lmethod=8))),
        ("a local header that gives other flags than the directory", row(lambda es: entry(
            es, "meta.conf.ed25519").update(lflags=entry(es, "meta.conf.ed25519")["flags"] & ~8))),
        ("bytes in the directory after its last entry", row(lambda es: None, cd_tail=b"\0" * 8)),
        ("a directory entry that is no entry", row(lambda es: es[1].update(csig=b"PK\x01\x03"))),
        ("a local header that is no entry", row(lambda es: es[1].update(lsig=b"PK\x03\x05"))),
        ("an end that names another disk", row(lambda es: None, disk=1)),
    ]


def without_descriptor(e, usize_delta=0, crc_delta=0, csize_delta=0):
    """e with its CRC and sizes in its local header and no data descriptor, the local header's CRC, compressed size
    and size each off by its delta."""
    e["flags"] &= ~8
    e["lflags"] &= ~8
    e["desc"] = b""
    e["lsizes"] = (e["crc"] ^ crc_delta, e["csize"] + csize_delta, e["usize"] + usize_delta)


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
    for k in range(int(extra.get("__dirs__", "0"))):
        os.makedirs(os.path.join(d, "many", "%04d" % k))
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
    as the file part, the grants and the phrase, the digest of the archive the upload was answered for, and an
    unverified package's consent registered and pressed before its install."""
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
    tier, consent, nonce, polls = ["community"], ["typed"], [], []
    DIGEST = "ab" * 32

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
                return self.reply(200 if ok else 400, {"tier": tier[0], "consent": consent[0], "update": False,
                                                       "needs_grant": ["hold"], "new_capabilities": [], "digest": DIGEST,
                                                       "package": {"id": "org.example.fixture", "version": "1.0.0",
                                                                   "author": "Test", "capabilities": ["hold", "machine.read"]}})
            if u.path == "/button/reserve":
                # The consent's registration and its renewals: not ready, then ready, then the press taken.
                q = dict(urllib.parse.parse_qsl(u.query))
                if q.get("on") == "0":
                    return self.reply(200, {"reserved": False, "ready": False, "pressed": False, "waits": ""})
                ok = q.get("for") == "install" and q.get("digest") == DIGEST and q.get("id", "").startswith("ffx")
                if not ok or (nonce and q["id"] != nonce[0]):
                    return self.reply(400, {"error": "not the consent: %s" % q})
                nonce[:] = [q["id"]]
                polls.append(q["id"])
                n = len(polls)
                return self.reply(200, {"reserved": True, "ready": n >= 2, "pressed": n >= 3,
                                        "waits": "" if n >= 2 else "a job waits for the button press: cancel it first"})
            if u.path == "/ext/install":
                f = dict(urllib.parse.parse_qsl(body.decode()))
                want = ({"grants": "hold", "phrase": "I UNDERSTAND", "digest": DIGEST} if consent[0] == "typed"
                        else {"grants": "hold", "digest": DIGEST, "consent": nonce[0] if nonce else "?"})
                ok = f == want
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
        # An unverified package: the consent registered for this archive and renewed, the press asked for once the
        # machine is ready, the install carrying the press's name and the digest, and the consent withdrawn after.
        tier[0], consent[0] = "unverified", "button"
        seen.clear()
        answers = iter([])
        with out:
            rc = ffx.main(["install", archive, "--machine", addr, "--user", "owner", "--grant", "hold"])
        posts = [p[1] for p in seen if p[0] == "POST"]
        check(rc == 0 and "installed: org.example.fixture" in out.text and "Press the machine's button once now." in out.text,
              "an unverified package installed on the press: rc %s, %s", rc, out.text[-300:])
        check(0 <= out.text.find("Not yet:") < out.text.find("Press the machine's button once now."),
              "the press asked for only once the machine is ready, after it named who waits: %s", out.text[-300:])
        check(posts == ["/login", "/ext/upload"] + ["/button/reserve"] * 3 + ["/ext/install", "/button/reserve"],
              "login, upload, the consent until pressed, install, the consent withdrawn: %s", posts)
        seen.clear()
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
        # A party in the middle that lets the first connection through to the machine and answers the next ones
        # with its own certificate: the password never goes over them.
        cert2, key2 = os.path.join(top, "cert2.pem"), os.path.join(top, "key2.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key2, "-out", cert2,
                        "-subj", "/CN=forgefirm", "-days", "1"], check=True, capture_output=True)
        cx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cx2.load_cert_chain(cert2, key2)
        handshakes = []

        class Swapping(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, peer = self.socket.accept()
                handshakes.append(peer)
                return (cx if len(handshakes) == 1 else cx2).wrap_socket(sock, server_side=True), peer

        mitm = Swapping(("127.0.0.1", 0), Forgectrl)
        threading.Thread(target=mitm.serve_forever, daemon=True).start()
        seen.clear()
        answers = iter(["y"])
        try:
            with out:
                rc = ffx.main(["logs", "--machine", "127.0.0.1:%d" % mitm.server_address[1], "--user", "owner"])
        finally:
            mitm.shutdown()
        check(rc == 1 and len(handshakes) >= 2 and not seen,
              "the certificate is checked on every connection, before anything is sent: rc %s, %d connections, sent %s",
              rc, len(handshakes), [s[:2] for s in seen])
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

        print("ffx's version order and reserved namespace are the host's (src/manifest.c, manifest_test)")
        for a, b, want in (("1.0.0-rc.10", "1.0.0-rc.9", 1), ("1.0.0-alpha", "1.0.0-alpha.1", -1), ("1.0.0-1", "1.0.0-alpha", -1),
                           ("1.0.0-ab", "1.0.0-abc", -1), ("1.0.0-beta.2", "1.0.0-beta.11", -1), ("1.0.0-rc.1", "1.0.0-rc.1", 0),
                           ("1.0.0", "1.0.0-rc.1", 1)):
            check(ffx.version_cmp(a, b) == want, "%s against %s: %d, expected %d", a, b, ffx.version_cmp(a, b), want)
        check(not any(ffx.version_ok(v) for v in ("1.0.0-rc.", "1.0.0-rc.1.", "1.0.0-rc..1", "1.0.0-.", "1.0.0-rc.01"))
              and ffx.version_ok("1.0.0-rc.0") and ffx.version_ok("1.0.0-0a"), "pre-release identifiers")
        check(ffx.official_ns("org.openglow") and ffx.official_ns("org.forgefirm") and ffx.official_ns("org.forgefirm.x")
              and not ffx.official_ns("org.openglowfan.x"), "the reserved namespace")

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
            want = extra.get("__words__")
            if want:
                check(mine == want and want in (theirs.get("error") or ""), "%s: lint and the host refuse it in these words "
                      "(%s / %s)", name, mine, theirs.get("error"))
                continue
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
            if out == a2:
                time.sleep(1.1)                         # a second apart: the clock is no part of the archive
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
        time.sleep(1.1)
        again = os.path.join(top, "signed-again.ffx")
        check(ffx.main(["pack", d, "--key", key + ".priv", "--out", again]) == 0
              and open(signed, "rb").read() == open(again, "rb").read(), "signed twice a second apart: one archive")
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
                  and "secrets: inherit" in wf and "\npermissions:\n  contents: write\n\n" in wf and ("apt: gcc-arm-linux-gnueabihf" in wf) == (runtime == "native")
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
        ixkey = os.path.join(top, "openglow-index")
        check(ffx.main(["keygen", ixkey]) == 0, "and one for the OpenGlow index key")
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
        # Two views of one archive: the fixture as the machine streams it, and, after its central directory, a
        # second package's payload with a directory naming it, which zip tools read. Both are the author's.
        other = os.path.join(top, "other-view.ffx")
        check(ffx.main(["pack", build(top, "the other view", with_(capabilities=["camera.lid"]), {}), "--key",
                        key + ".priv", "--out", other]) == 0, "a second package, signed by the same author")
        twoview = os.path.join(top, "two-view.ffx")
        open(twoview, "wb").write(two_views(open(signed, "rb").read(), open(other, "rb").read()))
        r = inspect(twoview)
        check(r.get("ok") is True and (r.get("package") or {}).get("capabilities") == ["machine.read"],
              "the host reads the first view: %s", r.get("error") or (r.get("package") or {}).get("capabilities"))
        rc, said = ffx_run("index", "record", twoview, "--url", url, "--key", key + ".pub", "--out",
                           os.path.join(top, "two-view.json"))
        check(rc == 1 and not os.path.exists(os.path.join(top, "two-view.json")),
              "an archive that reads two ways is recorded neither way: %s", said)
        # The archive reader's rules, a row each: the signed fixture with one thing changed is refused.
        fixture = open(signed, "rb").read()
        check(zip_join(zip_entries(fixture)) == fixture, "the archive table writes the fixture back byte for byte")
        row = os.path.join(top, "row.ffx")
        es = zip_entries(fixture)
        without_descriptor(next(e for e in es if e["name"] == b"meta.conf.ed25519"))
        open(row, "wb").write(zip_join(es))
        check(sorted(ffx._archive_entries(row)) == sorted(ffx._archive_entries(signed)),
              "an entry with its sizes in its local header, and no data descriptor, is read")
        es = zip_entries(fixture)
        ux = b"\x75\x78\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00"
        for e in es:
            # Info-ZIP's uid/gid (0x7875: uid and gid 1000), as libarchive 3.7.2's zip writer puts it on every entry
            e["lx"] += ux
            e["cx"] += ux
        open(row, "wb").write(zip_join(es))
        try:
            check(sorted(ffx._archive_entries(row)) == sorted(ffx._archive_entries(signed)),
                  "an archive with Info-ZIP's uid/gid field on every entry is read")
        except ffx.Refused as e:
            check(False, "an archive with Info-ZIP's uid/gid field on every entry is read: %s", e)
        for what, z in zip_rows(fixture) + [("a local header cut short by the file's end", local_header_cut_short())]:
            open(row, "wb").write(z)
            try:
                ffx._archive_entries(row)
                check(False, "an archive with %s is refused", what)
            except ffx.Refused:
                check(True, "an archive with %s is refused", what)
            except Exception as e:  # noqa: BLE001 - a crash is no refusal
                check(False, "an archive with %s is refused: %r", what, e)
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
            p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "--official-key", ogkey + ".pub",
                                "--index-key", ixkey + ".pub"] + list(args), capture_output=True, text=True)
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
        check(rc == 1 and "YYYY.MDD.N" in said, "an index version that is none: %s", said)

        i1, i2 = os.path.join(top, "i1.ffi"), os.path.join(top, "i2.ffi")
        for o in (i1, i2):
            if o == i2:
                time.sleep(1.1)                         # a second apart: the clock is no part of the index
            rc, said = index_build(o, ixkey)
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
        rc, said = index_build(i1, ixkey, version="2026.923.2")
        check(rc == 0 and "1 package, 2 versions, 1 withdrawn whole" in said, "the catalog of versions and withdrawals: %s", said)
        r = host("index-verify", i1)
        check(r.get("ok") is True and r.get("packages") == 1, "the host keeps it: %s", r)
        p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--no-reserve", "--index-key", ixkey + ".pub",
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

        machine_client(ffx, top, a1)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
