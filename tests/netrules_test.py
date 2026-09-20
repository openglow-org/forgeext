#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""Host test of forgeext's network allowlist against the image's deny rules.

In a network and mount namespace of its own, with a peer namespace on a veth
pair, a private /etc/hosts and /etc/resolv.conf, and the image's rule file
(ffx.nft, from the forgefirm repository) loaded: `forgeext net-check` holds
the table to its shape; `net-allow` opens a pool account's declared
destination, by name, and nothing else, and replaces what the account had; a
destination that is this machine, by address or by name, is refused in
words, and so are a name that does not resolve and an account outside the
pool; --listen lets the account answer on its port; --dns opens the
resolvers that are not this machine; `net-revoke` closes everything.

Needs root, nft, ip, nsenter, unshare, the built forgeext (FORGEEXT), and
the rule file (FFX_RULES, default the sibling forgefirm checkout). Exits 77
when one is missing, 0 on a pass, 1 on a failure.
"""
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
RULES = os.environ.get("FFX_RULES") or os.path.join(HERE, "..", "..", "forgefirm", "meta-forgefirm", "recipes-forgefirm",
                                                    "forgefirm-sandbox", "files", "ffx.nft")
NFT = os.environ.get("NFT") or shutil.which("nft") or "/usr/sbin/nft"
HERE_ADDR, PEER_ADDR = "10.99.1.1", "10.99.1.2"
UID = 800
SKIP = 77

PEER = r'''
import socket, sys
print("pid", flush=True)
sys.stdin.readline()
tcp = []
for _ in range(2):
    s = socket.socket()
    s.bind(("%s", 0))
    s.listen(128)
    tcp.append(s)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("%s", 53))
print(tcp[0].getsockname()[1], tcp[1].getsockname()[1], flush=True)
sys.stdin.readline()
''' % (PEER_ADDR, PEER_ADDR)

failures = []


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


def attempt(uid, addr, port, udp=False):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        word = "ok"
        try:
            if uid:
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            s.settimeout(3.0)
            if udp:
                s.sendto(b"x", (addr, port))
            else:
                s.connect((addr, port))
            s.close()
        except socket.timeout:
            word = "timeout"
        except OSError as e:
            word = {errno.ECONNREFUSED: "refused", errno.EPERM: "eperm"}.get(e.errno, errno.errorcode.get(e.errno, str(e.errno)))
        os.write(w, word.encode())
        os._exit(0)
    os.close(w)
    word = os.read(r, 64).decode()
    os.close(r)
    os.waitpid(pid, 0)
    return word


def fx(*args):
    p = subprocess.run([FORGEEXT, "--nft", NFT] + list(args), capture_output=True, text=True)
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = {"ok": None, "error": "not JSON: %r %r" % (p.stdout[:200], p.stderr[:200])}
    return out


def main():
    if os.environ.get("FFX_NET_NS") != "1":
        missing = [t for t in ("unshare", "nsenter", "ip", "mount") if not shutil.which(t)]
        if os.geteuid() != 0 or missing or not os.path.isfile(NFT) or not os.path.isfile(FORGEEXT) or not os.path.isfile(RULES):
            print("skipped: needs root, nft, ip, nsenter, unshare, the built forgeext (FORGEEXT), and the rule file "
                  "(FFX_RULES); missing tools: %s; forgeext %s; rules %s"
                  % (", ".join(missing) or "none", os.path.isfile(FORGEEXT), os.path.isfile(RULES)))
            return SKIP
        os.execvpe("unshare", ["unshare", "-n", "-m", sys.executable, os.path.abspath(__file__)],
                   dict(os.environ, FFX_NET_NS="1"))

    top = tempfile.mkdtemp(prefix="forgeext-net.")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    if subprocess.run([NFT, "list", "tables"], capture_output=True).returncode != 0:
        print("skipped: this kernel has no nf_tables")
        return SKIP
    # Names and resolvers of the test's own, seen by nobody outside this mount namespace.
    for name, text in (("hosts", "127.0.0.1 localhost\n%s peer.test\n%s self.test\n" % (PEER_ADDR, HERE_ADDR)),
                       ("resolv.conf", "nameserver 127.0.0.53\nnameserver %s\n" % PEER_ADDR)):
        path = os.path.join(top, name)
        with open(path, "w") as f:
            f.write(text)
        subprocess.run(["mount", "--bind", path, os.path.realpath("/etc/" + name)], check=True)

    peer = subprocess.Popen(["unshare", "-n", sys.executable, "-u", "-c", PEER], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    peer.stdout.readline()
    ns = ["nsenter", "-t", str(peer.pid), "-n"]
    for cmd in (["ip", "link", "add", "ffxn0", "type", "veth", "peer", "name", "ffxn1"],
                ["ip", "link", "set", "ffxn1", "netns", str(peer.pid)],
                ["ip", "addr", "add", HERE_ADDR + "/24", "dev", "ffxn0"], ["ip", "link", "set", "ffxn0", "up"],
                ns + ["ip", "addr", "add", PEER_ADDR + "/24", "dev", "ffxn1"], ns + ["ip", "link", "set", "ffxn1", "up"],
                ns + ["ip", "link", "set", "lo", "up"]):
        subprocess.run(cmd, check=True, capture_output=True)
    peer.stdin.write("go\n")
    peer.stdin.flush()
    p1, p2 = [int(x) for x in peer.stdout.readline().split()]
    for _ in range(50):
        if attempt(0, PEER_ADDR, p1) == "ok":
            break
        time.sleep(0.1)

    print("the table is held to its shape")
    r = fx("net-check")
    check(r.get("ok") is False and "not loaded" in r.get("error", ""), "no table -> %s", r.get("error"))
    r = fx("net-allow", str(UID), "%s:%d" % (PEER_ADDR, p1))
    check(r.get("ok") is False and "not loaded" in r.get("error", ""), "net-allow with no table -> %s", r.get("error"))
    crippled = os.path.join(top, "no-lo.nft")
    with open(RULES) as f, open(crippled, "w") as g:
        g.write("".join(line for line in f if 'oifname "lo"' not in line))
    subprocess.run([NFT, "-f", crippled], check=True)
    r = fx("net-check")
    check(r.get("ok") is False and "machine itself" in r.get("error", ""), "a table without the lo rule -> %s", r.get("error"))
    subprocess.run([NFT, "-f", RULES], check=True)
    check(fx("net-check").get("ok") is True, "the image's table")

    print("a declared destination, by name")
    check(attempt(UID, PEER_ADDR, p1) == "refused", "before anything, the account is refused at the peer")
    r = fx("net-allow", str(UID), "peer.test:%d" % p1)
    check(r.get("ok") is True, "net-allow peer.test:%d -> %s", p1, r)
    check(attempt(UID, PEER_ADDR, p1) == "ok", "the declared port answers")
    check(attempt(UID, PEER_ADDR, p2) == "refused", "another port of the peer does not")
    check(attempt(UID + 1, PEER_ADDR, p1) == "refused", "another account does not get through on it")
    check(attempt(UID, "127.0.0.1", 9) in ("refused",), "loopback stays shut")
    listed = subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True, text=True).stdout
    check("ip daddr %s tcp dport %d accept" % (PEER_ADDR, p1) in listed and "peer.test" not in listed,
          "the rule names the address that was judged, not the name: %s", " ".join(listed.split()))
    r = fx("net-allow", str(UID), "%s:%d" % (PEER_ADDR, p2))
    check(r.get("ok") is True and attempt(UID, PEER_ADDR, p2) == "ok" and attempt(UID, PEER_ADDR, p1) == "refused",
          "a second net-allow replaces the first")

    print("what is refused in words, the account's rules left as they were")
    for args, words in ((["127.0.0.1:80"], "is this machine"), (["self.test:23"], "is this machine (%s)" % HERE_ADDR),
                        (["%s:23" % HERE_ADDR], "is this machine"), (["[::1]:443"], "is this machine"),
                        (["nowhere.invalid:443"], "cannot resolve"), (["peer.test"], "host:port")):
        r = fx("net-allow", str(UID), *args)
        check(r.get("ok") is False and words in r.get("error", ""), "%s -> %s", args[0], r.get("error"))
    r = fx("net-allow", "799", "%s:%d" % (PEER_ADDR, p1))
    check("not one of the pool's" in r.get("error", ""), "account 799 -> %s", r.get("error"))
    check(attempt(UID, PEER_ADDR, p2) == "ok", "the refusals left the account's rules alone")

    print("--dns opens the resolvers that are not this machine")
    check(attempt(UID, PEER_ADDR, 53, udp=True) == "eperm", "without it, a lookup cannot leave")
    r = fx("net-allow", str(UID), "--dns", "peer.test:%d" % p1)
    check(r.get("ok") is True and attempt(UID, PEER_ADDR, 53, udp=True) == "ok", "with it, the peer's port 53 takes UDP: %s", r)
    listed = subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True, text=True).stdout
    check("127.0.0.53" not in listed, "the resolver on this machine is not in the chain")
    check(attempt(UID, PEER_ADDR, 5353, udp=True) == "eperm", "and no other UDP port opens")

    print("--listen lets the account answer on its port")
    lport = 18080
    hold_r, hold_w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(hold_w)
        os.setgroups([])
        os.setgid(UID)
        os.setuid(UID)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HERE_ADDR, lport))
        s.listen(16)
        os.read(hold_r, 1)
        os._exit(0)
    os.close(hold_r)
    time.sleep(0.3)
    dial = ns + [sys.executable, "-c", "import socket,sys\ns=socket.socket()\ns.settimeout(2)\n"
                 "try:\n s.connect(('%s',%d)); print('ok')\nexcept Exception as e:\n print(type(e).__name__)" % (HERE_ADDR, lport)]
    before = subprocess.run(dial, capture_output=True, text=True).stdout.strip()
    check(before != "ok", "without --listen the peer cannot complete a connection to the account's port -> %s", before)
    r = fx("net-allow", str(UID), "--listen", str(lport))
    after = subprocess.run(dial, capture_output=True, text=True).stdout.strip()
    check(r.get("ok") is True and after == "ok", "with --listen %d it can -> %s", lport, after)
    os.close(hold_w)
    os.waitpid(child, 0)

    print("net-revoke closes everything")
    fx("net-allow", str(UID), "peer.test:%d" % p1)
    check(attempt(UID, PEER_ADDR, p1) == "ok", "open before the revoke")
    check(fx("net-revoke", str(UID)).get("ok") is True and attempt(UID, PEER_ADDR, p1) == "refused", "shut after it")
    check(subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True).returncode != 0,
          "the account's chain is gone")
    check(fx("net-revoke", str(UID)).get("ok") is True, "a second revoke is not an error")
    check(fx("net-check").get("ok") is True, "and the table is still the image's")

    peer.stdin.close()
    peer.wait(timeout=5)
    shutil.rmtree(top, ignore_errors=True)
    print("%s: netrules_test, %d failure%s" % ("FAIL" if failures else "PASS", len(failures), "" if len(failures) == 1 else "s"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
