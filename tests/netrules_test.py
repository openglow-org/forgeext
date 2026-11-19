#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""Host test of forgeext's network allowlist against the image's deny rules.

In a network and mount namespace of its own, with a peer namespace on a veth
pair, a private /etc/hosts and /etc/resolv.conf, and the image's rule file
(ffx.nft, from the forgefirm repository) loaded: `forgeext net-check` holds
the table to its shape, each part of it taken out in turn refused; nft runs
with no signal blocked and none ignored; `net-allow` opens a pool account's declared
destination, by name, and nothing else, and replaces what the account had; a
destination that is this machine, by address or by name, is refused in
words, and so are a name that does not resolve and an account outside the
pool; a name a manifest gives that answers a private, local or own-subnet
address (IPv4 inside IPv6 judged as itself, each of two that one address
carries, the local-use NAT64 prefix as a whole, this side's IPv6 subnet by
its address's mask and an on-link prefix beside a /128 address by its
route; how the route table is read is lookups_test's) is refused, while
the address
itself is taken, IPv6 too, and so is such a name the operator typed
(--typed), unless it is this machine (its address or loopback carried in a
mapped, compatible, translated, NAT64, 6to4 or ISATAP one, or at any of the
four places of the local-use NAT64 prefix); a
stand-in resolver answering two names in 3.5 s and 2.5 s has both taken
in about 3.5 s, each name with its own bound; --listen lets the account
answer on its port; --dns opens the
resolvers that are not this machine; `net-revoke` closes everything. The listening port answers callers and is no
way out: a connection the account opens from it reaches its declared
destinations and nothing else.

Needs root, nft, ip, nsenter, unshare, the built forgeext (FORGEEXT), and
the rule file (FFX_RULES, default the sibling forgefirm checkout). Exits 77
when one is missing, 0 on a pass, 1 on a failure.
"""
import errno
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(HERE, "..", "build", "forgeext")
RULES = os.environ.get("FFX_RULES") or os.path.join(HERE, "..", "..", "forgefirm", "meta-forgefirm", "recipes-forgefirm",
                                                    "forgefirm-sandbox", "files", "ffx.nft")
NFT = os.environ.get("NFT") or shutil.which("nft") or "/usr/sbin/nft"
# Two documentation networks, routed to each other over the veth pair: the peer is on no subnet of this
# namespace's own, so a name may lead to it, while NEIGHBOR_ADDR is on this side's subnet.
HERE_ADDR, PEER_ADDR, NEIGHBOR_ADDR = "203.0.113.1", "198.51.100.2", "203.0.113.9"
# The local-use NAT64 prefix (64:ff9b:1::/48, a network's own translator): an address in it that carries no
# private one at any place (198.51.100.7 as a /96 translator keeps it), and this side's own address as a /96
# translator keeps it.
LOCAL_USE_NAME, LOCAL_USE_ADDR, SELF_LOCAL_USE = "localnat64.test", "64:ff9b:1::c633:6407", "64:ff9b:1::cb00:7101"
# A name answered by each kind of private or local address, IPv4 inside IPv6 included: each is refused.
LOCAL_NAMES = (("rfc1918b.test", "172.16.5.5"), ("rfc1918c.test", "192.168.7.7"), ("linklocal.test", "169.254.3.3"),
               ("cgnat.test", "100.64.2.2"), ("ula.test", "fd00::1"), ("linklocal6.test", "fe80::1"),
               ("mapped.test", "::ffff:10.1.2.3"), ("compat.test", "::10.1.2.3"), ("nat64.test", "64:ff9b::a01:203"),
               ("sixtofour.test", "2002:a01:203::1"), ("neighbor6.test", "2001:db8:1::9"),
               ("translated.test", "::ffff:0:c0a8:114"), (LOCAL_USE_NAME, LOCAL_USE_ADDR),
               ("onlink6.test", "2002:c633:6401::9"), ("sixtofourisatap.test", "2002:a01:203::5efe:c633:6407"))
# This side's own IPv6 subnet, which neighbor6.test answers into: the address's mask alone says so (no route).
HERE6 = "2001:db8:1::1/64"
# An address of /128 with its /64 as an on-link route, as a network that numbers hosts by DHCPv6 leaves it:
# onlink6.test answers into that prefix, and the route alone says so. The prefix is of a form that carries an
# IPv4 address (6to4, 198.51.100.1, which is nobody's here): an address is judged as its own IPv6 self as well as
# by what it carries.
HERE6_HOST, ONLINK6 = "2002:c633:6401::1", "2002:c633:6401::/64"
# A name answered by this machine in each IPv6 form that carries an IPv4 address (mapped, compatible, NAT64's
# 64:ff9b::/96, 6to4's 2002::/16, translated ::ffff:0:0/96, an ISATAP interface identifier of either kind, a
# 6to4 address with an ISATAP interface identifier whichever of the two carries it, and each place a translator
# of the local-use NAT64 prefix 64:ff9b:1::/48 may keep it: /96, /48, /56, /64), its own address and loopback:
# each is this machine, typed or not.
SELF_EMBEDDED = (("selfmapped.test", "::ffff:203.0.113.1"), ("selfcompat.test", "::203.0.113.1"),
                 ("selfnat64.test", "64:ff9b::cb00:7101"), ("self6to4.test", "2002:cb00:7101::1"),
                 ("lomapped.test", "::ffff:127.0.0.1"), ("locompat.test", "::127.0.0.1"),
                 ("lonat64.test", "64:ff9b::7f00:1"), ("lo6to4.test", "2002:7f00:1::1"),
                 ("selftranslated.test", "::ffff:0:cb00:7101"), ("selfisatap.test", "2001:db8:9::5efe:cb00:7101"),
                 ("selfisatap200.test", "2001:db8:9:0:200:5efe:cb00:7101"),
                 ("self6to4isatap.test", "2002:cb00:7101::5efe:c633:6407"),
                 ("selfisatap6to4.test", "2002:c633:6407::5efe:cb00:7101"),
                 ("selflocal96.test", SELF_LOCAL_USE), ("selflocal48.test", "64:ff9b:1:cb00:71:100::"),
                 ("selflocal56.test", "64:ff9b:1:cb:0:7101::"), ("selflocal64.test", "64:ff9b:1:0:cb:71:100:0"),
                 ("lolocal.test", "64:ff9b:1::7f00:2"))
# Names the stand-in resolver answers, each after its own delay (seconds); every other name it leaves unanswered.
SLOW_NAMES = {"slow.test": 3.5, "fast.test": 2.5}

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


def resolver(sock):
    """A stand-in resolver on this namespace's 127.0.0.53: each name of SLOW_NAMES answered (A 198.51.100.7, AAAA
    empty) after its delay, each on a thread of its own; any other name never."""
    def answer(pkt, addr):
        i, labels = 12, []
        while pkt[i]:
            labels.append(pkt[i + 1:i + 1 + pkt[i]].decode())
            i += 1 + pkt[i]
        name, qtype = ".".join(labels), struct.unpack("!H", pkt[i + 1:i + 3])[0]
        if name not in SLOW_NAMES:
            return
        time.sleep(SLOW_NAMES[name])
        body = pkt[12:i + 5]
        if qtype == 1:
            body += struct.pack("!HHHIH", 0xc00c, 1, 1, 60, 4) + socket.inet_aton("198.51.100.7")
        sock.sendto(pkt[:2] + struct.pack("!HHHHH", 0x8180, 1, 1 if qtype == 1 else 0, 0, 0) + body, addr)

    while True:
        pkt, addr = sock.recvfrom(512)
        threading.Thread(target=answer, args=(pkt, addr), daemon=True).start()


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


def attempt(uid, addr, port, udp=False, sport=0):
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
            if sport:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", sport))
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
    # Names and resolvers of the test's own, seen by nobody outside this mount namespace. The C library counts its
    # own wait for a resolver (5 s unless told) on the wall clock: where that clock is stepped ahead while a name
    # is asked, it gives the first resolver up early and asks the second, which never answers. Its wait is set
    # past any such step, so that the bounds these cases see are forgeext's own.
    for name, text in (("hosts", "127.0.0.1 localhost\n%s peer.test\n%s self.test\n%s neighbor.test\n10.20.30.40 lan.test\n"
                                 % (PEER_ADDR, HERE_ADDR, NEIGHBOR_ADDR)
                + "".join("%s %s\n" % (a, n) for n, a in LOCAL_NAMES + SELF_EMBEDDED) + "192.168.1.20 broker.lan\n"),
                       ("resolv.conf", "nameserver 127.0.0.53\nnameserver %s\noptions timeout:30\n" % PEER_ADDR)):
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
                ns + ["ip", "link", "set", "lo", "up"], ["ip", "route", "add", PEER_ADDR.rsplit(".", 1)[0] + ".0/24", "dev", "ffxn0"],
                ns + ["ip", "route", "add", HERE_ADDR.rsplit(".", 1)[0] + ".0/24", "dev", "ffxn1"],
                ["ip", "-6", "addr", "add", HERE6, "dev", "ffxn0", "nodad", "noprefixroute"],
                ["ip", "-6", "addr", "add", HERE6_HOST + "/128", "dev", "ffxn0", "nodad"],
                ["ip", "-6", "route", "add", ONLINK6, "dev", "ffxn0"]):
        subprocess.run(cmd, check=True, capture_output=True)
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(("127.0.0.53", 53))
    threading.Thread(target=resolver, args=(stub,), daemon=True).start()
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
    # Each part of the table that net-check holds it to, taken out in turn.
    with open(RULES) as f:
        image = f.read()
    for what, crippled_text, words in (
            ("without the lo rule", "".join(l for l in image.splitlines(True) if 'oifname "lo"' not in l), "machine itself"),
            ("with its allow map under another name", image.replace("map allow {", "map allowed {").replace("@allow", "@allowed"),
             "no allow map"),
            ("sending part of the pool only", image.replace("meta skuid 800-831 jump pool", "meta skuid 800-830 jump pool"),
             "does not send the account pool"),
            ("letting what the map lets fall through go", image.replace("\t\tjump refuse\n", ""), "lets fall through"),
            ("whose refusal resets nothing", "".join(l for l in image.splitlines(True) if "reject with tcp reset" not in l),
             "does not refuse")):
        crippled = os.path.join(top, "crippled.nft")
        with open(crippled, "w") as g:
            g.write(crippled_text)
        check(crippled_text != image, "the table %s differs from the image's", what)
        subprocess.run([NFT, "-f", crippled], check=True)
        r = fx("net-check")
        check(r.get("ok") is False and words in r.get("error", ""), "a table %s -> %s", what, r.get("error"))
    subprocess.run([NFT, "-f", RULES], check=True)
    check(fx("net-check").get("ok") is True, "the image's table")

    print("nft starts with no signal blocked and none ignored (this program ignores SIGPIPE)")
    stub, seen = os.path.join(top, "nft-stub"), os.path.join(top, "nft-signals")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\ngrep -E '^Sig(Blk|Ign):' /proc/$$/status > %s\nexec %s \"$@\"\n" % (seen, NFT))
    os.chmod(stub, 0o755)
    p = subprocess.run([FORGEEXT, "--nft", stub, "net-check"], capture_output=True, text=True)
    sig = dict(line.split(":\t") for line in open(seen).read().splitlines()) if os.path.exists(seen) else {}
    try:
        took = json.loads(p.stdout).get("ok") is True
    except ValueError:
        took = False
    check(took and sig == {"SigBlk": "0000000000000000", "SigIgn": "0000000000000000"}, "nft's signal state: %s", sig)

    print("a declared destination, by name (the rules' own effect is sandbox-rules-test.py's)")
    r = fx("net-allow", str(UID), "peer.test:%d" % p1)
    check(r.get("ok") is True, "net-allow peer.test:%d -> %s", p1, r)
    listed = subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True, text=True).stdout
    check("ip daddr %s tcp dport %d accept" % (PEER_ADDR, p1) in listed and "peer.test" not in listed,
          "the rule names the address that was judged, not the name: %s", " ".join(listed.split()))
    r = fx("net-allow", str(UID), "%s:%d" % (PEER_ADDR, p2))
    check(r.get("ok") is True and attempt(UID, PEER_ADDR, p2) == "ok" and attempt(UID, PEER_ADDR, p1) == "refused",
          "a second net-allow replaces the first")

    print("what is refused in words, the account's rules left as they were")
    for args, words in ((["127.0.0.1:80"], "is this machine"), (["self.test:23"], "is this machine (%s)" % HERE_ADDR),
                        (["%s:23" % HERE_ADDR], "is this machine"), (["[::1]:443"], "is this machine"),
                        (["[%s]:23" % SELF_LOCAL_USE], "is this machine"), (["[%s]:23" % HERE6_HOST], "is this machine"),
                        (["lan.test:443"], "a private or local address"),
                        (["neighbor.test:443"], "a private or local address")) + tuple(
                        ([n + ":443"], "a private or local address") for n, _a in LOCAL_NAMES) + (
                        (["010.20.30.40:443"], "host:port"), (["peer.test"], "host:port")):
        r = fx("net-allow", str(UID), *args)
        check(r.get("ok") is False and words in r.get("error", ""), "%s -> %s", args[0], r.get("error"))
    # Neither resolver answers nowhere.test (the stand-in leaves it, the
    # peer's port 53 takes the query and says nothing): the lookup is given
    # up at the host's bound for that name, 5 s from its own ask, where the
    # C library alone would wait out its own timeouts and retries.
    t0 = time.monotonic()
    r = fx("net-allow", str(UID), "nowhere.test:443")
    took = time.monotonic() - t0
    check(r.get("ok") is False and "did not answer in 5 s" in r.get("error", "") and took < 7.5,
          "a name the resolver never answers -> %s, in %.1f s", r.get("error"), took)
    r = fx("net-allow", "799", "%s:%d" % (PEER_ADDR, p1))
    check("not one of the pool's" in r.get("error", ""), "account 799 -> %s", r.get("error"))
    check(attempt(UID, PEER_ADDR, p2) == "ok", "the refusals left the account's rules alone")
    # Each name has its own bound, counted from when its own lookup was asked, and the names of one start are
    # looked up side by side: two the resolver answers in 3.5 s and 2.5 s are both taken, in about 3.5 s.
    t0 = time.monotonic()
    r = fx("net-allow", str(UID), "slow.test:443", "fast.test:443")
    took = time.monotonic() - t0
    check(r.get("ok") is True and took < 4.5, "two slow names, each inside its own bound -> %s, in %.1f s", r, took)
    r = fx("net-allow", str(UID), "10.20.30.40:443", "%s:443" % NEIGHBOR_ADDR, "[fd00::5]:1883")
    check(r.get("ok") is True, "a private address, one on this side's own subnet and a unique local one, named as the "
          "address itself -> %s", r)
    # A name the operator typed for the package may lead into the machine's own network (the operator chose that
    # host); the same name in a manifest may not, and neither may be this machine.
    r = fx("net-allow", str(UID), "--typed", "broker.lan:1883")
    listed = subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True, text=True).stdout
    check(r.get("ok") is True and "ip daddr 192.168.1.20 tcp dport 1883 accept" in listed,
          "broker.lan:1883 typed by the operator, answering 192.168.1.20 -> %s", r)
    r = fx("net-allow", str(UID), "broker.lan:1883")
    check(r.get("ok") is False and "a private or local address" in r.get("error", ""),
          "broker.lan:1883 named by a manifest -> %s", r.get("error"))
    r = fx("net-allow", str(UID), "--typed", "self.test:23")
    check(r.get("ok") is False and "is this machine" in r.get("error", ""), "a typed name for this machine -> %s",
          r.get("error"))
    # The local-use NAT64 prefix is a place on the operator's own network too: a typed name may answer there.
    r = fx("net-allow", str(UID), "--typed", LOCAL_USE_NAME + ":1883")
    listed = subprocess.run([NFT, "list", "chain", "inet", "ffx", "u%d" % UID], capture_output=True, text=True).stdout
    check(r.get("ok") is True and "ip6 daddr %s tcp dport 1883 accept" % LOCAL_USE_ADDR in listed,
          "%s typed by the operator, answering %s -> %s", LOCAL_USE_NAME, LOCAL_USE_ADDR, r)
    # Nor may it answer this machine inside an IPv6 address: a translator, a 6to4 relay or an ISATAP router
    # carries that back in.
    for name, addr in SELF_EMBEDDED:
        r = fx("net-allow", str(UID), "--typed", name + ":443")
        check(r.get("ok") is False and "is this machine (%s)" % addr in r.get("error", ""),
              "%s typed, answering %s -> %s", name, addr, r.get("error"))

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
    up_r, up_w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(hold_w)
        os.close(up_r)
        os.setgroups([])
        os.setgid(UID)
        os.setuid(UID)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HERE_ADDR, lport))
        s.listen(16)
        os.write(up_w, b"l")                            # listening: the dials below find it there
        os.read(hold_r, 1)
        os._exit(0)
    os.close(hold_r)
    os.close(up_w)
    check(os.read(up_r, 1) == b"l", "the account's listener is up")
    os.close(up_r)
    dial = ns + [sys.executable, "-c", "import socket,sys\ns=socket.socket()\ns.settimeout(2)\n"
                 "try:\n s.connect(('%s',%d)); print('ok')\nexcept Exception as e:\n print(type(e).__name__)" % (HERE_ADDR, lport)]
    before = subprocess.run(dial, capture_output=True, text=True).stdout.strip()
    check(before != "ok", "without --listen the peer cannot complete a connection to the account's port -> %s", before)
    r = fx("net-allow", str(UID), "--listen", str(lport))
    after = subprocess.run(dial, capture_output=True, text=True).stdout.strip()
    check(r.get("ok") is True and after == "ok", "with --listen %d it can -> %s", lport, after)
    os.close(hold_w)
    os.waitpid(child, 0)

    print("and does not let it dial out of that port")
    # The rule matches the source port. Bound to it, a connection out would
    # reach anywhere at all if the rule did not tell a SYN from a reply, and
    # the declared destinations would mean nothing.
    out = attempt(UID, PEER_ADDR, p2, sport=lport)
    check(out != "ok", "an undeclared destination from the listening port -> %s", out)
    r = fx("net-allow", str(UID), "--listen", str(lport), "peer.test:%d" % p1)
    check(r.get("ok") is True, "the destination beside the listening port -> %s", r.get("error"))
    out = attempt(UID, PEER_ADDR, p1, sport=lport)
    check(out == "ok", "and the declared one still opens from it -> %s", out)
    out = attempt(UID, PEER_ADDR, p2, sport=lport)
    check(out != "ok", "the undeclared one still does not -> %s", out)

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
