# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT
"""ffx - a package service's side of the ForgeFIRM extension API, version 0.1.

A service reaches the machine through one Unix socket, the one its
environment names in FFX_API, and through nothing else. This module is that
conversation: one request per connection, JSON both ways, the host's
refusal raised as ApiError with its status and its words. It uses the
standard library alone, inside the release image's module list, so a
package copies this file next to its own code (it is not on the image).

    import ffx
    me = ffx.me()                              # id, version, api, capabilities
    ffx.hold(True, "the exhaust is not on")    # hold (granted)
    for ev in ffx.follow():                    # events
        ...

A service whose package has a page also answers that page (serve()): the
host hands it the listening end of a socket, and each call the page makes
arrives there, relayed by the panel.

The machine has no clock that keeps the date: time every wait and every
schedule with time.monotonic(), never with the wall clock.
"""
import json
import os
import socket
import threading
import time

API_VERSION = "0.1"
CALL_ANSWER_MAX = 64 * 1024                    # what the host takes back from a service
_CALL_TIMEOUT = 10.0                           # what the host waits for the whole answer


class ApiError(Exception):
    """The host said no: `status` is the HTTP status and `words` its sentence."""

    def __init__(self, status, words):
        super().__init__("%d %s" % (status, words))
        self.status = status
        self.words = words


def _socket_path():
    path = os.environ.get("FFX_API")
    if not path:
        raise ApiError(0, "FFX_API is not set: this runs as a package's service")
    return path


def request(method, path, body=None, timeout=60.0):
    """One request and its whole answer: (status, content type, bytes)."""
    data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    head = "%s %s HTTP/1.1\r\nHost: forgeext\r\n" % (method, path)
    if body is not None:
        head += "Content-Type: application/json\r\nContent-Length: %d\r\n" % len(data)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(_socket_path())
        s.sendall(head.encode() + b"\r\n" + data)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        raise ApiError(0, "the extension host did not answer: %s" % e)
    finally:
        s.close()
    top, _, content = buf.partition(b"\r\n\r\n")
    lines = top.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise ApiError(0, "the extension host's answer is not HTTP")
    ctype = ""
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-type":
            ctype = v.strip()
    return status, ctype, content


def call(method, path, body=None, timeout=60.0):
    """A request whose answer is JSON: the document, or ApiError."""
    status, ctype, content = request(method, path, body, timeout)
    try:
        doc = json.loads(content or b"null")
    except ValueError:
        doc = None
    if status != 200:
        words = doc.get("error") if isinstance(doc, dict) else content[:200].decode("utf-8", "replace")
        raise ApiError(status, words or "refused")
    return doc


def me():
    """GET /v0/self: {id, version, api, capabilities} - what this package may use."""
    return call("GET", "/v0/self")


class machine:
    """machine.read: forgectrl's own answers, relayed."""

    @staticmethod
    def status():
        return call("GET", "/v0/machine/status")

    @staticmethod
    def cool():
        return call("GET", "/v0/machine/cool")

    @staticmethod
    def mode():
        return call("GET", "/v0/machine/mode")


def settings():
    """settings.own: {settings, schema}."""
    return call("GET", "/v0/settings")


def set_settings(**patch):
    """settings.own: a patch, applied whole or not at all; the new {settings, schema}."""
    return call("POST", "/v0/settings", patch)


def camera(camera="lid", resolution=None, quality=None, lamp=None, timeout=40.0):
    """camera.lid or camera.head: one frame, as JPEG bytes."""
    body = {"camera": camera}
    for k, v in (("resolution", resolution), ("quality", quality), ("lamp", lamp)):
        if v is not None:
            body[k] = v
    status, ctype, content = request("POST", "/v0/camera", body, timeout)
    if status != 200 or not ctype.startswith("image/"):
        try:
            words = json.loads(content or b"null").get("error")
        except (ValueError, AttributeError):
            words = None
        raise ApiError(status, words or "no frame")
    return content


def jog(x=None, y=None, z=None, feed=None, timeout=120.0):
    """motion.jog: one bounded, dark jog in millimeters (feed in mm/min); the machine's answer."""
    body = {k: v for k, v in (("x", x), ("y", y), ("z", z), ("feed", feed)) if v is not None}
    return call("POST", "/v0/motion/jog", body, timeout)


def cancel():
    """motion.jog: ends a jog."""
    return call("POST", "/v0/motion/cancel", {})


def write_program(name, text):
    """A program for job(), written into this package's own data directory. The name is a file name
    with no directory in it."""
    if os.sep in name or name in ("", ".", ".."):
        raise ValueError("a program's name is a file name with no directory in it")
    path = os.path.join(os.environ["FFX_DATA"], name)
    with open(path, "w") as f:
        f.write(text)
    return name


def job(program, lit_within_s=None, timeout_s=None):
    """motion.job (granted): runs a program of this package's own data as the machine's one sender."""
    body = {"program": program}
    if lit_within_s is not None:
        body["lit_within_s"] = lit_within_s
    if timeout_s is not None:
        body["timeout_s"] = timeout_s
    return call("POST", "/v0/motion/job", body)


def job_abort():
    """motion.job (granted): ends the running job."""
    return call("POST", "/v0/motion/job/abort", {})


def hold(raised, reason=""):
    """hold (granted): raise or clear this package's hold; the new state."""
    return call("POST", "/v0/hold", {"raised": bool(raised), "reason": reason})


def hold_state():
    """hold (granted): {raised, reason}."""
    return call("GET", "/v0/hold")


def events(since=None, wait=None):
    """events: {next, dropped, connected, events} after `since`, waiting up to `wait` seconds for one."""
    body = {}
    if since is not None:
        body["since"] = since
    if wait is not None:
        body["wait"] = wait
    return call("POST", "/v0/events", body, timeout=(wait or 0) + 30.0)


def follow(since=None, wait=25):
    """events: every event from now on (or after `since`), one at a time. A feed that started over
    under the reader (the host restarted) is followed from where it now stands."""
    if since is None:
        since = events()["next"]
    while True:
        try:
            doc = events(since, wait)
        except ApiError:
            time.sleep(5)
            continue
        for ev in doc.get("events", []):
            yield ev
        since = doc.get("next", since)


class CallError(Exception):
    """Raised by a serve() handler to answer the page with `status` and {"error": words}."""

    def __init__(self, status, words):
        super().__init__("%d %s" % (status, words))
        self.status = status
        self.words = words


def _answer(conn, status, doc):
    data = json.dumps(doc, separators=(",", ":")).encode()
    if len(data) > CALL_ANSWER_MAX - 256:
        status, data = 500, json.dumps({"error": "the answer is more than the host takes"}).encode()
    head = "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (
        status, "OK" if status == 200 else "Refused", len(data))
    conn.sendall(head.encode() + data)


def _one(conn, handler):
    conn.settimeout(_CALL_TIMEOUT)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
    top, _, body = buf.partition(b"\r\n\r\n")
    lines = top.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3:
        return
    want = 0
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-length":
            want = int(v.strip() or 0)
    while len(body) < want:
        chunk = conn.recv(4096)
        if not chunk:
            return
        body += chunk
    try:
        doc = json.loads(body[:want] or b"{}")
        _answer(conn, 200, handler(parts[0], parts[1], doc))
    except CallError as e:
        _answer(conn, e.status, {"error": e.words})
    except Exception as e:
        _answer(conn, 500, {"error": "%s: %s" % (type(e).__name__, e)})


def serve(handler, background=False):
    """ui: answer this package's page. handler(method, path, body) gets "GET" or "POST", the path the
    page named, and the JSON object it sent ({} for a GET), and returns a JSON value, answered as 200;
    raising CallError answers that status and words, and any other exception answers 500. Calls come
    one at a time, each on a connection of its own. background=True answers on a thread of its own and
    returns the thread; otherwise this never returns."""
    fd = os.environ.get("FFX_CALL_FD")
    if not fd:
        raise ApiError(0, "FFX_CALL_FD is not set: this package has no page, or this is not its service")
    listener = socket.socket(fileno=int(fd))

    def loop():
        while True:
            conn, _ = listener.accept()
            try:
                _one(conn, handler)
            except (OSError, ValueError):
                pass                                   # a call cut short, or not the host's form
            finally:
                conn.close()

    if background:
        t = threading.Thread(target=loop, name="ffx.serve", daemon=True)
        t.start()
        return t
    loop()
