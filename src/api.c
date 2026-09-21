/*
 * api.c - a package's one way to the machine: its API socket, and the capability broker behind it
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See api.h. api_dispatch() is the broker's whole judgment and does no I/O
 * of its own; the rest of the file is the thread that carries requests to
 * it and answers them.
 */
#define _GNU_SOURCE
#include "api.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "fflog.h"

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- the broker's judgment ------------------------------------------------------ */

int api_may(const api_who_t *who, const char *cap)
{
    for (int i = 0; i < who->ncaps; i++)
        if (strcmp(who->caps[i], cap) == 0)
            return 1;
    return 0;
}

static int say(char *body, size_t blen, int status, json_t *j)
{
    char *text = j ? json_dumps(j, JSON_COMPACT) : NULL;
    json_decref(j);
    if (!text || strlen(text) >= blen) {
        free(text);
        snprintf(body, blen, "{\"error\":\"the answer did not fit\"}");
        return 500;
    }
    snprintf(body, blen, "%s", text);
    free(text);
    return status;
}

static int refuse(char *body, size_t blen, int status, const char *words)
{
    return say(body, blen, status, json_pack("{s:s}", "error", words));
}

static json_t *hold_json(const api_hold_t *h)
{
    return json_pack("{s:b, s:s}", "raised", h->raised, "reason", h->reason);
}

/* {"raised": bool, "reason": "printable ASCII"}: those two keys and no other. */
static int hold_from(const httpreq_t *req, api_hold_t *out, const char **why)
{
    json_error_t je;
    json_t *j = json_loadb(req->body, req->body_len, JSON_REJECT_DUPLICATES, &je);
    *why = "the body is a JSON object: {\"raised\": true|false, \"reason\": \"...\"}";
    if (!json_is_object(j)) {
        json_decref(j);
        return -1;
    }
    const char *key;
    json_t *v;
    int have = 0;
    api_hold_t h = { 0, "" };
    json_object_foreach(j, key, v) {
        if (strcmp(key, "raised") == 0 && json_is_boolean(v)) {
            h.raised = json_is_true(v);
            have = 1;
        } else if (strcmp(key, "reason") == 0 && json_is_string(v)) {
            const char *s = json_string_value(v);
            size_t n = json_string_length(v);
            if (n >= sizeof(h.reason) || strlen(s) != n) {
                *why = "the reason is at most 95 bytes";
                have = -1;
                break;
            }
            for (size_t i = 0; i < n; i++)
                if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e || s[i] == '"' || s[i] == '\\') {
                    *why = "the reason is printable ASCII without the quote and the backslash";
                    have = -1;
                }
            if (have < 0)
                break;
            snprintf(h.reason, sizeof(h.reason), "%s", s);
        } else {
            *why = "the body holds raised (true or false) and reason (a string), and nothing else";
            have = -1;
            break;
        }
    }
    json_decref(j);
    if (have <= 0)
        return -1;
    if (!h.raised)
        h.reason[0] = '\0';
    *out = h;
    return 0;
}

int api_dispatch(const api_who_t *who, api_hold_t *hold, const httpreq_t *req, api_upstream_fn up, void *upctx,
                 char *body, size_t blen)
{
    static const struct { const char *path, *upstream; } machine[] = {
        { "/v0/machine/status", "/status" }, { "/v0/machine/cool", "/cool/status" }, { "/v0/machine/mode", "/mode" },
    };
    const char *p = req->path;

    if (strcmp(p, "/v0/self") == 0) {
        if (req->method != HTTPREQ_GET)
            return refuse(body, blen, 405, "GET /v0/self");
        json_t *caps = json_array();
        for (int i = 0; i < who->ncaps; i++)
            json_array_append_new(caps, json_string(who->caps[i]));
        return say(body, blen, 200, json_pack("{s:s, s:s, s:s, s:o}", "id", who->id, "version", who->version, "api",
                                              API_VERSION, "capabilities", caps));
    }
    for (size_t i = 0; i < sizeof(machine) / sizeof(machine[0]); i++) {
        if (strcmp(p, machine[i].path) != 0)
            continue;
        if (req->method != HTTPREQ_GET)
            return refuse(body, blen, 405, "the machine is read with GET");
        if (!api_may(who, "machine.read"))
            return refuse(body, blen, 403, "this package does not hold machine.read");
        if (!up || up(upctx, machine[i].upstream, body, blen) != 0)
            return refuse(body, blen, 502, "forgectrl does not answer");
        /* What goes on to the package is JSON, or nothing. */
        json_t *j = json_loads(body, JSON_REJECT_DUPLICATES, NULL);
        if (!json_is_object(j)) {
            json_decref(j);
            return refuse(body, blen, 502, "forgectrl's answer is not a JSON object");
        }
        json_decref(j);
        return 200;
    }
    if (strcmp(p, "/v0/hold") == 0) {
        if (!api_may(who, "hold"))
            return refuse(body, blen, 403, "this package has no hold: the operator did not grant it one");
        if (req->method == HTTPREQ_GET)
            return say(body, blen, 200, hold_json(hold));
        const char *why;
        api_hold_t h;
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/hold takes application/json");
        if (hold_from(req, &h, &why) != 0)
            return refuse(body, blen, 400, why);
        *hold = h;
        return say(body, blen, 200, hold_json(hold));
    }
    return refuse(body, blen, 404, "the extension API has no such path");
}

/* ---- the thread ------------------------------------------------------------------ */

static const char *status_text(int code)
{
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 505: return "HTTP Version Not Supported";
    default: return "Internal Server Error";
    }
}

/* The whole reply, then the connection is done with. The socket is
 * non-blocking: a peer that does not read loses the rest. */
static void answer(int fd, int status, const char *body)
{
    char head[256];
    size_t blen = strlen(body);
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     status, status_text(status), blen);
    struct iovec iov[2] = { { head, (size_t)n }, { (void *)body, blen } };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    (void)sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static void answer_error(int fd, int status, const char *words)
{
    char body[256];
    json_t *j = json_pack("{s:s}", "error", words);
    char *text = j ? json_dumps(j, JSON_COMPACT) : NULL;
    json_decref(j);
    snprintf(body, sizeof(body), "%s", text ? text : "{\"error\":\"refused\"}");
    free(text);
    answer(fd, status, body);
}

/* Done with a connection. What the peer still had on its way is read and
 * thrown away first: a Unix socket closed over unread bytes resets the
 * peer, and the reset would take the answer with it. */
static void conn_drop(api_conn_t *c)
{
    if (c->fd > 0) {
        char rest[1024];
        shutdown(c->fd, SHUT_WR);
        for (int i = 0; i < 16 && read(c->fd, rest, sizeof(rest)) > 0; i++)
            ;
        close(c->fd);
    }
    memset(c, 0, sizeof(*c));
}

static int upstream_get(void *ctx, const char *path, char *out, size_t olen)
{
    return machine_get(ctx, path, out, olen);
}

/* One whole request is in the buffer: judge it and answer. Called with the
 * lock held; the lock is let go for the one call that can wait. */
static void serve(api_t *a, api_conn_t *c, const httpreq_t *req)
{
    static char body[API_BODY_MAX];
    api_svc_t *s = &a->svc[c->svc];
    api_who_t who = s->who;
    api_hold_t hold = s->hold;
    int fd = c->fd;

    pthread_mutex_unlock(&a->mu);
    int status = api_dispatch(&who, &hold, req, upstream_get, &a->upstream, body, sizeof(body));
    pthread_mutex_lock(&a->mu);
    /* The service may have ended while forgectrl was being asked. */
    if (s->used && strcmp(s->who.id, who.id) == 0) {
        if (s->hold.raised != hold.raised || strcmp(s->hold.reason, hold.reason) != 0) {
            if (hold.raised)
                fflog(LOG_NOTICE, "%s: it raised its hold: %s", who.id, hold.reason[0] ? hold.reason : "(no words)");
            else
                fflog(LOG_NOTICE, "%s: it cleared its hold", who.id);
        }
        s->hold = hold;
    }
    if (c->fd == fd)
        answer(fd, status, body);
}

static void *broker(void *arg)
{
    api_t *a = arg;
    for (;;) {
        struct pollfd fds[API_MAX_SERVICES + API_MAX_CONNS];
        int what[API_MAX_SERVICES + API_MAX_CONNS], n = 0;          /* >= 0 a service's listener, < 0 connection -(i+1) */
        pthread_mutex_lock(&a->mu);
        if (a->stop) {
            pthread_mutex_unlock(&a->mu);
            return NULL;
        }
        for (int i = 0; i < API_MAX_SERVICES; i++)
            if (a->svc[i].used) {
                what[n] = i;
                fds[n].fd = a->svc[i].lfd;
                fds[n++].events = POLLIN;
            }
        for (int i = 0; i < API_MAX_CONNS; i++)
            if (a->conn[i].fd > 0) {
                what[n] = -(i + 1);
                fds[n].fd = a->conn[i].fd;
                fds[n++].events = POLLIN;
            }
        pthread_mutex_unlock(&a->mu);

        poll(fds, (nfds_t)n, 250);

        pthread_mutex_lock(&a->mu);
        double now = mono();
        for (int k = 0; k < n; k++) {
            if (!(fds[k].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            if (what[k] >= 0) {
                api_svc_t *s = &a->svc[what[k]];
                if (!s->used || s->lfd != fds[k].fd)
                    continue;                           /* closed since the poll */
                int fd = accept4(s->lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (fd < 0)
                    continue;
                struct ucred cr;
                socklen_t cl = sizeof(cr);
                if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 || cr.uid != s->who.uid) {
                    fflog(LOG_WARNING, "%s: a connection to its API socket that is not its account's: closed", s->who.id);
                    close(fd);
                    continue;
                }
                s->tokens += (now - s->refilled) * API_RATE_PER_S;
                if (s->tokens > API_RATE_PER_S)
                    s->tokens = API_RATE_PER_S;
                s->refilled = now;
                api_conn_t *c = NULL;
                for (int i = 0; i < API_MAX_CONNS && !c; i++)
                    if (a->conn[i].fd <= 0)
                        c = &a->conn[i];
                int mine = 0;
                for (int i = 0; i < API_MAX_CONNS; i++)
                    mine += a->conn[i].fd > 0 && a->conn[i].svc == what[k];
                if (!c || mine >= API_CONNS_EACH) {
                    close(fd);                          /* its share of the connections is taken: the caller tries again */
                    continue;
                }
                memset(c, 0, sizeof(*c));
                c->fd = fd;
                c->svc = what[k];
                c->since = now;
                /* Over its rate, the request is still read, and then told so. */
                if (s->tokens < 1.0)
                    c->limited = 1;
                else
                    s->tokens -= 1.0;
                continue;
            }
            api_conn_t *c = &a->conn[-what[k] - 1];
            if (c->fd != fds[k].fd)
                continue;
            ssize_t got = read(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
            if (got <= 0) {
                if (got < 0 && (errno == EAGAIN || errno == EINTR))
                    continue;
                conn_drop(c);
                continue;
            }
            c->len += (size_t)got;
            httpreq_t req;
            const char *why = "";
            int rc = httpreq_parse(c->buf, c->len, &req, &why);
            if (rc == 0 && c->len < sizeof(c->buf))
                continue;
            if (rc == 0)
                answer_error(c->fd, 413, "the request is too long");
            else if (rc < 0)
                answer_error(c->fd, -rc, why);
            else if (c->limited)
                answer_error(c->fd, 429, "too many requests: slow down");
            else
                serve(a, c, &req);
            conn_drop(c);
        }
        for (int i = 0; i < API_MAX_CONNS; i++)
            if (a->conn[i].fd > 0 && now - a->conn[i].since > API_CONN_TIMEOUT_S) {
                answer_error(a->conn[i].fd, 408, "the request did not arrive in time");
                conn_drop(&a->conn[i]);
            }
        pthread_mutex_unlock(&a->mu);
    }
}

/* ---- the main loop's side ------------------------------------------------------- */

static void sock_path(const api_t *a, const char *id, char *p, size_t plen)
{
    snprintf(p, plen, "%.255s/%.63s.sock", a->dir, id);
}

int api_start(api_t *a, const char *dir, const machine_cfg_t *upstream, char *err, size_t elen)
{
    memset(a, 0, sizeof(*a));
    pthread_mutex_init(&a->mu, NULL);
    if (strlen(dir) >= sizeof(a->dir) - 72) {
        snprintf(err, elen, "the API directory's path is too long");
        return -1;
    }
    snprintf(a->dir, sizeof(a->dir), "%s", dir);
    a->upstream = *upstream;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        snprintf(err, elen, "cannot make the API directory %s: %s", dir, strerror(errno));
        return -1;
    }
    chmod(dir, 0755);
    /* A socket a previous host left answers nobody. */
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            size_t n = strlen(de->d_name);
            if (n > 5 && strcmp(de->d_name + n - 5, ".sock") == 0) {
                char p[600];
                snprintf(p, sizeof(p), "%.255s/%.300s", dir, de->d_name);
                unlink(p);
            }
        }
        closedir(d);
    }
    if (pthread_create(&a->thread, NULL, broker, a) != 0) {
        snprintf(err, elen, "cannot start the broker's thread");
        return -1;
    }
    a->started = 1;
    return 0;
}

static void svc_shut(api_t *a, int i)
{
    char p[400];
    api_svc_t *s = &a->svc[i];
    for (int k = 0; k < API_MAX_CONNS; k++)
        if (a->conn[k].fd > 0 && a->conn[k].svc == i)
            conn_drop(&a->conn[k]);
    if (s->lfd > 0)
        close(s->lfd);
    sock_path(a, s->who.id, p, sizeof(p));
    unlink(p);
    memset(s, 0, sizeof(*s));
}

void api_stop(api_t *a)
{
    if (!a->started)
        return;
    pthread_mutex_lock(&a->mu);
    a->stop = 1;
    pthread_mutex_unlock(&a->mu);
    pthread_join(a->thread, NULL);
    for (int i = 0; i < API_MAX_SERVICES; i++)
        if (a->svc[i].used)
            svc_shut(a, i);
    a->started = 0;
}

int api_open(api_t *a, const api_who_t *who, char *path, size_t plen, char *err, size_t elen)
{
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    char p[400];
    if (!a->started) {
        snprintf(err, elen, "the broker is not running");
        return -1;
    }
    sock_path(a, who->id, p, sizeof(p));
    if (strlen(p) >= sizeof(sa.sun_path)) {
        snprintf(err, elen, "its API socket's path is too long");
        return -1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", p);

    pthread_mutex_lock(&a->mu);
    int slot = -1;
    for (int i = 0; i < API_MAX_SERVICES; i++)
        if (a->svc[i].used && strcmp(a->svc[i].who.id, who->id) == 0)
            svc_shut(a, i);                             /* a start that follows an end nobody closed */
    for (int i = 0; i < API_MAX_SERVICES && slot < 0; i++)
        if (!a->svc[i].used)
            slot = i;
    int fd = slot < 0 ? -1 : socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    unlink(p);
    /* Closed to everybody until it is its account's, root:account 0660. The
     * mode is put on the socket before it has a name (bind makes the file
     * with it): the umask is the whole process's, and another thread is
     * writing files. */
    int ok = fd >= 0 && fchmod(fd, 0600) == 0 && bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
    ok = ok && chown(p, 0, (gid_t)who->uid) == 0 && chmod(p, 0660) == 0 && listen(fd, 8) == 0;
    if (!ok) {
        snprintf(err, elen, "cannot make its API socket %s: %s", p, slot < 0 ? "no room" : strerror(errno));
        if (fd >= 0)
            close(fd);
        unlink(p);
        pthread_mutex_unlock(&a->mu);
        return -1;
    }
    api_svc_t *s = &a->svc[slot];
    memset(s, 0, sizeof(*s));
    s->used = 1;
    s->who = *who;
    s->lfd = fd;
    s->tokens = API_RATE_PER_S;
    s->refilled = mono();
    pthread_mutex_unlock(&a->mu);
    snprintf(path, plen, "%s", p);
    return 0;
}

void api_close(api_t *a, const char *id)
{
    if (!a->started)
        return;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < API_MAX_SERVICES; i++)
        if (a->svc[i].used && strcmp(a->svc[i].who.id, id) == 0)
            svc_shut(a, i);
    pthread_mutex_unlock(&a->mu);
}

int api_hold_said(api_t *a, const char *id, api_hold_t *out)
{
    int rc = -1;
    memset(out, 0, sizeof(*out));
    if (!a->started)
        return -1;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < API_MAX_SERVICES; i++)
        if (a->svc[i].used && strcmp(a->svc[i].who.id, id) == 0) {
            *out = a->svc[i].hold;
            rc = 0;
        }
    pthread_mutex_unlock(&a->mu);
    return rc;
}
