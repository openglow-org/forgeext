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
#include <math.h>
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

/* {"since": a number, "wait": seconds}: those two keys, both optional,
 * and no other. */
static int events_from(const httpreq_t *req, unsigned long *since, int *have_since, double *wait,
                       const char **why)
{
    json_error_t je;
    json_t *j = json_loadb(req->body, req->body_len, JSON_REJECT_DUPLICATES, &je);
    const char *key;
    json_t *v;
    int bad = 0;

    *since = 0;
    *have_since = 0;
    *wait = 0;
    *why = "the body is a JSON object: {\"since\": 0, \"wait\": 20}";
    if (!json_is_object(j)) {
        json_decref(j);
        return -1;
    }
    json_object_foreach(j, key, v) {
        if (strcmp(key, "since") == 0 && json_is_integer(v) && json_integer_value(v) >= 0) {
            *since = (unsigned long)json_integer_value(v);
            *have_since = 1;
        } else if (strcmp(key, "wait") == 0 && json_is_number(v) && json_number_value(v) >= 0) {
            *wait = json_number_value(v);
            if (*wait > API_EVENTS_WAIT_MAX)
                *wait = API_EVENTS_WAIT_MAX;            /* asking for longer is not an error: it is capped */
        } else {
            *why = "the body holds since (a number, 0 or more) and wait (seconds), and nothing else";
            bad = 1;
            break;
        }
    }
    json_decref(j);
    return bad ? -1 : 0;
}

int api_events_answer(evfeed_t *feed, unsigned long since, char *body, size_t blen)
{
    evfeed_ev_t ev[API_EVENTS_MAX];
    unsigned long next = 0, dropped = 0;
    int n = feed ? evfeed_since(feed, since, ev, API_EVENTS_MAX, &next, &dropped) : 0;
    json_t *list = json_array();

    for (int i = 0; i < n; i++) {
        /* The data is forgectrl's JSON, passed on as it was written. What
         * cannot be read as JSON is passed on as a string, so one odd
         * event never costs a package the rest of them. */
        json_t *d = json_loads(ev[i].data, 0, NULL);
        if (!d)
            d = json_string(ev[i].data);
        json_array_append_new(list, json_pack("{s:I, s:s, s:o}", "seq", (json_int_t)ev[i].seq,
                                              "event", ev[i].name, "data", d));
    }
    return say(body, blen, 200, json_pack("{s:I, s:I, s:b, s:o}", "next", (json_int_t)next,
                                          "dropped", (json_int_t)dropped,
                                          "connected", feed ? evfeed_connected(feed) : 0, "events", list));
}

/* {"camera": "lid"|"head", "resolution": "full"|"half", "quality": n}:
 * those three keys, the camera required, and no other. */
static int shot_from(const httpreq_t *req, api_shot_t *out, const char **why)
{
    json_error_t je;
    json_t *j = json_loadb(req->body, req->body_len, JSON_REJECT_DUPLICATES, &je);
    const char *key;
    json_t *v;
    int bad = 0;

    memset(out, 0, sizeof(*out));
    out->full = 0;                                  /* half a frame unless it asks for the whole */
    out->quality = 0;                               /* the machine's own default */
    *why = "the body is a JSON object: {\"camera\": \"lid\", \"resolution\": \"half\"}";
    if (!json_is_object(j)) {
        json_decref(j);
        return -1;
    }
    json_object_foreach(j, key, v) {
        const char *sv = json_string_value(v);
        if (strcmp(key, "camera") == 0 && sv && (strcmp(sv, "lid") == 0 || strcmp(sv, "head") == 0)) {
            snprintf(out->cam, sizeof(out->cam), "%s", sv);
        } else if (strcmp(key, "resolution") == 0 && sv
                   && (strcmp(sv, "full") == 0 || strcmp(sv, "half") == 0)) {
            out->full = strcmp(sv, "full") == 0;
        } else if (strcmp(key, "quality") == 0 && json_is_integer(v)
                   && json_integer_value(v) >= 1 && json_integer_value(v) <= 100) {
            out->quality = (int)json_integer_value(v);
        } else {
            *why = "the body holds camera (lid or head), resolution (full or half), and quality "
                   "(1 to 100), and nothing else";
            bad = 1;
            break;
        }
    }
    json_decref(j);
    if (bad)
        return -1;
    if (!out->cam[0]) {
        *why = "camera is lid or head";
        return -1;
    }
    return 0;
}

int api_dispatch(const api_who_t *who, api_hold_t *hold, const httpreq_t *req, const api_world_t *world,
                 api_park_t *park, api_shot_t *shot, char *body, size_t blen)
{
    evfeed_t *feed = world ? world->feed : NULL;
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
        if (!world || !world->machine || world->machine(world->machine_ctx, machine[i].upstream, body, blen) != 0)
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
    if (strcmp(p, "/v0/motion/job") == 0 || strcmp(p, "/v0/motion/job/abort") == 0) {
        int abort_ = strcmp(p, "/v0/motion/job/abort") == 0;
        if (req->method != HTTPREQ_POST)
            return refuse(body, blen, 405, "a job is a POST");
        if (!api_may(who, "motion.job"))
            return refuse(body, blen, 403, "this package does not hold motion.job");
        if (!world || !world->job)
            return refuse(body, blen, 502, "the host cannot reach the machine's job route");
        if (abort_)
            return world->job(world->job_ctx, who->id, NULL, NULL, body, blen);
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/motion/job takes application/json");

        json_error_t je;
        json_t *j = json_loadb(req->body, req->body_len, JSON_REJECT_DUPLICATES, &je);
        const char *key, *program = NULL;
        json_t *v;
        double lit = 0, run = 0;
        const char *why = "the body is a JSON object: {\"program\": \"job.gcode\"}";
        int bad = !json_is_object(j);
        if (!bad) {
            json_object_foreach(j, key, v) {
                if (strcmp(key, "program") == 0 && json_is_string(v)) {
                    program = json_string_value(v);
                } else if (strcmp(key, "lit_within_s") == 0 && json_is_number(v)
                           && json_number_value(v) >= 0 && json_number_value(v) <= 3600) {
                    lit = json_number_value(v);
                } else if (strcmp(key, "timeout_s") == 0 && json_is_number(v)
                           && json_number_value(v) >= 0 && json_number_value(v) <= 86400) {
                    run = json_number_value(v);
                } else {
                    why = "the body holds program (a file of its own data), lit_within_s, and "
                          "timeout_s, and nothing else";
                    bad = 1;
                    break;
                }
            }
        }
        char prog[200], fields[120];
        if (!bad && program)
            snprintf(prog, sizeof(prog), "%s", program);
        json_decref(j);
        if (bad)
            return refuse(body, blen, 400, why);
        if (!program)
            return refuse(body, blen, 400, "program names a file of this package's own data");
        /* The name that goes with the job is this host's word for who
         * sent it. A package naming itself would be a package able to
         * say a job came from somewhere else. */
        snprintf(fields, sizeof(fields), "lit_within_s=%.0f&timeout_s=%.0f", lit, run);
        return world->job(world->job_ctx, who->id, prog, fields, body, blen);
    }
    if (strcmp(p, "/v0/motion/jog") == 0 || strcmp(p, "/v0/motion/cancel") == 0) {
        int cancel = strcmp(p, "/v0/motion/cancel") == 0;
        if (req->method != HTTPREQ_POST)
            return refuse(body, blen, 405, "a jog is a POST");
        if (!api_may(who, "motion.jog"))
            return refuse(body, blen, 403, "this package does not hold motion.jog");
        if (!world || !world->motion)
            return refuse(body, blen, 502, "the host cannot reach the machine's motion");
        if (cancel)
            return world->motion(world->motion_ctx, "/motion/cancel", body, blen);
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/motion/jog takes application/json");

        json_error_t je;
        json_t *j = json_loadb(req->body, req->body_len, JSON_REJECT_DUPLICATES, &je);
        const char *key;
        json_t *v;
        double axis[3] = { 0, 0, 0 }, feed = 0;
        const char *why = "the body is a JSON object: {\"x\": 10, \"feed\": 3000}";
        int bad = !json_is_object(j);
        if (!bad) {
            json_object_foreach(j, key, v) {
                double *at = strcmp(key, "x") == 0 ? &axis[0]
                           : strcmp(key, "y") == 0 ? &axis[1]
                           : strcmp(key, "z") == 0 ? &axis[2]
                           : strcmp(key, "feed") == 0 ? &feed : NULL;
                if (!at || !json_is_number(v) || json_is_boolean(v)) {
                    why = "the body holds x, y, z, and feed, each a number, and nothing else";
                    bad = 1;
                    break;
                }
                *at = json_number_value(v);
            }
        }
        json_decref(j);
        if (bad)
            return refuse(body, blen, 400, why);
        /* The machine owns these bounds; this is the host keeping to
         * them too, so a request past them never becomes a line the
         * machine has to refuse. */
        if (!(axis[0] == axis[0]) || !(axis[1] == axis[1]) || !(axis[2] == axis[2]) || !(feed == feed))
            return refuse(body, blen, 400, "x, y, z, and feed must be numbers");
        if (fabs(axis[0]) > API_JOG_MAX_XY_MM || fabs(axis[1]) > API_JOG_MAX_XY_MM)
            return refuse(body, blen, 400, "one jog moves X and Y at most 100 mm");
        if (fabs(axis[2]) > API_JOG_MAX_Z_MM)
            return refuse(body, blen, 400, "one jog moves Z at most 5 mm");
        if (feed != 0 && (feed < API_JOG_FEED_MIN || feed > API_JOG_FEED_MAX))
            return refuse(body, blen, 400, "feed must be 10 to 12000 mm/min");
        if (axis[0] == 0 && axis[1] == 0 && axis[2] == 0)
            return refuse(body, blen, 400, "a jog moves at least one axis");

        char path[200];
        int n = snprintf(path, sizeof(path), "/motion/jog?x=%.3f&y=%.3f&z=%.3f", axis[0], axis[1], axis[2]);
        if (feed != 0 && n > 0 && (size_t)n < sizeof(path))
            snprintf(path + n, sizeof(path) - (size_t)n, "&feed=%.3f", feed);
        return world->motion(world->motion_ctx, path, body, blen);
    }
    if (strcmp(p, "/v0/camera") == 0) {
        if (req->method != HTTPREQ_POST)
            return refuse(body, blen, 405, "POST /v0/camera with {\"camera\": \"lid\"}");
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/camera takes application/json");
        api_shot_t want;
        const char *why;
        if (shot_from(req, &want, &why) != 0)
            return refuse(body, blen, 400, why);
        /* The capability is the one for the camera it asked for, so a
         * package granted the lid camera cannot reach the head's. */
        char cap[16];
        snprintf(cap, sizeof(cap), "camera.%.7s", want.cam);
        if (!api_may(who, cap))
            return refuse(body, blen, 403, "this package does not hold that camera");
        if (!world || !world->camera || !shot)
            return refuse(body, blen, 502, "the host cannot reach the cameras");
        *shot = want;
        return API_SHOOT;
    }
    if (strcmp(p, "/v0/settings") == 0) {
        if (!api_may(who, "settings.own"))
            return refuse(body, blen, 403, "this package does not hold settings.own");
        if (!world || !world->settings)
            return refuse(body, blen, 502, "the host cannot reach this package's settings");
        if (req->method == HTTPREQ_GET)
            return world->settings(world->settings_ctx, who->id, NULL, 0, body, blen);
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/settings takes application/json");
        return world->settings(world->settings_ctx, who->id, req->body, req->body_len, body, blen);
    }
    if (strcmp(p, "/v0/events") == 0) {
        if (req->method != HTTPREQ_POST)
            return refuse(body, blen, 405, "POST /v0/events with {\"since\": n, \"wait\": s}");
        if (!api_may(who, "events"))
            return refuse(body, blen, 403, "this package does not hold events");
        if (!req->json_body)
            return refuse(body, blen, 415, "POST /v0/events takes application/json");
        unsigned long since = 0;
        double wait = 0;
        const char *why;
        int have_since = 0;
        if (events_from(req, &since, &have_since, &wait, &why) != 0)
            return refuse(body, blen, 400, why);
        if (!have_since)
            return api_events_answer(feed, feed ? evfeed_head(feed) : 0, body, blen);
        /* It waits only when it is level with the feed. Behind it, there
         * is something to say now; past it, the feed started over and
         * saying so at once is what lets the reader find its place. */
        if (wait > 0 && park && feed && since == evfeed_head(feed)) {
            park->since = since;
            park->seconds = wait;
            return API_PARK;
        }
        return api_events_answer(feed, since, body, blen);
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
static void answer_typed(int fd, int status, const char *type, const void *body, size_t blen)
{
    char head[256];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     status, status_text(status), type, blen);
    /* A frame is larger than one send takes, so it goes out in turns
     * rather than in one that would be cut short. */
    struct iovec iov[2] = { { head, (size_t)n }, { (void *)body, blen } };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (sent < 0)
        return;
    size_t done = (size_t)sent;
    if (done < (size_t)n)
        return;                                     /* not even the head went: the peer is gone */
    done -= (size_t)n;
    double until = mono() + 5.0;
    while (done < blen && mono() < until) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, 200) != 1)
            continue;
        ssize_t k = send(fd, (const unsigned char *)body + done, blen - done, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (k > 0)
            done += (size_t)k;
        else if (k < 0 && errno != EAGAIN && errno != EINTR)
            break;
    }
}

static void answer(int fd, int status, const char *body)
{
    answer_typed(fd, status, "application/json", body, strlen(body));
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

/* One capture at a time, off the broker's thread. The connection it is
 * for is held open meanwhile; if it goes away first, the frame is taken
 * and thrown away, which is the cheapest way to be sure the machine is
 * never left mid-capture. */
static void *camera_thread(void *arg)
{
    api_t *a = arg;
    for (;;) {
        pthread_mutex_lock(&a->mu);
        while (!a->stop && !a->cam_busy)
            pthread_cond_wait(&a->cam_wake, &a->mu);
        if (a->stop) {
            pthread_mutex_unlock(&a->mu);
            return NULL;
        }
        api_shot_t shot = a->cam_shot;
        api_who_t who = a->cam_who;
        api_camera_fn fn = a->world.camera;
        void *ctx = a->world.camera_ctx;
        int idx = a->cam_conn;
        pthread_mutex_unlock(&a->mu);

        unsigned char *jpeg = NULL;
        size_t len = 0;
        char ctype[64] = "", body[1024];
        int status = fn ? fn(ctx, shot.cam, shot.full, shot.quality, &jpeg, &len, ctype, sizeof(ctype),
                             body, sizeof(body))
                        : 502;
        if (!fn)
            snprintf(body, sizeof(body), "{\"error\":\"the host cannot reach the cameras\"}");

        pthread_mutex_lock(&a->mu);
        api_conn_t *c = idx >= 0 && idx < API_MAX_CONNS ? &a->conn[idx] : NULL;
        if (c && c->fd > 0 && c->shooting && strcmp(a->svc[c->svc].who.id, who.id) == 0) {
            if (status == 200 && jpeg)
                answer_typed(c->fd, 200, ctype[0] ? ctype : "image/jpeg", jpeg, len);
            else
                answer(c->fd, status, body);
            conn_drop(c);
        }
        a->cam_busy = 0;
        a->cam_conn = -1;
        pthread_mutex_unlock(&a->mu);
        free(jpeg);
    }
}

/* One whole request is in the buffer: judge it and answer. Called with the
 * lock held; the lock is let go for the one call that can wait. */
/* 0 when the connection was answered and is done with, 1 when it was
 * parked and the loop is to keep it. */
static int serve(api_t *a, api_conn_t *c, const httpreq_t *req)
{
    static char body[API_BODY_MAX];
    api_svc_t *s = &a->svc[c->svc];
    api_who_t who = s->who;
    api_hold_t hold = s->hold;
    api_park_t park = { 0, 0 };
    api_shot_t shot;
    int fd = c->fd;

    memset(&shot, 0, sizeof(shot));
    pthread_mutex_unlock(&a->mu);
    int status = api_dispatch(&who, &hold, req, &a->world, &park, &shot, body, sizeof(body));
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
    if (c->fd != fd)
        return 0;                                       /* it went away while forgectrl was being asked */
    if (status == API_PARK) {
        c->parked = 1;
        c->ev_since = park.since;
        c->ev_until = mono() + park.seconds;
        c->len = 0;
        return 1;
    }
    if (status == API_SHOOT) {
        if (a->cam_busy) {
            answer_error(fd, 503, "a capture is already under way: try again");
            return 0;
        }
        a->cam_busy = 1;
        a->cam_shot = shot;
        a->cam_who = who;
        a->cam_conn = (int)(c - a->conn);
        c->shooting = 1;
        c->parked = 1;                              /* the loop leaves it alone; the camera answers it */
        c->ev_until = mono() + API_SHOT_TIMEOUT_S;
        c->len = 0;
        pthread_cond_signal(&a->cam_wake);
        return 1;
    }
    answer(fd, status, body);
    return 0;
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
            if (c->parked) {
                /* It has said all it has to say. Anything readable now is
                 * the peer hanging up, and then there is nobody to tell. */
                char rest[256];
                ssize_t k2 = read(c->fd, rest, sizeof(rest));
                if (k2 <= 0 && !(k2 < 0 && (errno == EAGAIN || errno == EINTR)))
                    conn_drop(c);
                continue;
            }
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
            else if (serve(a, c, &req))
                continue;                               /* parked: answered when an event comes, or at its deadline */
            conn_drop(c);
        }
        /* A parked poll is answered when the feed moves past it, or when
         * its own wait runs out - with an empty list, which is how a
         * reader learns that nothing happened. */
        unsigned long head = a->world.feed ? evfeed_head(a->world.feed) : 0;
        for (int i = 0; i < API_MAX_CONNS; i++) {
            api_conn_t *c = &a->conn[i];
            if (c->fd <= 0)
                continue;
            if (c->shooting) {
                if (now >= c->ev_until) {
                    answer_error(c->fd, 504, "the capture did not come back in time");
                    conn_drop(c);
                }
                continue;
            }
            if (c->parked) {
                if (head > c->ev_since || now >= c->ev_until) {
                    static char body[API_BODY_MAX];
                    int status = api_events_answer(a->world.feed, c->ev_since, body, sizeof(body));
                    answer(c->fd, status, body);
                    conn_drop(c);
                }
                continue;
            }
            if (now - c->since > API_CONN_TIMEOUT_S) {
                answer_error(c->fd, 408, "the request did not arrive in time");
                conn_drop(c);
            }
        }
        pthread_mutex_unlock(&a->mu);
    }
}

/* ---- the main loop's side ------------------------------------------------------- */

static void sock_path(const api_t *a, const char *id, char *p, size_t plen)
{
    snprintf(p, plen, "%.255s/%.63s.sock", a->dir, id);
}

int api_start(api_t *a, const char *dir, const machine_cfg_t *upstream, evfeed_t *feed,
              api_settings_fn settings, void *settings_ctx,
              api_camera_fn camera, void *camera_ctx,
              api_motion_fn motion, void *motion_ctx,
              api_job_fn job, void *job_ctx, char *err, size_t elen)
{
    memset(a, 0, sizeof(*a));
    pthread_mutex_init(&a->mu, NULL);
    pthread_cond_init(&a->cam_wake, NULL);
    a->cam_conn = -1;
    a->world.feed = feed;
    a->world.machine = upstream_get;
    a->world.machine_ctx = &a->upstream;
    a->world.settings = settings;
    a->world.settings_ctx = settings_ctx;
    a->world.camera = camera;
    a->world.camera_ctx = camera_ctx;
    a->world.motion = motion;
    a->world.motion_ctx = motion_ctx;
    a->world.job = job;
    a->world.job_ctx = job_ctx;
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
    if (pthread_create(&a->cam_thread, NULL, camera_thread, a) != 0) {
        snprintf(err, elen, "cannot start the camera's thread");
        pthread_mutex_lock(&a->mu);
        a->stop = 1;
        pthread_mutex_unlock(&a->mu);
        pthread_join(a->thread, NULL);
        return -1;
    }
    a->cam_started = 1;
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
    pthread_cond_broadcast(&a->cam_wake);
    pthread_mutex_unlock(&a->mu);
    pthread_join(a->thread, NULL);
    if (a->cam_started)
        pthread_join(a->cam_thread, NULL);
    a->cam_started = 0;
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

int api_events_wanted(api_t *a)
{
    int n = 0;
    if (!a->started)
        return 0;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < API_MAX_SERVICES; i++)
        if (a->svc[i].used && api_may(&a->svc[i].who, "events"))
            n++;
    pthread_mutex_unlock(&a->mu);
    return n;
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
