/*
 * api.h - a package's one way to the machine: its API socket, and the capability broker behind it
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Every running service has one Unix stream socket, <dir>/<id>.sock, owned
 * root:<its account> and mode 0660: the account is the only one that can
 * connect, the socket it connected to says which package it is, and the
 * peer's credentials are checked against that anyway. Its path is FFX_API
 * in the service's environment. One request per connection, HTTP/1.x in
 * the closed form of httpreq.h, JSON both ways.
 *
 * The broker answers from what the operator granted and nothing else. A
 * capability the package does not hold is 403 in words; a path the API
 * does not have is 404. Version 0 of the API (no stability promise):
 *
 *   GET  /v0/self              who the host takes the caller for, and what it may use
 *   GET  /v0/machine/status    forgectrl's /status        (machine.read)
 *   GET  /v0/machine/cool      forgectrl's /cool/status   (machine.read)
 *   GET  /v0/machine/mode      forgectrl's /mode          (machine.read)
 *   GET  /v0/hold              the package's own hold      (hold, granted)
 *   POST /v0/hold              {"raised": bool, "reason": "..."}: raise it, or clear it
 *   POST /v0/events            {"since": n, "wait": s}: the machine's events after n (events)
 *   GET  /v0/settings          its own settings, its schema's defaults filling what is unset (settings.own)
 *   POST /v0/settings          a patch of them, all applied or none (settings.own)
 *   POST /v0/camera            {"camera": "lid"|"head", ...}: one frame (camera.lid, camera.head)
 *   POST /v0/motion/jog        {"x":, "y":, "z":, "feed":}: one bounded dark jog (motion.jog)
 *   POST /v0/motion/cancel     ends a jog this package started (motion.jog)
 *   POST /v0/motion/job        {"program": "<a file of its own data>"}: run it (motion.job, granted)
 *   POST /v0/motion/job/abort  end the running job (motion.job, granted)
 *
 * A program is named, not sent: the request reader takes 4 KiB of body
 * and a program is not that, so a package writes it into its own data
 * directory and names it here. The host reads it from there - inside that
 * directory and nowhere else - and hands it to the machine, which runs it
 * under the machine lease, refuses it while a sender is connected, and
 * holds it to every arm gate and the button press like any other sender.
 * Who the job is from is the host's word, not the package's.
 *
 * A jog moves the machine, so it is the one call here that does. It is
 * bounded twice - once by this host, and again by the machine, which
 * owns the bounds and is the only thing that can enforce them - and it
 * is a jog and nothing else, which is the one motion that ships dark
 * whatever the laser's modal state is. A sender at the controller port
 * always wins: a line from LightBurn cancels a package's jog.
 *
 * The camera answer is a JPEG and not JSON, and a capture takes seconds,
 * so it is neither answered from the JSON buffer nor waited for on this
 * thread: the request is parked as an events poll is, one capture runs at
 * a time on a thread of its own, and the bytes go out when it is done. A
 * package's capture is always a background one, so it yields to an
 * operator who is watching a camera rather than stuttering their stream.
 *
 * The events call is a poll and not a stream: it says the sequence number
 * it has and is answered with what came after it, waiting up to `wait`
 * seconds for something to come. It is a POST because the reader above
 * refuses a query string on purpose and a poll needs its two numbers; the
 * body carries them instead. A body with no `since` at all asks where the
 * present is: the answer is the head and no events, which is how a package
 * that does not want the past starts. That is a different question from
 * `since: 0`, which is the beginning of what the host still holds, and it
 * has to be, or a package that started before the first event could never
 * be told of it. A reader that falls a whole ring behind is told how many
 * it lost, never handed a stale event as if it were new.
 *
 * The machine routes are forgectrl's read-only loopback routes, relayed:
 * the package itself can reach no listener of the machine. The broker runs
 * on a thread of its own, so that a slow answer from forgectrl delays
 * other packages' requests and never the supervisor's turn, and it gives
 * each package API_RATE_PER_S requests a second.
 *
 * A package's word on its hold is the host's to keep (holdkeep.h): it
 * starts clear with every start of the service.
 */
#ifndef FORGEEXT_API_H
#define FORGEEXT_API_H

#include <pthread.h>
#include <stddef.h>
#include <sys/types.h>

#include "caps.h"
#include "evfeed.h"
#include "holdkeep.h"
#include "httpreq.h"
#include "machine.h"
#include "manifest.h"

#define API_DIR_DEFAULT     "/run/forgefirm/ext/api"
#define API_VERSION         "0.1"
#define API_MAX_SERVICES    32
#define API_MAX_CONNS       16
#define API_CONNS_EACH      4               /* of them, to one package: a package that opens and says nothing delays only itself */
#define API_CONN_TIMEOUT_S  5.0
#define API_RATE_PER_S      20
#define API_BODY_MAX        32768           /* a reply's body: forgectrl's /status with room to spare */
#define API_EVENTS_MAX      32              /* events in one answer: the rest waits for the next call */
#define API_EVENTS_WAIT_MAX 30.0            /* seconds a poll may wait */
#define API_PARK            (-1)            /* dispatch's word for "this one waits" */
#define API_SHOT_TIMEOUT_S  25.0            /* a capture that never comes back frees its connection */

/* What the broker knows of a package: what it may use. */
typedef struct {
    char id[64];
    char version[33];
    uid_t uid;
    char caps[MANIFEST_MAX_CAPS][CAP_MAX_LEN];  /* the capabilities it may use: those that need no grant, and its grants */
    int ncaps;
} api_who_t;

typedef struct {
    int raised;
    char reason[HOLDKEEP_REASON_MAX];
} api_hold_t;

/* One GET of the machine: the body into out, 0 on a 200. */
typedef int (*api_upstream_fn)(void *ctx, const char *path, char *out, size_t olen);

/* One motion request relayed to the machine: the path, and the answer's
 * JSON into out. Returns the status. */
typedef int (*api_motion_fn)(void *ctx, const char *path, char *out, size_t olen);

/* A package's program: the file it named, inside its own data directory,
 * handed to the machine's job route. Returns the status. */
typedef int (*api_job_fn)(void *ctx, const char *id, const char *program, const char *fields,
                          char *out, size_t olen);

/* A package's own settings (settings.h). patch is NULL to read them, or
 * the request's body to apply. The whole answer, JSON either way, into
 * out; the return is the status to send. */
typedef int (*api_settings_fn)(void *ctx, const char *id, const char *patch, size_t plen,
                               char *out, size_t olen);

/* One frame from a camera. Returns the status; on 200 *jpeg and *len are
 * the frame (malloc'd, the caller frees) and ctype its type, otherwise
 * out holds the JSON error. Runs on the camera thread, never the
 * broker's. */
typedef int (*api_camera_fn)(void *ctx, const char *cam, int full, int quality,
                             unsigned char **jpeg, size_t *len, char *ctype, size_t clen,
                             char *out, size_t olen);

/* What the broker can reach past itself. api_dispatch() does no I/O but
 * through this, so a test hands it fakes and the daemon hands it the
 * machine. */
typedef struct {
    api_upstream_fn machine;
    void *machine_ctx;
    api_settings_fn settings;
    void *settings_ctx;
    api_camera_fn camera;
    void *camera_ctx;
    api_motion_fn motion;
    void *motion_ctx;
    api_job_fn job;
    void *job_ctx;
    evfeed_t *feed;
} api_world_t;

/* A package's jog, in millimetres and mm/min. The bounds are the
 * machine's; these are the host's copy of them, so that a request past
 * them is refused here rather than carried to the machine and refused
 * there. Kept the same as the machine's on purpose: if they ever
 * disagree, the machine's answer is the one that stands. */
#define API_JOG_MAX_XY_MM   100.0
#define API_JOG_MAX_Z_MM    5.0
#define API_JOG_FEED_MIN    10.0
#define API_JOG_FEED_MAX    12000.0

/* What a package asked a camera for, once the broker has judged it. */
typedef struct {
    char cam[8];
    int full;
    int quality;
} api_shot_t;

/* A request that is to wait: from which event, and until when. */
typedef struct {
    unsigned long since;
    double seconds;
} api_park_t;

/* An answer that is bytes rather than JSON. When bytes is set the caller
 * sends them with this type and frees them. */
typedef struct {
    unsigned char *bytes;
    size_t len;
    char type[64];
} api_bin_t;


/* The broker's judgment of one request: the status, and the JSON body into
 * body. hold is the package's word, changed by a POST /v0/hold. No I/O but
 * through up. */
int api_dispatch(const api_who_t *who, api_hold_t *hold, const httpreq_t *req, const api_world_t *world,
                 api_park_t *park, api_shot_t *shot, char *body, size_t blen);

#define API_SHOOT (-2)          /* dispatch's word for "this one wants a camera frame" */

/* The answer to an events poll: what the feed holds after `since`. The
 * broker builds it when the wait is over, or at once when it need not
 * wait. Returns the status. */
int api_events_answer(evfeed_t *feed, unsigned long since, char *body, size_t blen);

int api_may(const api_who_t *who, const char *cap);

typedef struct {
    int used;
    api_who_t who;
    api_hold_t hold;
    int lfd;                            /* the listening socket */
    double tokens, refilled;            /* the rate limit */
} api_svc_t;

typedef struct {
    int fd, svc;
    int limited;                        /* over its rate: the request is read, and answered 429 */
    int parked;                         /* an events poll, waiting for an event or its deadline */
    int shooting;                       /* a camera request, waiting for the camera thread */
    unsigned long ev_since;
    double ev_until;
    double since;
    size_t len;
    char buf[HTTPREQ_HEAD_MAX + HTTPREQ_BODY_MAX];
} api_conn_t;

typedef struct {
    pthread_mutex_t mu;
    pthread_t thread;
    int started, stop;
    char dir[256];
    machine_cfg_t upstream;
    api_world_t world;                  /* the feed, the machine, a package's settings, the cameras */
    /* One capture at a time, on its own thread: a capture takes seconds
     * and the broker carries holds and event polls that cannot wait for
     * it. The connection waiting for it is remembered by index. */
    pthread_t cam_thread;
    int cam_started, cam_busy, cam_conn;
    api_shot_t cam_shot;
    api_who_t cam_who;
    pthread_cond_t cam_wake;
    api_svc_t svc[API_MAX_SERVICES];
    api_conn_t conn[API_MAX_CONNS];
} api_t;

/* Make the directory, remove the sockets a previous host left, start the thread. */
int api_start(api_t *a, const char *dir, const machine_cfg_t *upstream, evfeed_t *feed,
              api_settings_fn settings, void *settings_ctx,
              api_camera_fn camera, void *camera_ctx,
              api_motion_fn motion, void *motion_ctx,
              api_job_fn job, void *job_ctx, char *err, size_t elen);
void api_stop(api_t *a);

/* A service is about to start: its socket exists before it does, and its
 * word on its hold starts clear. The socket's path into path. */
int api_open(api_t *a, const api_who_t *who, char *path, size_t plen, char *err, size_t elen);
/* It ended or was stopped: the socket goes. */
void api_close(api_t *a, const char *id);

/* What the package last said of its hold. 0 when it has a socket. */
int api_hold_said(api_t *a, const char *id, api_hold_t *out);

/* Running services that hold the events capability. The subscription to
 * the machine's stream follows this number: with none of them, forgectrl
 * has nobody listening and its sampler goes back to sleep. */
int api_events_wanted(api_t *a);

#endif
