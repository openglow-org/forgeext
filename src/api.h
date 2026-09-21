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

/* The broker's judgment of one request: the status, and the JSON body into
 * body. hold is the package's word, changed by a POST /v0/hold. No I/O but
 * through up. */
int api_dispatch(const api_who_t *who, api_hold_t *hold, const httpreq_t *req, api_upstream_fn up, void *upctx,
                 char *body, size_t blen);

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
    api_svc_t svc[API_MAX_SERVICES];
    api_conn_t conn[API_MAX_CONNS];
} api_t;

/* Make the directory, remove the sockets a previous host left, start the thread. */
int api_start(api_t *a, const char *dir, const machine_cfg_t *upstream, char *err, size_t elen);
void api_stop(api_t *a);

/* A service is about to start: its socket exists before it does, and its
 * word on its hold starts clear. The socket's path into path. */
int api_open(api_t *a, const api_who_t *who, char *path, size_t plen, char *err, size_t elen);
/* It ended or was stopped: the socket goes. */
void api_close(api_t *a, const char *id);

/* What the package last said of its hold. 0 when it has a socket. */
int api_hold_said(api_t *a, const char *id, api_hold_t *out);

#endif
