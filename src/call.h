/*
 * call.h - a package's page asking its own service
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A package that has a page and a service may have the one answer the
 * other. The host binds the socket, in a directory that is root's alone,
 * and hands the service only its listening end, as descriptor CALL_FD: the
 * service answers, it never names a path, so there is no socket the host
 * could be pointed at but the one it made. A call is one request per
 * connection, HTTP/1.1, JSON both ways, the same closed form the extension
 * API takes; the panel relays a page's call through the command line.
 */
#ifndef FORGEEXT_CALL_H
#define FORGEEXT_CALL_H

#include <stddef.h>

#define CALL_DIR_DEFAULT  "/run/forgefirm/ext/call"
#define CALL_FD           4                     /* where a service finds the listening end */
#define CALL_BODY_MAX     4096                  /* what a page may send its service */
#define CALL_ANSWER_MAX   (64 * 1024)           /* what a service may answer */
#define CALL_TIMEOUT_MS   10000
/* An M-code's answer: under the GRBL controller's 30 s wait, with room for
 * forgectrl to bring it back. */
#define MCODE_TIMEOUT_MS  20000

/* The listening socket for id's service under dir: bound, 0600, listening,
 * close-on-exec. 0 with *fd and the path, or -1 with the words. */
int call_open(const char *dir, const char *id, char *path, size_t plen, int *fd, char *err, size_t elen);

/* The socket's name gone again (the service's end goes with the service). */
void call_close(const char *dir, const char *id);

/* A path a call may name: an origin-form path of letters, digits, '/',
 * '.', '-' and '_', no "..", at most 200 bytes. */
int call_path_ok(const char *p);

/* One call to id's service: 0 with the service's status and its answer's
 * body (malloc'd, NUL-terminated), or -1 with the words: the service is
 * not running, it did not answer in time, or its answer was not HTTP. */
int call_service(const char *dir, const char *id, const char *method, const char *path, const char *json,
                 int timeout_ms, int *status, char **body, size_t *blen, char *err, size_t elen);

#endif
