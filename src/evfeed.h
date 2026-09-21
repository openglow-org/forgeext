/*
 * evfeed.h - the machine's event stream, held once and handed to every package
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * forgectrl publishes the machine's edges as server-sent events and caps
 * the streams at three, because each one holds a thread of its own for
 * hours. The host takes one - the slot forgectrl keeps for it, outside
 * that cap - and every package reads from the ring it fills, so a machine
 * with ten packages still costs forgectrl one stream.
 *
 * A package reads the ring with GET /v0/events (api.h), which is a poll
 * and not a stream: it says the sequence number it has, and the answer is
 * what came after it. That keeps a package's connection to the host short
 * and the broker single-threaded, and it means a package that stops
 * reading costs the host nothing but its place in a ring that moves on
 * without it. Falling a whole ring behind is reported, never papered
 * over: the answer says how many it lost.
 *
 * The subscription is held only while some running service holds the
 * events capability. forgectrl's sampler sleeps when nobody listens, and
 * a host that subscribed for its own sake would keep the machine reading
 * its own state five times a second for nothing.
 */
#ifndef FORGEEXT_EVFEED_H
#define FORGEEXT_EVFEED_H

#include <pthread.h>
#include <stddef.h>

#include "machine.h"

/* How the host asks forgectrl for the slot it keeps for it. These are
 * forgectrl's own EVENTS_HOST_HEADER and EVENTS_HOST_CLIENT: the two
 * daemons agree on the words, and the host builds against neither's
 * headers. */
#define EVFEED_HOST_HEADER "X-ForgeFIRM-Client"
#define EVFEED_HOST_CLIENT "extension-host"

#define EVFEED_RING      64
#define EVFEED_NAME_MAX  32
#define EVFEED_DATA_MAX  224
#define EVFEED_RETRY_S   2.0                /* after a stream ends, before another is tried */
#define EVFEED_RETRY_MAX 30.0

typedef struct {
    unsigned long seq;                      /* the host's own, from 1: forgectrl's ids restart with its stream */
    char name[EVFEED_NAME_MAX];
    char data[EVFEED_DATA_MAX];             /* the event's JSON, as forgectrl wrote it */
} evfeed_ev_t;

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t news;
    pthread_t thread;
    int started, stop;
    int want;                               /* services that hold the events capability */
    int connected;                          /* a stream is open now */
    unsigned long head;                     /* the next sequence number */
    unsigned long drops;                    /* events the ring lost, over the host's life */
    machine_cfg_t upstream;
    evfeed_ev_t ring[EVFEED_RING];
} evfeed_t;

/* ---- the reader, pure: for the thread and for a test ---- */

/* One event out of a server-sent-events stream. Bytes are handed in as
 * they arrive; the parser keeps what is left of a partial event in buf
 * and says how much it used. Returns 1 with an event in out, 0 when more
 * bytes are needed, and -1 when the stream said goodbye (event: bye).
 * A comment line (a keep-alive) is used and reported as 0. */
typedef struct {
    char name[EVFEED_NAME_MAX];
    char data[EVFEED_DATA_MAX];
    int has_data;
} evfeed_sse_t;

int evfeed_sse_feed(evfeed_sse_t *st, const char *line, evfeed_ev_t *out);

/* ---- the ring ---- */

void evfeed_add(evfeed_t *f, const char *name, const char *data);

/* What came after `since`, at most max of them into out. Returns the
 * count; *next is the sequence number to ask for next time and *dropped
 * how many were lost between `since` and the oldest one still held. A
 * `since` of 0 is the beginning of what is still held, which is where a
 * reader that was there before the first event stands. A `since` past the
 * head is a feed that started over (the host was restarted under a
 * reader that kept its place): nothing is invented, *next comes back at
 * the head, and a reader that compares the two can see the rewind. */
int evfeed_since(evfeed_t *f, unsigned long since, evfeed_ev_t *out, int max,
                 unsigned long *next, unsigned long *dropped);

/* ---- the thread ---- */

int evfeed_start(evfeed_t *f, const machine_cfg_t *upstream, char *err, size_t elen);
void evfeed_stop(evfeed_t *f);
/* How many running services hold the events capability. The subscription
 * follows: none, and the stream is let go. */
void evfeed_want(evfeed_t *f, int n);
/* Whether a stream is open, for the status document. */
int evfeed_connected(evfeed_t *f);
/* The newest sequence number. The broker asks it to know whether a
 * waiting reader has something to be told. */
unsigned long evfeed_head(evfeed_t *f);

#endif
