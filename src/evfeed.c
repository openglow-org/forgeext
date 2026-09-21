/*
 * evfeed.c - the machine's event stream, held once and handed to every package
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See evfeed.h. The parser and the ring are pure and take no lock of
 * their own beyond the feed's; the thread is the part that talks to
 * forgectrl.
 */
#define _GNU_SOURCE
#include "evfeed.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "fflog.h"

#define READ_CHUNK 2048
#define LINE_MAX   (EVFEED_DATA_MAX + EVFEED_NAME_MAX + 64)

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- the reader ------------------------------------------------------------------ */

static const char *field(const char *line, const char *name)
{
    size_t n = strlen(name);
    if (strncmp(line, name, n) != 0 || line[n] != ':')
        return NULL;
    const char *v = line + n + 1;
    while (*v == ' ')
        v++;
    return v;
}

int evfeed_sse_feed(evfeed_sse_t *st, const char *line, evfeed_ev_t *out)
{
    const char *v;

    if (line[0] == '\0') {                              /* the blank line ends an event */
        int done = st->has_data && st->name[0];
        char name[EVFEED_NAME_MAX];
        snprintf(name, sizeof(name), "%s", st->name);
        if (done) {
            out->seq = 0;
            snprintf(out->name, sizeof(out->name), "%s", st->name);
            snprintf(out->data, sizeof(out->data), "%s", st->data);
        }
        memset(st, 0, sizeof(*st));
        /* A stream that was replaced says goodbye before it ends; the
         * host asks for another rather than waiting for a close that a
         * keep-alive interval away. */
        if (done && strcmp(name, "bye") == 0)
            return -1;
        return done;
    }
    if (line[0] == ':')                                 /* a comment: the keep-alive, or a note */
        return 0;
    if ((v = field(line, "event")) != NULL)
        snprintf(st->name, sizeof(st->name), "%s", v);
    else if ((v = field(line, "data")) != NULL) {
        snprintf(st->data, sizeof(st->data), "%s", v);
        st->has_data = 1;
    }
    /* id and retry are forgectrl's to keep: the host numbers its own ring. */
    return 0;
}

/* ---- the ring -------------------------------------------------------------------- */

void evfeed_add(evfeed_t *f, const char *name, const char *data)
{
    pthread_mutex_lock(&f->mu);
    evfeed_ev_t *e = &f->ring[f->head % EVFEED_RING];
    e->seq = ++f->head;
    snprintf(e->name, sizeof(e->name), "%s", name);
    snprintf(e->data, sizeof(e->data), "%s", data ? data : "{}");
    pthread_cond_broadcast(&f->news);
    pthread_mutex_unlock(&f->mu);
}

int evfeed_since(evfeed_t *f, unsigned long since, evfeed_ev_t *out, int max,
                 unsigned long *next, unsigned long *dropped)
{
    int n = 0;
    pthread_mutex_lock(&f->mu);
    *dropped = 0;
    if (since > f->head) {
        /* A place this feed never had: it started over under the reader.
         * The present is where it starts again, and nothing is invented. */
        *next = f->head;
        pthread_mutex_unlock(&f->mu);
        return 0;
    }
    unsigned long oldest = f->head > EVFEED_RING ? f->head - EVFEED_RING : 0;
    if (since < oldest) {
        *dropped = oldest - since;
        since = oldest;
    }
    for (unsigned long s = since + 1; s <= f->head && n < max; s++)
        out[n++] = f->ring[(s - 1) % EVFEED_RING];
    *next = n ? out[n - 1].seq : since;
    pthread_mutex_unlock(&f->mu);
    return n;
}

/* ---- the thread ------------------------------------------------------------------ */

/* The stream's socket, connected and asking, or -1. Non-blocking. */
static int subscribe(const machine_cfg_t *cfg)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg->port) };
    char req[256];
    struct pollfd p;
    int soerr = 0;
    socklen_t sl = sizeof(soerr);

    if (inet_pton(AF_INET, cfg->host, &a.sin_addr) != 1)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        p.fd = fd;
        p.events = POLLOUT;
        if (errno != EINPROGRESS || poll(&p, 1, 2000) != 1
            || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            close(fd);
            return -1;
        }
    }
    int n = snprintf(req, sizeof(req),
                     "GET /events HTTP/1.0\r\nHost: %s\r\n" EVFEED_HOST_HEADER ": " EVFEED_HOST_CLIENT
                     "\r\nAccept: text/event-stream\r\n\r\n", cfg->host);
    if (n <= 0 || (size_t)n >= sizeof(req) || send(fd, req, (size_t)n, MSG_NOSIGNAL) != n) {
        close(fd);
        return -1;
    }
    return fd;
}

/* The status line and the headers, up to the blank line. 0 on a 200, and
 * whatever the stream sent past the headers is left in buf. */
static int read_head(int fd, char *buf, size_t blen, size_t *len)
{
    double until = mono() + 5.0;
    *len = 0;
    while (*len + 1 < blen) {
        char *end = memmem(buf, *len, "\r\n\r\n", 4);
        if (end) {
            size_t used = (size_t)(end - buf) + 4;
            buf[*len] = '\0';
            int ok = strncmp(buf, "HTTP/1.", 7) == 0 && strncmp(buf + 8, " 200", 4) == 0;
            memmove(buf, buf + used, *len - used);
            *len -= used;
            return ok ? 0 : -1;
        }
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int left = (int)((until - mono()) * 1000);
        if (left <= 0 || poll(&p, 1, left) != 1)
            return -1;
        ssize_t k = recv(fd, buf + *len, blen - 1 - *len, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            return -1;
        *len += (size_t)k;
    }
    return -1;
}

/* One stream, until it ends or the host stops wanting it. */
static void hold_stream(evfeed_t *f, int fd, char *buf, size_t blen, size_t len)
{
    evfeed_sse_t st;
    memset(&st, 0, sizeof(st));
    for (;;) {
        char *nl;
        while ((nl = memchr(buf, '\n', len)) != NULL) {
            size_t k = (size_t)(nl - buf);
            char line[LINE_MAX];
            size_t n = k && buf[k - 1] == '\r' ? k - 1 : k;
            if (n >= sizeof(line))
                n = sizeof(line) - 1;
            memcpy(line, buf, n);
            line[n] = '\0';
            memmove(buf, nl + 1, len - k - 1);
            len -= k + 1;
            evfeed_ev_t ev;
            int rc = evfeed_sse_feed(&st, line, &ev);
            if (rc < 0) {
                fflog(LOG_INFO, "events: the machine ended this stream; another is asked for");
                return;
            }
            if (rc > 0)
                evfeed_add(f, ev.name, ev.data);
        }
        if (len + 1 >= blen)
            len = 0;                                    /* a line longer than the buffer: start clean */
        pthread_mutex_lock(&f->mu);
        int go = !f->stop && f->want > 0;
        pthread_mutex_unlock(&f->mu);
        if (!go)
            return;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 250) != 1)
            continue;
        ssize_t k = recv(fd, buf + len, blen - 1 - len, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            return;
        len += (size_t)k;
    }
}

static void *feeder(void *arg)
{
    evfeed_t *f = arg;
    char buf[8192];
    double retry = EVFEED_RETRY_S, quiet = 0;

    for (;;) {
        pthread_mutex_lock(&f->mu);
        while (!f->stop && (f->want <= 0 || mono() < quiet)) {
            struct timespec until;
            clock_gettime(CLOCK_REALTIME, &until);
            until.tv_sec += 1;
            pthread_cond_timedwait(&f->news, &f->mu, &until);
        }
        int stop = f->stop;
        machine_cfg_t cfg = f->upstream;
        pthread_mutex_unlock(&f->mu);
        if (stop)
            return NULL;

        size_t len = 0;
        int fd = subscribe(&cfg);
        if (fd >= 0 && read_head(fd, buf, sizeof(buf), &len) == 0) {
            pthread_mutex_lock(&f->mu);
            f->connected = 1;
            pthread_mutex_unlock(&f->mu);
            fflog(LOG_INFO, "events: subscribed to the machine's stream");
            retry = EVFEED_RETRY_S;
            hold_stream(f, fd, buf, sizeof(buf), len);
            pthread_mutex_lock(&f->mu);
            f->connected = 0;
            pthread_mutex_unlock(&f->mu);
        } else if (fd >= 0) {
            fflog(LOG_WARNING, "events: the machine refused the stream");
        }
        if (fd >= 0)
            close(fd);
        /* A stream that ends at once is a machine that is not answering:
         * back off, so a forgectrl that is restarting is not hammered. */
        quiet = mono() + retry;
        retry = retry * 2 > EVFEED_RETRY_MAX ? EVFEED_RETRY_MAX : retry * 2;
    }
}

int evfeed_start(evfeed_t *f, const machine_cfg_t *upstream, char *err, size_t elen)
{
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->mu, NULL);
    pthread_cond_init(&f->news, NULL);
    f->upstream = *upstream;
    if (pthread_create(&f->thread, NULL, feeder, f) != 0) {
        snprintf(err, elen, "cannot start the event feed's thread");
        return -1;
    }
    f->started = 1;
    return 0;
}

void evfeed_stop(evfeed_t *f)
{
    if (!f->started)
        return;
    pthread_mutex_lock(&f->mu);
    f->stop = 1;
    pthread_cond_broadcast(&f->news);
    pthread_mutex_unlock(&f->mu);
    pthread_join(f->thread, NULL);
    f->started = 0;
}

void evfeed_want(evfeed_t *f, int n)
{
    pthread_mutex_lock(&f->mu);
    int was = f->want;
    f->want = n;
    if (n > 0 && was <= 0)
        pthread_cond_broadcast(&f->news);
    pthread_mutex_unlock(&f->mu);
}

unsigned long evfeed_head(evfeed_t *f)
{
    pthread_mutex_lock(&f->mu);
    unsigned long h = f->head;
    pthread_mutex_unlock(&f->mu);
    return h;
}

int evfeed_connected(evfeed_t *f)
{
    pthread_mutex_lock(&f->mu);
    int c = f->connected;
    pthread_mutex_unlock(&f->mu);
    return c;
}
