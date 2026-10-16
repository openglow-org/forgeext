/*
 * evfeed_test.c - host test: the event reader and the ring behind it
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Two pure parts of evfeed.h: the server-sent-events reader, fed the lines
 * forgectrl writes, and the ring every package reads from: what the host
 * makes of the bytes, and what a reader is told when it falls behind.
 * Then the feeder's thread, against a listener on loopback that closes
 * every connection, with the wall clock an hour ahead of where it was, as
 * NTP steps the clock of a board with no RTC: the feeder's backoff rides
 * CLOCK_MONOTONIC, so it asks for the stream again two seconds after the
 * first try. clock_gettime is a stand-in defined here, which the feeder in
 * forgeext_core calls; it moves CLOCK_REALTIME and nothing else.
 */
#define _GNU_SOURCE
#include "../src/evfeed.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

/* The wall clock, an hour ahead while a case says so. */
static int realtime_ahead;

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real)(clockid_t, struct timespec *);
    if (!real)
        *(void **)&real = dlsym(RTLD_NEXT, "clock_gettime");
    int rc = real(id, ts);
    if (rc == 0 && realtime_ahead && id == CLOCK_REALTIME)
        ts->tv_sec += 3600;
    return rc;
}

/* A forgectrl that takes each connection and closes it at once: every
 * try for the stream ends, and the feeder backs off. */
static int refuser;
static int tries;
static pthread_mutex_t tries_mu = PTHREAD_MUTEX_INITIALIZER;

static void *refuse(void *arg)
{
    (void)arg;
    for (;;) {
        int c = accept(refuser, NULL, NULL);
        if (c < 0)
            return NULL;
        pthread_mutex_lock(&tries_mu);
        tries++;
        pthread_mutex_unlock(&tries_mu);
        close(c);
    }
}

/* A whole stream, as one string with its line ends, through the reader.
 * The events it made into out; the return is the last verdict. */
static int feed_text(const char *text, evfeed_ev_t *out, int max, int *n)
{
    evfeed_sse_t st;
    char buf[4096];
    int rc = 0;

    memset(&st, 0, sizeof(st));
    *n = 0;
    snprintf(buf, sizeof(buf), "%s", text);
    for (char *line = buf, *nl; line < buf + strlen(buf) || *line; ) {
        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        size_t k = strlen(line);
        if (k && line[k - 1] == '\r')
            line[k - 1] = '\0';
        evfeed_ev_t ev;
        memset(&ev, 0, sizeof(ev));
        int r = evfeed_sse_feed(&st, line, &ev);
        if (r > 0 && *n < max)
            out[(*n)++] = ev;
        if (r < 0)
            rc = -1;
        if (!nl)
            break;
        line = nl + 1;
    }
    return rc;
}

int main(void)
{
    evfeed_ev_t ev[16];
    int n = 0;

    /* What forgectrl writes: an id, a name, one data line, a blank line. */
    feed_text("id: 7\r\nevent: lid\r\ndata: {\"open\":true}\r\n\r\n", ev, 16, &n);
    CHECK(n == 1 && !strcmp(ev[0].name, "lid") && !strcmp(ev[0].data, "{\"open\":true}"),
          "one event: %d, %s %s", n, n ? ev[0].name : "", n ? ev[0].data : "");

    /* The greeting, two events, and a keep-alive between them. */
    feed_text("retry: 5000\nevent: hello\ndata: {\"max_streams\":3}\n\n"
              "event: cooling.verdict\ndata: {\"verdict\":\"OK\"}\n\n"
              ": keep-alive\n\n"
              "event: mode.changed\ndata: {\"mode\":\"grbl\"}\n\n", ev, 16, &n);
    CHECK(n == 3 && !strcmp(ev[0].name, "hello") && !strcmp(ev[1].name, "cooling.verdict") &&
          !strcmp(ev[2].name, "mode.changed"), "three events past a keep-alive: %d", n);

    /* A comment that is not a keep-alive is no event either. */
    feed_text(": 12 events were lost to a slow reader\n\n", ev, 16, &n);
    CHECK(n == 0, "a comment is not an event: %d", n);

    /* Half an event is not an event until its blank line. */
    {
        evfeed_sse_t st;
        evfeed_ev_t one;
        memset(&st, 0, sizeof(st));
        CHECK(evfeed_sse_feed(&st, "event: alarm", &one) == 0, "a name alone is not an event");
        CHECK(evfeed_sse_feed(&st, "data: {\"code\":1}", &one) == 0, "a name and data are not an event");
        CHECK(evfeed_sse_feed(&st, "", &one) == 1 && !strcmp(one.name, "alarm"), "the blank line ends it");
    }
    /* Neither is a name without data, or data without a name. */
    feed_text("event: alarm\n\ndata: {\"code\":1}\n\n", ev, 16, &n);
    CHECK(n == 0, "half an event either way is none: %d", n);

    /* The machine's goodbye ends the stream, and what came before it stands. */
    CHECK(feed_text("event: lid\ndata: {}\n\nevent: bye\ndata: {\"reason\":\"replaced\"}\n\n", ev, 16, &n) == -1,
          "a bye ends the stream");
    CHECK(n == 1 && !strcmp(ev[0].name, "lid"), "what came before the bye stands: %d", n);

    /* A data line longer than the reader holds is cut, not run past. */
    {
        char text[EVFEED_DATA_MAX * 3];
        int k = snprintf(text, sizeof(text), "event: telemetry.tick\ndata: {\"x\":\"");
        memset(text + k, 'y', EVFEED_DATA_MAX + 100);
        snprintf(text + k + EVFEED_DATA_MAX + 100, sizeof(text) - (size_t)k - EVFEED_DATA_MAX - 100, "\"}\n\n");
        feed_text(text, ev, 16, &n);
        CHECK(n == 1 && strlen(ev[0].data) == EVFEED_DATA_MAX - 1, "a long data line is cut to the room there is: %zu",
              n ? strlen(ev[0].data) : 0);
    }

    /* ---- the ring ---- */
    evfeed_t f;
    unsigned long next = 0, dropped = 0;
    memset(&f, 0, sizeof(f));
    pthread_mutex_init(&f.mu, NULL);
    pthread_cond_init(&f.news, NULL);

    CHECK(evfeed_since(&f, 0, ev, 16, &next, &dropped) == 0 && next == 0, "an empty ring: nothing, at 0");
    CHECK(evfeed_since(&f, 9, ev, 16, &next, &dropped) == 0 && next == 0,
          "a place an empty ring never had is the present: next %lu", next);
    CHECK(evfeed_head(&f) == 0, "an empty ring's head is 0");
    evfeed_add(&f, "lid", "{\"open\":false}");
    evfeed_add(&f, "interlock", "{\"closed\":true}");
    CHECK(evfeed_head(&f) == 2, "two events: the head is 2");
    /* A reader that was there before the first event stands at 0, and 0
     * is the beginning of what is held - not the present, or it could
     * never be told of the events it was there for. */
    int got = evfeed_since(&f, 0, ev, 16, &next, &dropped);
    CHECK(got == 2 && ev[0].seq == 1 && ev[1].seq == 2 && next == 2 && dropped == 0,
          "both events, in order, numbered from one: %d, next %lu", got, next);
    got = evfeed_since(&f, 2, ev, 16, &next, &dropped);
    CHECK(got == 0 && next == 2, "nothing new: %d, next %lu", got, next);
    got = evfeed_since(&f, 99, ev, 16, &next, &dropped);
    CHECK(got == 0 && next == 2 && dropped == 0,
          "a place past the head is a feed that started over: next %lu, and the reader can see it went back", next);

    /* Asking for fewer than there are leaves the rest for the next call. */
    for (int i = 0; i < 6; i++)
        evfeed_add(&f, "telemetry.tick", "{}");
    got = evfeed_since(&f, 2, ev, 4, &next, &dropped);
    CHECK(got == 4 && next == 6 && ev[3].seq == 6, "at most what was asked for: %d, next %lu", got, next);
    got = evfeed_since(&f, next, ev, 4, &next, &dropped);
    CHECK(got == 2 && next == 8, "the rest, at the next call: %d, next %lu", got, next);

    /* A whole ring behind: the count of what was lost, and no stale event. */
    unsigned long before = evfeed_head(&f);
    for (int i = 0; i < EVFEED_RING; i++)
        evfeed_add(&f, "telemetry.tick", "{}");
    got = evfeed_since(&f, before - 4, ev, 16, &next, &dropped);
    CHECK(dropped == 4 && got == 16 && ev[0].seq == before + 1,
          "four lost, and the oldest still held is the first back: dropped %lu, first %lu", dropped, ev[0].seq);
    CHECK(evfeed_since(&f, evfeed_head(&f), ev, 16, &next, &dropped) == 0 && dropped == 0,
          "a reader that is current loses nothing");

    /* ---- the feeder, with the wall clock an hour ahead ---- */
    {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        socklen_t al = sizeof(a);
        struct timespec start, now, nap = { 0, 100 * 1000 * 1000 };
        static evfeed_t g;
        pthread_t th;
        char err[200] = "";
        int seen = 0, listening;

        refuser = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        listening = refuser >= 0 && bind(refuser, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(refuser, 16) == 0
                    && getsockname(refuser, (struct sockaddr *)&a, &al) == 0
                    && pthread_create(&th, NULL, refuse, NULL) == 0;
        CHECK(listening, "no listener on loopback");
        if (listening) {
            machine_cfg_t up;
            machine_cfg_defaults(&up);
            up.host = "127.0.0.1";
            up.port = ntohs(a.sin_port);
            clock_gettime(CLOCK_MONOTONIC, &start);
            realtime_ahead = 1;
            CHECK(evfeed_start(&g, &up, err, sizeof(err)) == 0, "the feeder did not start: %s", err);
            evfeed_want(&g, 1);
            /* The first try at once, the next after the 2 s backoff, the
             * third 4 s after that: two inside 4.5 s. */
            do {
                nanosleep(&nap, NULL);
                clock_gettime(CLOCK_MONOTONIC, &now);
            } while ((double)(now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) * 1e-9 < 4.5);
            pthread_mutex_lock(&tries_mu);
            seen = tries;
            pthread_mutex_unlock(&tries_mu);
            evfeed_stop(&g);
            realtime_ahead = 0;
            shutdown(refuser, SHUT_RDWR);
            pthread_join(th, NULL);
            CHECK(seen >= 2, "with the wall clock an hour ahead, the feeder asked %d time%s in 4.5 s, not twice: its "
                  "backoff rode the wall clock", seen, seen == 1 ? "" : "s");
        }
        if (refuser >= 0)
            close(refuser);
    }

    printf("%s: evfeed_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
