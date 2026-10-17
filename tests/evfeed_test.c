/*
 * evfeed_test.c - host test: the event reader, the ring behind it, and the host's timeouts on a stepped clock
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Two pure parts of evfeed.h: the server-sent-events reader, fed the lines
 * forgectrl writes, and the ring every package reads from: what the host
 * makes of the bytes, and what a reader is told when it falls behind.
 * Then the feeder's thread, against a listener on loopback that closes
 * every connection, with the wall clock an hour ahead of where it was and
 * stepped back that hour 1 s in, inside the feeder's first backoff, as
 * NTP steps the clock of a board with no RTC. The feeder asks for the
 * stream again two seconds after its first try, and only then, and its
 * waits sleep: the backoff, the deadline of each wait, and the clock of
 * the condvar it waits on all ride CLOCK_MONOTONIC. Last, the bounds on
 * fwup (pkg_open_product, over an archive the test makes) and on nft
 * (net_sweep): each runs a stand-in that writes its answer in two parts a
 * second apart, and the wall clock steps ten years ahead between them.
 * Each answer is read whole, so neither bound rides the wall clock.
 *
 * clock_gettime and time are stand-ins defined here, which the host's
 * code in forgeext_core calls. They move CLOCK_REALTIME and time(), and
 * nothing else. clock_gettime goes through to the call of the name the
 * C library's headers give it: a 32-bit build with 64-bit time renames
 * it.
 */
#define _GNU_SOURCE
#include "../src/evfeed.h"
#include "../src/netrules.h"
#include "../src/pkg.h"

#include <archive.h>
#include <archive_entry.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __USE_TIME_BITS64
#define REAL_CLOCK_GETTIME "__clock_gettime64"
#else
#define REAL_CLOCK_GETTIME "clock_gettime"
#endif

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

/* How far ahead of the real one the wall clock is, in seconds, as a case
 * sets it. Threads of the host read it, so it is read and written whole. */
static int wall_ahead;

static void set_wall_ahead(int s)
{
    __atomic_store_n(&wall_ahead, s, __ATOMIC_SEQ_CST);
}

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real)(clockid_t, struct timespec *);
    if (!real)
        *(void **)&real = dlsym(RTLD_NEXT, REAL_CLOCK_GETTIME);
    int rc = real(id, ts);
    if (rc == 0 && id == CLOCK_REALTIME)
        ts->tv_sec += (time_t)__atomic_load_n(&wall_ahead, __ATOMIC_SEQ_CST);
    return rc;
}

time_t time(time_t *t)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);                 /* the stand-in above: the wall clock as the case has it */
    if (t)
        *t = ts.tv_sec;
    return ts.tv_sec;
}

static double since(const struct timespec *a, const struct timespec *b)
{
    return (double)(b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec) * 1e-9;
}

/* The step a bound case is made under: ten years ahead, 0.5 s in, while
 * the stand-in child is between the two parts of its answer. */
static void *step_ahead(void *arg)
{
    struct timespec half = { 0, 500 * 1000 * 1000 };
    (void)arg;
    nanosleep(&half, NULL);
    set_wall_ahead(10 * 365 * 86400);
    return NULL;
}

/* A program of the test's own, a shell script with that text. 0 when it is there. */
static int script(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    int ok = fputs(text, f) >= 0;
    ok &= fclose(f) == 0;
    return ok && chmod(path, 0755) == 0 ? 0 : -1;
}

/* An extension archive the reader takes, unsigned: its metadata, then the
 * payload that metadata names by its length and its blake2b-256. 0 when
 * it is written. */
static int archive_of(const char *path)
{
    static const char payload[] = "payload bytes\n";
    unsigned char h[32];
    char hexd[65], meta[512];
    if (sodium_init() < 0)
        return -1;
    crypto_generichash(h, sizeof(h), (const unsigned char *)payload, sizeof(payload) - 1, NULL, 0);
    for (int i = 0; i < 32; i++)
        snprintf(hexd + 2 * i, 3, "%02x", h[i]);
    int n = snprintf(meta, sizeof(meta),
                     "meta-product=\"%s\"\nmeta-version=\"1.0.0\"\nmeta-platform=\"forgefirm-ext\"\n"
                     "file-resource \"payload.tar.gz\" {\n  length=%zu\n  blake2b-256=\"%s\"\n}\n",
                     PKG_PRODUCT, sizeof(payload) - 1, hexd);
    const char *names[] = { "meta.conf", "data/payload.tar.gz" }, *data[] = { meta, payload };
    size_t lens[] = { (size_t)n, sizeof(payload) - 1 };
    struct archive *a = archive_write_new();
    int ok = a && archive_write_set_format_zip(a) == ARCHIVE_OK && archive_write_open_filename(a, path) == ARCHIVE_OK;
    for (int i = 0; ok && i < 2; i++) {
        struct archive_entry *e = archive_entry_new();
        archive_entry_set_pathname(e, names[i]);
        archive_entry_set_filetype(e, AE_IFREG);
        archive_entry_set_perm(e, 0644);
        archive_entry_set_size(e, (la_int64_t)lens[i]);
        ok = archive_write_header(a, e) == ARCHIVE_OK && archive_write_data(a, data[i], lens[i]) == (la_ssize_t)lens[i];
        archive_entry_free(e);
    }
    if (a) {
        ok &= archive_write_close(a) == ARCHIVE_OK;
        archive_write_free(a);
    }
    return ok ? 0 : -1;
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

    /* ---- the feeder, with the wall clock an hour ahead and stepped back ---- */
    {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        socklen_t al = sizeof(a);
        struct timespec start, now, cpu0, cpu1, nap = { 0, 100 * 1000 * 1000 };
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
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu0);
            clock_gettime(CLOCK_MONOTONIC, &start);
            set_wall_ahead(3600);
            CHECK(evfeed_start(&g, &up, err, sizeof(err)) == 0, "the feeder did not start: %s", err);
            evfeed_want(&g, 1);
            /* The first try at once, the next after the 2 s backoff, the
             * third 4 s after that: two inside 4.5 s. The wall clock steps
             * back the hour 1 s in, inside the first backoff. */
            do {
                nanosleep(&nap, NULL);
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (since(&start, &now) >= 1.0)
                    set_wall_ahead(0);
            } while (since(&start, &now) < 4.5);
            pthread_mutex_lock(&tries_mu);
            seen = tries;
            pthread_mutex_unlock(&tries_mu);
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1);
            evfeed_stop(&g);
            set_wall_ahead(0);
            shutdown(refuser, SHUT_RDWR);
            pthread_join(th, NULL);
            CHECK(seen == 2, "with the wall clock an hour ahead and stepped back 1 s in, the feeder asked %d time%s in "
                  "4.5 s, not twice: once is a wait's deadline or the backoff on the wall clock, more is no backoff",
                  seen, seen == 1 ? "" : "s");
            CHECK(since(&cpu0, &cpu1) < 1.0, "the feeder did not sleep between its tries: %.2f s of CPU in 4.5 s",
                  since(&cpu0, &cpu1));
        }
        if (refuser >= 0)
            close(refuser);
    }

    /* ---- fwup's and nft's bounds, with the wall clock stepped ten years ahead ---- */
    {
        char dir[] = "/tmp/ffx-evfeed-test.XXXXXX", fwup[64], nft[64], ffx[64], err[300];
        pthread_t th;
        int made = mkdtemp(dir) != NULL;
        snprintf(fwup, sizeof(fwup), "%s/fwup", dir);
        snprintf(nft, sizeof(nft), "%s/nft", dir);
        snprintf(ffx, sizeof(ffx), "%s/x.ffx", dir);
        /* fwup's reading of the metadata in two parts; nothing listed; verified. */
        made = made && script(fwup, "#!/bin/sh\nif [ \"$1\" = -m ]; then\n    echo 'meta-product=\"" PKG_PRODUCT "\"'\n"
                                    "    sleep 1\n    echo 'meta-version=\"1.0.0\"'\nfi\nexit 0\n") == 0
               && script(nft, "#!/bin/sh\necho 'table inet ffx {'\nsleep 1\necho '}'\nexit 0\n") == 0
               && archive_of(ffx) == 0;
        CHECK(made, "the stand-ins and the archive were not made in %s", dir);
        if (made) {
            pkg_trust_t trust;
            pkg_info_t info;
            memset(&trust, 0, sizeof(trust));
            trust.fwup = fwup;
            err[0] = '\0';
            set_wall_ahead(0);
            pthread_create(&th, NULL, step_ahead, NULL);
            int rc = pkg_open_product(&trust, ffx, PKG_PRODUCT, NULL, &info, err, sizeof(err));
            pthread_join(th, NULL);
            set_wall_ahead(0);
            CHECK(rc == 0, "fwup's answer, read across a step of the wall clock: %d (%s): its bound rides the wall clock",
                  rc, err);

            net_env_t env;
            memset(&env, 0, sizeof(env));
            env.nft = nft;
            err[0] = '\0';
            pthread_create(&th, NULL, step_ahead, NULL);
            rc = net_sweep(&env, err, sizeof(err));
            pthread_join(th, NULL);
            set_wall_ahead(0);
            CHECK(rc == 0, "nft's answer, read across a step of the wall clock: %d (%s): its bound rides the wall clock",
                  rc, err);
        }
        unlink(fwup);
        unlink(nft);
        unlink(ffx);
        rmdir(dir);
    }

    printf("%s: evfeed_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
