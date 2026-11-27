/*
 * holdkeep_test.c - host test: what the host says for a package's hold, and how it keeps it
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * hold_decide() for every case, and the keeper against a real directory:
 * the files are there at once, their timestamps stay fresh while the main
 * loop speaks and stop when it goes silent, a package that is no longer
 * named loses its file, a previous host's files stay until this one has
 * spoken, and a clean stop leaves the required ones to go stale. A raise
 * between turns is on disk when it returns, only toward raised and only
 * for a package the turn named; a claim is on disk when it returns; a
 * required-hold marker holds the modes it was given.
 */
#include "../src/holdkeep.h"

#include <jansson.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static char dir[] = "/tmp/holdkeep-test-XXXXXX";

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static void nap(double s)
{
    struct timespec t = { (time_t)s, (long)((s - (double)(time_t)s) * 1e9) };
    nanosleep(&t, NULL);
}

/* The file of one package under d: 1 when it is there, with its fields. */
static int look_at(const char *d, const char *id, int *required, int *raised, char *reason, size_t rlen, double *age)
{
    char p[400];
    snprintf(p, sizeof(p), "%s/%s.json", d, id);
    json_t *j = json_load_file(p, 0, NULL);
    if (!j)
        return 0;
    *required = json_is_true(json_object_get(j, "required"));
    *raised = json_is_true(json_object_get(j, "raised"));
    snprintf(reason, rlen, "%s", json_string_value(json_object_get(j, "reason")) ? json_string_value(json_object_get(j, "reason")) : "?");
    *age = mono() - json_number_value(json_object_get(j, "ts_mono"));
    int ok = !strcmp(json_string_value(json_object_get(j, "id")) ? json_string_value(json_object_get(j, "id")) : "", id);
    json_decref(j);
    return ok;
}

static int look(const char *id, int *required, int *raised, char *reason, size_t rlen, double *age)
{
    return look_at(dir, id, required, raised, reason, rlen, age);
}

int main(void)
{
    hold_entry_t e[3];
    int req, up, dropped;
    double age;
    char why[128], err[200];

    /* What the host says. */
    dropped = hold_decide("org.example.badge", 1, 1, 1, 0, NULL, &e[0]);
    CHECK(!dropped && e[0].required && !e[0].raised && !e[0].reason[0], "running healthy, nothing said: clear");
    dropped = hold_decide("org.example.badge", 1, 1, 1, 1, "no badge presented", &e[0]);
    CHECK(!dropped && e[0].raised && !strcmp(e[0].reason, "no badge presented"), "running healthy, raised: its own words");
    dropped = hold_decide("org.example.badge", 1, 0, 0, 0, NULL, &e[0]);
    CHECK(!dropped && e[0].raised && !strcmp(e[0].reason, "the extension is not running"),
          "required and not running: the host raises it");
    dropped = hold_decide("org.example.badge", 1, 0, 0, 1, "stale words", &e[0]);
    CHECK(e[0].raised && !strcmp(e[0].reason, "the extension is not running"), "and says so in its own words, not the package's last");
    dropped = hold_decide("org.example.badge", 1, 1, 0, 0, NULL, &e[0]);
    CHECK(!dropped && e[0].raised && !strcmp(e[0].reason, "the extension has only just started"),
          "required, started, not yet healthy: still raised (one that ends at every start must not flicker clear)");
    dropped = hold_decide("org.example.filter", 0, 0, 0, 1, "filter life under 5 percent", &e[1]);
    CHECK(dropped && !e[1].required && !e[1].raised && !e[1].reason[0], "advisory and not running: dropped, and the caller told");
    dropped = hold_decide("org.example.filter", 0, 1, 0, 1, "filter life under 5 percent", &e[1]);
    CHECK(!dropped && e[1].raised, "advisory and running, healthy or not: what it said");

    /* The keeper. */
    if (!mkdtemp(dir)) {
        printf("FAIL mkdtemp\n");
        return 1;
    }
    /* what a previous host left: it stays until this one has spoken for it */
    char left[400];
    snprintf(left, sizeof(left), "%s/org.example.gone.json", dir);
    FILE *f = fopen(left, "w");
    if (f) {
        fputs("{\"id\": \"org.example.gone\", \"required\": true, \"raised\": false, \"reason\": \"\", \"ts_mono\": 1.0}\n", f);
        fclose(f);
    }
    static holdkeep_t k;
    CHECK(holdkeep_start(&k, dir, 1.5, err, sizeof(err)) == 0, "the keeper did not start: %s", err);
    nap(0.7);
    CHECK(access(left, F_OK) == 0, "a previous host's file went before this host had spoken");

    hold_decide("org.example.badge", 1, 0, 0, 0, NULL, &e[0]);
    hold_decide("org.example.filter", 0, 1, 0, 1, "filter life under 5 percent", &e[1]);
    holdkeep_set(&k, e, 2);
    CHECK(access(left, F_OK) != 0, "a file nobody names stayed after the host spoke");
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && req && up && age < 0.3 &&
          !strcmp(why, "the extension is not running"), "the required hold is on disk at once: age %.2f, %s", age, why);
    CHECK(look("org.example.filter", &req, &up, why, sizeof(why), &age) && !req && up &&
          !strcmp(why, "filter life under 5 percent"), "the advisory hold is on disk at once");

    /* the thread keeps them fresh between the main loop's turns, a write
     * each HOLDKEEP_PERIOD_MS and no more often: on one core a keeper that
     * did not sleep would take the core from everything else */
    int ino = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    CHECK(ino >= 0 && inotify_add_watch(ino, dir, IN_MOVED_TO) >= 0, "a watch on the holds directory");
    nap(1.2);
    int writes = 0;
    char evbuf[4096];
    ssize_t got;
    while ((got = read(ino, evbuf, sizeof(evbuf))) > 0)
        for (char *q = evbuf; q < evbuf + got;) {
            struct inotify_event *ev = (struct inotify_event *)q;
            writes += ev->len && strcmp(ev->name, "org.example.badge.json") == 0;      /* one rename into place per write */
            q += sizeof(*ev) + ev->len;
        }
    close(ino);
    CHECK(writes >= 1 && writes <= 1200 / HOLDKEEP_PERIOD_MS + 2,
          "%d writes of one hold in 1.2 s, at a period of %d ms", writes, HOLDKEEP_PERIOD_MS);
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && age < 0.9, "kept fresh between turns: age %.2f", age);
    /* a main loop that goes silent: the files stop */
    nap(2.5);
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && age > 2.0,
          "a silent main loop's holds still read fresh: age %.2f", age);
    /* it speaks again */
    holdkeep_set(&k, e, 2);
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && age < 0.3, "fresh again when it speaks: age %.2f", age);

    /* a package that is no longer named loses its file; none named, none left */
    holdkeep_set(&k, e, 1);
    CHECK(!look("org.example.filter", &req, &up, why, sizeof(why), &age) &&
          look("org.example.badge", &req, &up, why, sizeof(why), &age), "the one no longer named kept its file");
    holdkeep_set(&k, NULL, 0);
    CHECK(!look("org.example.badge", &req, &up, why, sizeof(why), &age), "extensions off: a file stayed");

    /* a clean stop: the advisory file goes, the required one is left to go stale */
    holdkeep_set(&k, e, 2);
    holdkeep_stop(&k);
    CHECK(!look("org.example.filter", &req, &up, why, sizeof(why), &age), "the advisory file outlived a clean stop");
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && req, "the required file went with a clean stop");
    nap(1.2);
    CHECK(look("org.example.badge", &req, &up, why, sizeof(why), &age) && age > 1.0, "and nobody refreshes it after the stop: age %.2f", age);

    /* A raise that does not wait for the turn, on a keeper whose own thread writes nothing (its main
     * loop is silent from the start): what reaches the disk is the set's write and the raise's own. */
    static char dir2[] = "/tmp/holdkeep-raise-XXXXXX";
    static holdkeep_t k2;
    CHECK(mkdtemp(dir2) && holdkeep_start(&k2, dir2, 0.0, err, sizeof(err)) == 0, "the second keeper did not start: %s", err);
    hold_decide("org.example.filter", 0, 1, 0, 0, NULL, &e[0]);
    holdkeep_set(&k2, e, 1);
    CHECK(look_at(dir2, "org.example.filter", &req, &up, why, sizeof(why), &age) && !up, "the advisory hold is clear");
    CHECK(holdkeep_raise(&k2, "org.example.filter", "the exhaust is off") == 1 &&
          look_at(dir2, "org.example.filter", &req, &up, why, sizeof(why), &age) && up && !strcmp(why, "the exhaust is off"),
          "a raise is not on disk when it returns: raised %d, %s", up, why);
    CHECK(holdkeep_raise(&k2, "org.example.filter", "other words") == 1 &&
          look_at(dir2, "org.example.filter", &req, &up, why, sizeof(why), &age) && up && !strcmp(why, "the exhaust is off"),
          "a raise over a raised hold changed its words: %s", why);
    CHECK(holdkeep_raise(&k2, "org.example.unnamed", "words") == 0 &&
          !look_at(dir2, "org.example.unnamed", &req, &up, why, sizeof(why), &age),
          "a raise added a package the turn does not name");
    CHECK(holdkeep_claim(&k2, "org.example.claim", "keeps the Grbl sender out") == 0 &&
          look_at(dir2, "org.example.claim", &req, &up, why, sizeof(why), &age) && up,
          "a claim is not on disk when it returns");
    holdkeep_stop(&k2);
    char mpath[400], mtext[32] = "";
    snprintf(mpath, sizeof(mpath), "%s/org.example.m", dir2);
    for (int i = 0; i < 4; i++) {
        static const char *const want[] = { "", "grbl\n", "cloud\n", "grbl cloud\n" };
        CHECK(holdkeep_marker_write(dir2, "org.example.m", i & 1, (i >> 1) & 1) == 0, "the marker was not written");
        FILE *mf = fopen(mpath, "r");
        size_t n = mf ? fread(mtext, 1, sizeof(mtext) - 1, mf) : 0;
        mtext[n] = '\0';
        if (mf)
            fclose(mf);
        CHECK(!strcmp(mtext, want[i]), "the marker for grbl %d cloud %d holds '%s'", i & 1, (i >> 1) & 1, mtext);
    }

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", dir, dir2);
    if (system(cmd) != 0)
        fails++;
    printf("%s: holdkeep_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
