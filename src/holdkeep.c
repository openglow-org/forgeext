/*
 * holdkeep.c - the holds packages have on a job: decided here, kept here
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See holdkeep.h. The thread does nothing that can wait on anything but
 * the tmpfs: it formats, writes, renames, and sleeps.
 */
#define _GNU_SOURCE
#include "holdkeep.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

int hold_decide(const char *id, int required, int running, int healthy, int said_raised, const char *said_reason,
                hold_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->id, sizeof(out->id), "%s", id);
    out->required = required ? 1 : 0;
    if (running && (healthy || !required)) {
        out->raised = said_raised ? 1 : 0;
        snprintf(out->reason, sizeof(out->reason), "%s", said_raised && said_reason ? said_reason : "");
        return 0;
    }
    /* It cannot speak for itself. */
    if (required) {
        out->raised = 1;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 running ? "the extension has only just started" : "the extension is not running");
        return 0;
    }
    return 1;
}

static void write_one(const char *dir, const hold_entry_t *e, double now)
{
    char path[400], tmp[420];
    snprintf(path, sizeof(path), "%.255s/%.63s.json", dir, e->id);
    snprintf(tmp, sizeof(tmp), "%.255s/.%.63s.json.new", dir, e->id);
    json_t *j = json_pack("{s:s, s:b, s:b, s:s, s:f}", "id", e->id, "required", e->required, "raised", e->raised,
                          "reason", e->reason, "ts_mono", now);
    char *text = j ? json_dumps(j, JSON_COMPACT | JSON_REAL_PRECISION(12)) : NULL;
    json_decref(j);
    if (!text)
        return;
    int fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd >= 0) {
        size_t n = strlen(text);
        int ok = write(fd, text, n) == (ssize_t)n && write(fd, "\n", 1) == 1;
        close(fd);
        if (!ok || rename(tmp, path) != 0)
            unlink(tmp);
    }
    free(text);
}

/* Remove every hold file the table does not name. */
static void prune(holdkeep_t *k)
{
    DIR *d = opendir(k->dir);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t n = strlen(de->d_name);
        if (de->d_name[0] == '.' || n <= 5 || strcmp(de->d_name + n - 5, ".json") != 0)
            continue;
        int named = 0;
        for (int i = 0; i < k->n; i++)
            named |= strlen(k->e[i].id) == n - 5 && strncmp(k->e[i].id, de->d_name, n - 5) == 0;
        if (!named) {
            char p[600];
            snprintf(p, sizeof(p), "%.255s/%.300s", k->dir, de->d_name);
            unlink(p);
        }
    }
    closedir(d);
}

static void *keeper(void *arg)
{
    holdkeep_t *k = arg;
    for (;;) {
        pthread_mutex_lock(&k->mu);
        int stop = k->stop;
        double now = mono();
        /* A main loop that has gone silent speaks for nobody: the files go
         * stale, and a required hold stands on that. */
        if (!stop && now - k->main_seen <= k->main_s)
            for (int i = 0; i < k->n; i++)
                write_one(k->dir, &k->e[i], now);
        pthread_mutex_unlock(&k->mu);
        if (stop)
            return NULL;
        struct timespec nap = { 0, HOLDKEEP_PERIOD_MS * 1000000L };
        nanosleep(&nap, NULL);
    }
}

int holdkeep_start(holdkeep_t *k, const char *dir, double main_s, char *err, size_t elen)
{
    memset(k, 0, sizeof(*k));
    pthread_mutex_init(&k->mu, NULL);
    snprintf(k->dir, sizeof(k->dir), "%s", dir);
    k->main_s = main_s;
    k->main_seen = mono();
    if (strlen(dir) >= sizeof(k->dir) || (mkdir(dir, 0755) != 0 && errno != EEXIST)) {
        snprintf(err, elen, "cannot make the holds directory %s: %s", dir, strerror(errno));
        return -1;
    }
    chmod(dir, 0755);
    if (pthread_create(&k->thread, NULL, keeper, k) != 0) {
        snprintf(err, elen, "cannot start the thread that keeps the holds fresh");
        return -1;
    }
    k->started = 1;
    return 0;
}

void holdkeep_set(holdkeep_t *k, const hold_entry_t *e, int n)
{
    if (!k->started)
        return;
    if (n > HOLDKEEP_MAX)
        n = HOLDKEEP_MAX;
    pthread_mutex_lock(&k->mu);
    if (n > 0)
        memcpy(k->e, e, (size_t)n * sizeof(*e));
    k->n = n > 0 ? n : 0;
    k->main_seen = mono();
    double now = k->main_seen;
    /* What changed is on disk before the turn goes on: a hold that was
     * raised stands now, and not half a second from now. */
    for (int i = 0; i < n; i++)
        write_one(k->dir, &k->e[i], now);
    prune(k);
    pthread_mutex_unlock(&k->mu);
}

void holdkeep_stop(holdkeep_t *k)
{
    if (!k->started)
        return;
    pthread_mutex_lock(&k->mu);
    k->stop = 1;
    /* Keep the required ones in the table, so that the prune takes the
     * advisory files and leaves those. */
    int m = 0;
    for (int i = 0; i < k->n; i++)
        if (k->e[i].required)
            k->e[m++] = k->e[i];
    k->n = m;
    prune(k);
    pthread_mutex_unlock(&k->mu);
    pthread_join(k->thread, NULL);
    k->started = 0;
}
