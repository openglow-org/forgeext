/*
 * cgroup.c - one cgroup v2 group per running package, under the image's ffx group
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#include "cgroup.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CG_PERIOD_US 100000

static int fail(char *err, size_t elen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t elen, const char *fmt, ...)
{
    if (err && elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, elen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* parent/id/file, or parent/file when id is NULL. -1 when it does not fit. */
static int path_of(char *out, size_t olen, const char *parent, const char *id, const char *file)
{
    int n = id ? snprintf(out, olen, "%s/%s/%s", parent, id, file) : snprintf(out, olen, "%s/%s", parent, file);
    return n > 0 && (size_t)n < olen ? 0 : -1;
}

static int put(const char *parent, const char *id, const char *file, const char *text)
{
    char p[512];
    if (path_of(p, sizeof(p), parent, id, file) != 0)
        return -1;
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, text, strlen(text));
    int saved = errno;
    close(fd);
    errno = saved;
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int get(const char *parent, const char *id, const char *file, char *out, size_t olen)
{
    char p[512];
    out[0] = '\0';
    if (path_of(p, sizeof(p), parent, id, file) != 0)
        return -1;
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, out, olen - 1);
    close(fd);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

/* The value of `key` in a flat-keyed file ("populated 1\nfrozen 0\n"), or -1. */
long long cg_event(const char *parent, const char *id, const char *file, const char *key)
{
    char text[1024];
    if (get(parent, id, file, text, sizeof(text)) != 0)
        return -1;
    size_t klen = strlen(key);
    for (char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL)
        if (strncmp(line, key, klen) == 0 && line[klen] == ' ')
            return atoll(line + klen + 1);
    return -1;
}

static void nap_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

int cg_ready(const char *parent, char *err, size_t elen)
{
    char text[256];
    if (get(parent, NULL, "cgroup.subtree_control", text, sizeof(text)) != 0)
        return fail(err, elen, "%s is not a cgroup v2 group (%s)", parent, strerror(errno));
    static const char *const want[] = { "cpu", "memory", "pids" };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        int found = 0;
        char copy[256];
        snprintf(copy, sizeof(copy), "%s", text);
        for (char *tok = strtok(copy, " \n"); tok; tok = strtok(NULL, " \n"))
            found |= strcmp(tok, want[i]) == 0;
        if (!found)
            return fail(err, elen, "%s does not hand the %s controller down", parent, want[i]);
    }
    return 0;
}

int cg_limits(const char *parent, const char *id, const cg_limits_t *lim, char *err, size_t elen)
{
    char v[64];
    if (lim->cpu_pct > 0)
        snprintf(v, sizeof(v), "%d %d", lim->cpu_pct * (CG_PERIOD_US / 100), CG_PERIOD_US);
    else
        snprintf(v, sizeof(v), "max %d", CG_PERIOD_US);
    if (put(parent, id, "cpu.max", v) != 0)
        return fail(err, elen, "cannot set cpu.max of %s: %s", id, strerror(errno));
    if (lim->memory_bytes > 0)
        snprintf(v, sizeof(v), "%lld", lim->memory_bytes);
    else
        snprintf(v, sizeof(v), "max");
    if (put(parent, id, "memory.max", v) != 0)
        return fail(err, elen, "cannot set memory.max of %s: %s", id, strerror(errno));
    put(parent, id, "memory.swap.max", "0");            /* absent without swap, which this kernel has none of */
    put(parent, id, "memory.oom.group", "1");           /* one process over the limit takes the package, not a part of it */
    if (lim->pids > 0)
        snprintf(v, sizeof(v), "%d", lim->pids);
    else
        snprintf(v, sizeof(v), "max");
    if (put(parent, id, "pids.max", v) != 0)
        return fail(err, elen, "cannot set pids.max of %s: %s", id, strerror(errno));
    return 0;
}

int cg_create(const char *parent, const char *id, const cg_limits_t *lim, char *err, size_t elen)
{
    char p[512];
    if (snprintf(p, sizeof(p), "%s/%s", parent, id) >= (int)sizeof(p))
        return fail(err, elen, "the group's path does not fit");
    if (mkdir(p, 0755) != 0 && errno != EEXIST)
        return fail(err, elen, "cannot make the group %s: %s", p, strerror(errno));
    if (cg_populated(parent, id) != 0)
        return fail(err, elen, "the group %s already holds a process", p);
    if (put(parent, id, "cgroup.freeze", "0") != 0)
        return fail(err, elen, "cannot thaw the group %s: %s", p, strerror(errno));
    return cg_limits(parent, id, lim, err, elen);
}

int cg_add(const char *parent, const char *id, pid_t pid)
{
    char v[32];
    snprintf(v, sizeof(v), "%d", (int)pid);
    return put(parent, id, "cgroup.procs", v);
}

int cg_populated(const char *parent, const char *id)
{
    long long v = cg_event(parent, id, "cgroup.events", "populated");
    return v < 0 ? -1 : v != 0;
}

int cg_frozen(const char *parent, const char *id)
{
    long long v = cg_event(parent, id, "cgroup.events", "frozen");
    return v < 0 ? -1 : v != 0;
}

int cg_freeze(const char *parent, const char *id, int on)
{
    if (put(parent, id, "cgroup.freeze", on ? "1" : "0") != 0)
        return -1;
    for (int i = 0; i < 100; i++) {                     /* the kernel reports it within milliseconds */
        if (cg_frozen(parent, id) == (on ? 1 : 0))
            return 0;
        nap_ms(20);
    }
    return -1;
}

int cg_destroy(const char *parent, const char *id)
{
    char p[512];
    if (snprintf(p, sizeof(p), "%s/%s", parent, id) >= (int)sizeof(p))
        return -1;
    if (cg_populated(parent, id) < 0)
        return rmdir(p) == 0 || errno == ENOENT ? 0 : -1;
    put(parent, id, "cgroup.kill", "1");
    for (int i = 0; i < 250; i++) {
        if (cg_populated(parent, id) == 0 && rmdir(p) == 0)
            return 0;
        nap_ms(20);
    }
    return -1;
}
