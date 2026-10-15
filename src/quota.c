/*
 * quota.c - how much of the machine's storage a package's data may take
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See quota.h.
 */
#define _GNU_SOURCE
#include "quota.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static long long fail(char *err, size_t elen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static long long fail(char *err, size_t elen, const char *fmt, ...)
{
    if (err && elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, elen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

long long quota_of(const manifest_t *m)
{
    for (int i = 0; i < m->ncaps; i++)
        if (strncmp(m->caps[i], "storage:", 8) == 0) {
            long long mib = atoll(m->caps[i] + 8);
            if (mib > 0)
                return mib << 20;
        }
    return (long long)QUOTA_DEFAULT_MIB << 20;
}

/* The tree under path, or -1 with the reason. What the walk cannot
 * measure is not counted as nothing: the measurement fails, and the
 * caller sets the service aside with the reason. */
static long long walk(const char *path, int depth, char *err, size_t elen)
{
    DIR *d;
    struct dirent *e;
    long long total = 0;

    if (depth > QUOTA_MAX_DEPTH)
        return fail(err, elen, "%s is deeper than the %d directories the host measures", path, QUOTA_MAX_DEPTH);
    d = opendir(path);
    if (!d)
        return fail(err, elen, "cannot read %s: %s", path, strerror(errno));
    while ((e = readdir(d)) != NULL) {
        char p[4096];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if ((size_t)snprintf(p, sizeof(p), "%s/%s", path, e->d_name) >= sizeof(p)) {
            total = fail(err, elen, "a path under %s does not fit", path);
            break;
        }
        if (lstat(p, &st) != 0) {
            if (errno == ENOENT)
                continue;                           /* gone between readdir and stat: it holds nothing now */
            total = fail(err, elen, "cannot examine %s: %s", p, strerror(errno));
            break;
        }
        /* The blocks, not the size: a sparse file has taken what it has
         * taken, and a small file has taken a whole block. */
        total += (long long)st.st_blocks * 512;
        if (S_ISDIR(st.st_mode)) {
            long long sub = walk(p, depth + 1, err, elen);
            if (sub < 0) {
                total = -1;
                break;
            }
            total += sub;
        }
    }
    closedir(d);
    return total;
}

long long quota_dir_bytes(const char *path, char *err, size_t elen)
{
    return walk(path, 0, err, elen);
}
