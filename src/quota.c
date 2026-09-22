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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static long long walk(const char *path, int depth)
{
    DIR *d;
    struct dirent *e;
    long long total = 0;

    if (depth > QUOTA_MAX_DEPTH)
        return 0;
    d = opendir(path);
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        char p[4096];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if ((size_t)snprintf(p, sizeof(p), "%s/%s", path, e->d_name) >= sizeof(p))
            continue;                               /* a path that long is not one this host made */
        if (lstat(p, &st) != 0)
            continue;
        /* The blocks, not the size: a sparse file has taken what it has
         * taken, and a small file has taken a whole block. */
        total += (long long)st.st_blocks * 512;
        if (S_ISDIR(st.st_mode)) {
            long long sub = walk(p, depth + 1);
            if (sub > 0)
                total += sub;
        }
    }
    closedir(d);
    return total;
}

long long quota_dir_bytes(const char *path)
{
    return walk(path, 0);
}
