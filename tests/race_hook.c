/*
 * race_hook.c - a preloaded hook that races a removal, for install_test
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Loaded into `forgeext wipe` with LD_PRELOAD, it does once, in the middle
 * of the walk, what a package's still-running service could do to its own
 * data directory. RACE_MODE picks it; RACE_TREE is the package's data
 * directory and RACE_OUT a directory beside it that is no package's:
 *   up       at the unlink of a/b/c/trigger, a/b/c moves to the top of the
 *            tree (the walk is inside it, and its ".." is no longer b)
 *   out      at the same unlink, a/b moves into RACE_OUT
 *   symlink  after the walk's look at a/b, a/b is swapped for a link to
 *            RACE_OUT, between the look and the open
 * Each one is said on stderr, as "race_hook: ...".
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int done;

static void move(const char *mode)
{
    const char *tree = getenv("RACE_TREE"), *out = getenv("RACE_OUT");
    char from[PATH_MAX], to[PATH_MAX];
    if (!tree || !out || done)
        return;
    done = 1;
    if (strcmp(mode, "up") == 0) {
        snprintf(from, sizeof(from), "%s/a/b/c", tree);
        snprintf(to, sizeof(to), "%s/c2", tree);
    } else {
        snprintf(from, sizeof(from), "%s/a/b", tree);
        snprintf(to, sizeof(to), "%s/b", out);
    }
    int rc = rename(from, to);
    fprintf(stderr, "race_hook: %s moved to %s: %d\n", from, to, rc);
}

int unlinkat(int dirfd, const char *name, int flags)
{
    static int (*real)(int, const char *, int);
    if (!real)
        real = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "unlinkat");
    const char *mode = getenv("RACE_MODE");
    if (mode && strcmp(name, "trigger") == 0 && (strcmp(mode, "up") == 0 || strcmp(mode, "out") == 0))
        move(mode);
    return real(dirfd, name, flags);
}

static void swap_after_look(int dirfd, const char *name)
{
    const char *mode = getenv("RACE_MODE"), *out = getenv("RACE_OUT");
    char self[64], dir[PATH_MAX], b[PATH_MAX + 8], kept[PATH_MAX + 16];
    if (done || !mode || strcmp(mode, "symlink") != 0 || strcmp(name, "b") != 0 || !out)
        return;
    snprintf(self, sizeof(self), "/proc/self/fd/%d", dirfd);
    ssize_t n = readlink(self, dir, sizeof(dir) - 1);
    if (n <= 0)
        return;
    dir[n] = '\0';
    size_t len = strlen(dir);
    if (len < 2 || strcmp(dir + len - 2, "/a") != 0)
        return;
    done = 1;
    snprintf(b, sizeof(b), "%s/b", dir);
    snprintf(kept, sizeof(kept), "%s/b.real", dir);
    int r1 = rename(b, kept), r2 = symlink(out, b);
    fprintf(stderr, "race_hook: %s swapped for a link to %s after its look: %d %d\n", b, out, r1, r2);
}

int fstatat(int dirfd, const char *name, struct stat *st, int flags)
{
    static int (*real)(int, const char *, struct stat *, int);
    if (!real)
        real = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "fstatat");
    int rc = real(dirfd, name, st, flags);
    if (rc == 0 && S_ISDIR(st->st_mode))
        swap_after_look(dirfd, name);
    return rc;
}
