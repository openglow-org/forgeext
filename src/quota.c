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
#include <fcntl.h>
#include <limits.h>
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

/* The tree under the directory fd is open on, or -1 with the reason;
 * the walk owns fd and closes it. Every entry is examined and opened
 * relative to the descriptor of the directory it was read from, by its
 * name and with O_NOFOLLOW: nothing here resolves a path and then opens
 * it by name a moment later, so a directory the package replaces with a
 * link while it is measured is not followed, and no path is built that
 * could fail to fit. What the walk cannot measure is not counted as
 * nothing: the measurement fails, and the caller sets the service aside
 * with the reason. The entries are counted in *entries across the whole
 * tree, and the walk fails past max_entries: what is over the bound is
 * not walked, so the bound is on the walk's time as well. */
static long long walk(int fd, int depth, long long max_entries, long long *entries, char *err, size_t elen)
{
    DIR *d;
    struct dirent *e;
    long long total = 0;

    d = fdopendir(fd);
    if (!d) {
        int saved = errno;
        close(fd);
        return fail(err, elen, "cannot read a directory: %s", strerror(saved));
    }
    while ((errno = 0, e = readdir(d)) != NULL) {
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;                           /* gone between readdir and stat: it holds nothing now */
            total = fail(err, elen, "cannot examine %s: %s", e->d_name, strerror(errno));
            break;
        }
        if (++*entries > max_entries) {
            total = fail(err, elen, "holds more than %lld files and directories", max_entries);
            break;
        }
        /* The blocks, not the size: a sparse file has taken what it has
         * taken, and a small file has taken a whole block. */
        total += (long long)st.st_blocks * 512;
        if (!S_ISDIR(st.st_mode))
            continue;
        if (depth + 1 > QUOTA_MAX_DEPTH) {
            total = fail(err, elen, "%s is deeper than the %d directories the host measures", e->d_name,
                         QUOTA_MAX_DEPTH);
            break;
        }
        int sub = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub < 0) {
            if (errno == ENOENT)
                continue;                           /* gone between its stat and its open: it holds nothing now */
            total = errno == ELOOP || errno == ENOTDIR
                    ? fail(err, elen, "%s changed while it was measured", e->d_name)
                    : fail(err, elen, "cannot read %s: %s", e->d_name, strerror(errno));
            break;
        }
        long long under = walk(sub, depth + 1, max_entries, entries, err, elen);
        if (under < 0) {
            total = -1;
            break;
        }
        total += under;
    }
    /* readdir returns NULL at the end of a listing and when the listing
     * fails, and only errno tells the two apart. A listing that fails part
     * way is a directory that cannot be read, never one that holds only
     * what came before the fault. */
    if (!e && errno != 0)
        total = fail(err, elen, "cannot read a directory: %s", strerror(errno));
    closedir(d);
    return total;
}

long long quota_dir_bytes(const char *path, long long max_entries, char *err, size_t elen)
{
    long long entries = 0;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return fail(err, elen, "cannot read %s: %s", path, strerror(errno));
    return walk(fd, 0, max_entries, &entries, err, elen);
}

/* One open file, by device and inode, for counting a file open more
 * than once as the one file it is. */
typedef struct {
    dev_t dev;
    ino_t ino;
} open_file_t;

static int seen_before(open_file_t *seen, int *nseen, const struct stat *st)
{
    for (int i = 0; i < *nseen; i++)
        if (seen[i].dev == st->st_dev && seen[i].ino == st->st_ino)
            return 1;
    if (*nseen < QUOTA_OPEN_MAX) {
        seen[*nseen].dev = st->st_dev;
        seen[*nseen].ino = st->st_ino;
        (*nseen)++;
    }
    return 0;
}

long long quota_open_bytes(const char *data, const pid_t *pids, int n, char *err, size_t elen)
{
    static open_file_t seen[QUOTA_OPEN_MAX];
    static const char gone[] = " (deleted)";
    char real[PATH_MAX];
    int nseen = 0;
    long long total = 0;

    /* The kernel names what a descriptor is open on by its path from
     * the root: the directory is matched as the kernel would name it. */
    if (!realpath(data, real))
        return fail(err, elen, "cannot read %s: %s", data, strerror(errno));
    size_t rlen = strlen(real);
    for (int i = 0; i < n; i++) {
        char dir[64];
        struct dirent *e;
        snprintf(dir, sizeof(dir), "/proc/%ld/fd", (long)pids[i]);
        int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT)
                continue;                               /* the process ended: it holds nothing now */
            return fail(err, elen, "cannot read the open files of process %ld: %s", (long)pids[i], strerror(errno));
        }
        DIR *d = fdopendir(fd);
        if (!d) {
            int saved = errno;
            close(fd);
            return fail(err, elen, "cannot read the open files of process %ld: %s", (long)pids[i], strerror(saved));
        }
        while ((errno = 0, e = readdir(d)) != NULL) {
            char target[PATH_MAX + sizeof(gone)];
            struct stat st;
            if (e->d_name[0] == '.')
                continue;
            ssize_t len = readlinkat(fd, e->d_name, target, sizeof(target) - 1);
            if (len < 0) {
                if (errno == ENOENT)
                    continue;                           /* closed between the listing and the look */
                total = fail(err, elen, "cannot examine an open file of process %ld: %s", (long)pids[i],
                             strerror(errno));
                break;
            }
            target[len] = '\0';
            /* Under the data directory, and unlinked: a file with a name
             * is the walk's to count. */
            if ((size_t)len < rlen + 1 + sizeof(gone) - 1 || strncmp(target, real, rlen) != 0 || target[rlen] != '/'
                || strcmp(target + len - (sizeof(gone) - 1), gone) != 0)
                continue;
            if (fstatat(fd, e->d_name, &st, 0) != 0) {     /* through the link, to the open file itself */
                if (errno == ENOENT)
                    continue;
                total = fail(err, elen, "cannot examine an open file of process %ld: %s", (long)pids[i],
                             strerror(errno));
                break;
            }
            if (!S_ISREG(st.st_mode) || seen_before(seen, &nseen, &st))
                continue;
            total += (long long)st.st_blocks * 512;
        }
        if (total >= 0 && !e && errno != 0)
            total = fail(err, elen, "cannot read the open files of process %ld: %s", (long)pids[i], strerror(errno));
        closedir(d);
        if (total < 0)
            return -1;
    }
    return total;
}
