/*
 * quota_test.c - host test: what a package may hold, and what it holds
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * quota_of() over a manifest's capabilities, and quota_dir_bytes() over a
 * real tree: nested directories counted, a symbolic link out of the tree
 * counted as a link and never followed, a sparse file counted by what
 * the filesystem gave it rather than by how large it claims to be, and a
 * measurement that did not complete (a tree deeper than the host
 * measures, a directory it cannot read, a listing that fails part way, a
 * directory swapped for a link between the walk's look at it and its
 * open, a data directory that is itself a link) read as -1 with the
 * reason, never as nothing. A directory the package removes between the
 * walk's look at it and its open, and a file it removes between the
 * walk's listing of it and its look, hold nothing now, and the
 * measurement completes without them. A tree whose path is longer than
 * PATH_MAX is measured like any other: the walk goes by descriptors, not
 * by a path it builds. The entries are counted against the bound the
 * caller gives: a directory of as many files as the bound measures, and
 * one file more does not. quota_open_bytes() over this process's own
 * descriptors and mappings: a file unlinked while it is held open is
 * counted, once however many times it is open, and a file that has its
 * name, one unlinked outside the tree, and one closed are not; one
 * unlinked and kept mapped with its descriptor closed is counted as
 * root, once when it is open and mapped both, and is a measurement that
 * did not complete where the kernel refuses the look at it (unprivileged);
 * as many such mappings as the bound (QUOTA_OPEN_MAX) are measured, and
 * one more is a measurement that did not complete (root).
 *
 * The walk's readdir and fstatat are stand-ins defined here, so that a
 * case can fail a listing, or remove or move an entry, at the moment the
 * walk reaches it. Until a case arms one, each goes through to the real
 * call, by the name the C library's headers give the call it stands in
 * for: a 32-bit build with 64-bit offsets and time renames both.
 */
#define _GNU_SOURCE
#include "../src/quota.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* The names the headers give readdir and fstatat, and so the names these
 * stand-ins take: each goes through to the call of that same name. The
 * conditions are the headers' own. 64-bit offsets rename both calls.
 * 64-bit time renames fstatat to __fstatat64_time64, but only on an ABI
 * whose time_t is 32 bits wide by default (__TIMESIZE == 32). A C
 * library can define __USE_TIME_BITS64 where time_t is always 64 bits
 * wide, and it renames nothing there. */
#ifdef __USE_FILE_OFFSET64
#define REAL_READDIR "readdir64"
#else
#define REAL_READDIR "readdir"
#endif
#ifndef __USE_FILE_OFFSET64
#define REAL_FSTATAT "fstatat"
#elif defined __USE_TIME_BITS64 && __TIMESIZE == 32
#define REAL_FSTATAT "__fstatat64_time64"
#else
#define REAL_FSTATAT "fstatat64"
#endif

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); \
                              fflush(stdout); } } while (0)

/* An entry bound no case here reaches, for the cases that are not about it. */
#define PLENTY (1LL << 20)

/* The listing that fails, as a fault in a directory block fails it: the
 * directory, by device and inode, and the calls made on it. The first
 * call goes through, and every call after it fails with EIO. */
static dev_t torn_dev;
static ino_t torn_ino;
static int torn_calls;

struct dirent *readdir(DIR *d)
{
    static struct dirent *(*real)(DIR *);
    struct stat st;
    if (!real)
        *(void **)&real = dlsym(RTLD_NEXT, REAL_READDIR);
    if (torn_ino && fstat(dirfd(d), &st) == 0 && st.st_dev == torn_dev && st.st_ino == torn_ino
        && torn_calls++ > 0) {
        errno = EIO;
        return NULL;
    }
    return real(d);
}

/* The entry that the walk's next look moves, once that look has found a
 * directory, before the walk opens it: the package removes it, or, with
 * swap_to set, renames it away and puts a link to swap_to in its place.
 * With before_look set, the package removes the entry before that look,
 * after the walk's listing has named it. */
static char moving[64];
static const char *swap_to;
static int before_look;
static int moved;

int fstatat(int fd, const char *restrict path, struct stat *restrict st, int flags)
{
    static int (*real)(int, const char *, struct stat *, int);
    if (!real)
        *(void **)&real = dlsym(RTLD_NEXT, REAL_FSTATAT);
    if (before_look && moving[0] && strcmp(path, moving) == 0) {
        moving[0] = '\0';
        moved = unlinkat(fd, path, 0) == 0;
    }
    int rc = real(fd, path, st, flags);
    if (rc == 0 && moving[0] && strcmp(path, moving) == 0 && S_ISDIR(st->st_mode)) {
        char away[80];
        moving[0] = '\0';
        snprintf(away, sizeof(away), "%.60s.away", path);
        moved = swap_to ? renameat(fd, path, fd, away) == 0 && symlinkat(swap_to, fd, path) == 0
                        : unlinkat(fd, path, AT_REMOVEDIR) == 0;
    }
    return rc;
}

static manifest_t with(const char *cap)
{
    manifest_t m;
    memset(&m, 0, sizeof(m));
    if (cap) {
        snprintf(m.caps[0], sizeof(m.caps[0]), "%s", cap);
        m.ncaps = 1;
    }
    return m;
}

static void fill(const char *path, size_t bytes)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    for (size_t i = 0; i < bytes; i++)
        fputc('x', f);
    fclose(f);
}

int main(void)
{
    char root[128], p[256], why[300];
    manifest_t m;

    /* ---- what a package may hold ---- */
    m = with(NULL);
    CHECK(quota_of(&m) == (long long)QUOTA_DEFAULT_MIB << 20,
          "a package that asks for no storage gets the default: %lld", quota_of(&m) >> 20);
    m = with("storage:4");
    CHECK(quota_of(&m) == 4LL << 20, "storage:4 is 4 MiB: %lld", quota_of(&m) >> 20);
    m = with("storage:256");
    CHECK(quota_of(&m) == 256LL << 20, "storage:256 is 256 MiB: %lld", quota_of(&m) >> 20);
    m = with("machine.read");
    CHECK(quota_of(&m) == (long long)QUOTA_DEFAULT_MIB << 20,
          "another capability is not a quota: %lld", quota_of(&m) >> 20);
    /* A capability whose name merely begins the same way is not storage. */
    m = with("storaged:4");
    CHECK(quota_of(&m) == (long long)QUOTA_DEFAULT_MIB << 20, "storaged:4 is not storage:4");

    /* ---- what it holds ---- */
    snprintf(root, sizeof(root), "/tmp/ffx-quota-test.%d", (int)getpid());
    why[0] = '\0';
    CHECK(quota_dir_bytes(root, PLENTY, why, sizeof(why)) == -1 && strstr(why, "cannot read"),
          "a directory that is not there reads as -1, with the reason: %s", why);
    mkdir(root, 0700);
    long long empty = quota_dir_bytes(root, PLENTY, why, sizeof(why));
    CHECK(empty == 0, "an empty directory holds nothing: %lld", empty);

    snprintf(p, sizeof(p), "%s/a", root);
    fill(p, 40 * 1024);
    long long one = quota_dir_bytes(root, PLENTY, why, sizeof(why));
    CHECK(one >= 40 * 1024 && one < 200 * 1024, "40 KiB of file reads as %lld bytes", one);

    snprintf(p, sizeof(p), "%s/sub", root);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/sub/b", root);
    fill(p, 40 * 1024);
    long long two = quota_dir_bytes(root, PLENTY, why, sizeof(why));
    CHECK(two >= one + 40 * 1024, "a file in a subdirectory is counted too: %lld then %lld", one, two);

    /* A link out of the tree is a link, not what it points at. */
    snprintf(p, sizeof(p), "%s/link", root);
    if (symlink("/usr", p) == 0) {
        long long three = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(three < two + 64 * 1024, "a symbolic link to /usr was followed: %lld then %lld", two, three);
    } else {
        printf("(no symbolic link made: that case is not checked)\n");
    }

    /* A sparse file claims much and holds little. */
    snprintf(p, sizeof(p), "%s/sparse", root);
    {
        FILE *f = fopen(p, "w");
        if (f) {
            if (fseek(f, 64 * 1024 * 1024, SEEK_SET) == 0)
                fputc('x', f);
            fclose(f);
            long long four = quota_dir_bytes(root, PLENTY, why, sizeof(why));
            CHECK(four < 8 * 1024 * 1024,
                  "a 64 MiB sparse file was counted by what it claims: %lld bytes", four);
        }
    }

    /* ---- what cannot be measured ---- */
    /* A tree deeper than the host measures is not measured, and what is
     * not measured is not nothing: -1, in words that say so. */
    long long before = quota_dir_bytes(root, PLENTY, why, sizeof(why));
    {
        char chain[256];
        snprintf(chain, sizeof(chain), "%s/deep", root);
        mkdir(chain, 0700);
        for (int i = 0; i < QUOTA_MAX_DEPTH + 1; i++) {
            size_t k = strlen(chain);
            snprintf(chain + k, sizeof(chain) - k, "/d");
            mkdir(chain, 0700);
        }
        why[0] = '\0';
        long long deep = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(deep == -1 && strstr(why, "deeper"),
              "a chain of %d directories reads as %lld, not -1 in words that say it is too deep: %s",
              QUOTA_MAX_DEPTH + 2, deep, why);
        char cmd[300];
        snprintf(cmd, sizeof(cmd), "rm -rf %s/deep", root);
        if (system(cmd)) { }
        long long again = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(again == before, "the chain removed, the tree measures as before: %lld then %lld", before, again);
    }
    /* A directory the host cannot read is a measurement that did not
     * complete, never a directory that holds nothing. Root reads every
     * directory, so the case needs an unprivileged run. */
    if (geteuid() != 0) {
        snprintf(p, sizeof(p), "%s/shut", root);
        mkdir(p, 0700);
        snprintf(p, sizeof(p), "%s/shut/c", root);
        fill(p, 40 * 1024);
        snprintf(p, sizeof(p), "%s/shut", root);
        chmod(p, 0);
        why[0] = '\0';
        long long shut = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(shut == -1 && strstr(why, "cannot read"),
              "an unreadable subdirectory reads as %lld, not -1 in words that say it cannot be read: %s", shut, why);
        chmod(p, 0700);
        long long readable = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(readable >= before + 40 * 1024, "readable again, its file is counted: %lld then %lld", before, readable);
    } else {
        printf("(root: the unreadable directory is not checked)\n");
    }
    /* A listing that fails part way is a directory that cannot be read:
     * -1, never the part of it that came before the fault. */
    {
        struct stat st;
        long long whole = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        if (stat(root, &st) == 0) {
            torn_dev = st.st_dev;
            torn_ino = st.st_ino;
            torn_calls = 0;
        }
        why[0] = '\0';
        long long torn = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        torn_ino = 0;
        CHECK(torn_calls > 1 && torn == -1 && strstr(why, "cannot read"),
              "a listing that fails part way reads as %lld after %lld, not -1 in words that say it cannot be read: %s",
              torn, whole, why);
    }
    /* A directory the package removes between the walk's look at it and
     * its open holds nothing now: the measurement completes without it.
     * The directory is the only entry of a directory of its own, so the
     * open's ENOENT is the last errno that listing sees: the walk that
     * takes it for a failed listing reads -1 here, whatever order the
     * filesystem lists the tree in. */
    char tmp[160];
    snprintf(tmp, sizeof(tmp), "%s/tmp", root);
    {
        mkdir(tmp, 0700);
        long long base = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        snprintf(p, sizeof(p), "%s/vanish", tmp);
        mkdir(p, 0700);
        snprintf(moving, sizeof(moving), "vanish");
        swap_to = NULL;
        moved = 0;
        why[0] = '\0';
        long long gone = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        moving[0] = '\0';
        CHECK(moved && gone >= base && !why[0],
              "a directory removed between its look and its open reads as %lld after %lld (removed: %d): %s", gone,
              base, moved, why);
        rmdir(p);
        rmdir(tmp);
    }
    /* A file the package removes between the walk's listing of it and its
     * look holds nothing now either, the only entry of its directory in
     * the same way. */
    {
        mkdir(tmp, 0700);
        long long base = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        snprintf(p, sizeof(p), "%s/lone", tmp);
        fill(p, 4096);
        snprintf(moving, sizeof(moving), "lone");
        before_look = 1;
        moved = 0;
        why[0] = '\0';
        long long gone = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        moving[0] = '\0';
        before_look = 0;
        CHECK(moved && gone >= base && !why[0],
              "a file removed between its listing and its look reads as %lld after %lld (removed: %d): %s", gone, base,
              moved, why);
        unlink(p);
        rmdir(tmp);
    }
    /* A directory the package swaps for a link between the walk's look at
     * it and its open is not followed: the open refuses the link, and the
     * measurement did not complete. The link points at a directory of the
     * test's own, outside the tree, with 40 KiB in it. */
    char elsewhere[160];
    snprintf(elsewhere, sizeof(elsewhere), "%s-elsewhere", root);
    {
        mkdir(elsewhere, 0700);
        snprintf(p, sizeof(p), "%s/out", elsewhere);
        fill(p, 40 * 1024);
        snprintf(p, sizeof(p), "%s/swap", root);
        mkdir(p, 0700);
        snprintf(moving, sizeof(moving), "swap");
        swap_to = elsewhere;
        moved = 0;
        why[0] = '\0';
        long long swapped = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        moving[0] = '\0';
        CHECK(moved && swapped == -1 && strstr(why, "changed while it was measured"),
              "a directory swapped for a link between its look and its open reads as %lld (swapped: %d), not -1 in "
              "words that say it changed: %s", swapped, moved, why);
        unlink(p);
        snprintf(p, sizeof(p), "%s/swap.away", root);
        rmdir(p);
    }
    /* A data directory that is itself a link is not measured: the walk
     * does not follow it to the tree behind it. */
    {
        char link[160];
        snprintf(link, sizeof(link), "%s-link", root);
        if (symlink(root, link) == 0) {
            why[0] = '\0';
            long long linked = quota_dir_bytes(link, PLENTY, why, sizeof(why));
            CHECK(linked == -1 && strstr(why, "cannot read"),
                  "a data directory that is a link reads as %lld, not -1 in words that say it cannot be read: %s",
                  linked, why);
            unlink(link);
        } else {
            CHECK(0, "no link to the tree was made");
        }
    }

    /* A path longer than the walk could hold is no reason not to measure
     * it: 16 directories of 255-byte names, made relative to a descriptor
     * since their path is past PATH_MAX, with 40 KiB at the bottom. The
     * chain's own directories take blocks too, so the file is judged
     * against the tree measured with the chain and without the file: only
     * the file at the bottom can make up the 40 KiB. */
    {
        long long prior = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        char name[256];
        memset(name, 'x', sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
        int dfd = open(root, O_RDONLY | O_DIRECTORY), made = 0;
        for (int i = 0; dfd >= 0 && i < QUOTA_MAX_DEPTH; i++) {
            int next = mkdirat(dfd, name, 0700) == 0 ? openat(dfd, name, O_RDONLY | O_DIRECTORY) : -1;
            close(dfd);
            dfd = next;
            made += next >= 0;
        }
        long long chain = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        int ffd = dfd >= 0 ? openat(dfd, "f", O_WRONLY | O_CREAT, 0600) : -1;
        long long wrote = 0;
        if (ffd >= 0) {
            char block[4096];
            memset(block, 'x', sizeof(block));
            for (int i = 0; i < 10; i++) {
                if (write(ffd, block, sizeof(block)) != (ssize_t)sizeof(block))
                    break;
                wrote += (long long)sizeof(block);
            }
            close(ffd);
        }
        if (dfd >= 0)
            close(dfd);
        why[0] = '\0';
        long long far = quota_dir_bytes(root, PLENTY, why, sizeof(why));
        CHECK(made == QUOTA_MAX_DEPTH && ffd >= 0 && wrote == 40 * 1024,
              "the long chain was made: %d directories, %lld bytes written at the bottom", made, wrote);
        CHECK(chain >= prior && far >= chain + 40 * 1024,
              "40 KiB under 16 directories of 255-byte names reads as %lld after %lld (%lld before the chain): %s", far,
              chain, prior, why);
    }

    /* The entries are counted against the bound: a directory of as many
     * empty files as the bound measures, and one file more is a
     * measurement that did not complete, in words that say so. The files
     * are empty, so by their blocks they cost nothing. */
    char many[160];
    snprintf(many, sizeof(many), "%s-many", root);
    {
        const long long bound = ((long long)QUOTA_DEFAULT_MIB << 20) / QUOTA_ENTRY_BYTES;  /* the default quota's: 4096 */
        int made = 0;
        mkdir(many, 0700);
        int dfd = open(many, O_RDONLY | O_DIRECTORY);
        for (long long i = 0; dfd >= 0 && i < bound; i++) {
            char name[32];
            snprintf(name, sizeof(name), "f%lld", i);
            int fd = openat(dfd, name, O_WRONLY | O_CREAT, 0600);
            made += fd >= 0;
            if (fd >= 0)
                close(fd);
        }
        why[0] = '\0';
        long long full = quota_dir_bytes(many, bound, why, sizeof(why));
        CHECK(made == bound && full >= 0 && !why[0], "%lld empty files under a bound of %lld read as %lld (made %d): %s",
              bound, bound, full, made, why);
        int fd = dfd >= 0 ? openat(dfd, "one-more", O_WRONLY | O_CREAT, 0600) : -1;
        if (fd >= 0)
            close(fd);
        if (dfd >= 0)
            close(dfd);
        why[0] = '\0';
        long long over = quota_dir_bytes(many, bound, why, sizeof(why));
        CHECK(fd >= 0 && over == -1 && strstr(why, "more than"),
              "%lld empty files under a bound of %lld read as %lld, not -1 in words that say there are too many: %s",
              bound + 1, bound, over, why);
    }

    /* A file the package unlinked while it holds it open has no name for
     * the walk to find and holds its blocks all the same: it is counted by
     * the descriptors of the package's processes, this process here. One
     * held open twice is counted once; one held open with its name is the
     * walk's, not this count's; one unlinked outside the tree is not
     * counted; and one closed no longer is. */
    {
        pid_t self = getpid();
        char block[4096];
        long long wrote = 0;
        memset(block, 'x', sizeof(block));
        snprintf(p, sizeof(p), "%s/gone", root);
        int gone = open(p, O_WRONLY | O_CREAT, 0600);
        int unlinked = gone >= 0 && unlink(p) == 0;
        for (int i = 0; gone >= 0 && i < 1024; i++)
            wrote += write(gone, block, sizeof(block)) == (ssize_t)sizeof(block) ? (long long)sizeof(block) : 0;
        snprintf(p, sizeof(p), "%s/twice", root);
        int twice = open(p, O_WRONLY | O_CREAT, 0600), again = open(p, O_RDONLY);
        unlinked = unlinked && unlink(p) == 0;
        for (int i = 0; twice >= 0 && i < 16; i++)
            if (write(twice, block, sizeof(block)) != (ssize_t)sizeof(block))
                break;
        snprintf(p, sizeof(p), "%s/named-and-still-there", root);
        int named = open(p, O_WRONLY | O_CREAT, 0600);
        for (int i = 0; named >= 0 && i < 64; i++)
            if (write(named, block, sizeof(block)) != (ssize_t)sizeof(block))
                break;
        snprintf(p, sizeof(p), "%s/gone", elsewhere);
        int outside = open(p, O_WRONLY | O_CREAT, 0600);
        unlinked = unlinked && outside >= 0 && unlink(p) == 0;
        for (int i = 0; outside >= 0 && i < 64; i++)
            if (write(outside, block, sizeof(block)) != (ssize_t)sizeof(block))
                break;
        why[0] = '\0';
        long long held = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(unlinked && wrote == 4LL << 20 && again >= 0 && named >= 0,
              "the open files were made: unlinked %d, %lld bytes written, open twice %d, named %d", unlinked, wrote,
              again >= 0, named >= 0);
        CHECK(held >= (4LL << 20) + 64 * 1024 && held < (4LL << 20) + 128 * 1024,
              "4 MiB unlinked and held open, and 64 KiB held open twice, read as %lld (named and outside files not "
              "counted would be 4 MiB plus 64 KiB): %s", held, why);
        close(gone);
        close(twice);
        close(again);
        close(named);
        close(outside);
        why[0] = '\0';
        long long closed = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(closed == 0, "closed, nothing is held: %lld: %s", closed, why);
        pid_t none = 2000000000;
        long long absent = quota_open_bytes(root, &none, 1, why, sizeof(why));
        CHECK(absent == 0, "a process that is gone holds nothing: %lld: %s", absent, why);
    }

    /* A file the package unlinked and keeps mapped, its descriptor
     * closed, holds its blocks by the mapping alone, and no descriptor
     * names it: it is counted by the mappings of the package's processes.
     * The kernel lets root alone follow a mapping to its file, which is
     * how the host runs; unprivileged, the look is refused, and a look
     * refused is a measurement that did not complete, never nothing. */
    {
        pid_t self = getpid();
        char block[4096];
        long long wrote = 0;
        int root_user = geteuid() == 0;
        memset(block, 'x', sizeof(block));
        snprintf(p, sizeof(p), "%s/mapped", root);
        int fd = open(p, O_RDWR | O_CREAT, 0600);
        for (int i = 0; fd >= 0 && i < 1024; i++)
            wrote += write(fd, block, sizeof(block)) == (ssize_t)sizeof(block) ? (long long)sizeof(block) : 0;
        void *map = fd >= 0 ? mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) : MAP_FAILED;
        int made = map != MAP_FAILED && unlink(p) == 0;
        CHECK(made && wrote == 4LL << 20, "the mapped file was made: %d, %lld bytes written", made, wrote);
        why[0] = '\0';
        long long both = quota_open_bytes(root, &self, 1, why, sizeof(why));
        if (fd >= 0)
            close(fd);
        why[0] = '\0';
        long long held = quota_open_bytes(root, &self, 1, why, sizeof(why));
        if (root_user) {
            CHECK(both >= (4LL << 20) && both < (4LL << 20) + 64 * 1024,
                  "4 MiB unlinked, held open and mapped both, read once as %lld: %s", both, why);
            CHECK(held >= (4LL << 20) && held < (4LL << 20) + 64 * 1024,
                  "4 MiB unlinked, its descriptor closed and one page of it mapped, read as %lld: %s", held, why);
        } else {
            CHECK(held == -1 && strstr(why, "mapped file"),
                  "unprivileged, the look at the mapped file is refused, and that is a measurement that did not "
                  "complete: %lld: %s", held, why);
        }
        if (map != MAP_FAILED)
            munmap(map, 4096);
        why[0] = '\0';
        long long unmapped = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(unmapped == 0, "unmapped, nothing is held: %lld: %s", unmapped, why);
    }

    /* The mappings of unlinked files are bounded as the descriptors are
     * by construction: as many as the bound, each of a distinct unlinked
     * one-page file, are measured, and one more is a measurement that
     * did not complete, in words that say there are too many. Root alone
     * can follow a mapping to its file; unprivileged, the first look is
     * refused, which is the case above. */
    if (geteuid() == 0) {
        pid_t self = getpid();
        void **maps = calloc(QUOTA_OPEN_MAX + 1, sizeof(*maps));
        int made = 0;
        for (int i = 0; maps && i <= QUOTA_OPEN_MAX; i++) {
            snprintf(p, sizeof(p), "%s/m%d", root, i);
            int fd = open(p, O_RDWR | O_CREAT, 0600);
            if (fd < 0)
                break;
            maps[i] = write(fd, "x", 1) == 1 ? mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) : MAP_FAILED;
            close(fd);
            unlink(p);
            if (maps[i] == MAP_FAILED)
                break;
            made++;
        }
        why[0] = '\0';
        long long over = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(made == QUOTA_OPEN_MAX + 1 && over == -1 && strstr(why, "more than"),
              "%d one-page files unlinked and mapped (made %d) read as %lld, not -1 in words that say there are too "
              "many: %s", QUOTA_OPEN_MAX + 1, made, over, why);
        if (made == QUOTA_OPEN_MAX + 1)
            munmap(maps[made - 1], 4096);
        why[0] = '\0';
        long long at_bound = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(at_bound >= (long long)QUOTA_OPEN_MAX * 512 && !why[0],
              "%d one-page files unlinked and mapped read as %lld: %s", QUOTA_OPEN_MAX, at_bound, why);
        for (int i = 0; i < made - 1; i++)
            munmap(maps[i], 4096);
        free(maps);
        why[0] = '\0';
        long long none = quota_open_bytes(root, &self, 1, why, sizeof(why));
        CHECK(none == 0, "all unmapped, nothing is held: %lld: %s", none, why);
    } else {
        printf("(unprivileged: the bound on the mappings is not checked)\n");
    }

    {
        char cmd[600];
        snprintf(cmd, sizeof(cmd), "rm -rf %s %s %s", root, elsewhere, many);
        if (system(cmd)) { }
    }
    printf("%s: quota_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
