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
 * measures, a directory it cannot read) read as -1 with the reason, never
 * as nothing. A tree whose path is longer than PATH_MAX is measured like
 * any other: the walk goes by descriptors, not by a path it builds.
 */
#include "../src/quota.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); \
                              fflush(stdout); } } while (0)

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
    CHECK(quota_dir_bytes(root, why, sizeof(why)) == -1 && strstr(why, "cannot read"),
          "a directory that is not there reads as -1, with the reason: %s", why);
    mkdir(root, 0700);
    long long empty = quota_dir_bytes(root, why, sizeof(why));
    CHECK(empty == 0, "an empty directory holds nothing: %lld", empty);

    snprintf(p, sizeof(p), "%s/a", root);
    fill(p, 40 * 1024);
    long long one = quota_dir_bytes(root, why, sizeof(why));
    CHECK(one >= 40 * 1024 && one < 200 * 1024, "40 KiB of file reads as %lld bytes", one);

    snprintf(p, sizeof(p), "%s/sub", root);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/sub/b", root);
    fill(p, 40 * 1024);
    long long two = quota_dir_bytes(root, why, sizeof(why));
    CHECK(two >= one + 40 * 1024, "a file in a subdirectory is counted too: %lld then %lld", one, two);

    /* A link out of the tree is a link, not what it points at. */
    snprintf(p, sizeof(p), "%s/link", root);
    if (symlink("/usr", p) == 0) {
        long long three = quota_dir_bytes(root, why, sizeof(why));
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
            long long four = quota_dir_bytes(root, why, sizeof(why));
            CHECK(four < 8 * 1024 * 1024,
                  "a 64 MiB sparse file was counted by what it claims: %lld bytes", four);
        }
    }

    /* ---- what cannot be measured ---- */
    /* A tree deeper than the host measures is not measured, and what is
     * not measured is not nothing: -1, in words that say so. */
    long long before = quota_dir_bytes(root, why, sizeof(why));
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
        long long deep = quota_dir_bytes(root, why, sizeof(why));
        CHECK(deep == -1 && strstr(why, "deeper"),
              "a chain of %d directories reads as %lld, not -1 in words that say it is too deep: %s",
              QUOTA_MAX_DEPTH + 2, deep, why);
        char cmd[300];
        snprintf(cmd, sizeof(cmd), "rm -rf %s/deep", root);
        if (system(cmd)) { }
        long long again = quota_dir_bytes(root, why, sizeof(why));
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
        long long shut = quota_dir_bytes(root, why, sizeof(why));
        CHECK(shut == -1 && strstr(why, "cannot read"),
              "an unreadable subdirectory reads as %lld, not -1 in words that say it cannot be read: %s", shut, why);
        chmod(p, 0700);
        long long readable = quota_dir_bytes(root, why, sizeof(why));
        CHECK(readable >= before + 40 * 1024, "readable again, its file is counted: %lld then %lld", before, readable);
    } else {
        printf("(root: the unreadable directory is not checked)\n");
    }

    /* A path longer than the walk could hold is no reason not to measure
     * it: 16 directories of 255-byte names, made relative to a descriptor
     * since their path is past PATH_MAX, with 40 KiB at the bottom. */
    {
        long long prior = quota_dir_bytes(root, why, sizeof(why));
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
        int ffd = dfd >= 0 ? openat(dfd, "f", O_WRONLY | O_CREAT, 0600) : -1;
        if (ffd >= 0) {
            char block[4096];
            memset(block, 'x', sizeof(block));
            for (int i = 0; i < 10; i++)
                if (write(ffd, block, sizeof(block)) != (ssize_t)sizeof(block))
                    break;
            close(ffd);
        }
        if (dfd >= 0)
            close(dfd);
        why[0] = '\0';
        long long far = quota_dir_bytes(root, why, sizeof(why));
        CHECK(made == QUOTA_MAX_DEPTH && ffd >= 0, "the long chain was made: %d directories, file %s", made,
              ffd >= 0 ? "made" : "not made");
        CHECK(far >= prior + 40 * 1024,
              "40 KiB under 16 directories of 255-byte names reads as %lld after %lld: %s", far, prior, why);
    }

    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
        if (system(cmd)) { }
    }
    printf("%s: quota_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
