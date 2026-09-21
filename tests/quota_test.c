/*
 * quota_test.c - host test: what a package may hold, and what it holds
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * quota_of() over a manifest's capabilities, and quota_dir_bytes() over a
 * real tree: nested directories counted, a symbolic link out of the tree
 * counted as a link and never followed, and a sparse file counted by what
 * the filesystem gave it rather than by how large it claims to be.
 */
#include "../src/quota.h"

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
    char root[128], p[256];
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
    CHECK(quota_dir_bytes(root) == -1, "a directory that is not there reads as -1");
    mkdir(root, 0700);
    long long empty = quota_dir_bytes(root);
    CHECK(empty == 0, "an empty directory holds nothing: %lld", empty);

    snprintf(p, sizeof(p), "%s/a", root);
    fill(p, 40 * 1024);
    long long one = quota_dir_bytes(root);
    CHECK(one >= 40 * 1024 && one < 200 * 1024, "40 KiB of file reads as %lld bytes", one);

    snprintf(p, sizeof(p), "%s/sub", root);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/sub/b", root);
    fill(p, 40 * 1024);
    long long two = quota_dir_bytes(root);
    CHECK(two >= one + 40 * 1024, "a file in a subdirectory is counted too: %lld then %lld", one, two);

    /* A link out of the tree is a link, not what it points at. */
    snprintf(p, sizeof(p), "%s/link", root);
    if (symlink("/usr", p) == 0) {
        long long three = quota_dir_bytes(root);
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
            long long four = quota_dir_bytes(root);
            CHECK(four < 8 * 1024 * 1024,
                  "a 64 MiB sparse file was counted by what it claims: %lld bytes", four);
        }
    }

    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
        if (system(cmd)) { }
    }
    printf("%s: quota_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
