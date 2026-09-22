/*
 * version_test.c - the firmware's own version, as the image writes it
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The host judges a package's "core" range against the version it reads
 * from /etc/forgefirm-version. The image build writes that file as
 * "v<version>" on a release image and as a build stamp on a dev image,
 * and a campaign only ever runs on a dev image, because the release
 * image does not ship the acceptance suite. So no acceptance test can
 * reach the judging path, and this is where the release form is proven:
 * the file as the release build writes it yields a version a range can
 * be judged against, and the dev build's stamp yields none.
 *
 * Cases: the reader over a file, every shape the build writes and the
 * ways a file can say nothing; and what the range does with each.
 */
#include "../src/install.h"
#include "../src/manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static char path[256];

/* The version the reader takes out of a version file holding `text`. */
static const char *read_back(const char *text)
{
    static char out[64];
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("FAIL: cannot write %s\n", path);
        fails++;
        return "";
    }
    fputs(text, f);
    fclose(f);
    ext_read_core_version_from(path, out, sizeof(out));
    return out;
}

int main(void)
{
    snprintf(path, sizeof(path), "/tmp/forgeext-version-test.%d", (int)getpid());

    /* What the release build writes: FORGEFIRM_VERSION_STRING is
     * "v${FORGEFIRM_RELEASE}". The "v" is the file's form, and a range
     * judged against "v0.0.6" would be judged against nothing at all. */
    CHECK(strcmp(read_back("v0.0.6\n"), "0.0.6") == 0, "v0.0.6 -> %s", read_back("v0.0.6\n"));
    CHECK(manifest_version_ok(read_back("v0.0.6\n")), "a release image's file is a version to judge by");
    CHECK(manifest_version_cmp(read_back("v0.0.6\n"), "0.0.7") < 0
          && manifest_version_cmp(read_back("v0.0.6\n"), "0.0.5") > 0
          && manifest_version_cmp(read_back("v0.0.6\n"), "0.0.6") == 0,
          "and it orders where 0.0.6 belongs");
    CHECK(strcmp(read_back("v1.2.3-rc1\n"), "1.2.3-rc1") == 0, "a prerelease keeps its tail");
    CHECK(strcmp(read_back("v0.0.6"), "0.0.6") == 0, "no newline at the end");

    /* What the dev build writes: "${DATETIME} (dev)". The first word is
     * a build stamp and no version, so nothing is judged - which is why
     * an acceptance test on a dev image cannot reach the other branch. */
    const char *stamp = read_back("20260922030317 (dev)\n");
    CHECK(strcmp(stamp, "20260922030317") == 0, "a dev stamp -> %s", stamp);
    CHECK(!manifest_version_ok(stamp), "a build stamp is no version and judges nothing");

    /* A file that says nothing, one way or another. */
    CHECK(strcmp(read_back(""), "") == 0, "an empty file");
    CHECK(strcmp(read_back("\n"), "") == 0, "a bare newline");
    CHECK(strcmp(read_back("   \n"), "") == 0, "spaces only");
    CHECK(!manifest_version_ok(read_back("")), "and nothing is no version");

    /* A leading v is dropped only where it is the file's form: before a
     * digit. A word that merely starts with v is left as it was, and is
     * no version either way. */
    CHECK(strcmp(read_back("vendor\n"), "vendor") == 0, "a word beginning with v is not a version file's form");
    CHECK(strcmp(read_back("0.0.6\n"), "0.0.6") == 0, "a bare version is taken as it is");
    CHECK(strcmp(read_back("vv0.0.6\n"), "vv0.0.6") == 0,
          "nothing comes off where no digit follows the v: %s", read_back("vv0.0.6\n"));
    CHECK(!manifest_version_ok(read_back("vv0.0.6\n")), "and it is no version");

    unlink(path);

    /* A file that is not there at all: the reader says nothing rather
     * than leaving whatever was in the buffer. */
    char out[64];
    snprintf(out, sizeof(out), "%s", "0.0.9");
    ext_read_core_version_from(path, out, sizeof(out));
    CHECK(out[0] == '\0', "a missing version file leaves nothing behind: %s", out);

    /* Longer than the buffer it is asked to fill: nothing, never a
     * version cut in half, which would compare as a different one. */
    char small[4];
    (void)read_back("v0.0.6\n");
    ext_read_core_version_from(path, small, sizeof(small));
    CHECK(small[0] == '\0', "a version that does not fit is not truncated into another: %s", small);
    unlink(path);

    printf(fails ? "FAIL: version_test, %d failures\n" : "PASS: version_test\n", fails);
    return fails ? 1 : 0;
}
