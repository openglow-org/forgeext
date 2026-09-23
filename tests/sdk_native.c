/*
 * sdk_native.c - the native package of sdk_test.py: ffx.h against the real host
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Built static by the test and run as a package's service in the sandbox.
 * It asks the host what a native package asks, and writes what it was told
 * into its data directory for the test to read.
 */
#define FFX_IMPLEMENTATION
#include "../sdk/c/ffx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void line(FILE *f, const char *what, const ffx_reply_t *r, int rc)
{
    char body[200];
    size_t n = r->body ? strcspn(r->body, "\n") : 0;
    if (n >= sizeof(body))
        n = sizeof(body) - 1;
    memcpy(body, r->body ? r->body : "", n);
    body[n] = '\0';
    fprintf(f, "%s %d %d %s %s\n", what, rc, r->status, r->ctype, body);
}

int main(void)
{
    char path[512], reason[128];
    const char *data = getenv("FFX_DATA");
    if (!data)
        return 2;
    snprintf(path, sizeof(path), "%s/report.txt.new", data);
    FILE *f = fopen(path, "w");
    if (!f)
        return 3;

    ffx_reply_t r;
    int rc = ffx_request("GET", "/v0/self", NULL, &r, 5000);
    line(f, "self", &r, rc);
    ffx_reply_free(&r);

    /* The escaper, on what a hold's reason may not hold and a setting may. */
    char esc[128];
    ffx_json_string("a \"b\" \\c\n", esc, sizeof(esc));
    fprintf(f, "escape %s\n", esc);
    fprintf(f, "escape_small %d\n", ffx_json_string("too long for this", esc, 8));

    char hold[256];
    ffx_json_string("from ffx.h", reason, sizeof(reason));
    snprintf(hold, sizeof(hold), "{\"raised\":true,\"reason\":%s}", reason);
    rc = ffx_request("POST", "/v0/hold", hold, &r, 5000);
    line(f, "raise", &r, rc);
    ffx_reply_free(&r);

    rc = ffx_request("GET", "/v0/hold", NULL, &r, 5000);
    line(f, "hold", &r, rc);
    ffx_reply_free(&r);

    rc = ffx_request("POST", "/v0/hold", "{\"raised\":false,\"reason\":\"\"}", &r, 5000);
    line(f, "clear", &r, rc);
    ffx_reply_free(&r);

    rc = ffx_request("GET", "/v0/machine/mode", NULL, &r, 5000);
    line(f, "mode", &r, rc);
    ffx_reply_free(&r);

    rc = ffx_request("GET", "/v0/nowhere", NULL, &r, 5000);
    line(f, "nowhere", &r, rc);
    ffx_reply_free(&r);

    fclose(f);
    char done[512];
    snprintf(done, sizeof(done), "%s/report.txt", data);
    rename(path, done);
    for (;;)
        pause();
}
