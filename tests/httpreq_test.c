/*
 * httpreq_test.c - host test: the request reader of a package's API socket
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * What the closed form takes, what it asks more bytes for, and what it
 * refuses, each with its status. Every good request is also fed a byte at
 * a time: nothing short of the whole request may read as one.
 */
#include "../src/httpreq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static int parse(const char *text, httpreq_t *r)
{
    const char *why = NULL;
    return httpreq_parse(text, strlen(text), r, &why);
}

static void refused(const char *text, int code, const char *name)
{
    httpreq_t r;
    const char *why = NULL;
    int rc = httpreq_parse(text, strlen(text), &r, &why);
    CHECK(rc == -code && why && why[0], "%s: got %d, expected %d (%s)", name, rc, -code, why ? why : "no words");
}

/* Fed a byte at a time, a good request reads 0 until its last byte. */
static void byte_by_byte(const char *text)
{
    httpreq_t r;
    const char *why;
    size_t n = strlen(text);
    for (size_t i = 1; i < n; i++) {
        int rc = httpreq_parse(text, i, &r, &why);
        if (rc != 0) {
            CHECK(0, "%zu of %zu bytes read as %d: %.30s", i, n, rc, text);
            return;
        }
    }
    CHECK(httpreq_parse(text, n, &r, &why) == 1, "the whole request did not read: %.30s", text);
}

int main(void)
{
    httpreq_t r;

    const char *get = "GET /v0/self HTTP/1.1\r\nHost: forgeext\r\nAccept: */*\r\n\r\n";
    CHECK(parse(get, &r) == 1 && r.method == HTTPREQ_GET && !strcmp(r.path, "/v0/self") && r.body_len == 0, "a plain GET");
    byte_by_byte(get);
    CHECK(parse("GET / HTTP/1.0\r\n\r\n", &r) == 1 && !strcmp(r.path, "/"), "HTTP/1.0 with no header at all");

    const char *post = "POST /v0/hold HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\ncontent-length: 17\r\n\r\n"
                       "{\"raised\": false}";
    CHECK(parse(post, &r) == 1 && r.method == HTTPREQ_POST && r.body_len == 17 && r.json_body &&
          !memcmp(r.body, "{\"raised\": false}", 17), "a POST with a JSON body, header names in any case");
    byte_by_byte(post);
    CHECK(parse("POST /v0/hold HTTP/1.1\r\nContent-Length: 0\r\n\r\n", &r) == 1 && r.body_len == 0 && !r.json_body,
          "a POST with an empty body");
    CHECK(parse("POST /v0/hold HTTP/1.1\r\nContent-Type: application/jsonx\r\nContent-Length: 0\r\n\r\n", &r) == 1 && !r.json_body,
          "application/jsonx is not application/json");

    /* The request line. */
    refused("PUT /v0/hold HTTP/1.1\r\n\r\n", 405, "another method");
    refused("get /v0/self HTTP/1.1\r\n\r\n", 405, "a method in lower case");
    refused("GET /v0/self HTTP/2.0\r\n\r\n", 505, "another version");
    refused("GET /v0/self\r\n\r\n", 400, "no version");
    refused("GET  /v0/self HTTP/1.1\r\n\r\n", 400, "two spaces");
    refused("GET /v0/self HTTP/1.1 \r\n\r\n", 400, "a trailing space");
    refused("GET v0/self HTTP/1.1\r\n\r\n", 400, "a path that does not start at the root");
    refused("GET http://127.0.0.1/status HTTP/1.1\r\n\r\n", 400, "an absolute-form target");
    refused("GET /v0/../../status HTTP/1.1\r\n\r\n", 400, "a path with ..");
    refused("GET /v0/self?x=1 HTTP/1.1\r\n\r\n", 400, "a query");
    refused("GET /v0/se%6cf HTTP/1.1\r\n\r\n", 400, "a percent escape");
    refused("GET /v0/self HTTP/1.1\nHost: x\r\n\r\n", 400, "a bare LF ending the request line");
    refused("GET /v0/self HTTP/1.1\rX\r\n\r\n", 400, "a bare CR in the request line");
    {
        char longpath[400] = "GET /";
        memset(longpath + 5, 'a', 300);
        strcpy(longpath + 305, " HTTP/1.1\r\n\r\n");
        refused(longpath, 400, "a path of 300 bytes");
    }

    /* The headers. */
    refused("GET /v0/self HTTP/1.1\r\nHost x\r\n\r\n", 400, "a header line with no colon");
    refused("GET /v0/self HTTP/1.1\r\n: x\r\n\r\n", 400, "a header line with no name");
    refused("GET /v0/self HTTP/1.1\r\nA: b\r\n c\r\n\r\n", 400, "a continuation line");
    refused("GET /v0/self HTTP/1.1\r\nA: b\nB: c\r\n\r\n", 400, "a bare LF between header lines");
    refused("POST /v0/hold HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501, "a chunked body");
    refused("POST /v0/hold HTTP/1.1\r\n\r\n", 411, "a POST with no Content-Length");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 400, "two Content-Length lines");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400, "a negative Content-Length");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n", 400, "a hexadecimal Content-Length");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", 400, "a Content-Length of eight digits");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: 5000\r\n\r\n", 413, "a body over the bound");
    refused("POST /v0/hold HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}GET / HTTP/1.1\r\n\r\n", 400, "a second request behind the body");
    refused("GET /v0/self HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", 400, "a GET with a body");
    refused("GET /v0/self HTTP/1.1\r\n\r\nX", 400, "bytes after a GET");

    /* NUL, and a head that never ends. */
    {
        const char nul[] = "GET /v0/self HTTP/1.1\r\nA: b\0c\r\n\r\n";
        const char *why = NULL;
        CHECK(httpreq_parse(nul, sizeof(nul) - 1, &r, &why) == -400, "a NUL byte in a header value");
        static char big[HTTPREQ_HEAD_MAX + 64];
        int n = snprintf(big, sizeof(big), "GET /v0/self HTTP/1.1\r\nA: ");
        memset(big + n, 'x', sizeof(big) - (size_t)n);
        CHECK(httpreq_parse(big, HTTPREQ_HEAD_MAX - 1, &r, &why) == 0, "a long head, not yet at the bound, is refused early");
        CHECK(httpreq_parse(big, HTTPREQ_HEAD_MAX, &r, &why) == -431, "a head at the bound with no end");
        memcpy(big + sizeof(big) - 4, "\r\n\r\n", 4);
        CHECK(httpreq_parse(big, sizeof(big), &r, &why) == -431, "a head that ends past the bound");
    }

    printf("%s: httpreq_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
