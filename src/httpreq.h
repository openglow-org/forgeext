/*
 * httpreq.h - one HTTP/1.x request off a package's API socket, or a refusal
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The bytes come from a package. The reader takes a closed form and
 * nothing else: a request line of METHOD, one space, an origin-form path,
 * one space, HTTP/1.0 or HTTP/1.1; header lines of name, colon, value;
 * CRLF line ends (a bare LF is refused); an empty line; and, for POST, a
 * body of exactly Content-Length bytes. No chunked coding, no
 * continuation lines, no NUL, no second Content-Length, nothing after the
 * body. The head is at most HTTPREQ_HEAD_MAX bytes and the body at most
 * HTTPREQ_BODY_MAX; whatever does not fit the form is a status code and a
 * few words, never a guess.
 */
#ifndef FORGEEXT_HTTPREQ_H
#define FORGEEXT_HTTPREQ_H

#include <stddef.h>

#define HTTPREQ_HEAD_MAX    4096
#define HTTPREQ_BODY_MAX    4096
#define HTTPREQ_PATH_MAX    256

typedef enum { HTTPREQ_GET, HTTPREQ_POST } httpreq_method_t;

typedef struct {
    httpreq_method_t method;
    char path[HTTPREQ_PATH_MAX];        /* without the query, which the API does not use: a '?' is refused */
    const char *body;                   /* inside the caller's buffer; not NUL-ended */
    size_t body_len;
    int json_body;                      /* Content-Type: application/json */
} httpreq_t;

/* What the buffer holds so far:
 *    1  a whole request, in *out (the buffer must outlive it)
 *    0  the beginning of one: read more
 *   <0  minus the status code to refuse it with, the words in *why
 * A buffer that is full (len == HTTPREQ_HEAD_MAX + HTTPREQ_BODY_MAX) and
 * still reads 0 is the caller's to refuse. */
int httpreq_parse(const char *buf, size_t len, httpreq_t *out, const char **why);

#endif
