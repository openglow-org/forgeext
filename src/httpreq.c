/*
 * httpreq.c - one HTTP/1.x request off a package's API socket, or a refusal
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See httpreq.h for the form it takes.
 */
#include "httpreq.h"

#include <string.h>
#include <strings.h>

static int refuse(int code, const char *words, const char **why)
{
    if (why)
        *why = words;
    return -code;
}

/* The end of the head: the offset just past the first CRLF CRLF, or 0. */
static size_t head_end(const char *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    return 0;
}

static int path_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '.' ||
           c == '-' || c == '_';
}

int httpreq_parse(const char *buf, size_t len, httpreq_t *out, const char **why)
{
    memset(out, 0, sizeof(*out));
    if (memchr(buf, '\0', len))
        return refuse(400, "a NUL byte in the request", why);
    size_t head = head_end(buf, len);
    if (!head) {
        if (len >= HTTPREQ_HEAD_MAX)
            return refuse(431, "the request head is too long", why);
        return 0;
    }
    if (head > HTTPREQ_HEAD_MAX)
        return refuse(431, "the request head is too long", why);

    /* The request line. */
    const char *eol = memchr(buf, '\r', head);
    size_t n = (size_t)(eol - buf);
    if (eol[1] != '\n' || memchr(buf, '\n', n))
        return refuse(400, "the request line does not end in CRLF", why);
    const char *sp1 = memchr(buf, ' ', n);
    if (!sp1)
        return refuse(400, "the request line is not METHOD SP path SP version", why);
    const char *sp2 = memchr(sp1 + 1, ' ', n - (size_t)(sp1 + 1 - buf));
    if (!sp2 || memchr(sp2 + 1, ' ', n - (size_t)(sp2 + 1 - buf)))
        return refuse(400, "the request line is not METHOD SP path SP version", why);
    size_t mlen = (size_t)(sp1 - buf), plen = (size_t)(sp2 - sp1 - 1), vlen = n - (size_t)(sp2 + 1 - buf);
    if (mlen == 3 && memcmp(buf, "GET", 3) == 0)
        out->method = HTTPREQ_GET;
    else if (mlen == 4 && memcmp(buf, "POST", 4) == 0)
        out->method = HTTPREQ_POST;
    else
        return refuse(405, "the method is GET or POST", why);
    if (vlen != 8 || (memcmp(sp2 + 1, "HTTP/1.1", 8) != 0 && memcmp(sp2 + 1, "HTTP/1.0", 8) != 0))
        return refuse(505, "the version is HTTP/1.0 or HTTP/1.1", why);
    if (plen == 0 || plen >= HTTPREQ_PATH_MAX || sp1[1] != '/')
        return refuse(400, "the path is an origin-form path of at most 255 bytes", why);
    for (size_t i = 0; i < plen; i++)
        if (!path_char((unsigned char)sp1[1 + i]))
            return refuse(400, "the path holds a character the API's paths do not", why);
    for (size_t i = 0; i + 1 < plen; i++)
        if (sp1[1 + i] == '.' && sp1[2 + i] == '.')
            return refuse(400, "the path holds ..", why);
    memcpy(out->path, sp1 + 1, plen);
    out->path[plen] = '\0';

    /* The header lines. */
    long clen = -1;
    const char *p = eol + 2, *end = buf + head - 2;      /* the empty line starts at end */
    while (p < end) {
        const char *le = memchr(p, '\r', (size_t)(end - p));
        if (!le || le[1] != '\n')
            return refuse(400, "a header line does not end in CRLF", why);
        if (memchr(p, '\n', (size_t)(le - p)))
            return refuse(400, "a bare LF in the request head", why);
        if (*p == ' ' || *p == '\t')
            return refuse(400, "a continuation line", why);
        const char *colon = memchr(p, ':', (size_t)(le - p));
        if (!colon || colon == p)
            return refuse(400, "a header line is not name: value", why);
        size_t nlen = (size_t)(colon - p);
        const char *v = colon + 1;
        while (v < le && (*v == ' ' || *v == '\t'))
            v++;
        const char *ve = le;
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
            ve--;
        size_t vl = (size_t)(ve - v);
        if (nlen == 14 && strncasecmp(p, "Content-Length", 14) == 0) {
            if (clen >= 0)
                return refuse(400, "a second Content-Length", why);
            if (vl == 0 || vl > 6)
                return refuse(400, "Content-Length is not a short decimal number", why);
            clen = 0;
            for (size_t i = 0; i < vl; i++) {
                if (v[i] < '0' || v[i] > '9')
                    return refuse(400, "Content-Length is not a short decimal number", why);
                clen = clen * 10 + (v[i] - '0');
            }
        } else if (nlen == 17 && strncasecmp(p, "Transfer-Encoding", 17) == 0) {
            return refuse(501, "no transfer coding is taken: send Content-Length", why);
        } else if (nlen == 12 && strncasecmp(p, "Content-Type", 12) == 0) {
            out->json_body = vl >= 16 && strncasecmp(v, "application/json", 16) == 0 &&
                             (vl == 16 || v[16] == ';' || v[16] == ' ');
        }
        p = le + 2;
    }

    /* The body. */
    if (out->method == HTTPREQ_GET) {
        if (clen > 0 || len > head)
            return refuse(400, "a GET carries no body", why);
        return 1;
    }
    if (clen < 0)
        return refuse(411, "a POST carries Content-Length", why);
    if (clen > HTTPREQ_BODY_MAX)
        return refuse(413, "the body is too long", why);
    if (len - head < (size_t)clen)
        return 0;
    if (len - head > (size_t)clen)
        return refuse(400, "bytes after the body", why);
    out->body = buf + head;
    out->body_len = (size_t)clen;
    return 1;
}
