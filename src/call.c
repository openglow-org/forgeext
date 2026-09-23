/*
 * call.c - a package's page asking its own service
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See call.h.
 */
#define _GNU_SOURCE
#include "call.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int fail(char *err, size_t elen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t elen, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, elen, fmt, ap);
    va_end(ap);
    return -1;
}

static int sock_path(const char *dir, const char *id, char *path, size_t plen)
{
    int n = snprintf(path, plen, "%s/%s.sock", dir, id);
    return n > 0 && (size_t)n < plen && (size_t)n < sizeof(((struct sockaddr_un *)0)->sun_path) ? 0 : -1;
}

/* The directory is root's and nobody else's: a service cannot put a name in
 * it, so the name the host connects to is the one the host bound. */
static int dir_ok(const char *dir, char *err, size_t elen)
{
    struct stat st;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return fail(err, elen, "cannot make %s: %s", dir, strerror(errno));
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077))
        return fail(err, elen, "%s is not a directory of this host's alone", dir);
    return 0;
}

int call_open(const char *dir, const char *id, char *path, size_t plen, int *fd, char *err, size_t elen)
{
    *fd = -1;
    if (dir_ok(dir, err, elen) != 0)
        return -1;
    if (sock_path(dir, id, path, plen) != 0)
        return fail(err, elen, "the call socket's name is too long");
    unlink(path);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return fail(err, elen, "cannot make the call socket: %s", strerror(errno));
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, path, strlen(path) + 1);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || chmod(path, 0600) != 0 || listen(s, 4) != 0) {
        int e = errno;
        close(s);
        unlink(path);
        return fail(err, elen, "cannot bind the call socket %s: %s", path, strerror(e));
    }
    *fd = s;
    return 0;
}

void call_close(const char *dir, const char *id)
{
    char path[400];
    if (sock_path(dir, id, path, sizeof(path)) == 0)
        unlink(path);
}

int call_path_ok(const char *p)
{
    size_t n = p ? strlen(p) : 0;
    if (n < 1 || n > 200 || p[0] != '/' || strstr(p, ".."))
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '.'
              || c == '-' || c == '_'))
            return 0;
    }
    return 1;
}

static long ms_left(const struct timespec *end)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(end->tv_sec - now.tv_sec) * 1000 + (end->tv_nsec - now.tv_nsec) / 1000000;
}

static int wait_fd(int fd, short ev, const struct timespec *end)
{
    for (;;) {
        long left = ms_left(end);
        if (left <= 0)
            return -1;
        struct pollfd p = { fd, ev, 0 };
        int n = poll(&p, 1, (int)left);
        if (n > 0)
            return 0;
        if (n < 0 && errno != EINTR)
            return -1;
    }
}

int call_service(const char *dir, const char *id, const char *method, const char *path, const char *json,
                 int timeout_ms, int *status, char **body, size_t *blen, char *err, size_t elen)
{
    char sp[400];
    struct stat st;
    *status = 0;
    *body = NULL;
    *blen = 0;
    if (sock_path(dir, id, sp, sizeof(sp)) != 0)
        return fail(err, elen, "the call socket's name is too long");
    if (lstat(sp, &st) != 0)
        return fail(err, elen, "its service is not running");
    if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid())
        return fail(err, elen, "%s is not the host's own call socket", sp);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_ms / 1000;
    end.tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (end.tv_nsec >= 1000000000) {
        end.tv_sec++;
        end.tv_nsec -= 1000000000;
    }

    char head[512];
    size_t jlen = json ? strlen(json) : 0;
    int hn = json ? snprintf(head, sizeof(head), "%s %s HTTP/1.1\r\nHost: forgeext\r\nContent-Type: application/json\r\n"
                             "Content-Length: %zu\r\n\r\n", method, path, jlen)
                  : snprintf(head, sizeof(head), "%s %s HTTP/1.1\r\nHost: forgeext\r\n\r\n", method, path);
    if (hn < 0 || (size_t)hn >= sizeof(head))
        return fail(err, elen, "the call does not fit");

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return fail(err, elen, "cannot make a socket: %s", strerror(errno));
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, sp, strlen(sp) + 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int e = errno;
        close(fd);
        return e == ECONNREFUSED || e == ENOENT ? fail(err, elen, "its service is not running")
                                                : fail(err, elen, "its service did not take the call: %s", strerror(e));
    }
    const char *parts[2] = { head, json };
    size_t lens[2] = { (size_t)hn, jlen };
    for (int k = 0; k < 2; k++)
        for (size_t off = 0; off < lens[k];) {
            if (wait_fd(fd, POLLOUT, &end) != 0) {
                close(fd);
                return fail(err, elen, "its service did not take the call in time");
            }
            ssize_t w = send(fd, parts[k] + off, lens[k] - off, MSG_NOSIGNAL);
            if (w < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            if (w <= 0) {
                close(fd);
                return fail(err, elen, "its service went away mid-call");
            }
            off += (size_t)w;
        }

    char *buf = malloc(CALL_ANSWER_MAX + 1);
    size_t len = 0;
    int done = 0;
    if (!buf) {
        close(fd);
        return fail(err, elen, "out of memory");
    }
    while (!done) {
        if (wait_fd(fd, POLLIN, &end) != 0)
            break;
        ssize_t n = recv(fd, buf + len, CALL_ANSWER_MAX - len, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n <= 0) {
            done = n == 0;
            break;
        }
        len += (size_t)n;
        if (len == CALL_ANSWER_MAX)
            break;
    }
    close(fd);
    buf[len] = '\0';
    if (len == CALL_ANSWER_MAX) {
        free(buf);
        return fail(err, elen, "its service answered more than %d bytes", CALL_ANSWER_MAX);
    }
    if (!done) {
        free(buf);
        return fail(err, elen, "its service did not answer in time");
    }
    char *sep = strstr(buf, "\r\n\r\n");
    if (!sep || sscanf(buf, "HTTP/1.%*1[01] %3d", status) != 1 || *status < 100 || *status > 599) {
        free(buf);
        *status = 0;
        return fail(err, elen, "its service's answer is not HTTP");
    }
    size_t off = (size_t)(sep + 4 - buf);
    *blen = len - off;
    memmove(buf, sep + 4, *blen + 1);
    *body = buf;
    return 0;
}
