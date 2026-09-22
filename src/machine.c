/*
 * machine.c - the machine's facts, as the supervisor needs them
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "machine.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HTTP_TIMEOUT_MS 2000
#define HTTP_MAX        (64 * 1024)

void machine_cfg_defaults(machine_cfg_t *cfg)
{
    cfg->conf = MACHINE_CONF_DEFAULT;
    cfg->safe_file = MACHINE_SAFE_DEFAULT;
    cfg->host = MACHINE_HOST_DEFAULT;
    cfg->port = MACHINE_PORT_DEFAULT;
}

int machine_conf_value(const char *conf, const char *key, char *out, size_t olen)
{
    FILE *f = fopen(conf, "re");
    char line[512];
    int found = 0;
    size_t klen = strlen(key);
    out[0] = '\0';
    while (f && fgets(line, sizeof(line), f)) {
        char *s = line;
        while (isspace((unsigned char)*s))
            s++;
        if (strncmp(s, key, klen) != 0)
            continue;
        char *eq = s + klen;
        while (isspace((unsigned char)*eq))
            eq++;
        if (*eq != '=')
            continue;
        char *v = eq + 1;
        while (isspace((unsigned char)*v))
            v++;
        size_t n = strlen(v);
        while (n && isspace((unsigned char)v[n - 1]))
            v[--n] = '\0';
        snprintf(out, olen, "%s", v);
        found = 1;                                      /* the last one wins, as a settings reader has it */
    }
    if (f)
        fclose(f);
    return found;
}

static int wait_fd(int fd, short events, long deadline_ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long left = deadline_ms - (ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
    if (left <= 0)
        return -1;
    struct pollfd p = { .fd = fd, .events = events };
    return poll(&p, 1, (int)left) == 1 ? 0 : -1;
}

int machine_get(const machine_cfg_t *cfg, const char *path, char *out, size_t olen)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg->port) };
    struct timespec ts;
    out[0] = '\0';
    if (inet_pton(AF_INET, cfg->host, &a.sin_addr) != 1)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long deadline = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L + HTTP_TIMEOUT_MS;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char *buf = NULL;
    int rc = -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) != 0
            || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0)
            goto done;
    }
    char req[256];
    int rlen = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, cfg->host);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req) || wait_fd(fd, POLLOUT, deadline) != 0
        || send(fd, req, (size_t)rlen, MSG_NOSIGNAL) != rlen)
        goto done;
    buf = malloc(HTTP_MAX + 1);
    if (!buf)
        goto done;
    size_t got = 0;
    while (got < HTTP_MAX && wait_fd(fd, POLLIN, deadline) == 0) {
        ssize_t k = recv(fd, buf + got, HTTP_MAX - got, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            break;
        got += (size_t)k;
    }
    buf[got] = '\0';
    const char *body = strstr(buf, "\r\n\r\n");
    if (strncmp(buf, "HTTP/1.", 7) != 0 || strncmp(buf + 8, " 200", 4) != 0 || !body)
        goto done;
    body += 4;
    if (strlen(body) >= olen)
        goto done;
    memcpy(out, body, strlen(body) + 1);
    rc = 0;
done:
    free(buf);
    close(fd);
    return rc;
}

/* One header's value out of a response head, or "". */
static void head_value(const char *head, const char *name, char *out, size_t olen)
{
    size_t n = strlen(name);
    out[0] = '\0';
    for (const char *p = head; p && *p; p = strchr(p, '\n')) {
        while (*p == '\n' || *p == '\r')
            p++;
        if (strncasecmp(p, name, n) != 0 || p[n] != ':')
            continue;
        const char *v = p + n + 1;
        while (*v == ' ')
            v++;
        size_t k = strcspn(v, "\r\n");
        if (k >= olen)
            k = olen - 1;
        memcpy(out, v, k);
        out[k] = '\0';
        return;
    }
}

int machine_get_blob(const machine_cfg_t *cfg, const char *path, unsigned char **out, size_t *len,
                     char *ctype, size_t clen)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg->port) };
    struct timespec ts;
    unsigned char *buf = NULL;
    size_t got = 0, cap = 64 * 1024;
    int rc = -1, status = 0;

    *out = NULL;
    *len = 0;
    if (ctype && clen)
        ctype[0] = '\0';
    if (inet_pton(AF_INET, cfg->host, &a.sin_addr) != 1)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long deadline = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L + MACHINE_BLOB_TIMEOUT_MS;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) != 0
            || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0)
            goto done;
    }
    char req[300];
    int rlen = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                        path, cfg->host);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req) || wait_fd(fd, POLLOUT, deadline) != 0
        || send(fd, req, (size_t)rlen, MSG_NOSIGNAL) != rlen)
        goto done;
    buf = malloc(cap);
    if (!buf)
        goto done;
    while (got < MACHINE_BLOB_MAX && wait_fd(fd, POLLIN, deadline) == 0) {
        if (got + 16384 > cap) {
            size_t want = cap * 2 > MACHINE_BLOB_MAX + 16384 ? MACHINE_BLOB_MAX + 16384 : cap * 2;
            unsigned char *bigger = realloc(buf, want);
            if (!bigger)
                goto done;
            buf = bigger;
            cap = want;
        }
        ssize_t k = recv(fd, buf + got, cap - got, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            break;
        got += (size_t)k;
    }
    /* The head, then the body: the body is bytes and is never a string. */
    unsigned char *end = memmem(buf, got, "\r\n\r\n", 4);
    if (got < 12 || strncmp((char *)buf, "HTTP/1.", 7) != 0 || !end)
        goto done;
    status = atoi((char *)buf + 9);
    size_t hlen = (size_t)(end - buf);
    char head[2048];
    snprintf(head, sizeof(head), "%.*s", (int)(hlen < sizeof(head) - 1 ? hlen : sizeof(head) - 1), (char *)buf);
    if (ctype && clen)
        head_value(head, "Content-Type", ctype, clen);
    size_t blen = got - hlen - 4;
    memmove(buf, end + 4, blen);
    *out = buf;
    *len = blen;
    buf = NULL;                                     /* the caller's now */
    rc = status == 200 ? 0 : -status;
done:
    free(buf);
    close(fd);
    return rc;
}

void machine_host_token(char *out, size_t olen)
{
    FILE *f = fopen(MACHINE_HOST_TOKEN_FILE, "re");
    out[0] = '\0';
    if (!f)
        return;
    if (fgets(out, (int)olen, f)) {
        size_t n = strcspn(out, " \t\r\n");
        out[n] = '\0';
    }
    fclose(f);
}

int machine_post(const machine_cfg_t *cfg, const char *path, char *out, size_t olen)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg->port) };
    struct timespec ts;
    char token[64];
    int rc = -1;

    out[0] = '\0';
    machine_host_token(token, sizeof(token));
    if (!token[0])
        return -1;
    if (inet_pton(AF_INET, cfg->host, &a.sin_addr) != 1)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long deadline = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L + HTTP_TIMEOUT_MS;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char *buf = NULL;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) != 0
            || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0)
            goto done;
    }
    char req[700];
    /* The credential goes in a header and never in the path: a path
     * ends up in a log. */
    int rlen = snprintf(req, sizeof(req),
                        "POST %s HTTP/1.0\r\nHost: %s\r\nX-ForgeFIRM-Token: %s\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n", path, cfg->host, token);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req) || wait_fd(fd, POLLOUT, deadline) != 0
        || send(fd, req, (size_t)rlen, MSG_NOSIGNAL) != rlen)
        goto done;
    buf = malloc(HTTP_MAX + 1);
    if (!buf)
        goto done;
    size_t got = 0;
    while (got < HTTP_MAX && wait_fd(fd, POLLIN, deadline) == 0) {
        ssize_t k = recv(fd, buf + got, HTTP_MAX - got, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            break;
        got += (size_t)k;
    }
    buf[got] = '\0';
    const char *body = strstr(buf, "\r\n\r\n");
    if (got < 12 || strncmp(buf, "HTTP/1.", 7) != 0 || !body)
        goto done;
    int status = atoi(buf + 9);
    body += 4;
    if (strlen(body) < olen)
        memcpy(out, body, strlen(body) + 1);
    rc = status == 200 ? 0 : -status;
done:
    free(buf);
    close(fd);
    return rc;
}

int machine_post_program(const machine_cfg_t *cfg, const char *path, const char *file,
                         const char *fields, char *out, size_t olen)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg->port) };
    struct timespec ts;
    struct stat st;
    char token[64];
    char *body = NULL, *reply = NULL;
    int rc = -1, fd = -1;
    FILE *f = NULL;

    out[0] = '\0';
    machine_host_token(token, sizeof(token));
    if (!token[0])
        return -1;
    f = fopen(file, "re");
    if (!f)
        return -1;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0
        || st.st_size > MACHINE_JOB_MAX) {
        fclose(f);
        return -1;
    }
    /* The whole request is built before anything is sent: a program is
     * bounded, and a length that is wrong would leave the machine
     * waiting on bytes that never come. */
    static const char *BOUND = "----forgefirm-ext-program";
    size_t cap = (size_t)st.st_size + strlen(fields) + 4096;
    body = malloc(cap);
    if (!body) {
        fclose(f);
        return -1;
    }
    size_t n = 0;
    /* the named fields, one part each: name=value, & separated */
    const char *p = fields;
    while (p && *p) {
        const char *amp = strchr(p, '&'), *eq = strchr(p, '=');
        size_t flen = amp ? (size_t)(amp - p) : strlen(p);
        if (eq && (size_t)(eq - p) < flen) {
            n += (size_t)snprintf(body + n, cap - n,
                                  "--%s\r\nContent-Disposition: form-data; name=\"%.*s\"\r\n\r\n%.*s\r\n",
                                  BOUND, (int)(eq - p), p, (int)(flen - (size_t)(eq - p) - 1), eq + 1);
        }
        p = amp ? amp + 1 : NULL;
    }
    n += (size_t)snprintf(body + n, cap - n,
                          "--%s\r\nContent-Disposition: form-data; name=\"program\"; "
                          "filename=\"program.gcode\"\r\nContent-Type: text/plain\r\n\r\n", BOUND);
    size_t got = fread(body + n, 1, (size_t)st.st_size, f);
    fclose(f);
    f = NULL;
    if (got != (size_t)st.st_size)
        goto done;
    n += got;
    n += (size_t)snprintf(body + n, cap - n, "\r\n--%s--\r\n", BOUND);

    if (inet_pton(AF_INET, cfg->host, &a.sin_addr) != 1)
        goto done;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long deadline = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L + MACHINE_BLOB_TIMEOUT_MS;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        goto done;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) != 0
            || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0)
            goto done;
    }
    char head[512];
    int hlen = snprintf(head, sizeof(head),
                        "POST %s HTTP/1.0\r\nHost: %s\r\nX-ForgeFIRM-Token: %s\r\n"
                        "Content-Type: multipart/form-data; boundary=%s\r\nContent-Length: %zu\r\n"
                        "Connection: close\r\n\r\n", path, cfg->host, token, BOUND, n);
    if (hlen <= 0 || (size_t)hlen >= sizeof(head))
        goto done;
    size_t sent = 0;
    while (sent < (size_t)hlen) {
        if (wait_fd(fd, POLLOUT, deadline) != 0)
            goto done;
        ssize_t k = send(fd, head + sent, (size_t)hlen - sent, MSG_NOSIGNAL);
        if (k <= 0)
            goto done;
        sent += (size_t)k;
    }
    sent = 0;
    while (sent < n) {
        if (wait_fd(fd, POLLOUT, deadline) != 0)
            goto done;
        ssize_t k = send(fd, body + sent, n - sent, MSG_NOSIGNAL);
        if (k <= 0)
            goto done;
        sent += (size_t)k;
    }
    reply = malloc(HTTP_MAX + 1);
    if (!reply)
        goto done;
    size_t rgot = 0;
    while (rgot < HTTP_MAX && wait_fd(fd, POLLIN, deadline) == 0) {
        ssize_t k = recv(fd, reply + rgot, HTTP_MAX - rgot, 0);
        if (k < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (k <= 0)
            break;
        rgot += (size_t)k;
    }
    reply[rgot] = '\0';
    const char *rbody = strstr(reply, "\r\n\r\n");
    if (rgot < 12 || strncmp(reply, "HTTP/1.", 7) != 0 || !rbody)
        goto done;
    int status = atoi(reply + 9);
    rbody += 4;
    if (strlen(rbody) < olen)
        memcpy(out, rbody, strlen(rbody) + 1);
    rc = status == 200 ? 0 : -status;
done:
    if (f)
        fclose(f);
    if (fd >= 0)
        close(fd);
    free(body);
    free(reply);
    return rc;
}

static json_t *get_json(const machine_cfg_t *cfg, const char *path)
{
    static char body[HTTP_MAX];
    json_error_t jerr;
    if (machine_get(cfg, path, body, sizeof(body)) != 0)
        return NULL;
    json_t *j = json_loads(body, 0, &jerr);
    if (j && !json_is_object(j)) {
        json_decref(j);
        return NULL;
    }
    return j;
}

void machine_read(const machine_cfg_t *cfg, machine_t *m, int with_start_facts)
{
    char v[32];
    memset(m, 0, sizeof(*m));
    m->armed = m->mode_cloud = -1;
    if (access(cfg->safe_file, F_OK) == 0)
        snprintf(m->off_reason, sizeof(m->off_reason), "safe mode (%s exists)", cfg->safe_file);
    else if (!machine_conf_value(cfg->conf, "ext_enabled", v, sizeof(v)) || strcmp(v, "1") != 0)
        snprintf(m->off_reason, sizeof(m->off_reason), "extensions are off (ext_enabled)");
    else
        m->enabled = 1;
    if (!m->enabled)
        return;                                         /* nothing runs: nothing to ask the machine */

    json_t *cool = get_json(cfg, "/cool/status");
    if (cool && json_is_boolean(json_object_get(cool, "armed")))
        m->armed = json_is_true(json_object_get(cool, "armed"));
    json_decref(cool);
    json_t *mode = get_json(cfg, "/mode");
    const char *mm = mode ? json_string_value(json_object_get(mode, "mode")) : NULL;
    if (mm)
        m->mode_cloud = strcmp(mm, "cloud") == 0;
    const char *ctl = mode ? json_string_value(json_object_get(mode, "controller")) : NULL;
    const char *motion = mode ? json_string_value(json_object_get(mode, "motion")) : NULL;
    if (!mode)
        snprintf(m->not_ready, sizeof(m->not_ready), "forgectrl does not answer");
    else if (!ctl || strcmp(ctl, "running") != 0)
        snprintf(m->not_ready, sizeof(m->not_ready), "the controller is %s", ctl ? ctl : "not reported");
    else if (!motion || strcmp(motion, "verified") != 0)
        snprintf(m->not_ready, sizeof(m->not_ready), "motion is %s", motion ? motion : "not reported");
    json_decref(mode);
    if (m->not_ready[0] || !with_start_facts)
        return;
    json_t *status = get_json(cfg, "/status"), *update = get_json(cfg, "/update/status");
    if (!status || !update)
        snprintf(m->not_ready, sizeof(m->not_ready), "forgectrl does not answer");
    else if (json_is_true(json_object_get(status, "diag")))
        snprintf(m->not_ready, sizeof(m->not_ready), "a diagnostic is running");
    else if (json_is_true(json_object_get(update, "running")))
        snprintf(m->not_ready, sizeof(m->not_ready), "a firmware job is running");
    else
        m->may_start = 1;
    json_decref(status);
    json_decref(update);
}
