/*
 * caps.c - the closed list of capabilities a package may ask for
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#include "caps.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The ports the firmware itself listens on: no package listens there,
 * whatever the deny rules would do with its answers. */
static const int firmware_ports[] = { 22, 23, 80, 443, 8090 };

static const cap_def_t defs[] = {
    { "machine.read",   0, 0, 1, "read the machine's status, cooling status, and mode" },
    { "events",         0, 0, 1, "follow the machine's event stream" },
    { "settings.own",   0, 0, 1, "keep its own settings" },
    { "camera.lid",     0, 0, 1, "take pictures with the lid camera" },
    { "camera.head",    0, 0, 1, "take pictures with the head camera" },
    { "motion.jog",     0, 0, 1, "jog the head, laser off, inside the jog bounds" },
    { "motion.offsets", 0, 1, 0, "change the work offsets" },
    { "motion.job",     0, 1, 1, "run a program as the machine's one sender" },
    { "hold",           0, 1, 1, "hold a job until it clears the hold" },
    { "job_time.run",   0, 1, 1, "keep running while a job is armed" },
    { "ui",             0, 0, 1, "show its own tab or cards in the control panel" },
    { "wizard",         0, 0, 0, "add a check to the Setup tab" },
    { "net.outbound",   1, 0, 1, "connect to" },
    { "net.listen",     1, 0, 1, "listen on port" },
    { "storage",        1, 0, 1, "keep data on the machine, in MiB up to" },
    { "mcode",          1, 0, 0, "handle the M-code" },
};

size_t caps_count(void)
{
    return sizeof(defs) / sizeof(defs[0]);
}

const cap_def_t *caps_at(size_t i)
{
    return i < caps_count() ? &defs[i] : NULL;
}

const char *caps_arg(const char *cap)
{
    const char *colon = cap ? strchr(cap, ':') : NULL;
    return colon ? colon + 1 : NULL;
}

const cap_def_t *caps_find(const char *cap)
{
    if (!cap)
        return NULL;
    size_t n = strcspn(cap, ":");
    for (size_t i = 0; i < caps_count(); i++)
        if (strlen(defs[i].name) == n && strncmp(defs[i].name, cap, n) == 0)
            return &defs[i];
    return NULL;
}

/* A whole decimal number in [lo, hi], no sign, no leading zero, no tail. */
static int number_in(const char *s, long lo, long hi, long *out)
{
    if (!s || !isdigit((unsigned char)s[0]) || (s[0] == '0' && s[1]) || strlen(s) > 9)
        return -1;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p))
            return -1;
    long v = strtol(s, NULL, 10);
    if (v < lo || v > hi)
        return -1;
    if (out)
        *out = v;
    return 0;
}

static int dns_name_ok(const char *h)
{
    size_t len = strlen(h), label = 0;
    if (len < 1 || len > 253 || h[0] == '.' || h[len - 1] == '.')
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)h[i];
        if (c == '.') {
            if (label == 0 || h[i - 1] == '-')
                return 0;
            label = 0;
        } else if (isalnum(c) || (c == '-' && label > 0)) {
            if (isupper(c) || ++label > 63)
                return 0;
        } else {
            return 0;
        }
    }
    return h[len - 1] != '-';
}

static int ipv6_text_ok(const char *h)
{
    size_t len = strlen(h);
    if (len < 2 || len > 45 || !strchr(h, ':'))
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)h[i];
        if (!(isdigit(c) || (c >= 'a' && c <= 'f') || c == ':' || c == '.'))
            return 0;
    }
    return 1;
}

int caps_outbound_parse(const char *arg, char *host, size_t hlen, int *port)
{
    if (!arg || !host || hlen == 0)
        return -1;
    const char *p;
    size_t n;
    if (arg[0] == '[') {
        const char *close = strchr(arg, ']');
        if (!close || close[1] != ':')
            return -1;
        n = (size_t)(close - arg - 1);
        if (n == 0 || n >= hlen)
            return -1;
        memcpy(host, arg + 1, n);
        host[n] = '\0';
        if (!ipv6_text_ok(host))
            return -1;
        p = close + 2;
    } else {
        const char *colon = strrchr(arg, ':');
        if (!colon || colon == arg)
            return -1;
        n = (size_t)(colon - arg);
        if (n >= hlen)
            return -1;
        memcpy(host, arg, n);
        host[n] = '\0';
        if (!dns_name_ok(host))
            return -1;
        p = colon + 1;
    }
    long v;
    if (number_in(p, 1, 65535, &v) != 0)
        return -1;
    if (port)
        *port = (int)v;
    return 0;
}

int caps_check(const char *cap, char *why, size_t wlen)
{
    char host[256];
    long v;

    if (why && wlen)
        why[0] = '\0';
    if (!cap || !cap[0] || strlen(cap) >= CAP_MAX_LEN) {
        snprintf(why, wlen, "a capability is 1 to %d characters", CAP_MAX_LEN - 1);
        return -1;
    }
    for (const char *p = cap; *p; p++)
        if ((unsigned char)*p <= ' ' || (unsigned char)*p > '~') {
            snprintf(why, wlen, "a capability is printable ASCII with no space");
            return -1;
        }
    const char *arg = caps_arg(cap);
    if (strncmp(cap, "role:", 5) == 0 || strcmp(cap, "role") == 0) {
        if (arg && (strcmp(arg, "homing") == 0 || strcmp(arg, "controller") == 0))
            snprintf(why, wlen, "role %s is part of the firmware: no package provides it", arg);
        else
            snprintf(why, wlen, "no package provides a role in this extension API");
        return -1;
    }
    const cap_def_t *d = caps_find(cap);
    if (!d) {
        snprintf(why, wlen, "%.*s is not a capability", (int)strcspn(cap, ":"), cap);
        return -1;
    }
    if (!d->offered) {
        snprintf(why, wlen, "%s is not offered by this extension API", d->name);
        return -1;
    }
    if (!d->takes_arg) {
        if (arg) {
            snprintf(why, wlen, "%s takes no argument", d->name);
            return -1;
        }
        return 0;
    }
    if (!arg || !arg[0]) {
        snprintf(why, wlen, "%s needs an argument (%s:<value>)", d->name, d->name);
        return -1;
    }
    if (strcmp(d->name, "net.outbound") == 0) {
        if (caps_outbound_parse(arg, host, sizeof(host), NULL) != 0) {
            snprintf(why, wlen, "net.outbound names one destination, host:port, the host a lowercase "
                                "DNS name, an IPv4 address, or an IPv6 address in brackets");
            return -1;
        }
        if (strcmp(host, "localhost") == 0 || strncmp(host, "127.", 4) == 0 || strcmp(host, "::1") == 0) {
            snprintf(why, wlen, "net.outbound never names the machine itself");
            return -1;
        }
        return 0;
    }
    if (strcmp(d->name, "net.listen") == 0) {
        if (number_in(arg, 1024, 65535, &v) != 0) {
            snprintf(why, wlen, "net.listen names one port, 1024 to 65535");
            return -1;
        }
        for (size_t i = 0; i < sizeof(firmware_ports) / sizeof(firmware_ports[0]); i++)
            if (v == firmware_ports[i]) {
                snprintf(why, wlen, "port %ld is the firmware's own", v);
                return -1;
            }
        return 0;
    }
    if (strcmp(d->name, "storage") == 0) {
        if (number_in(arg, 1, 256, NULL) != 0) {
            snprintf(why, wlen, "storage names a quota in MiB, 1 to 256");
            return -1;
        }
        return 0;
    }
    snprintf(why, wlen, "%s is not offered by this extension API", d->name);
    return -1;
}

int caps_needs_grant(const char *cap)
{
    const cap_def_t *d = caps_find(cap);
    return d ? d->explicit_grant : 0;
}
