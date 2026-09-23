/*
 * caps.h - the closed list of capabilities a package may ask for
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A capability is a string in a package's manifest: a bare name
 * ("machine.read") or a name with one argument ("storage:16",
 * "net.outbound:mqtt.example.org:8883"). The list is closed and
 * compile-time: a manifest that asks for anything else is refused, and
 * nothing a manifest can spell reaches the two privileged roles or a
 * provider kind.
 */
#ifndef FORGEEXT_CAPS_H
#define FORGEEXT_CAPS_H

#include <stddef.h>

#define CAP_MAX_LEN 96          /* a capability string, argument included */

/* The M-codes a package may answer (mcode:<n>), each one package's: the
 * GRBL controller's range for them. */
#define CAPS_MCODE_MIN 160
#define CAPS_MCODE_MAX 179

typedef struct {
    const char *name;           /* without the argument */
    int takes_arg;              /* "name:<arg>" and never bare */
    int explicit_grant;         /* the operator grants it per package at install, whatever the tier */
    int offered;                /* served by this extension API version */
    const char *grants;         /* what the operator is shown */
} cap_def_t;

size_t caps_count(void);
const cap_def_t *caps_at(size_t i);

/* The definition a capability string falls under, or NULL. */
const cap_def_t *caps_find(const char *cap);

/* 0 when cap is one a manifest may carry; otherwise -1 with the words
 * in why. A role is refused by name: `homing` and `controller` are image
 * content, and no other role exists. */
int caps_check(const char *cap, char *why, size_t wlen);

/* Does the capability need the operator's own grant? */
int caps_needs_grant(const char *cap);

/* The argument of a parameterized capability ("16" of "storage:16"), or
 * NULL for a bare one. Points into cap. */
const char *caps_arg(const char *cap);

/* net.outbound's argument split into host and port: 0 or -1. The host is
 * a DNS name, an IPv4 address, or an IPv6 address in brackets (returned
 * without them). */
int caps_outbound_parse(const char *arg, char *host, size_t hlen, int *port);

#endif
