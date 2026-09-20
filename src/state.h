/*
 * state.h - what is installed, as forgeext remembers it (state.json)
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * One file under the extension root, written whole and renamed into
 * place. It holds what no package can say about itself: which key signed
 * it (an update must verify under the same one), which account of the
 * pool it runs as, what the operator granted it, and whether it is
 * enabled or quarantined.
 */
#ifndef FORGEEXT_STATE_H
#define FORGEEXT_STATE_H

#include <stddef.h>

#include "manifest.h"
#include "pkg.h"

#define STATE_SCHEMA     1
#define STATE_MAX_PKGS   64
#define STATE_POOL_SIZE  32         /* ffx0 to ffx31: the image's account pool */
#define STATE_POOL_UID   800        /* ffx<n> is uid and gid 800 + n */

typedef struct {
    char id[64];
    char version[33];
    char previous[33];              /* kept until the new version has run healthy once; "" when none */
    pkg_tier_t tier;
    char key_id[65];                /* "" for an unverified package */
    int slot;                       /* the pool account, or -1 for a package with no service */
    int enabled;
    int quarantined;
    char grants[MANIFEST_MAX_CAPS][CAP_MAX_LEN];
    int ngrants;
} state_pkg_t;

typedef struct {
    state_pkg_t pkgs[STATE_MAX_PKGS];
    int n;
} state_t;

/* A root with no state file is an empty state, not an error. */
int state_load(const char *root, state_t *s, char *err, size_t elen);
int state_save(const char *root, const state_t *s, char *err, size_t elen);

state_pkg_t *state_find(state_t *s, const char *id);
state_pkg_t *state_add(state_t *s, const char *id);        /* NULL when full */
void state_remove(state_t *s, const char *id);

/* The lowest pool account no installed package holds, or -1. */
int state_slot_free(const state_t *s);

int state_granted(const state_pkg_t *p, const char *cap);

#endif
