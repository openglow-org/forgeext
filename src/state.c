/*
 * state.c - what is installed, as forgeext remembers it (state.json)
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(char *err, size_t elen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t elen, const char *fmt, ...)
{
    if (err && elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, elen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

state_pkg_t *state_find(state_t *s, const char *id)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->pkgs[i].id, id) == 0)
            return &s->pkgs[i];
    return NULL;
}

state_pkg_t *state_add(state_t *s, const char *id)
{
    if (s->n >= STATE_MAX_PKGS || !manifest_id_ok(id))
        return NULL;
    state_pkg_t *p = &s->pkgs[s->n++];
    memset(p, 0, sizeof(*p));
    snprintf(p->id, sizeof(p->id), "%s", id);
    p->slot = -1;
    return p;
}

void state_remove(state_t *s, const char *id)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->pkgs[i].id, id) == 0) {
            memmove(&s->pkgs[i], &s->pkgs[i + 1], (size_t)(s->n - i - 1) * sizeof(s->pkgs[0]));
            s->n--;
            return;
        }
}

int state_slot_free(const state_t *s)
{
    for (int slot = 0; slot < STATE_POOL_SIZE; slot++) {
        int held = 0;
        for (int i = 0; i < s->n; i++)
            held |= s->pkgs[i].slot == slot;
        if (!held)
            return slot;
    }
    return -1;
}

int state_granted(const state_pkg_t *p, const char *cap)
{
    for (int i = 0; i < p->ngrants; i++)
        if (strcmp(p->grants[i], cap) == 0)
            return 1;
    return 0;
}

static const char *text_of(json_t *obj, const char *key)
{
    const char *s = json_string_value(json_object_get(obj, key));
    return s ? s : "";
}

/* One package's entry. Whatever does not read as this daemon wrote it
 * refuses the whole file: a state that was edited by hand or cut short is
 * not one to guess at. */
static int pkg_from_json(const char *id, json_t *j, state_pkg_t *p)
{
    char why[160];
    memset(p, 0, sizeof(*p));
    if (!manifest_id_ok(id) || !json_is_object(j))
        return -1;
    snprintf(p->id, sizeof(p->id), "%s", id);
    const char *version = text_of(j, "version"), *previous = text_of(j, "previous");
    const char *tier = text_of(j, "tier"), *key = text_of(j, "key");
    if (!manifest_version_ok(version) || (previous[0] && !manifest_version_ok(previous)))
        return -1;
    snprintf(p->version, sizeof(p->version), "%s", version);
    snprintf(p->previous, sizeof(p->previous), "%s", previous);
    if (strcmp(tier, "official") == 0)
        p->tier = TIER_OFFICIAL;
    else if (strcmp(tier, "community") == 0)
        p->tier = TIER_COMMUNITY;
    else if (strcmp(tier, "unverified") == 0)
        p->tier = TIER_UNVERIFIED;
    else
        return -1;
    if ((key[0] && (strlen(key) != 64 || strspn(key, "0123456789abcdef") != 64))
        || (!key[0]) != (p->tier == TIER_UNVERIFIED))
        return -1;
    snprintf(p->key_id, sizeof(p->key_id), "%s", key);
    json_t *slot = json_object_get(j, "slot");
    if (!json_is_integer(slot) || json_integer_value(slot) < -1 || json_integer_value(slot) >= STATE_POOL_SIZE)
        return -1;
    p->slot = (int)json_integer_value(slot);
    p->enabled = json_is_true(json_object_get(j, "enabled"));
    p->quarantined = json_is_true(json_object_get(j, "quarantined"));
    p->hold_required = json_is_true(json_object_get(j, "hold_required"));
    json_t *grants = json_object_get(j, "grants");
    if (!json_is_array(grants) || json_array_size(grants) > MANIFEST_MAX_CAPS)
        return -1;
    for (size_t i = 0; i < json_array_size(grants); i++) {
        const char *cap = json_string_value(json_array_get(grants, i));
        if (!cap || caps_check(cap, why, sizeof(why)) != 0 || !caps_needs_grant(cap))
            return -1;
        snprintf(p->grants[p->ngrants++], sizeof(p->grants[0]), "%s", cap);
    }
    /* Absent in a state written before the operator could name any. */
    json_t *dests = json_object_get(j, "destinations");
    if (dests && (!json_is_array(dests) || json_array_size(dests) > STATE_MAX_DESTS))
        return -1;
    for (size_t i = 0; dests && i < json_array_size(dests); i++) {
        const char *d = json_string_value(json_array_get(dests, i));
        char host[256];
        int port;
        if (!d || strlen(d) >= CAP_MAX_LEN || caps_outbound_parse(d, host, sizeof(host), &port) != 0)
            return -1;
        snprintf(p->dests[p->ndests++], sizeof(p->dests[0]), "%s", d);
    }
    return 0;
}

int state_load(const char *root, state_t *s, char *err, size_t elen)
{
    char path[512];
    json_error_t jerr;

    memset(s, 0, sizeof(*s));
    snprintf(path, sizeof(path), "%.255s/state.json", root);
    if (access(path, F_OK) != 0 && errno == ENOENT)
        return 0;
    json_t *top = json_load_file(path, JSON_REJECT_DUPLICATES, &jerr);
    if (!top)
        return fail(err, elen, "state.json does not read: %s", jerr.text);
    json_t *pkgs = json_object_get(top, "packages");
    int rc = 0;
    if (json_integer_value(json_object_get(top, "state")) != STATE_SCHEMA || !json_is_object(pkgs)
        || json_object_size(pkgs) > STATE_MAX_PKGS) {
        rc = fail(err, elen, "state.json is not this daemon's (schema %d)", STATE_SCHEMA);
    } else {
        const char *id;
        json_t *j;
        json_object_foreach(pkgs, id, j) {
            if (pkg_from_json(id, j, &s->pkgs[s->n]) != 0) {
                rc = fail(err, elen, "state.json: the entry for \"%.63s\" does not read", id);
                break;
            }
            for (int i = 0; i < s->n; i++)
                if (s->pkgs[i].slot >= 0 && s->pkgs[i].slot == s->pkgs[s->n].slot)
                    rc = fail(err, elen, "state.json: two packages hold account ffx%d", s->pkgs[i].slot);
            if (rc != 0)
                break;
            s->n++;
        }
    }
    json_decref(top);
    if (rc != 0)
        memset(s, 0, sizeof(*s));
    return rc;
}

int state_save(const char *root, const state_t *s, char *err, size_t elen)
{
    char path[512], tmp[512];
    json_t *top = json_object(), *pkgs = json_object();

    json_object_set_new(top, "state", json_integer(STATE_SCHEMA));
    json_object_set_new(top, "packages", pkgs);
    for (int i = 0; i < s->n; i++) {
        const state_pkg_t *p = &s->pkgs[i];
        json_t *j = json_object(), *grants = json_array();
        json_object_set_new(j, "version", json_string(p->version));
        json_object_set_new(j, "previous", json_string(p->previous));
        json_object_set_new(j, "tier", json_string(pkg_tier_name(p->tier)));
        json_object_set_new(j, "key", json_string(p->key_id));
        json_object_set_new(j, "slot", json_integer(p->slot));
        json_object_set_new(j, "enabled", json_boolean(p->enabled));
        json_object_set_new(j, "quarantined", json_boolean(p->quarantined));
        json_object_set_new(j, "hold_required", json_boolean(p->hold_required));
        for (int k = 0; k < p->ngrants; k++)
            json_array_append_new(grants, json_string(p->grants[k]));
        json_object_set_new(j, "grants", grants);
        json_t *dests = json_array();
        for (int k = 0; k < p->ndests; k++)
            json_array_append_new(dests, json_string(p->dests[k]));
        json_object_set_new(j, "destinations", dests);
        json_object_set_new(pkgs, p->id, j);
    }
    char *text = json_dumps(top, JSON_INDENT(1) | JSON_SORT_KEYS);
    json_decref(top);
    if (!text)
        return fail(err, elen, "out of memory");
    snprintf(path, sizeof(path), "%.255s/state.json", root);
    snprintf(tmp, sizeof(tmp), "%.255s/state.json.new", root);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    size_t len = strlen(text);
    int ok = fd >= 0 && write(fd, text, len) == (ssize_t)len && write(fd, "\n", 1) == 1 && fsync(fd) == 0;
    if (fd >= 0)
        close(fd);
    free(text);
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return fail(err, elen, "cannot write state.json: %s", strerror(errno));
    }
    return 0;
}
