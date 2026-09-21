/*
 * settings.c - a package's own settings: declared in its manifest, kept by the host
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See settings.h. setting_value_ok() is the whole judgment of one value
 * and does no I/O; the rest is the file under the extension root.
 */
#define _GNU_SOURCE
#include "settings.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int say(char *err, size_t elen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int say(char *err, size_t elen, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, elen, fmt, ap);
    va_end(ap);
    return -1;
}

int setting_value_ok(const setting_t *t, json_t *v, char *err, size_t elen)
{
    switch (t->type) {
    case SETTING_NUMBER:
        if (!json_is_number(v) || json_is_boolean(v))
            return say(err, elen, "\"%s\" takes a number", t->name);
        if (t->has_min && json_number_value(v) < t->min)
            return say(err, elen, "\"%s\" is at least %g", t->name, t->min);
        if (t->has_max && json_number_value(v) > t->max)
            return say(err, elen, "\"%s\" is at most %g", t->name, t->max);
        return 0;
    case SETTING_BOOL:
        if (!json_is_boolean(v))
            return say(err, elen, "\"%s\" takes true or false", t->name);
        return 0;
    case SETTING_CHOICE: {
        const char *s = json_string_value(v);
        if (!s || json_string_length(v) != strlen(s))
            return say(err, elen, "\"%s\" takes a string", t->name);
        for (int i = 0; i < t->nchoices; i++)
            if (strcmp(t->choices[i], s) == 0)
                return 0;
        return say(err, elen, "\"%s\" takes one of its choices", t->name);
    }
    case SETTING_STRING:
    default: {
        const char *s = json_string_value(v);
        if (!s || json_string_length(v) != strlen(s))
            return say(err, elen, "\"%s\" takes a string", t->name);
        /* A NUL inside is caught above: the length and the C string agree
         * only when there is none. */
        if (strlen(s) > t->text_max)
            return say(err, elen, "\"%s\" is at most %zu bytes", t->name, t->text_max);
        for (const char *p = s; *p; p++)
            if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
                return say(err, elen, "\"%s\" takes printable text: no control characters", t->name);
        return 0;
    }
    }
}

json_t *setting_default(const setting_t *t)
{
    switch (t->type) {
    case SETTING_NUMBER: return json_real(t->number);
    case SETTING_BOOL:   return json_boolean(t->boolean);
    default:             return json_string(t->text);
    }
}

static void store_path(const char *root, const char *id, char *p, size_t plen)
{
    snprintf(p, plen, "%.255s/%s/%.63s.json", root, SETTINGS_DIR, id);
}

/* What the file holds, or NULL. The file is the host's own, but it is
 * read as if it were not: anything in it that the schema does not
 * declare, or that no longer fits, is passed over. */
static json_t *stored(const char *root, const char *id)
{
    char p[400];
    struct stat st;
    store_path(root, id, p, sizeof(p));
    if (stat(p, &st) != 0 || st.st_size > SETTINGS_MAX_FILE)
        return NULL;
    json_t *j = json_load_file(p, JSON_REJECT_DUPLICATES, NULL);
    if (j && !json_is_object(j)) {
        json_decref(j);
        return NULL;
    }
    return j;
}

json_t *settings_read(const char *root, const char *id, const manifest_t *m)
{
    json_t *have = stored(root, id), *out = json_object();
    char why[160];

    for (int i = 0; i < m->nsettings; i++) {
        const setting_t *t = &m->settings[i];
        json_t *v = have ? json_object_get(have, t->name) : NULL;
        if (v && setting_value_ok(t, v, why, sizeof(why)) == 0)
            json_object_set(out, t->name, v);
        else
            json_object_set_new(out, t->name, setting_default(t));
    }
    json_decref(have);
    return out;
}

int settings_write(const char *root, const char *id, const manifest_t *m, json_t *patch,
                   char *err, size_t elen)
{
    char p[400], dir[400], tmp[420], why[160];
    const char *key;
    json_t *v;

    if (!json_is_object(patch))
        return say(err, elen, "the body is a JSON object of settings");
    if (json_object_size(patch) == 0)
        return say(err, elen, "the body names no setting");
    /* Every key and every value first: nothing is written until the whole
     * patch is one the schema takes. */
    json_object_foreach(patch, key, v) {
        const setting_t *t = manifest_setting(m, key);
        if (!t)
            return say(err, elen, "this package declares no setting \"%.32s\"", key);
        if (setting_value_ok(t, v, why, sizeof(why)) != 0)
            return say(err, elen, "%s", why);
    }
    json_t *next = settings_read(root, id, m);
    json_object_foreach(patch, key, v)
        json_object_set(next, key, v);

    snprintf(dir, sizeof(dir), "%.255s/%s", root, SETTINGS_DIR);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        json_decref(next);
        return say(err, elen, "cannot make %s: %s", dir, strerror(errno));
    }
    store_path(root, id, p, sizeof(p));
    snprintf(tmp, sizeof(tmp), "%.400s.new", p);
    /* Written whole and renamed: a reader never sees half a file, and a
     * host that dies mid-write leaves the old values standing. */
    int rc = json_dump_file(next, tmp, JSON_INDENT(1) | JSON_SORT_KEYS);
    json_decref(next);
    if (rc != 0)
        return say(err, elen, "cannot write %s: %s", tmp, strerror(errno));
    if (chmod(tmp, 0600) != 0 || rename(tmp, p) != 0) {
        unlink(tmp);
        return say(err, elen, "cannot put %s in place: %s", p, strerror(errno));
    }
    return 0;
}

json_t *settings_schema_json(const manifest_t *m)
{
    json_t *out = json_array();
    static const char *const names[] = { "string", "number", "bool", "choice" };

    for (int i = 0; i < m->nsettings; i++) {
        const setting_t *t = &m->settings[i];
        json_t *one = json_pack("{s:s, s:s, s:s, s:o}", "name", t->name, "label", t->label,
                                "type", names[t->type], "default", setting_default(t));
        if (t->type == SETTING_NUMBER) {
            if (t->has_min)
                json_object_set_new(one, "min", json_real(t->min));
            if (t->has_max)
                json_object_set_new(one, "max", json_real(t->max));
        } else if (t->type == SETTING_STRING) {
            json_object_set_new(one, "max", json_integer((json_int_t)t->text_max));
        } else if (t->type == SETTING_CHOICE) {
            json_t *c = json_array();
            for (int k = 0; k < t->nchoices; k++)
                json_array_append_new(c, json_string(t->choices[k]));
            json_object_set_new(one, "choices", c);
        }
        json_array_append_new(out, one);
    }
    return out;
}

void settings_forget(const char *root, const char *id)
{
    char p[400];
    store_path(root, id, p, sizeof(p));
    unlink(p);
}
