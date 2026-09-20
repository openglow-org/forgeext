/*
 * manifest.c - a package's manifest.json, parsed and held to the schema
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#include "manifest.h"

#include <ctype.h>
#include <jansson.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const known_keys[] = {
    "manifest", "id", "name", "version", "description", "author", "license", "homepage",
    "api", "core", "runtime", "service", "modes", "capabilities", "conflicts",
};

static const char *const runtime_names[] = { "data", "ui", "shell", "native", "python" };

/* Capabilities that are about a running process: a package with no
 * service has nothing that could use them. */
static const char *const service_only[] = { "hold", "job_time.run", "net.outbound", "net.listen", "storage" };

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

const char *manifest_runtime_name(manifest_runtime_t r)
{
    return (size_t)r < sizeof(runtime_names) / sizeof(runtime_names[0]) ? runtime_names[r] : "?";
}

int manifest_has_service(const manifest_t *m)
{
    return m->runtime == RUNTIME_SHELL || m->runtime == RUNTIME_NATIVE || m->runtime == RUNTIME_PYTHON;
}

int manifest_has_cap(const manifest_t *m, const char *cap)
{
    for (int i = 0; i < m->ncaps; i++)
        if (strcmp(m->caps[i], cap) == 0)
            return 1;
    return 0;
}

int manifest_id_ok(const char *id)
{
    if (!id)
        return 0;
    size_t len = strlen(id), label = 0;
    int labels = 1;
    if (len < 3 || len > 63)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)id[i];
        if (c == '.') {
            if (label == 0 || id[i - 1] == '-')
                return 0;
            label = 0;
            labels++;
        } else if (c >= 'a' && c <= 'z') {
            label++;
        } else if ((isdigit(c) || c == '-') && label > 0) {
            label++;
        } else {
            return 0;
        }
        if (label > 31)
            return 0;
    }
    return label > 0 && id[len - 1] != '-' && labels >= 2;
}

int manifest_id_reserved(const char *id)
{
    return id && (strncmp(id, "org.openglow.", 13) == 0 || strncmp(id, "org.forgefirm.", 14) == 0);
}

/* One dotted number of a version: digits, no leading zero. Advances *p. */
static int version_number(const char **p, long *out)
{
    const char *s = *p;
    if (!isdigit((unsigned char)*s) || (s[0] == '0' && isdigit((unsigned char)s[1])))
        return -1;
    char *end;
    long v = strtol(s, &end, 10);
    if (end - s > 9)
        return -1;
    *out = v;
    *p = end;
    return 0;
}

static int version_split(const char *v, long n[3], const char **pre)
{
    const char *p = v;
    if (!v || strlen(v) > 32)
        return -1;
    for (int i = 0; i < 3; i++) {
        if (version_number(&p, &n[i]) != 0)
            return -1;
        if (i < 2 && *p++ != '.')
            return -1;
    }
    *pre = NULL;
    if (*p == '\0')
        return 0;
    if (*p != '-' || !p[1])
        return -1;
    for (const char *q = p + 1; *q; q++)
        if (!(isalnum((unsigned char)*q) || *q == '.' || *q == '-'))
            return -1;
    *pre = p + 1;
    return 0;
}

int manifest_version_ok(const char *v)
{
    long n[3];
    const char *pre;
    return version_split(v, n, &pre) == 0;
}

int manifest_version_cmp(const char *a, const char *b)
{
    long na[3] = { 0, 0, 0 }, nb[3] = { 0, 0, 0 };
    const char *pa = NULL, *pb = NULL;
    version_split(a, na, &pa);
    version_split(b, nb, &pb);
    for (int i = 0; i < 3; i++)
        if (na[i] != nb[i])
            return na[i] < nb[i] ? -1 : 1;
    if (!pa && !pb)
        return 0;
    if (!pa)
        return 1;
    if (!pb)
        return -1;
    return strcmp(pa, pb);
}

/* A display string: present, a JSON string, no control character, and
 * short enough for its field. With required 0 the key may be absent or
 * empty. */
static int take_text(json_t *root, const char *key, int required, char *out, size_t olen,
                     char *err, size_t elen)
{
    json_t *j = json_object_get(root, key);
    out[0] = '\0';
    if (!j)
        return required ? fail(err, elen, "\"%s\" is missing", key) : 0;
    if (!json_is_string(j))
        return fail(err, elen, "\"%s\" is not a string", key);
    const char *s = json_string_value(j);
    size_t len = json_string_length(j);
    if (len != strlen(s))
        return fail(err, elen, "\"%s\" holds a NUL", key);
    if (len == 0 && required)
        return fail(err, elen, "\"%s\" is empty", key);
    if (len >= olen)
        return fail(err, elen, "\"%s\" is longer than %zu bytes", key, olen - 1);
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)s[i] < ' ' || s[i] == 0x7f)
            return fail(err, elen, "\"%s\" holds a control character", key);
    memcpy(out, s, len + 1);
    return 0;
}

/* A path inside the package: relative, forward slashes, no "." or ".."
 * segment, no empty segment, printable ASCII without a space. */
static int inside_path_ok(const char *p)
{
    size_t seg = 0;
    if (!p[0] || p[0] == '/')
        return 0;
    for (const char *q = p;; q++) {
        unsigned char c = (unsigned char)*q;
        if (c == '/' || c == '\0') {
            if (seg == 0)
                return 0;
            if ((seg == 1 && q[-1] == '.') || (seg == 2 && q[-1] == '.' && q[-2] == '.'))
                return 0;
            seg = 0;
            if (c == '\0')
                return 1;
        } else if (c <= ' ' || c > '~' || c == '\\') {
            return 0;
        } else {
            seg++;
        }
    }
}

static int take_api(json_t *root, manifest_t *m, char *err, size_t elen)
{
    char api[17];
    if (take_text(root, "api", 1, api, sizeof(api), err, elen) != 0)
        return -1;
    const char *p = api;
    long major, minor;
    if (version_number(&p, &major) != 0 || *p++ != '.' || version_number(&p, &minor) != 0 || *p)
        return fail(err, elen, "\"api\" is MAJOR.MINOR, for example \"%d.%d\"", EXT_API_MAJOR, EXT_API_MINOR);
    m->api_major = (int)major;
    m->api_minor = (int)minor;
    int fits = major == EXT_API_MAJOR && (major == 0 ? minor == EXT_API_MINOR : minor <= EXT_API_MINOR);
    if (!fits)
        return fail(err, elen, "built for extension API %ld.%ld; this firmware serves %d.%d",
                    major, minor, EXT_API_MAJOR, EXT_API_MINOR);
    return 0;
}

static int take_core(json_t *root, manifest_t *m, char *err, size_t elen)
{
    json_t *core = json_object_get(root, "core");
    m->core_min[0] = m->core_max[0] = '\0';
    if (!core)
        return 0;
    if (!json_is_object(core))
        return fail(err, elen, "\"core\" is not an object");
    const char *key;
    json_t *val;
    json_object_foreach(core, key, val) {
        char *dst = strcmp(key, "min") == 0 ? m->core_min : strcmp(key, "max") == 0 ? m->core_max : NULL;
        if (!dst)
            return fail(err, elen, "\"core\" has an unknown key \"%.32s\"", key);
        if (!json_is_string(val) || !manifest_version_ok(json_string_value(val)))
            return fail(err, elen, "\"core\".\"%s\" is not a version (MAJOR.MINOR.PATCH)", key);
        snprintf(dst, sizeof(m->core_min), "%s", json_string_value(val));
    }
    if (m->core_min[0] && m->core_max[0] && manifest_version_cmp(m->core_min, m->core_max) > 0)
        return fail(err, elen, "\"core\".\"min\" is above \"core\".\"max\"");
    return 0;
}

static int take_runtime(json_t *root, manifest_t *m, char *err, size_t elen)
{
    char name[17];
    if (take_text(root, "runtime", 1, name, sizeof(name), err, elen) != 0)
        return -1;
    for (size_t i = 0; i < sizeof(runtime_names) / sizeof(runtime_names[0]); i++)
        if (strcmp(name, runtime_names[i]) == 0) {
            m->runtime = (manifest_runtime_t)i;
            return 0;
        }
    return fail(err, elen, "\"runtime\" is one of data, ui, shell, native, python");
}

static int take_service(json_t *root, manifest_t *m, char *err, size_t elen)
{
    json_t *svc = json_object_get(root, "service");
    m->exec[0] = '\0';
    m->nargs = 0;
    if (!manifest_has_service(m)) {
        if (svc)
            return fail(err, elen, "runtime %s runs nothing on the machine: it has no \"service\"",
                        manifest_runtime_name(m->runtime));
        return 0;
    }
    if (!svc)
        return fail(err, elen, "runtime %s needs a \"service\"", manifest_runtime_name(m->runtime));
    if (!json_is_object(svc))
        return fail(err, elen, "\"service\" is not an object");
    const char *key;
    json_t *val;
    json_object_foreach(svc, key, val)
        if (strcmp(key, "exec") != 0 && strcmp(key, "args") != 0)
            return fail(err, elen, "\"service\" has an unknown key \"%.32s\"", key);
    if (take_text(svc, "exec", 1, m->exec, sizeof(m->exec), err, elen) != 0)
        return -1;
    if (!inside_path_ok(m->exec))
        return fail(err, elen, "\"service\".\"exec\" is a path inside the package: relative, no \"..\", "
                               "no space, forward slashes");
    json_t *args = json_object_get(svc, "args");
    if (!args)
        return 0;
    if (!json_is_array(args) || json_array_size(args) > MANIFEST_MAX_ARGS)
        return fail(err, elen, "\"service\".\"args\" is an array of at most %d strings", MANIFEST_MAX_ARGS);
    for (size_t i = 0; i < json_array_size(args); i++) {
        json_t *a = json_array_get(args, i);
        if (!json_is_string(a) || json_string_length(a) != strlen(json_string_value(a))
            || json_string_length(a) >= sizeof(m->args[0]))
            return fail(err, elen, "\"service\".\"args\"[%zu] is not a string of at most %zu bytes", i,
                        sizeof(m->args[0]) - 1);
        for (const char *p = json_string_value(a); *p; p++)
            if ((unsigned char)*p < ' ' || *p == 0x7f)
                return fail(err, elen, "\"service\".\"args\"[%zu] holds a control character", i);
        snprintf(m->args[m->nargs++], sizeof(m->args[0]), "%s", json_string_value(a));
    }
    return 0;
}

static int take_modes(json_t *root, manifest_t *m, char *err, size_t elen)
{
    json_t *modes = json_object_get(root, "modes");
    m->mode_grbl = m->mode_cloud = 1;
    if (!modes)
        return 0;
    if (!json_is_array(modes) || json_array_size(modes) == 0)
        return fail(err, elen, "\"modes\" is a list of grbl, cloud, or both");
    m->mode_grbl = m->mode_cloud = 0;
    for (size_t i = 0; i < json_array_size(modes); i++) {
        const char *s = json_string_value(json_array_get(modes, i));
        int *flag = !s ? NULL : strcmp(s, "grbl") == 0 ? &m->mode_grbl : strcmp(s, "cloud") == 0 ? &m->mode_cloud : NULL;
        if (!flag || *flag)
            return fail(err, elen, "\"modes\" is a list of grbl, cloud, or both, each once");
        *flag = 1;
    }
    return 0;
}

static int take_caps(json_t *root, manifest_t *m, char *err, size_t elen)
{
    char why[200];
    json_t *caps = json_object_get(root, "capabilities");
    m->ncaps = 0;
    if (!caps)
        return fail(err, elen, "\"capabilities\" is missing (an empty list asks for nothing)");
    if (!json_is_array(caps) || json_array_size(caps) > MANIFEST_MAX_CAPS)
        return fail(err, elen, "\"capabilities\" is an array of at most %d strings", MANIFEST_MAX_CAPS);
    for (size_t i = 0; i < json_array_size(caps); i++) {
        json_t *c = json_array_get(caps, i);
        if (!json_is_string(c) || json_string_length(c) != strlen(json_string_value(c)))
            return fail(err, elen, "\"capabilities\"[%zu] is not a string", i);
        const char *cap = json_string_value(c);
        if (caps_check(cap, why, sizeof(why)) != 0)
            return fail(err, elen, "capability \"%.80s\": %s", cap, why);
        if (manifest_has_cap(m, cap))
            return fail(err, elen, "capability \"%s\" is listed twice", cap);
        if (m->runtime == RUNTIME_DATA)
            return fail(err, elen, "runtime data executes nothing and holds no capability (\"%s\")", cap);
        if (!manifest_has_service(m))
            for (size_t k = 0; k < sizeof(service_only) / sizeof(service_only[0]); k++)
                if (strcmp(caps_find(cap)->name, service_only[k]) == 0)
                    return fail(err, elen, "capability \"%s\" belongs to a service, and runtime %s has none",
                                cap, manifest_runtime_name(m->runtime));
        snprintf(m->caps[m->ncaps++], sizeof(m->caps[0]), "%s", cap);
    }
    int storage = 0;
    for (int i = 0; i < m->ncaps; i++)
        if (strncmp(m->caps[i], "storage:", 8) == 0 && storage++)
            return fail(err, elen, "\"storage\" is asked for twice");
    return 0;
}

static int take_conflicts(json_t *root, manifest_t *m, char *err, size_t elen)
{
    json_t *list = json_object_get(root, "conflicts");
    m->nconflicts = 0;
    if (!list)
        return 0;
    if (!json_is_array(list) || json_array_size(list) > MANIFEST_MAX_LIST)
        return fail(err, elen, "\"conflicts\" is an array of at most %d package ids", MANIFEST_MAX_LIST);
    for (size_t i = 0; i < json_array_size(list); i++) {
        const char *id = json_string_value(json_array_get(list, i));
        if (!id || !manifest_id_ok(id))
            return fail(err, elen, "\"conflicts\"[%zu] is not a package id", i);
        if (strcmp(id, m->id) == 0)
            return fail(err, elen, "a package does not conflict with itself");
        for (int k = 0; k < m->nconflicts; k++)
            if (strcmp(m->conflicts[k], id) == 0)
                return fail(err, elen, "\"conflicts\" lists %s twice", id);
        snprintf(m->conflicts[m->nconflicts++], sizeof(m->conflicts[0]), "%s", id);
    }
    return 0;
}

int manifest_parse(const char *text, size_t len, manifest_t *m, char *err, size_t elen)
{
    json_error_t jerr;
    int rc = -1;

    memset(m, 0, sizeof(*m));
    if (len > MANIFEST_MAX_BYTES)
        return fail(err, elen, "the manifest is larger than %d bytes", MANIFEST_MAX_BYTES);
    json_t *root = json_loadb(text, len, JSON_REJECT_DUPLICATES, &jerr);
    if (!root)
        return fail(err, elen, "the manifest is not JSON: line %d: %s", jerr.line, jerr.text);
    if (!json_is_object(root)) {
        fail(err, elen, "the manifest is not a JSON object");
        goto out;
    }
    const char *key;
    json_t *val;
    json_object_foreach(root, key, val) {
        int known = 0;
        for (size_t i = 0; i < sizeof(known_keys) / sizeof(known_keys[0]); i++)
            known |= strcmp(key, known_keys[i]) == 0;
        if (!known) {
            fail(err, elen, "unknown key \"%.48s\"", key);
            goto out;
        }
    }
    json_t *schema = json_object_get(root, "manifest");
    if (!json_is_integer(schema) || json_integer_value(schema) != MANIFEST_SCHEMA) {
        fail(err, elen, "\"manifest\" is the schema number, %d", MANIFEST_SCHEMA);
        goto out;
    }
    if (take_text(root, "id", 1, m->id, sizeof(m->id), err, elen) != 0)
        goto out;
    if (!manifest_id_ok(m->id)) {
        fail(err, elen, "\"id\" is a reverse-DNS name in lowercase: two or more labels of a-z, 0-9, "
                        "and -, each starting with a letter, 63 characters in all");
        goto out;
    }
    if (take_text(root, "name", 1, m->name, sizeof(m->name), err, elen) != 0
        || take_text(root, "version", 1, m->version, sizeof(m->version), err, elen) != 0)
        goto out;
    if (!manifest_version_ok(m->version)) {
        fail(err, elen, "\"version\" is MAJOR.MINOR.PATCH with an optional -prerelease");
        goto out;
    }
    if (take_text(root, "description", 0, m->description, sizeof(m->description), err, elen) != 0
        || take_text(root, "author", 1, m->author, sizeof(m->author), err, elen) != 0
        || take_text(root, "license", 1, m->license, sizeof(m->license), err, elen) != 0
        || take_text(root, "homepage", 0, m->homepage, sizeof(m->homepage), err, elen) != 0)
        goto out;
    if (take_api(root, m, err, elen) != 0 || take_core(root, m, err, elen) != 0
        || take_runtime(root, m, err, elen) != 0 || take_service(root, m, err, elen) != 0
        || take_modes(root, m, err, elen) != 0 || take_caps(root, m, err, elen) != 0
        || take_conflicts(root, m, err, elen) != 0)
        goto out;
    rc = 0;
out:
    json_decref(root);
    return rc;
}

int manifest_load(const char *path, manifest_t *m, char *err, size_t elen)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return fail(err, elen, "the package has no manifest.json");
    char *buf = malloc(MANIFEST_MAX_BYTES + 1);
    if (!buf) {
        fclose(f);
        return fail(err, elen, "out of memory");
    }
    size_t n = fread(buf, 1, MANIFEST_MAX_BYTES + 1, f);
    fclose(f);
    int rc = manifest_parse(buf, n, m, err, elen);
    free(buf);
    return rc;
}
