/*
 * index.c - the signed index
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See index.h.
 */
#define _GNU_SOURCE
#include "index.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "caps.h"
#include "manifest.h"
#include "pkg.h"

static int fail(char *err, size_t elen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

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

void index_keys_dir(const ext_env_t *env, char *out, size_t len)
{
    snprintf(out, len, "%.255s/index/keys", env->root);
}

static int official_id(const char *id)
{
    return strncmp(id, "org.openglow.", 13) == 0 || strncmp(id, "org.forgefirm.", 14) == 0;
}

/* Text of at most max bytes with no control character; required or not. */
static int text_ok(json_t *o, const char *key, int required, size_t max)
{
    json_t *v = json_object_get(o, key);
    if (!v)
        return !required;
    const char *s = json_string_value(v);
    if (!s || strlen(s) > max || (required && !s[0]))
        return 0;
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return 0;
    return 1;
}

static int https_ok(const char *u, size_t max)
{
    if (!u || strncmp(u, "https://", 8) != 0 || strlen(u) > max || !u[8])
        return 0;
    for (const unsigned char *p = (const unsigned char *)u; *p; p++)
        if (*p <= 0x20 || *p == 0x7f)
            return 0;
    const char *end = strpbrk(u + 8, "/?#"), *at = strchr(u + 8, '@');
    return !at || (end && at > end);                   /* no user or password in the authority */
}

int index_check(json_t *doc, char *err, size_t elen)
{
    char why[200];
    if (!json_is_object(doc) || json_integer_value(json_object_get(doc, "index")) != INDEX_SCHEMA)
        return fail(err, elen, "an index is {\"index\": %d, \"packages\": [...]}", INDEX_SCHEMA);
    json_t *list = json_object_get(doc, "packages");
    if (!json_is_array(list) || json_array_size(list) > INDEX_MAX_PKGS)
        return fail(err, elen, "the index's packages are a list of at most %d", INDEX_MAX_PKGS);
    for (size_t i = 0; i < json_array_size(list); i++) {
        json_t *p = json_array_get(list, i);
        const char *id = json_string_value(json_object_get(p, "id"));
        if (!json_is_object(p) || !id || !manifest_id_ok(id))
            return fail(err, elen, "entry %zu of the index has no package id", i + 1);
        for (size_t k = 0; k < i; k++)
            if (!strcmp(id, json_string_value(json_object_get(json_array_get(list, k), "id"))))
                return fail(err, elen, "the index lists %s twice", id);
        if (!text_ok(p, "name", 1, 64) || !text_ok(p, "description", 0, 256) || !text_ok(p, "author", 1, 128)
            || !text_ok(p, "license", 0, 64))
            return fail(err, elen, "%s: its name, author, description, or license is not text of its size", id);
        const char *v = json_string_value(json_object_get(p, "version"));
        if (!v || !manifest_version_ok(v))
            return fail(err, elen, "%s: its version is not one", id);
        if (!https_ok(json_string_value(json_object_get(p, "url")), 1024))
            return fail(err, elen, "%s: it is fetched from an https:// address, with no user or password in it", id);
        json_t *home = json_object_get(p, "homepage");
        if (home && !https_ok(json_string_value(home), 256))
            return fail(err, elen, "%s: its homepage is an https:// address", id);
        const char *sha = json_string_value(json_object_get(p, "sha256"));
        if (!sha || strlen(sha) != 64 || strspn(sha, "0123456789abcdef") != 64)
            return fail(err, elen, "%s: its sha256 is 64 lowercase hex digits", id);
        json_t *size = json_object_get(p, "size");
        if (!json_is_integer(size) || json_integer_value(size) < 1 || json_integer_value(size) > PKG_MAX_ARCHIVE)
            return fail(err, elen, "%s: its size is a whole number of bytes, at most %lld MiB", id, PKG_MAX_ARCHIVE >> 20);
        json_t *key = json_object_get(p, "key");
        const char *ks = json_string_value(key);
        if (official_id(id) && key)
            return fail(err, elen, "%s is in OpenGlow's namespace: only the OpenGlow extension key signs it, and the "
                                   "index endorses no key for it", id);
        if (!official_id(id) && (!ks || strlen(ks) < 40 || strlen(ks) > 64 || strchr(ks, '\n')))
            return fail(err, elen, "%s: the index names its author's public key, as fwup writes it", id);
        json_t *caps = json_object_get(p, "capabilities");
        if (caps && (!json_is_array(caps) || json_array_size(caps) > MANIFEST_MAX_CAPS))
            return fail(err, elen, "%s: its capabilities are a list", id);
        for (size_t k = 0; caps && k < json_array_size(caps); k++) {
            const char *c = json_string_value(json_array_get(caps, k));
            if (!c || caps_check(c, why, sizeof(why)) != 0)
                return fail(err, elen, "%s: %s", id, c ? why : "a capability is text");
        }
    }
    return 0;
}

static int write_file(const char *path, const char *text, size_t len, mode_t mode)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    int ok = write(fd, text, len) == (ssize_t)len && fsync(fd) == 0;
    close(fd);
    return ok ? 0 : -1;
}

int index_install(const ext_env_t *env, const char *file, int *npkgs, char *version, size_t vlen, char *err,
                  size_t elen)
{
    char work[400], payload[440], tree[440], list[440], json_path[480], dir[340], next[360], old[360];
    pkg_info_t info;
    pkg_tree_t t;
    json_t *doc = NULL;
    int rc = -1;
    *npkgs = 0;
    if (version && vlen)
        version[0] = '\0';

    /* Signed with the OpenGlow extension key and by nothing else: no owner
     * key and no endorsed key speaks for the index. */
    pkg_trust_t trust = env->trust;
    trust.owner_keys_dir = NULL;
    trust.endorsed_dir = NULL;
    snprintf(work, sizeof(work), "%.255s/tmp/index.XXXXXX", env->root);
    if (!mkdtemp(work))
        return fail(err, elen, "cannot make a work directory: %s", strerror(errno));
    snprintf(payload, sizeof(payload), "%s/payload.tar.gz", work);
    snprintf(tree, sizeof(tree), "%s/tree", work);
    snprintf(list, sizeof(list), "%s/files", work);
    if (pkg_open_product(&trust, file, PKG_INDEX_PRODUCT, payload, &info, err, elen) != 0)
        goto out;
    if (info.tier != TIER_OFFICIAL) {
        fail(err, elen, "the index is not signed with the OpenGlow extension key");
        goto out;
    }
    if (mkdir(tree, 0700) != 0 || pkg_unpack(payload, tree, list, &t, err, elen) != 0) {
        if (!err[0])
            fail(err, elen, "cannot unpack the index: %s", strerror(errno));
        goto out;
    }
    snprintf(json_path, sizeof(json_path), "%s/index.json", tree);
    struct stat st;
    if (t.files != 1 || stat(json_path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > INDEX_MAX_BYTES) {
        fail(err, elen, "an index holds index.json and nothing else, at most %d KiB", INDEX_MAX_BYTES >> 10);
        goto out;
    }
    json_error_t je;
    doc = json_load_file(json_path, JSON_REJECT_DUPLICATES, &je);
    if (!doc) {
        fail(err, elen, "index.json is not JSON: %s", je.text);
        goto out;
    }
    if (index_check(doc, err, elen) != 0)
        goto out;

    /* Laid out beside the one in use, then swapped in. */
    int lock = ext_lock(env, err, elen);
    if (lock < 0)
        goto out;
    snprintf(dir, sizeof(dir), "%.255s/index", env->root);
    snprintf(next, sizeof(next), "%.255s/index.next", env->root);
    snprintf(old, sizeof(old), "%.255s/index.old", env->root);
    pkg_rmtree(next);
    pkg_rmtree(old);
    char path[500];
    snprintf(path, sizeof(path), "%s/keys", next);
    if (mkdir(next, 0755) != 0 || mkdir(path, 0755) != 0) {
        fail(err, elen, "cannot make %s: %s", next, strerror(errno));
        ext_unlock(lock);
        goto out;
    }
    json_t *list_ = json_object_get(doc, "packages");
    for (size_t i = 0; i < json_array_size(list_); i++) {
        json_t *p = json_array_get(list_, i);
        const char *id = json_string_value(json_object_get(p, "id")), *key = json_string_value(json_object_get(p, "key"));
        char kid[65], text[80];
        if (!key)
            continue;
        snprintf(path, sizeof(path), "%s/keys/%s.pub", next, id);
        int n = snprintf(text, sizeof(text), "%s\n", key);
        if (write_file(path, text, (size_t)n, 0644) != 0 || pkg_key_id(path, kid) != 0) {
            fail(err, elen, "%s: the key the index names for it is no Ed25519 public key", id);
            pkg_rmtree(next);
            ext_unlock(lock);
            goto out;
        }
        json_object_set_new(p, "key_id", json_string(kid));
    }
    json_object_set_new(doc, "version", json_string(info.version));
    char *text = json_dumps(doc, JSON_INDENT(1) | JSON_SORT_KEYS);
    snprintf(path, sizeof(path), "%s/index.json", next);
    if (!text || write_file(path, text, strlen(text), 0644) != 0) {
        free(text);
        fail(err, elen, "cannot write the index");
        pkg_rmtree(next);
        ext_unlock(lock);
        goto out;
    }
    free(text);
    if ((access(dir, F_OK) == 0 && rename(dir, old) != 0) || rename(next, dir) != 0) {
        fail(err, elen, "cannot put the index in place: %s", strerror(errno));
        if (access(dir, F_OK) != 0 && access(old, F_OK) == 0)
            rename(old, dir);
        pkg_rmtree(next);
        ext_unlock(lock);
        goto out;
    }
    pkg_rmtree(old);
    ext_unlock(lock);
    *npkgs = (int)json_array_size(list_);
    if (version && vlen)
        snprintf(version, vlen, "%s", info.version);
    rc = 0;
out:
    json_decref(doc);
    pkg_rmtree(work);
    return rc;
}

json_t *index_read(const ext_env_t *env)
{
    char path[400];
    snprintf(path, sizeof(path), "%.255s/index/index.json", env->root);
    json_t *doc = json_load_file(path, JSON_REJECT_DUPLICATES, NULL);
    if (doc && !json_is_object(doc)) {
        json_decref(doc);
        return NULL;
    }
    return doc;
}
