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

/* The key an entry names: the author's, required outside OpenGlow's
 * namespace and refused inside it. */
static int key_ok(json_t *o, const char *id, char *err, size_t elen)
{
    json_t *key = json_object_get(o, "key");
    const char *ks = json_string_value(key);
    if (manifest_id_reserved(id) && key)
        return fail(err, elen, "%s is in OpenGlow's namespace: only the OpenGlow extension key signs it, and the "
                               "index endorses no key for it", id);
    if (!manifest_id_reserved(id) && (!ks || strlen(ks) < 40 || strlen(ks) > 64 || strchr(ks, '\n')))
        return fail(err, elen, "%s: the index names its author's public key, as fwup writes it", id);
    return 0;
}

/* A capability in form: printable ASCII with no space. Whether this
 * firmware has it is index_judge's question, not the form's. */
static int cap_form_ok(const char *c)
{
    size_t n = c ? strlen(c) : 0;
    if (n < 1 || n > 255)
        return 0;
    for (; *c; c++)
        if ((unsigned char)*c <= ' ' || (unsigned char)*c > '~')
            return 0;
    return 1;
}

/* One listed version of a package, in form. */
static int version_ok(json_t *v, const char *id, char *err, size_t elen)
{
    const char *ver = json_string_value(json_object_get(v, "version"));
    if (!json_is_object(v) || !ver || !manifest_version_ok(ver))
        return fail(err, elen, "%s: a listed version is not one", id);
    if (!https_ok(json_string_value(json_object_get(v, "url")), 1024))
        return fail(err, elen, "%s %s: it is fetched from an https:// address, with no user or password in it", id, ver);
    const char *sha = json_string_value(json_object_get(v, "sha256"));
    if (!sha || strlen(sha) != 64 || strspn(sha, "0123456789abcdef") != 64)
        return fail(err, elen, "%s %s: its sha256 is 64 lowercase hex digits", id, ver);
    json_t *size = json_object_get(v, "size");
    if (!json_is_integer(size) || json_integer_value(size) < 1)
        return fail(err, elen, "%s %s: its size is a whole number of bytes", id, ver);
    json_t *caps = json_object_get(v, "capabilities");
    if (caps && (!json_is_array(caps) || json_array_size(caps) > INDEX_MAX_CAPS))
        return fail(err, elen, "%s %s: its capabilities are a list of at most %d", id, ver, INDEX_MAX_CAPS);
    for (size_t k = 0; caps && k < json_array_size(caps); k++)
        if (!cap_form_ok(json_string_value(json_array_get(caps, k))))
            return fail(err, elen, "%s %s: a capability is printable text with no space", id, ver);
    if (!text_ok(v, "api", 0, 16))
        return fail(err, elen, "%s %s: its api is MAJOR.MINOR", id, ver);
    json_t *core = json_object_get(v, "core");
    if (core) {
        const char *lo = json_string_value(json_object_get(core, "min")), *hi = json_string_value(json_object_get(core, "max"));
        if (!json_is_object(core) || (json_object_get(core, "min") && !manifest_version_ok(lo))
            || (json_object_get(core, "max") && !manifest_version_ok(hi)))
            return fail(err, elen, "%s %s: its core range is {\"min\", \"max\"}, each a version", id, ver);
        if (lo && hi && manifest_version_cmp(lo, hi) > 0)
            return fail(err, elen, "%s %s: its core range's min is above its max", id, ver);
    }
    return 0;
}

static int listed_twice(json_t *list, size_t i, const char *field, const char *value)
{
    for (size_t k = 0; k < i; k++) {
        const char *s = json_string_value(json_object_get(json_array_get(list, k), field));
        if (s && !strcmp(s, value))
            return 1;
    }
    return 0;
}

static int in_list(json_t *list, const char *field, const char *value)
{
    return listed_twice(list, json_array_size(list), field, value);
}

/* One listed package: what it is, its key, its versions, and the versions
 * of it OpenGlow withdrew. */
static int package_ok(json_t *list, size_t i, char *err, size_t elen)
{
    json_t *p = json_array_get(list, i);
    const char *id = json_string_value(json_object_get(p, "id"));
    if (!json_is_object(p) || !id || !manifest_id_ok(id))
        return fail(err, elen, "entry %zu of the index has no package id", i + 1);
    if (listed_twice(list, i, "id", id))
        return fail(err, elen, "the index lists %s twice", id);
    if (!text_ok(p, "name", 1, 64) || !text_ok(p, "description", 0, 256) || !text_ok(p, "author", 1, 128)
        || !text_ok(p, "license", 0, 64))
        return fail(err, elen, "%s: its name, author, description, or license is not text of its size", id);
    json_t *home = json_object_get(p, "homepage");
    if (home && !https_ok(json_string_value(home), 256))
        return fail(err, elen, "%s: its homepage is an https:// address", id);
    if (key_ok(p, id, err, elen) != 0)
        return -1;
    json_t *vers = json_object_get(p, "versions");
    if (!json_is_array(vers) || json_array_size(vers) < 1 || json_array_size(vers) > INDEX_MAX_VERSIONS)
        return fail(err, elen, "%s: its versions are a list of 1 to %d", id, INDEX_MAX_VERSIONS);
    for (size_t k = 0; k < json_array_size(vers); k++) {
        if (version_ok(json_array_get(vers, k), id, err, elen) != 0)
            return -1;
        const char *ver = json_string_value(json_object_get(json_array_get(vers, k), "version"));
        if (listed_twice(vers, k, "version", ver))
            return fail(err, elen, "the index lists %s %s twice", id, ver);
    }
    json_t *gone = json_object_get(p, "withdrawn");
    if (gone && (!json_is_array(gone) || json_array_size(gone) > INDEX_MAX_WITHDRAWN))
        return fail(err, elen, "%s: its withdrawn versions are a list of at most %d", id, INDEX_MAX_WITHDRAWN);
    for (size_t k = 0; gone && k < json_array_size(gone); k++) {
        json_t *w = json_array_get(gone, k);
        const char *ver = json_string_value(json_object_get(w, "version"));
        if (!json_is_object(w) || !ver || !manifest_version_ok(ver) || !text_ok(w, "reason", 0, 256))
            return fail(err, elen, "%s: a withdrawn version is {\"version\", \"reason\"}", id);
        if (listed_twice(gone, k, "version", ver))
            return fail(err, elen, "the index withdraws %s %s twice", id, ver);
        if (in_list(vers, "version", ver))
            return fail(err, elen, "the index both lists and withdraws %s %s", id, ver);
    }
    return 0;
}

int index_check(json_t *doc, char *err, size_t elen)
{
    if (!json_is_object(doc) || json_integer_value(json_object_get(doc, "index")) != INDEX_SCHEMA)
        return fail(err, elen, "an index is {\"index\": %d, \"packages\": [...]}", INDEX_SCHEMA);
    json_t *list = json_object_get(doc, "packages");
    if (!json_is_array(list) || json_array_size(list) > INDEX_MAX_PKGS)
        return fail(err, elen, "the index's packages are a list of at most %d", INDEX_MAX_PKGS);
    for (size_t i = 0; i < json_array_size(list); i++)
        if (package_ok(list, i, err, elen) != 0)
            return -1;

    /* The packages withdrawn whole: out of the catalog, their key endorsed
     * for nothing, and named so that a machine holding one can say so. */
    json_t *gone = json_object_get(doc, "withdrawn");
    if (gone && (!json_is_array(gone) || json_array_size(gone) > INDEX_MAX_PKGS))
        return fail(err, elen, "the index's withdrawn packages are a list of at most %d", INDEX_MAX_PKGS);
    for (size_t i = 0; gone && i < json_array_size(gone); i++) {
        json_t *w = json_array_get(gone, i);
        const char *id = json_string_value(json_object_get(w, "id"));
        if (!json_is_object(w) || !id || !manifest_id_ok(id) || !text_ok(w, "reason", 0, 256))
            return fail(err, elen, "withdrawn package %zu of the index is {\"id\", \"key\", \"reason\"}", i + 1);
        if (key_ok(w, id, err, elen) != 0)
            return -1;
        if (listed_twice(gone, i, "id", id))
            return fail(err, elen, "the index withdraws %s twice", id);
        if (in_list(list, "id", id))
            return fail(err, elen, "the index both lists and withdraws %s", id);
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

/* The id of the key an entry names, written to path first: the same id an
 * installed package's "key" is. */
static int entry_key_id(json_t *e, const char *path, char kid[65])
{
    char text[80];
    int n = snprintf(text, sizeof(text), "%s\n", json_string_value(json_object_get(e, "key")));
    if (write_file(path, text, (size_t)n, 0644) != 0 || pkg_key_id(path, kid) != 0)
        return -1;
    return 0;
}

int index_install(const ext_env_t *env, const char *file, int *npkgs, char *version, size_t vlen, char *err,
                  size_t elen)
{
    char work[400], payload[440], tree[440], list[440], json_path[480], dir[340], next[360], old[360];
    pkg_info_t info;
    pkg_tree_t t;
    json_t *doc = NULL, *kept = NULL;
    int rc = -1;
    *npkgs = 0;
    if (version && vlen)
        version[0] = '\0';

    /* Signed with the OpenGlow extension key and by nothing else: no owner
     * key and no endorsed key speaks for the index. */
    pkg_trust_t trust = env->trust;
    trust.owner_keys_dir = NULL;
    trust.endorsed_dir = NULL;
    if (ext_root_prepare(env, err, elen) != 0)          /* the catalog can be the first thing a root holds */
        return -1;
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
    if (!manifest_version_ok(info.version)) {
        fail(err, elen, "the index's version, %.40s, is not a version (MAJOR.MINOR.PATCH)", info.version);
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

    /* Laid out beside the one in use, then swapped in, and never over a
     * newer one: an index OpenGlow signed once stays signed, so a copy of
     * an old one would list again what was withdrawn since. */
    int lock = ext_lock(env, err, elen);
    if (lock < 0)
        goto out;
    kept = index_read(env);
    const char *was = json_string_value(json_object_get(kept, "version"));
    if (was && manifest_version_ok(was) && manifest_version_cmp(info.version, was) < 0) {
        fail(err, elen, "the index is version %s, older than the one kept here (%s): the catalog never goes back",
             info.version, was);
        ext_unlock(lock);
        goto out;
    }
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
    /* The keys it endorses, one file per listed id; the keys of packages
     * it withdrew whole are only named, by their id, and endorse nothing. */
    json_t *pkgs = json_object_get(doc, "packages"), *gone = json_object_get(doc, "withdrawn"), *p;
    size_t i;
    json_array_foreach(pkgs, i, p) {
        const char *id = json_string_value(json_object_get(p, "id"));
        char kid[65];
        if (!json_object_get(p, "key"))
            continue;
        snprintf(path, sizeof(path), "%s/keys/%s.pub", next, id);
        if (entry_key_id(p, path, kid) != 0) {
            fail(err, elen, "%s: the key the index names for it is no Ed25519 public key", id);
            pkg_rmtree(next);
            ext_unlock(lock);
            goto out;
        }
        json_object_set_new(p, "key_id", json_string(kid));
    }
    json_array_foreach(gone, i, p) {
        const char *id = json_string_value(json_object_get(p, "id"));
        char kid[65];
        if (!json_object_get(p, "key"))
            continue;
        snprintf(path, sizeof(path), "%s/withdrawn.pub", work);
        if (entry_key_id(p, path, kid) != 0) {
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
    *npkgs = (int)json_array_size(pkgs);
    if (version && vlen)
        snprintf(version, vlen, "%s", info.version);
    rc = 0;
out:
    json_decref(kept);
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

/* Does this version run on this firmware: its core range (when this
 * firmware has a version to judge it by), the extension API it was built
 * for, every capability it asks for, and its size. 1, or 0 with the first
 * reason it does not. */
static int usable(const ext_env_t *env, int checked, json_t *v, char *why, size_t wlen)
{
    json_t *core = json_object_get(v, "core");
    const char *lo = json_string_value(json_object_get(core, "min")), *hi = json_string_value(json_object_get(core, "max"));
    const char *api = json_string_value(json_object_get(v, "api"));
    char words[256];
    if (checked && lo && manifest_version_cmp(env->core_version, lo) < 0) {
        snprintf(why, wlen, "needs firmware %s or newer, and this is %s", lo, env->core_version);
        return 0;
    }
    if (checked && hi && manifest_version_cmp(env->core_version, hi) > 0) {
        snprintf(why, wlen, "needs firmware %s or older, and this is %s", hi, env->core_version);
        return 0;
    }
    if (api && manifest_api_check(api, words, sizeof(words)) != 0) {
        snprintf(why, wlen, "%s", words);
        return 0;
    }
    json_t *c;
    size_t k;
    json_array_foreach(json_object_get(v, "capabilities"), k, c) {
        if (caps_check(json_string_value(c), words, sizeof(words)) != 0) {
            snprintf(why, wlen, "asks for what this firmware does not have: %s", words);
            return 0;
        }
    }
    if (json_integer_value(json_object_get(v, "size")) > PKG_MAX_ARCHIVE) {
        snprintf(why, wlen, "is larger than this firmware takes, %lld MiB", PKG_MAX_ARCHIVE >> 20);
        return 0;
    }
    return 1;
}

void index_judge(const ext_env_t *env, json_t *doc)
{
    int checked = manifest_version_ok(env->core_version);
    json_t *p, *v;
    size_t i, k;
    json_array_foreach(json_object_get(doc, "packages"), i, p) {
        const char *offer = NULL, *newest = NULL, *newest_why = NULL;
        json_array_foreach(json_object_get(p, "versions"), k, v) {
            char why[320] = "";
            const char *ver = json_string_value(json_object_get(v, "version"));
            int ok = usable(env, checked, v, why, sizeof(why));
            json_object_set_new(v, "usable", json_boolean(ok));
            if (ok)
                json_object_del(v, "why");
            else
                json_object_set_new(v, "why", json_string(why));
            if (ok && ver && (!offer || manifest_version_cmp(ver, offer) > 0))
                offer = ver;
            if (ver && (!newest || manifest_version_cmp(ver, newest) > 0)) {
                newest = ver;
                newest_why = json_string_value(json_object_get(v, "why"));
            }
        }
        json_object_set_new(p, "offer", offer ? json_string(offer) : json_null());
        /* Offered nothing: what keeps the newest listed version off this
         * firmware, for the operator. */
        if (!offer && newest_why)
            json_object_set_new(p, "why", json_sprintf("%s %s %s", json_string_value(json_object_get(p, "id")), newest,
                                                       newest_why));
        else
            json_object_del(p, "why");
    }
}

/* Is it the listed package: the key the entry names, or the OpenGlow
 * extension key in OpenGlow's own namespace. */
static int names_signer(json_t *e, const char *id, const char *key_id, int official)
{
    if (manifest_id_reserved(id))
        return official;
    const char *k = json_string_value(json_object_get(e, "key_id"));
    return k && key_id && key_id[0] && !strcmp(k, key_id);
}

static void copy_reason(json_t *e, char *reason, size_t rlen)
{
    const char *r = json_string_value(json_object_get(e, "reason"));
    if (reason && rlen)
        snprintf(reason, rlen, "%s", r ? r : "");
}

int index_withdrawn(json_t *doc, const char *id, const char *version, const char *key_id, int official, char *reason,
                    size_t rlen)
{
    json_t *p, *w;
    size_t i, k;
    if (reason && rlen)
        reason[0] = '\0';
    if (!doc || !id)
        return INDEX_NOT_WITHDRAWN;
    json_array_foreach(json_object_get(doc, "withdrawn"), i, p) {
        const char *pid = json_string_value(json_object_get(p, "id"));
        if (pid && !strcmp(pid, id) && names_signer(p, id, key_id, official)) {
            copy_reason(p, reason, rlen);
            return INDEX_PACKAGE_WITHDRAWN;
        }
    }
    json_array_foreach(json_object_get(doc, "packages"), i, p) {
        const char *pid = json_string_value(json_object_get(p, "id"));
        if (!pid || strcmp(pid, id) != 0 || !names_signer(p, id, key_id, official))
            continue;
        json_array_foreach(json_object_get(p, "withdrawn"), k, w) {
            const char *ver = json_string_value(json_object_get(w, "version"));
            if (ver && version && !strcmp(ver, version)) {
                copy_reason(w, reason, rlen);
                return INDEX_VERSION_WITHDRAWN;
            }
        }
    }
    return INDEX_NOT_WITHDRAWN;
}
