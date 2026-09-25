/*
 * install.c - an archive becomes an installed package, or is refused
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "install.h"
#include "index.h"
#include "netrules.h"

#include "settings.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define KEY_EXT_OFFICIAL  "/etc/forgefirm/keys/ext/forgefirm-ext.pub"
#define KEY_FW_RELEASE    "/etc/forgefirm/keys/forgefirm-release.pub"
#define KEY_FW_FACTORY    "/etc/forgefirm/keys/gf"

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

void ext_env_defaults(ext_env_t *env)
{
    memset(env, 0, sizeof(*env));
    env->root = EXT_ROOT_DEFAULT;
    env->trust.fwup = "fwup";
    env->trust.official_key = KEY_EXT_OFFICIAL;
    env->trust.owner_keys_dir = EXT_ROOT_DEFAULT "/keys";
    env->trust.endorsed_dir = EXT_ROOT_DEFAULT "/index/keys";
    env->trust.firmware_keys[0] = KEY_FW_RELEASE;
    env->trust.firmware_keys[1] = KEY_FW_FACTORY;
    env->budget_bytes = EXT_BUDGET_DEFAULT;
    env->reserve_bytes = EXT_RESERVE_DEFAULT;
    ext_read_core_version(env->core_version, sizeof(env->core_version));
}

void ext_read_core_version_from(const char *path, char *out, size_t olen)
{
    FILE *f = fopen(path, "re");
    char line[128];
    out[0] = '\0';
    if (!f)
        return;
    if (fgets(line, sizeof(line), f)) {
        /* "v0.0.6", or "20260921190848 (dev)": the first word either way,
         * and the release form's leading "v" is the file's, not the
         * version's. */
        size_t n = strcspn(line, " \t\r\n");
        line[n] = '\0';
        const char *v = manifest_version_text(line);
        if (strlen(v) < olen)
            snprintf(out, olen, "%s", v);
    }
    fclose(f);
}

void ext_read_core_version(char *out, size_t olen)
{
    ext_read_core_version_from(EXT_VERSION_FILE, out, olen);
}

int ext_root_prepare(const ext_env_t *env, char *err, size_t elen)
{
    static const struct { const char *name; mode_t mode; } dirs[] = {
        { "", 0755 }, { "/pkg", 0755 }, { "/data", 0755 }, { "/keys", 0755 }, { "/required-holds", 0755 },
        { "/" SETTINGS_DIR, 0700 }, { "/tmp", 0700 },
    };
    if (!env->root || !env->root[0] || strlen(env->root) > EXT_ROOT_MAX)
        return fail(err, elen, "the extension root is a path of at most %d bytes", EXT_ROOT_MAX);
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[512];
        struct stat st;
        snprintf(p, sizeof(p), "%.255s%.24s", env->root, dirs[i].name);
        if (mkdir(p, dirs[i].mode) != 0 && errno != EEXIST)
            return fail(err, elen, "cannot make %s: %s", p, strerror(errno));
        if (lstat(p, &st) != 0 || !S_ISDIR(st.st_mode))
            return fail(err, elen, "%s is not a directory", p);
        if (chmod(p, dirs[i].mode) != 0)
            return fail(err, elen, "cannot set the mode of %s: %s", p, strerror(errno));
    }
    return 0;
}

int ext_root_reachable(const ext_env_t *env, char *err, size_t elen)
{
    char p[512];
    struct stat st;
    static const char *const below[] = { "/pkg", "/data" };
    if (!env->root || env->root[0] != '/' || strlen(env->root) > EXT_ROOT_MAX)
        return fail(err, elen, "the extension root is an absolute path of at most %d bytes", EXT_ROOT_MAX);
    size_t n = strlen(env->root);
    for (size_t i = 1; i <= n; i++) {
        if (env->root[i] != '/' && env->root[i] != '\0')
            continue;
        snprintf(p, sizeof(p), "%.*s", (int)i, env->root);
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
            return fail(err, elen, "%s is not a directory", p);
        if (!(st.st_mode & S_IXOTH))
            return fail(err, elen, "%s (mode %04o) does not let a package's account through", p,
                        (unsigned)(st.st_mode & 07777));
    }
    for (size_t i = 0; i < sizeof(below) / sizeof(below[0]); i++) {
        snprintf(p, sizeof(p), "%.255s%.8s", env->root, below[i]);
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode) || !(st.st_mode & S_IXOTH))
            return fail(err, elen, "%s does not let a package's account through", p);
    }
    return 0;
}

int ext_lock(const ext_env_t *env, char *err, size_t elen)
{
    char p[300];
    if (!env->root || strlen(env->root) > EXT_ROOT_MAX)
        return fail(err, elen, "the extension root is a path of at most %d bytes", EXT_ROOT_MAX);
    snprintf(p, sizeof(p), "%.255s/lock", env->root);
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return fail(err, elen, "cannot open %s: %s", p, strerror(errno));
    if (flock(fd, LOCK_EX) != 0) {
        int saved = errno;
        close(fd);
        return fail(err, elen, "cannot lock %s: %s", p, strerror(saved));
    }
    return fd;
}

void ext_unlock(int lock)
{
    if (lock >= 0)
        close(lock);                                    /* the lock goes with the descriptor */
}

/* The bytes of the regular files under a directory (0 when absent). */
static long long tree_bytes(const char *dir, int depth)
{
    long long total = 0;
    DIR *d = depth < 64 ? opendir(dir) : NULL;
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char p[1024];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0
            || snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= (int)sizeof(p) || lstat(p, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            total += tree_bytes(p, depth + 1);
        else if (S_ISREG(st.st_mode))
            total += st.st_size;
    }
    closedir(d);
    return total;
}

int ext_ui_html(const ext_env_t *env, const char *id, char **html, size_t *len, char *err, size_t elen)
{
    char p[900], cur[600];
    struct stat st;
    FILE *f;

    *html = NULL;
    *len = 0;
    snprintf(cur, sizeof(cur), "%.255s/pkg/%.63s/current", env->root, id);
    snprintf(p, sizeof(p), "%.600s/%s", cur, EXT_UI_FILE);
    f = fopen(p, "re");
    if (!f)
        return fail(err, elen, "this package has no interface");
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > EXT_UI_MAX) {
        fclose(f);
        return fail(err, elen, "this package's interface is not a file of a size that is served");
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        fclose(f);
        return fail(err, elen, "out of memory");
    }
    size_t got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[got] = '\0';
    /* A NUL inside would cut the page short wherever it landed, and what
     * is served has to be the whole file or nothing. */
    if (got != (size_t)st.st_size || strlen(buf) != got) {
        free(buf);
        return fail(err, elen, "this package's interface is not text");
    }
    *html = buf;
    *len = got;
    return 0;
}

int ext_manifest_of(const ext_env_t *env, const char *id, manifest_t *m, char *err, size_t elen)
{
    char p[512];
    snprintf(p, sizeof(p), "%.255s/pkg/%.63s/current/manifest.json", env->root, id);
    return manifest_load(p, m, err, elen);
}

int ext_check(const ext_env_t *env, const state_pkg_t *p, char *err, size_t elen)
{
    char dir[512], list[512];
    snprintf(dir, sizeof(dir), "%.255s/pkg/%.63s/%.32s", env->root, p->id, p->version);
    snprintf(list, sizeof(list), "%.255s/pkg/%.63s/%.32s.files", env->root, p->id, p->version);
    return pkg_tree_check(dir, list, err, elen);
}

/* The port of a package's net.listen capability, or 0. */
static int listen_port(const manifest_t *m)
{
    for (int i = 0; i < m->ncaps; i++)
        if (strncmp(m->caps[i], "net.listen:", 11) == 0)
            return atoi(m->caps[i] + 11);
    return 0;
}

/* How many net.outbound destinations the manifest declares. */
static int outbound_count(const manifest_t *m)
{
    int n = 0;
    for (int i = 0; i < m->ncaps; i++)
        n += strncmp(m->caps[i], "net.outbound:", 13) == 0;
    return n;
}

static int lists(const manifest_t *m, const char *id)
{
    for (int i = 0; i < m->nconflicts; i++)
        if (strcmp(m->conflicts[i], id) == 0)
            return 1;
    return 0;
}

/* The rules that need the machine's state: the version, the namespace,
 * the key an update must share, conflicts, and the capability diff. */
static int judge(const ext_env_t *env, state_t *st, install_result_t *res, char *err, size_t elen)
{
    const manifest_t *m = &res->manifest;
    char p[512], why[256];

    if (strcmp(res->info.version, m->version) != 0)
        return fail(err, elen, "the archive says version %s and its manifest says %s", res->info.version, m->version);
    if (manifest_id_reserved(m->id) && res->info.tier != TIER_OFFICIAL)
        return fail(err, elen, "the id %s is in OpenGlow's namespace, and this archive is not signed with "
                               "the OpenGlow extension key", m->id);

    /* The firmware range the package says it needs. A dev image's version
     * is a build stamp and no version at all, so there is nothing to
     * compare against and the range is not judged; res->core_checked says
     * which of the two happened, so that an operator is never left to
     * guess whether the range was honored. */
    res->core_checked = manifest_version_ok(env->core_version);
    if (res->core_checked) {
        if (m->core_min[0] && manifest_version_cmp(env->core_version, m->core_min) < 0)
            return fail(err, elen, "this package needs firmware %s or newer, and this is %s",
                        m->core_min, env->core_version);
        if (m->core_max[0] && manifest_version_cmp(env->core_version, m->core_max) > 0)
            return fail(err, elen, "this package needs firmware %s or older, and this is %s",
                        m->core_max, env->core_version);
    }

    /* What the kept index says of the listed package - this id, signed by
     * the key the catalog names for it. A version OpenGlow withdrew is not
     * installed, from the catalog or from anywhere else; a package it
     * withdrew whole is the owner's to judge by who signed it, and the
     * answer says so. */
    json_t *idx = index_read(env);
    char reason[260];
    int w = index_withdrawn(idx, m->id, m->version, res->info.key_id, res->info.tier == TIER_OFFICIAL, reason,
                            sizeof(reason));
    json_decref(idx);
    if (w == INDEX_VERSION_WITHDRAWN)
        return fail(err, elen, "OpenGlow withdrew %s %s from its catalog%s%s", m->id, m->version, reason[0] ? ": " : "",
                    reason);
    if (w == INDEX_PACKAGE_WITHDRAWN) {
        res->withdrawn = w;
        snprintf(res->withdrawn_reason, sizeof(res->withdrawn_reason), "%s", reason);
    }

    state_pkg_t *have = state_find(st, m->id);
    res->update = have != NULL;
    res->nnew = res->nneeds = 0;
    manifest_t old;
    int have_old = 0;
    if (have) {
        snprintf(res->from_version, sizeof(res->from_version), "%s", have->version);
        int cmp = manifest_version_cmp(m->version, have->version);
        if (cmp == 0)
            return fail(err, elen, "%s %s is already installed", m->id, m->version);
        res->downgrade = cmp < 0;
        if (have->tier != res->info.tier || strcmp(have->key_id, res->info.key_id) != 0)
            return fail(err, elen, "an update is signed by the key that signed the installed version (%s, %s); "
                                   "this archive is %s. Remove the package first to change its signer",
                        pkg_tier_name(have->tier), have->key_id[0] ? have->key_id : "no key",
                        pkg_tier_name(res->info.tier));
        have_old = ext_manifest_of(env, m->id, &old, why, sizeof(why)) == 0;
    }
    for (int i = 0; i < m->ncaps; i++) {
        if (caps_needs_grant(m->caps[i]))
            snprintf(res->needs_grant[res->nneeds++], CAP_MAX_LEN, "%s", m->caps[i]);
        if (!have_old || !manifest_has_cap(&old, m->caps[i]))
            snprintf(res->new_caps[res->nnew++], CAP_MAX_LEN, "%s", m->caps[i]);
    }

    int port = listen_port(m);
    for (int i = 0; i < st->n; i++) {
        manifest_t other;
        if (strcmp(st->pkgs[i].id, m->id) == 0)
            continue;
        if (lists(m, st->pkgs[i].id))
            return fail(err, elen, "%s conflicts with %s, which is installed", m->id, st->pkgs[i].id);
        if (ext_manifest_of(env, st->pkgs[i].id, &other, why, sizeof(why)) != 0)
            continue;
        if (lists(&other, m->id))
            return fail(err, elen, "%s, which is installed, conflicts with %s", other.id, m->id);
        if (port && listen_port(&other) == port)
            return fail(err, elen, "%s, which is installed, already listens on port %d", other.id, port);
        for (int k = 0; k < m->ncaps; k++)
            if (strncmp(m->caps[k], "mcode:", 6) == 0 && manifest_has_cap(&other, m->caps[k]))
                return fail(err, elen, "%s, which is installed, already answers M%s", other.id, m->caps[k] + 6);
    }
    if (have && manifest_has_cap(m, "net.outbound.operator") && have->ndests + outbound_count(m) > EXT_DESTS_MAX)
        return fail(err, elen, "the operator named %d destinations for %s and this version declares %d: a service has "
                               "at most %d", have->ndests, m->id, outbound_count(m), EXT_DESTS_MAX);
    if (!have && st->n >= STATE_MAX_PKGS)
        return fail(err, elen, "%d packages are installed, and that is the limit", STATE_MAX_PKGS);
    if (manifest_has_service(m) && (!have || have->slot < 0) && state_slot_free(st) < 0)
        return fail(err, elen, "all %d service accounts are taken", STATE_POOL_SIZE);

    snprintf(p, sizeof(p), "%.255s/pkg", env->root);
    long long held = tree_bytes(p, 0);
    if (env->budget_bytes > 0 && held + res->tree.bytes > env->budget_bytes)
        return fail(err, elen, "installed packages hold %lld MiB and this one needs %lld more: the limit is %lld MiB",
                    held >> 20, (res->tree.bytes >> 20) + 1, env->budget_bytes >> 20);
    struct statvfs vfs;
    if (env->reserve_bytes > 0 && statvfs(env->root, &vfs) == 0) {
        long long avail = (long long)vfs.f_bavail * (long long)vfs.f_frsize;
        if (avail - res->tree.bytes < env->reserve_bytes)
            return fail(err, elen, "the install would leave less than the %lld MiB a firmware update needs",
                        env->reserve_bytes >> 20);
    }
    return 0;
}

/* The service's entry point is a file of the package, and executable
 * where the runtime runs it directly. */
/* A package that asks for `ui` ships one, and it is one file of a size
 * a panel can hold. A package that ships one without asking for `ui`
 * would render nothing, so that is refused too rather than left to
 * puzzle its author. */
static int judge_ui(const char *tree, const manifest_t *m, char *err, size_t elen)
{
    char p[1024];
    struct stat st;
    int wants = manifest_has_cap(m, "ui");

    snprintf(p, sizeof(p), "%.400s/%s", tree, EXT_UI_FILE);
    int have = lstat(p, &st) == 0 && S_ISREG(st.st_mode);
    if (wants && !have)
        return fail(err, elen, "this package asks for ui and has no %s", EXT_UI_FILE);
    if (!wants && have)
        return fail(err, elen, "this package has a %s and does not ask for ui", EXT_UI_FILE);
    if (have && st.st_size > EXT_UI_MAX)
        return fail(err, elen, "%s is %lld bytes and at most %d are taken", EXT_UI_FILE,
                    (long long)st.st_size, EXT_UI_MAX);
    if (have && st.st_size == 0)
        return fail(err, elen, "%s is empty", EXT_UI_FILE);
    return 0;
}

static int judge_exec(const char *tree, const manifest_t *m, char *err, size_t elen)
{
    char p[1024];
    struct stat st;
    if (!manifest_has_service(m))
        return 0;
    snprintf(p, sizeof(p), "%.400s/%.192s", tree, m->exec);
    if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode))
        return fail(err, elen, "the service's entry point, %s, is not a file of the package", m->exec);
    if (m->runtime == RUNTIME_NATIVE && !(st.st_mode & 0100))
        return fail(err, elen, "the service's entry point, %s, is not executable", m->exec);
    return 0;
}

/* Verify, unpack into a staging directory, read the manifest, and judge.
 * On success the staging directory (staging/tree, staging/files) is the
 * caller's to commit or remove; on failure it is gone. */
static int stage(const ext_env_t *env, const char *file, state_t *st, install_result_t *res,
                 char *staging, size_t slen, char *err, size_t elen)
{
    char payload[400], tree[400], list[400], mf[400];

    memset(res, 0, sizeof(*res));
    if (ext_root_prepare(env, err, elen) != 0 || state_load(env->root, st, err, elen) != 0)
        return -1;
    snprintf(staging, slen, "%.255s/tmp/in.XXXXXX", env->root);
    if (!mkdtemp(staging))
        return fail(err, elen, "cannot make a staging directory: %s", strerror(errno));
    snprintf(payload, sizeof(payload), "%.280s/payload.tar.gz", staging);
    snprintf(tree, sizeof(tree), "%.280s/tree", staging);
    snprintf(list, sizeof(list), "%.280s/files", staging);
    snprintf(mf, sizeof(mf), "%.280s/tree/manifest.json", staging);
    int rc = pkg_open(&env->trust, file, payload, &res->info, err, elen);
    if (rc == 0 && mkdir(tree, 0755) != 0)
        rc = fail(err, elen, "cannot make a staging directory: %s", strerror(errno));
    if (rc == 0)
        rc = pkg_unpack(payload, tree, list, &res->tree, err, elen);
    if (rc == 0)
        rc = manifest_load(mf, &res->manifest, err, elen);
    if (rc == 0 && res->info.endorsed_id[0] && strcmp(res->info.endorsed_id, res->manifest.id) != 0) {
        /* The key that verified it is endorsed, and the file it was found
         * in names another id. One author's key may be endorsed for
         * several ids, so the question is whether the index endorses this
         * same key for this id too; if it does not, for this id the key
         * is nobody's, and the archive is judged as signed by nobody. */
        char own[600], kid[65];
        snprintf(own, sizeof(own), "%.400s/%s.pub", env->trust.endorsed_dir ? env->trust.endorsed_dir : "",
                 res->manifest.id);
        if (env->trust.endorsed_dir && pkg_key_id(own, kid) == 0 && strcmp(kid, res->info.key_id) == 0) {
            snprintf(res->info.endorsed_id, sizeof(res->info.endorsed_id), "%s", res->manifest.id);
            snprintf(res->info.key_file, sizeof(res->info.key_file), "%.255s", own);
        } else {
            res->info.tier = TIER_UNVERIFIED;
            res->info.key_id[0] = res->info.key_file[0] = res->info.endorsed_id[0] = '\0';
        }
    }
    if (rc == 0)
        rc = judge_exec(tree, &res->manifest, err, elen);
    if (rc == 0)
        rc = judge_ui(tree, &res->manifest, err, elen);
    if (rc == 0)
        rc = judge(env, st, res, err, elen);
    unlink(payload);
    if (rc != 0)
        pkg_rmtree(staging);
    return rc;
}

int ext_inspect(const ext_env_t *env, const char *file, install_result_t *res, char *err, size_t elen)
{
    char staging[288];
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int rc = stage(env, file, st, res, staging, sizeof(staging), err, elen);
    if (rc == 0)
        pkg_rmtree(staging);
    free(st);
    return rc;
}

static int granted_by(const install_opts_t *opts, const char *cap)
{
    for (int i = 0; i < opts->ngrants; i++)
        if (opts->grants[i] && strcmp(opts->grants[i], cap) == 0)
            return 1;
    return 0;
}

/* `current` -> version, replaced in one step. */
static int point_current(const char *pkgdir, const char *version)
{
    char link[400], tmp[400];
    snprintf(link, sizeof(link), "%.340s/current", pkgdir);
    snprintf(tmp, sizeof(tmp), "%.340s/current.new", pkgdir);
    unlink(tmp);
    if (symlink(version, tmp) != 0 || rename(tmp, link) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void drop_version(const char *pkgdir, const char *version)
{
    char p[400];
    if (!version[0])
        return;
    snprintf(p, sizeof(p), "%.340s/%.32s", pkgdir, version);
    pkg_rmtree(p);
    snprintf(p, sizeof(p), "%.340s/%.32s.files", pkgdir, version);
    unlink(p);
}

int ext_install(const ext_env_t *env, const char *file, const install_opts_t *opts,
                install_result_t *res, char *err, size_t elen)
{
    char staging[288], pkgdir[340], from[400], to[400], datadir[340], missing[400] = "";
    int rc = -1;
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    if (ext_root_prepare(env, err, elen) != 0) {
        free(st);
        return -1;
    }
    int lock = ext_lock(env, err, elen);
    if (lock < 0) {
        free(st);
        return -1;
    }
    if (stage(env, file, st, res, staging, sizeof(staging), err, elen) != 0) {
        ext_unlock(lock);
        free(st);
        return -1;
    }
    const manifest_t *m = &res->manifest;

    /* The operator's part: consent for the tier, and a grant for every
     * capability that needs one and for nothing the package did not ask. */
    if (res->info.tier == TIER_UNVERIFIED && !opts->consent_unverified) {
        fail(err, elen, "nobody this machine trusts signed this package: installing it takes the button held");
        goto out;
    }
    if (res->info.tier == TIER_COMMUNITY && !opts->consent_community) {
        fail(err, elen, "this package is signed by a key the owner added, not by OpenGlow: installing it takes "
                        "the operator's typed consent");
        goto out;
    }
    for (int i = 0; i < res->nneeds; i++)
        if (!granted_by(opts, res->needs_grant[i])) {
            size_t used = strlen(missing);
            snprintf(missing + used, sizeof(missing) - used, "%s%s", used ? ", " : "", res->needs_grant[i]);
        }
    if (missing[0]) {
        fail(err, elen, "the package asks for what only the operator grants: %s", missing);
        goto out;
    }
    for (int i = 0; i < opts->ngrants; i++)
        if (opts->grants[i] && (!manifest_has_cap(m, opts->grants[i]) || !caps_needs_grant(opts->grants[i]))) {
            fail(err, elen, "a grant was given for %.80s, which the package does not ask for or does not need",
                 opts->grants[i]);
            goto out;
        }

    /* Commit: the tree and its list move into place, `current` turns to
     * them, and the state is written last. A version older than the one
     * being replaced's own predecessor goes now; the predecessor stays
     * until the new version has run healthy once. */
    snprintf(pkgdir, sizeof(pkgdir), "%.255s/pkg/%.63s", env->root, m->id);
    if (mkdir(pkgdir, 0755) != 0 && errno != EEXIST) {
        fail(err, elen, "cannot make %s: %s", pkgdir, strerror(errno));
        goto out;
    }
    drop_version(pkgdir, m->version);                       /* a leftover of an install that did not finish */
    snprintf(from, sizeof(from), "%.280s/tree", staging);
    snprintf(to, sizeof(to), "%.340s/%.32s", pkgdir, m->version);
    if (rename(from, to) != 0) {
        fail(err, elen, "cannot move the package into place: %s", strerror(errno));
        goto out;
    }
    snprintf(from, sizeof(from), "%.280s/files", staging);
    snprintf(to, sizeof(to), "%.340s/%.32s.files", pkgdir, m->version);
    if (rename(from, to) != 0 || point_current(pkgdir, m->version) != 0) {
        fail(err, elen, "cannot move the package into place: %s", strerror(errno));
        drop_version(pkgdir, m->version);
        goto out;
    }
    state_pkg_t *p = state_find(st, m->id);
    if (p) {
        drop_version(pkgdir, p->previous);
        snprintf(p->previous, sizeof(p->previous), "%s", p->version);
        p->quarantined = 0;
    } else {
        p = state_add(st, m->id);
        p->enabled = 1;
    }
    snprintf(p->version, sizeof(p->version), "%s", m->version);
    p->tier = res->info.tier;
    snprintf(p->key_id, sizeof(p->key_id), "%s", res->info.key_id);
    if (manifest_has_service(m) && p->slot < 0)
        p->slot = state_slot_free(st);
    if (!manifest_has_service(m))
        p->slot = -1;
    p->ngrants = 0;
    for (int i = 0; i < res->nneeds; i++)
        snprintf(p->grants[p->ngrants++], CAP_MAX_LEN, "%s", res->needs_grant[i]);
    if (!manifest_has_cap(m, "net.outbound.operator"))
        p->ndests = 0;                                  /* a version that does not ask keeps none of them */
    if (p->slot >= 0) {
        snprintf(datadir, sizeof(datadir), "%.255s/data/%.63s", env->root, m->id);
        if (mkdir(datadir, 0700) != 0 && errno != EEXIST) {
            fail(err, elen, "cannot make %s: %s", datadir, strerror(errno));
            goto out;
        }
        if (geteuid() == 0 && (chown(datadir, (uid_t)(STATE_POOL_UID + p->slot), (gid_t)(STATE_POOL_UID + p->slot)) != 0
                               || chmod(datadir, 0700) != 0)) {
            fail(err, elen, "cannot hand %s to ffx%d: %s", datadir, p->slot, strerror(errno));
            goto out;
        }
    }
    rc = state_save(env->root, st, err, elen);
out:
    pkg_rmtree(staging);
    ext_unlock(lock);
    free(st);
    return rc;
}

int ext_remove(const ext_env_t *env, const char *id, int keep_data, char *err, size_t elen)
{
    char p[340];
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int rc = -1;
    int lock = ext_lock(env, err, elen);
    if (lock < 0) {
        free(st);
        return -1;
    }
    if (!manifest_id_ok(id)) {
        fail(err, elen, "that is not a package id");
    } else if (state_load(env->root, st, err, elen) == 0) {
        if (!state_find(st, id)) {
            fail(err, elen, "%s is not installed", id);
        } else {
            state_remove(st, id);
            settings_forget(env->root, id);                 /* its settings are its own: they go with it */
            rc = state_save(env->root, st, err, elen);      /* forgotten first: a half-removed tree is never started */
            if (rc == 0)
                ext_required_holds_sync(env, st);           /* and its hold goes with it: removal is the operator's exit */
            snprintf(p, sizeof(p), "%.255s/pkg/%.63s", env->root, id);
            if (rc == 0 && pkg_rmtree(p) != 0)
                rc = fail(err, elen, "cannot remove %s: %s", p, strerror(errno));
            snprintf(p, sizeof(p), "%.255s/data/%.63s", env->root, id);
            if (rc == 0 && !keep_data && pkg_rmtree(p) != 0)
                rc = fail(err, elen, "cannot remove %s: %s", p, strerror(errno));
        }
    }
    ext_unlock(lock);
    free(st);
    return rc;
}

int ext_wipe(const ext_env_t *env, int *packages, int *keys, char *err, size_t elen)
{
    char p[400];
    state_t *st = calloc(1, sizeof(*st));
    int rc = -1, npkg = 0, nkey = 0;

    if (packages)
        *packages = 0;
    if (keys)
        *keys = 0;
    if (!st)
        return fail(err, elen, "out of memory");
    int lock = ext_lock(env, err, elen);
    if (lock < 0) {
        free(st);
        return -1;
    }
    if (state_load(env->root, st, err, elen) == 0) {
        rc = 0;
        /* The state is emptied and written first, so that nothing is ever
         * started from a tree that is half gone: a host reading the state
         * between the write and the last unlink finds no package at all. */
        int n = st->n;
        char ids[STATE_MAX_PKGS][64];
        for (int i = 0; i < n; i++)
            snprintf(ids[i], sizeof(ids[i]), "%s", st->pkgs[i].id);
        st->n = 0;
        rc = state_save(env->root, st, err, elen);
        if (rc == 0 && ext_required_holds_sync(env, st) != 0)
            rc = fail(err, elen, "the required holds under %s could not be emptied", env->root);
        for (int i = 0; i < n && rc == 0; i++) {
            settings_forget(env->root, ids[i]);
            snprintf(p, sizeof(p), "%.255s/pkg/%.63s", env->root, ids[i]);
            if (pkg_rmtree(p) != 0)
                rc = fail(err, elen, "cannot remove %s: %s", p, strerror(errno));
            snprintf(p, sizeof(p), "%.255s/data/%.63s", env->root, ids[i]);
            if (rc == 0 && pkg_rmtree(p) != 0)
                rc = fail(err, elen, "cannot remove %s: %s", p, strerror(errno));
            if (rc == 0)
                npkg++;
        }
        /* Whatever else is under data/. A package removed with its data
         * kept leaves a directory the state no longer names, and it holds
         * exactly what this is here to take. The directory holds nothing
         * but per-package data, so everything in it goes. */
        snprintf(p, sizeof(p), "%.255s/data", env->root);
        DIR *dd = rc == 0 ? opendir(p) : NULL;
        if (dd) {
            struct dirent *e;
            while ((e = readdir(dd)) != NULL) {
                char left[400];
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                    continue;
                snprintf(left, sizeof(left), "%.255s/data/%.120s", env->root, e->d_name);
                if (pkg_rmtree(left) != 0)
                    rc = fail(err, elen, "cannot remove %s: %s", left, strerror(errno));
            }
            closedir(dd);
        }
        /* The owner's keys. A key the last owner added would go on making
         * their packages read as community rather than as unverified. */
        DIR *d = rc == 0 && env->trust.owner_keys_dir ? opendir(env->trust.owner_keys_dir) : NULL;
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                size_t len = strlen(e->d_name);
                if (e->d_name[0] == '.' || len < 5 || strcmp(e->d_name + len - 4, ".pub") != 0)
                    continue;
                snprintf(p, sizeof(p), "%.255s/%.128s", env->trust.owner_keys_dir, e->d_name);
                if (unlink(p) == 0)
                    nkey++;
                else if (errno != ENOENT)
                    rc = fail(err, elen, "cannot remove %s: %s", p, strerror(errno));
            }
            closedir(d);
        }
    }
    ext_unlock(lock);
    free(st);
    if (packages)
        *packages = npkg;
    if (keys)
        *keys = nkey;
    return rc;
}

/* Load, change one package's entry, save: under the lock. */
int ext_required_holds_sync(const ext_env_t *env, const state_t *st)
{
    char dir[300], p[400];
    snprintf(dir, sizeof(dir), "%.255s/required-holds", env->root);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return -1;
    int bad = 0;
    for (int i = 0; i < st->n; i++) {
        const state_pkg_t *pk = &st->pkgs[i];
        if (!(pk->enabled && pk->hold_required && state_granted(pk, "hold")))
            continue;
        snprintf(p, sizeof(p), "%.299s/%.63s", dir, pk->id);
        int fd = open(p, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
        if (fd < 0)
            bad = 1;
        else
            close(fd);
    }
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        int wanted = 0;
        for (int i = 0; i < st->n; i++) {
            const state_pkg_t *pk = &st->pkgs[i];
            wanted |= pk->enabled && pk->hold_required && state_granted(pk, "hold") && !strcmp(pk->id, de->d_name);
        }
        if (!wanted) {
            snprintf(p, sizeof(p), "%.299s/%.90s", dir, de->d_name);
            if (unlink(p) != 0)
                bad = 1;
        }
    }
    closedir(d);
    return bad ? -1 : 0;
}

static int change(const ext_env_t *env, const char *id, int drop_previous, int quarantined, char *err, size_t elen)
{
    char pkgdir[340];
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int lock = ext_lock(env, err, elen), rc = -1;
    if (lock >= 0 && state_load(env->root, st, err, elen) == 0) {
        state_pkg_t *p = state_find(st, id);
        if (!p) {
            fail(err, elen, "%s is not installed", id);
        } else {
            if (drop_previous && p->previous[0]) {
                snprintf(pkgdir, sizeof(pkgdir), "%.255s/pkg/%.63s", env->root, id);
                drop_version(pkgdir, p->previous);
                p->previous[0] = '\0';
            }
            if (quarantined >= 0)
                p->quarantined = quarantined;
            rc = state_save(env->root, st, err, elen);
        }
    }
    ext_unlock(lock);
    free(st);
    return rc;
}

int ext_drop_previous(const ext_env_t *env, const char *id, char *err, size_t elen)
{
    return change(env, id, 1, -1, err, elen);
}

int ext_set_quarantined(const ext_env_t *env, const char *id, int on, char *err, size_t elen)
{
    return change(env, id, 0, on ? 1 : 0, err, elen);
}

/* A key's name: what may be a file name under the keys directory, and
 * nothing that is a path. */
static int key_name_ok(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (n < 1 || n > 48 || name[0] == '.' || name[0] == '-')
        return 0;
    return strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == n;
}

int ext_key_add(const ext_env_t *env, const char *name, const char *text, size_t tlen, char *err, size_t elen)
{
    char path[400], tmp[420], id[65];
    if (!key_name_ok(name))
        return fail(err, elen, "a key's name is letters, digits, dash, underscore, and dot, at most 48 bytes");
    if (!text || tlen == 0 || tlen > 4096)
        return fail(err, elen, "a key is the text fwup writes, or its 32 raw bytes");
    snprintf(path, sizeof(path), "%.255s/keys/%.48s.pub", env->root, name);
    snprintf(tmp, sizeof(tmp), "%.255s/keys/.%.48s.pub.new", env->root, name);
    if (access(path, F_OK) == 0)
        return fail(err, elen, "a key called %s is already here", name);
    int fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0)
        return fail(err, elen, "cannot write %s: %s", tmp, strerror(errno));
    int ok = write(fd, text, tlen) == (ssize_t)tlen;
    close(fd);
    /* It is a key or it is not: what cannot be read as one never becomes a
     * trust anchor. */
    if (!ok || pkg_key_id(tmp, id) != 0) {
        unlink(tmp);
        return fail(err, elen, ok ? "that is no Ed25519 public key" : "cannot write the key");
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return fail(err, elen, "cannot put the key in place: %s", strerror(errno));
    }
    return 0;
}

int ext_key_remove(const ext_env_t *env, const char *name, char *err, size_t elen)
{
    char path[400];
    if (!key_name_ok(name))
        return fail(err, elen, "a key's name is letters, digits, dash, underscore, and dot, at most 48 bytes");
    snprintf(path, sizeof(path), "%.255s/keys/%.48s.pub", env->root, name);
    if (unlink(path) != 0)
        return fail(err, elen, "no key called %s is here", name);
    return 0;
}

json_t *ext_keys_json(const ext_env_t *env)
{
    char dir[340], path[400], id[65];
    json_t *arr = json_array();
    struct dirent **list = NULL;
    snprintf(dir, sizeof(dir), "%.255s/keys", env->root);
    int n = scandir(dir, &list, NULL, alphasort);
    for (int i = 0; i < n; i++) {
        size_t len = strlen(list[i]->d_name);
        if (list[i]->d_name[0] != '.' && len > 4 && strcmp(list[i]->d_name + len - 4, ".pub") == 0) {
            snprintf(path, sizeof(path), "%.339s/%.56s", dir, list[i]->d_name);
            json_t *j = json_object();
            json_object_set_new(j, "name", json_stringn(list[i]->d_name, len - 4));
            json_object_set_new(j, "key", json_string(pkg_key_id(path, id) == 0 ? id : ""));
            json_array_append_new(arr, j);
        }
        free(list[i]);
    }
    free(list);
    return arr;
}

int ext_set_enabled(const ext_env_t *env, const char *id, int on, char *err, size_t elen)
{
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int lock = ext_lock(env, err, elen), rc = -1;
    if (lock >= 0 && state_load(env->root, st, err, elen) == 0) {
        state_pkg_t *p = state_find(st, id);
        if (!p) {
            fail(err, elen, "%s is not installed", id);
        } else {
            p->enabled = on ? 1 : 0;
            if (on)
                p->quarantined = 0;
            rc = state_save(env->root, st, err, elen);
            if (rc == 0 && ext_required_holds_sync(env, st) != 0)
                rc = fail(err, elen, "the required holds under %s could not be made to match", env->root);
        }
    }
    ext_unlock(lock);
    free(st);
    return rc;
}

int ext_dest(const ext_env_t *env, const char *id, int add, const char *dest, char *err, size_t elen)
{
    char host[256];
    int port;
    manifest_t m;
    if (!dest || strlen(dest) >= CAP_MAX_LEN || caps_outbound_parse(dest, host, sizeof(host), &port) != 0)
        return fail(err, elen, "a destination is host:port, the host a lowercase DNS name, an IPv4 address, or an "
                               "IPv6 address in brackets");
    /* A numeric address is judged now; a name is judged by what it
     * resolves to when the service starts, and the table refuses the
     * machine whatever this says. */
    if (net_addr_is_self(host) == 1)
        return fail(err, elen, "%s is this machine: no package reaches the machine", host);
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int lock = ext_lock(env, err, elen), rc = -1;
    if (lock >= 0 && state_load(env->root, st, err, elen) == 0) {
        state_pkg_t *p = state_find(st, id);
        int at = -1;
        for (int i = 0; p && i < p->ndests; i++)
            if (strcmp(p->dests[i], dest) == 0)
                at = i;
        if (!p) {
            fail(err, elen, "%s is not installed", id);
        } else if (ext_manifest_of(env, id, &m, err, elen) != 0) {
            /* the words are the manifest's */
        } else if (!manifest_has_cap(&m, "net.outbound.operator")) {
            fail(err, elen, "%s does not ask for destinations of the operator's (net.outbound.operator)", id);
        } else if (add && at >= 0) {
            fail(err, elen, "%s is already one of its destinations", dest);
        } else if (add && p->ndests >= STATE_MAX_DESTS) {
            fail(err, elen, "the operator has named %d destinations for it, and that is the limit", STATE_MAX_DESTS);
        } else if (add && p->ndests + outbound_count(&m) >= EXT_DESTS_MAX) {
            fail(err, elen, "it has %d destinations, its manifest's and the operator's, and a service has at most %d",
                 p->ndests + outbound_count(&m), EXT_DESTS_MAX);
        } else if (!add && at < 0) {
            fail(err, elen, "%s is not one of the destinations the operator named for it", dest);
        } else {
            if (add) {
                snprintf(p->dests[p->ndests++], sizeof(p->dests[0]), "%s", dest);
            } else {
                for (int i = at; i + 1 < p->ndests; i++)
                    memcpy(p->dests[i], p->dests[i + 1], sizeof(p->dests[0]));
                p->ndests--;
            }
            rc = state_save(env->root, st, err, elen);
        }
    }
    ext_unlock(lock);
    free(st);
    return rc;
}

int ext_set_hold_required(const ext_env_t *env, const char *id, int on, char *err, size_t elen)
{
    state_t *st = calloc(1, sizeof(*st));
    if (!st)
        return fail(err, elen, "out of memory");
    int lock = ext_lock(env, err, elen), rc = -1;
    if (lock >= 0 && state_load(env->root, st, err, elen) == 0) {
        state_pkg_t *p = state_find(st, id);
        if (!p) {
            fail(err, elen, "%s is not installed", id);
        } else if (!state_granted(p, "hold")) {
            fail(err, elen, "%s has no hold: the operator did not grant it one", id);
        } else {
            p->hold_required = on ? 1 : 0;
            rc = state_save(env->root, st, err, elen);
            if (rc == 0 && ext_required_holds_sync(env, st) != 0)
                rc = fail(err, elen, "the required holds under %s could not be made to match", env->root);
        }
    }
    ext_unlock(lock);
    free(st);
    return rc;
}
