/*
 * install.c - an archive becomes an installed package, or is refused
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "install.h"

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
    env->trust.firmware_keys[0] = KEY_FW_RELEASE;
    env->trust.firmware_keys[1] = KEY_FW_FACTORY;
    env->budget_bytes = EXT_BUDGET_DEFAULT;
    env->reserve_bytes = EXT_RESERVE_DEFAULT;
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
    }
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
    if (rc == 0)
        rc = judge_exec(tree, &res->manifest, err, elen);
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
