/*
 * install.h - an archive becomes an installed package, or is refused
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The extension root (/data/forgefirm/ext on the machine):
 *
 *   pkg/<id>/<version>/        the package's files, root-owned, never written again
 *   pkg/<id>/<version>.files   what was unpacked: hash, mode, size, path
 *   pkg/<id>/current           -> <version>
 *   data/<id>/                 a service's own data, owned by its account
 *   keys/                      public keys the owner added
 *   tmp/                       staging, this daemon's alone
 *   state.json
 */
#ifndef FORGEEXT_INSTALL_H
#define FORGEEXT_INSTALL_H

#include <stddef.h>

#include "manifest.h"
#include <jansson.h>

#include "pkg.h"
#include "state.h"

#define EXT_ROOT_DEFAULT      "/data/forgefirm/ext"
#define EXT_ROOT_MAX          255                       /* bytes; every path under it is built to fit */
#define EXT_BUDGET_DEFAULT    (256LL * 1024 * 1024)    /* every installed package together */
/* The updater may hold a 256 MiB transfer twice; an install never takes
 * the free space under that, with a margin. */
#define EXT_RESERVE_DEFAULT   (576LL * 1024 * 1024)

typedef struct {
    const char *root;
    pkg_trust_t trust;
    long long budget_bytes;
    long long reserve_bytes;
    /* This firmware's version, for a package's "core" range. A release
     * image writes a version here (0.0.7); a dev image writes its build
     * stamp, which is no version at all, and then the range cannot be
     * judged and is not. */
    char core_version[33];
} ext_env_t;

#define EXT_VERSION_FILE "/etc/forgefirm-version"

/* The firmware's version as EXT_VERSION_FILE has it, or "" when the file
 * says nothing. What it holds may be a version or a build stamp; telling
 * them apart is manifest_version_ok()'s job. */
void ext_read_core_version(char *out, size_t olen);

typedef struct {
    const char *grants[MANIFEST_MAX_CAPS];  /* what the operator granted, of the capabilities that need it */
    int ngrants;
    int consent_community;                  /* the operator typed the consent for a community package */
    int consent_unverified;                 /* the button was held for an unverified one */
} install_opts_t;

typedef struct {
    manifest_t manifest;
    pkg_info_t info;
    pkg_tree_t tree;
    int update;                             /* a version of this id is installed */
    int core_checked;                       /* the "core" range was judged: 0 when this firmware has no version to judge it by */
    int downgrade;
    char from_version[33];
    char needs_grant[MANIFEST_MAX_CAPS][CAP_MAX_LEN];   /* asked for, needs the operator's grant */
    int nneeds;
    char new_caps[MANIFEST_MAX_CAPS][CAP_MAX_LEN];      /* asked for and not held by the installed version */
    int nnew;
} install_result_t;

void ext_env_defaults(ext_env_t *env);

/* Make the root's directories (0755; tmp 0700). */
int ext_root_prepare(const ext_env_t *env, char *err, size_t elen);

/* Can a package's account walk to its files? Every directory from / down
 * to the root, and the root's pkg and data, must let others through (the
 * search bit); landlock, not the mode of a parent, is what keeps a service
 * out of everything that is not its own. -1 with the directory that does
 * not. */
int ext_root_reachable(const ext_env_t *env, char *err, size_t elen);

/* Everything an install checks short of the operator's consent and
 * grants, with nothing left behind: what the panel shows before it asks. */
int ext_inspect(const ext_env_t *env, const char *file, install_result_t *res, char *err, size_t elen);

int ext_install(const ext_env_t *env, const char *file, const install_opts_t *opts,
                install_result_t *res, char *err, size_t elen);

/* Remove a package and, unless keep_data, its data. */
int ext_remove(const ext_env_t *env, const char *id, int keep_data, char *err, size_t elen);

/* An installed package's manifest, from its current version. */
int ext_manifest_of(const ext_env_t *env, const char *id, manifest_t *m, char *err, size_t elen);

/* Does an installed package's tree still match what was installed? */
int ext_check(const ext_env_t *env, const state_pkg_t *p, char *err, size_t elen);

/* One writer of the root at a time: the command line and the daemon both
 * change state.json and what is under pkg/. The lock is a file of the
 * root held with flock; ext_install and ext_remove take it themselves.
 * The descriptor, or -1. */
int ext_lock(const ext_env_t *env, char *err, size_t elen);
void ext_unlock(int lock);

/* The daemon's two writes, each under the lock. A package that has run
 * healthy once gives up the version it replaced; a package the supervisor
 * gave up on is remembered as quarantined (and let out by quarantined=0). */
int ext_drop_previous(const ext_env_t *env, const char *id, char *err, size_t elen);
int ext_set_quarantined(const ext_env_t *env, const char *id, int on, char *err, size_t elen);

/* The owner's keys: the trust anchor the owner may replace. A key file
 * under <root>/keys is what makes a package community rather than
 * unverified, so adding one is the operator's own act (forgectrl asks for
 * the machine's button to be held, as for unsigned firmware).
 *
 * name is what the key is called: letters, digits, dash, underscore, dot,
 * at most 48 bytes, no path. text is the key as fwup writes it (base64) or
 * 32 raw bytes; it is parsed before it is written, so a file that is no
 * Ed25519 public key never lands. 0, or -1 with the words. */
int ext_key_add(const ext_env_t *env, const char *name, const char *text, size_t tlen, char *err, size_t elen);
int ext_key_remove(const ext_env_t *env, const char *name, char *err, size_t elen);

/* The keys, as a JSON array of {"name", "key"} (the key's id, as a
 * package's "key" names it). NULL on failure. */
json_t *ext_keys_json(const ext_env_t *env);

/* The operator's switch for one package. A package that is disabled keeps
 * its files, its data, its grants, and its account; its service is
 * stopped and its hold, of either kind, is gone: that is the operator's
 * exit. Enabling it again also lets it out of quarantine, because the
 * operator has looked at it. */
int ext_set_enabled(const ext_env_t *env, const char *id, int on, char *err, size_t elen);

/* Mark a package's hold required or advisory. Only a package that has the
 * operator's hold grant has a hold to mark. */
int ext_set_hold_required(const ext_env_t *env, const char *id, int on, char *err, size_t elen);

/* <root>/required-holds holds one empty file named after each enabled
 * package whose hold is granted and marked required, and nothing else.
 * forgectrl reads the names: a required hold nobody speaks for (no host
 * since the boot) stands. Made to match the state, by every command that
 * changes it and by the host on every turn. */
int ext_required_holds_sync(const ext_env_t *env, const state_t *st);

#endif
