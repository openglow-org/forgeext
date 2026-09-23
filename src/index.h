/*
 * index.h - the signed index: the packages OpenGlow lists, and the author keys it endorses
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The index is an archive of the extension container's own form, with the
 * product "ForgeFIRM extension index", signed with the OpenGlow extension
 * key and by nothing else, holding one file, index.json. It lists packages
 * - each one's id, what it is, where to fetch it, its SHA-256 and size -
 * and binds an id to its author's public key. A package signed by that key
 * for that id reads as community on a machine whose owner never added the
 * key; for any other id the key counts for nothing.
 *
 * The machine fetches it only when the operator asks (forgectrl), and the
 * host keeps the last one it verified under <root>/index: index.json as
 * verified, and keys/<id>.pub for each endorsed key.
 */
#ifndef FORGEEXT_INDEX_H
#define FORGEEXT_INDEX_H

#include <jansson.h>
#include <stddef.h>

#include "install.h"

#define INDEX_SCHEMA     1
#define INDEX_MAX_PKGS   256
#define INDEX_MAX_BYTES  (1024 * 1024)

/* Is the document an index in form: every entry, ids unique, a key where
 * one is needed and none where it may not be. 0, or -1 with the words. */
int index_check(json_t *doc, char *err, size_t elen);

/* Verify the index archive, and when it holds, keep it as the one this
 * host knows (it replaces the last). The number of packages it lists into
 * *npkgs and its version into version. 0, or -1 with the words. */
int index_install(const ext_env_t *env, const char *file, int *npkgs, char *version, size_t vlen, char *err,
                  size_t elen);

/* The index this host keeps: its document with "version", or NULL when it
 * keeps none. */
json_t *index_read(const ext_env_t *env);

/* The directory of endorsed keys, for pkg_trust_t.endorsed_dir. */
void index_keys_dir(const ext_env_t *env, char *out, size_t len);

#endif
