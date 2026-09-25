/*
 * index.h - the signed index: the packages OpenGlow lists, and the author keys it endorses
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The index is an archive of the extension container's own form, with the
 * product "ForgeFIRM extension index", signed with the OpenGlow extension
 * key and by nothing else, holding one file, index.json. It lists packages
 * - each one's id, what it is, and every listed version of it with where
 * to fetch it, its SHA-256 and size, and the firmware it runs on - and
 * binds an id to its author's public key. A package signed by that key for
 * that id reads as community on a machine whose owner never added the key;
 * for any other id the key counts for nothing. It also names what OpenGlow
 * withdrew: one version of a listed package, or a whole package.
 *
 * One index serves every firmware. Keeping it judges only its form, which
 * never changes for schema 1, and a field this host does not know is
 * passed over; whether a version runs on this firmware (its range, its
 * extension API, its capabilities, its size) is judged when the index is
 * read, so a newer catalog never stops an older machine from keeping it,
 * and a firmware update needs no fetch to see what it now runs.
 *
 * The machine fetches it only when the operator asks (forgectrl), and the
 * host keeps the last one it verified under <root>/index: index.json as
 * verified, and keys/<id>.pub for each endorsed key. An index older than
 * the one kept is refused: the catalog never goes back.
 */
#ifndef FORGEEXT_INDEX_H
#define FORGEEXT_INDEX_H

#include <jansson.h>
#include <stddef.h>

#include "install.h"

#define INDEX_SCHEMA         1
#define INDEX_MAX_PKGS       512         /* listed packages, and packages withdrawn whole */
#define INDEX_MAX_VERSIONS   16          /* listed versions of one package */
#define INDEX_MAX_WITHDRAWN  64          /* withdrawn versions of one package */
#define INDEX_MAX_CAPS       64          /* one version's capabilities, judged in form when kept */
#define INDEX_MAX_BYTES      (1024 * 1024)

/* Is the document an index in form: every entry, ids unique, a key where
 * one is needed and none where it may not be, each version once. 0, or -1
 * with the words. */
int index_check(json_t *doc, char *err, size_t elen);

/* Verify the index archive, and when it holds and is not older than the
 * one kept, keep it as the one this host knows (it replaces the last). The
 * number of packages it lists into *npkgs and its version into version. 0,
 * or -1 with the words. */
int index_install(const ext_env_t *env, const char *file, int *npkgs, char *version, size_t vlen, char *err,
                  size_t elen);

/* The index this host keeps: its document with "version", or NULL when it
 * keeps none. */
json_t *index_read(const ext_env_t *env);

/* The kept document judged against this firmware, in place: each version
 * gets "usable" and, when it is not, "why"; each package gets "offer", the
 * newest usable version, or null. */
void index_judge(const ext_env_t *env, json_t *doc);

/* What the kept document says about an archive or an installed package:
 * INDEX_NOT_WITHDRAWN, or INDEX_VERSION_WITHDRAWN / INDEX_PACKAGE_WITHDRAWN
 * with OpenGlow's reason (maybe empty). A withdrawal names the listed
 * package: its id, signed by the key the index names for it (key_id), or
 * with the OpenGlow extension key in OpenGlow's own namespace (official).
 * An archive of that id under anyone else's key is another package. */
enum { INDEX_NOT_WITHDRAWN = 0, INDEX_VERSION_WITHDRAWN = 1, INDEX_PACKAGE_WITHDRAWN = 2 };
int index_withdrawn(json_t *doc, const char *id, const char *version, const char *key_id, int official, char *reason,
                    size_t rlen);

/* The directory of endorsed keys, for pkg_trust_t.endorsed_dir. */
void index_keys_dir(const ext_env_t *env, char *out, size_t len);

#endif
