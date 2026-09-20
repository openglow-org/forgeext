/*
 * pkg.h - an extension archive (.ffx): who signed it, what is in it, and
 *         its payload unpacked where nothing in it can reach outside
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * An .ffx is an fwup archive: a ZIP whose first entries are
 * meta.conf.ed25519 (the signature, absent when unsigned) and meta.conf,
 * followed by data/payload.tar.gz, the one resource. Firmware is the same
 * container, so the verifier is a product gate first: it takes
 * "ForgeFIRM extension" and nothing else, no archive that lists a task
 * (a task is what fwup would write to a disk), and no archive whose only
 * valid signature is a firmware key's.
 *
 * The bytes that are parsed are the bytes that were verified: the
 * signature is checked here, with libsodium, over the meta.conf this
 * reader took from the archive, and the payload is hashed against the
 * blake2b-256 that same meta.conf names. fwup is asked as well (-m, -l,
 * -V), because it is the program a firmware archive would be handed to,
 * and its reading of the metadata must agree with this one.
 */
#ifndef FORGEEXT_PKG_H
#define FORGEEXT_PKG_H

#include <stddef.h>

#define PKG_PRODUCT          "ForgeFIRM extension"
#define PKG_MAX_ARCHIVE      (32LL * 1024 * 1024)   /* the .ffx itself */
#define PKG_MAX_UNPACKED     (64LL * 1024 * 1024)   /* every file of the payload together */
#define PKG_MAX_FILE         (32LL * 1024 * 1024)
#define PKG_MAX_FILES        4096
#define PKG_MAX_DEPTH        16
#define PKG_MAX_PATH         192
#define PKG_MAX_META         (64 * 1024)
#define PKG_MAX_KEYS         32

typedef enum {
    TIER_UNVERIFIED = 0,    /* no key this machine trusts */
    TIER_COMMUNITY,         /* a key the owner added */
    TIER_OFFICIAL,          /* the OpenGlow extension key in the image */
} pkg_tier_t;

typedef struct {
    const char *fwup;               /* the fwup binary; NULL is "fwup" on PATH */
    const char *official_key;       /* the image's extension public key; NULL or absent file: no official tier */
    const char *owner_keys_dir;     /* owner-added public keys (*.pub); may be NULL */
    const char *firmware_keys[4];   /* files or directories of keys that sign firmware, NULL-ended */
} pkg_trust_t;

typedef struct {
    pkg_tier_t tier;
    char key_id[65];                /* blake2b-256 of the verifying key's 32 bytes, hex; "" when unverified */
    char key_file[256];             /* that key's path; "" when unverified */
    char version[33];               /* meta-version */
    char payload_b2[65];            /* blake2b-256 of payload.tar.gz, from the verified meta.conf */
    long long payload_len;
} pkg_info_t;

typedef struct {
    int files, dirs;
    long long bytes;
} pkg_tree_t;

const char *pkg_tier_name(pkg_tier_t t);

/* Verify archive `file` and, when out_payload is not NULL, write its
 * payload.tar.gz there (0600), hashed against the verified metadata as
 * it is written. 0, or -1 with the words in err; on failure no payload
 * file is left behind. */
int pkg_open(const pkg_trust_t *trust, const char *file, const char *out_payload,
             pkg_info_t *info, char *err, size_t elen);

/* Unpack payload.tar.gz into dest, a directory that exists and is empty.
 * Regular files and directories only, every path inside dest, modes
 * reduced to 0644, 0755, and 0755 for directories, within the limits
 * above. The list of what was written (hash, mode, size, path per line,
 * sorted by path) goes to list_path. */
int pkg_unpack(const char *payload, const char *dest, const char *list_path,
               pkg_tree_t *tree, char *err, size_t elen);

/* Does the tree under dir still match the list pkg_unpack wrote? Every
 * listed file present with its hash and mode, and nothing else there. */
int pkg_tree_check(const char *dir, const char *list_path, char *err, size_t elen);

/* blake2b-256 of a public key file's 32 key bytes, hex; 0 or -1. */
int pkg_key_id(const char *key_file, char out[65]);

/* Remove a directory tree (the unpack's own cleanup; also used for a
 * package's removal). Never follows a symbolic link. */
int pkg_rmtree(const char *dir);

#endif
