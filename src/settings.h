/*
 * settings.h - a package's own settings: declared in its manifest, kept by the host
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A package's data directory is its own, and it could keep a file there
 * without asking anybody. These are the settings that are not only its
 * own business: the ones the operator is shown and may change, and the
 * ones that must survive the package being updated or reinstalled. They
 * are never keys of forgefirm.conf, and a package can reach no key but
 * the ones its own manifest declares.
 *
 * The manifest is the schema (manifest.h): each key's type, its bounds,
 * and what it is before anybody sets it. The values live in one file per
 * package under <root>/settings/<id>.json, owned by root at 0600 - the
 * package reads and writes them through its API socket and never touches
 * the file, so a package cannot put in what its own schema refuses.
 *
 * A write is all or nothing. A patch naming one key the schema does not
 * declare, or one value that does not fit, changes none of them: half an
 * applied patch is a state the package never asked for.
 */
#ifndef FORGEEXT_SETTINGS_H
#define FORGEEXT_SETTINGS_H

#include <jansson.h>
#include <stddef.h>

#include "manifest.h"

#define SETTINGS_DIR      "settings"
#define SETTINGS_MAX_FILE (16 * 1024)

/* Is v a value this setting takes? 0, or -1 with the words in err. */
int setting_value_ok(const setting_t *t, json_t *v, char *err, size_t elen);

/* The value of one setting as the schema has it before anybody sets it. */
json_t *setting_default(const setting_t *t);

/* Every declared key with its value, the default filling anything unset
 * and anything the file holds that the schema no longer declares left
 * out - an update that drops a key drops its value with it. Never NULL
 * for a package with settings; an empty object for one without. */
json_t *settings_read(const char *root, const char *id, const manifest_t *m);

/* Apply a patch. 0, or -1 with the words in err and nothing written. */
int settings_write(const char *root, const char *id, const manifest_t *m, json_t *patch,
                   char *err, size_t elen);

/* The schema itself, for the operator's side: each key with its type,
 * its label, its bounds, and its default. */
json_t *settings_schema_json(const manifest_t *m);

/* The package is gone: its values go with it. */
void settings_forget(const char *root, const char *id);

#endif
