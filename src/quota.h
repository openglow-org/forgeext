/*
 * quota.h - how much of the machine's storage a package's data may take
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * `storage:<MiB>` said what a package wanted and nothing kept it to it: a
 * package could fill /data and take the machine down with it, and the
 * number in its manifest was decoration. The host measures each running
 * service's data directory and sets aside one that is over.
 *
 * Measuring costs a walk of the directory, so it is done on its own slow
 * cadence (QUOTA_EVERY_S) and only for services that are running. What is
 * counted is what the filesystem gives the files (their blocks), not the
 * sum of their apparent sizes: a package that makes one enormous sparse
 * file has taken nothing, and a package that makes ten thousand small
 * ones has taken more than their bytes.
 *
 * A package that declares no `storage` still has a data directory, and it
 * gets QUOTA_DEFAULT_MIB. Declaring the capability raises it, to what it
 * asked for.
 *
 * Over its quota, a service is quarantined: stopped, remembered as
 * stopped across restarts, and shown to the operator with the reason. It
 * is not the host's place to delete a package's data, and the operator
 * has two ways out - remove the package, which takes its data with it, or
 * clear the data and enable the package again.
 */
#ifndef FORGEEXT_QUOTA_H
#define FORGEEXT_QUOTA_H

#include <stddef.h>

#include "manifest.h"

#define QUOTA_DEFAULT_MIB 16        /* a service that asks for no storage */
#define QUOTA_EVERY_S     30.0
#define QUOTA_MAX_DEPTH   16        /* deeper than this is not walked, and what is there is not counted */

/* What a package may hold, in bytes: its `storage:<MiB>`, or the default. */
long long quota_of(const manifest_t *m);

/* The bytes a directory's tree holds, by the blocks the filesystem gave
 * it. Symbolic links are counted as links and never followed, so a link
 * out of the directory adds nothing and cannot be walked. -1 when the
 * directory cannot be read at all. */
long long quota_dir_bytes(const char *path);

#endif
