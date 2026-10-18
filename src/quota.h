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
 * Measuring costs a walk of the directory, so it is done on its own
 * cadence (QUOTA_EVERY_S), which is the longest a package writes
 * unmeasured, and only for services that are running. What is
 * counted is what the filesystem gives the files (their blocks), not the
 * sum of their apparent sizes: a package that makes one enormous sparse
 * file has taken nothing, and a package that makes ten thousand small
 * ones has taken more than their bytes. The entries are counted too: an
 * empty file takes no block and costs the quota nothing by its bytes,
 * and the machine's storage has a fixed number of inodes, so a package
 * may hold one file or directory per QUOTA_ENTRY_BYTES of its quota. The
 * bound on the entries also bounds the walk, which runs on the host's
 * one thread.
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
#include <sys/types.h>

#include "manifest.h"

#define QUOTA_DEFAULT_MIB 16        /* a service that asks for no storage */
#define QUOTA_EVERY_S     10.0      /* a package writes unmeasured for at most this long */
#define QUOTA_MAX_DEPTH   16        /* a tree deeper than this is not measured, and what is not measured sets the service aside */
/* One file or directory per this much of the quota: 4096 entries for the
 * default 16 MiB, 65536 for storage:256. */
#define QUOTA_ENTRY_BYTES 4096

/* What a package may hold, in bytes: its `storage:<MiB>`, or the default. */
long long quota_of(const manifest_t *m);

/* The bytes a directory's tree holds, by the blocks the filesystem gave
 * it. Symbolic links are counted as links and never followed, so a link
 * out of the directory adds nothing and cannot be walked; a directory
 * that becomes a link while it is measured is not followed either, since
 * the walk goes by descriptors and never by a path it built. -1, with
 * the reason in err, when the measurement did not complete: the
 * directory (or the path given, if it is a link) or one under it cannot
 * be read, an entry cannot be examined for a reason other than its being
 * gone, an entry changed while it was measured, the tree is deeper than
 * QUOTA_MAX_DEPTH, or it holds more than max_entries files and
 * directories together (the quota over QUOTA_ENTRY_BYTES). What is not
 * measured is never taken for nothing. */
long long quota_dir_bytes(const char *path, long long max_entries, char *err, size_t elen);

/* The most files one package's processes can hold open together: 32
 * processes (RUN_PIDS), each under the sandbox's RLIMIT_NOFILE of 256.
 * Past this many, a file held open more than once is counted again
 * rather than not at all: counting twice is the closed side. */
#define QUOTA_OPEN_MAX (32 * 256)

/* What a service holds open or mapped after unlinking it is counted too,
 * by the descriptors and the mappings of its processes: a name is not
 * what takes the space, and a file with no name for the walk to find
 * holds its blocks until the last descriptor on it is closed and the
 * last mapping of it is gone. The bytes, by their blocks, of the regular
 * files under the data directory that the processes given hold open or
 * mapped unlinked, each read from /proc/<pid>/fd and /proc/<pid>/maps
 * (the mapped file itself through /proc/<pid>/map_files, which the
 * kernel lets root follow), a file held more than once counted once by
 * its inode. A process that is gone holds nothing. -1, with the reason,
 * when a process's open files or mappings cannot be read or examined
 * for a reason other than its ending. What is not seen: a descriptor in
 * flight in a socket's queue, sent and never received, has no entry
 * under /proc; the partition's root reserve is the floor under that. */
long long quota_open_bytes(const char *data, const pid_t *pids, int n, char *err, size_t elen);

#endif
