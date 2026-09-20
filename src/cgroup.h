/*
 * cgroup.h - one cgroup v2 group per running package, under the image's ffx group
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The image mounts cgroup v2 and hands the cpu, memory, and pids
 * controllers down to /sys/fs/cgroup/ffx, which is idle-class as a whole
 * (forgefirm-sandbox). This file makes a group per package under it, sets
 * its limits before anything runs there, and freezes, kills, and removes
 * it. Nothing here touches the root group, where the firmware lives.
 */
#ifndef FORGEEXT_CGROUP_H
#define FORGEEXT_CGROUP_H

#include <stddef.h>
#include <sys/types.h>

#define CG_PARENT_DEFAULT "/sys/fs/cgroup/ffx"

typedef struct {
    int cpu_pct;                /* cpu.max as a percentage of the core; 0 = no limit */
    long long memory_bytes;     /* memory.max; 0 = no limit */
    int pids;                   /* pids.max; 0 = no limit */
} cg_limits_t;

/* Is the parent what the image promises: a cgroup v2 group with cpu,
 * memory, and pids handed down to its children? 0, or -1 with words. */
int cg_ready(const char *parent, char *err, size_t elen);

/* Make (or reuse, when empty) the package's group and set its limits.
 * A group that still holds a process is refused: it is somebody's. */
int cg_create(const char *parent, const char *id, const cg_limits_t *lim, char *err, size_t elen);

int cg_limits(const char *parent, const char *id, const cg_limits_t *lim, char *err, size_t elen);
int cg_add(const char *parent, const char *id, pid_t pid);

/* Freeze or thaw, and wait (bounded) until the kernel says it is so. */
int cg_freeze(const char *parent, const char *id, int on);
int cg_frozen(const char *parent, const char *id);          /* 1, 0, or -1 */

int cg_populated(const char *parent, const char *id);       /* 1, 0, or -1 when there is no group */
long long cg_event(const char *parent, const char *id, const char *file, const char *key);

/* Kill every process in the group (cgroup.kill, which reaches a frozen
 * one too), wait until it is empty, and remove it. 0 when it is gone. */
int cg_destroy(const char *parent, const char *id);

#endif
