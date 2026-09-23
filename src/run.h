/*
 * run.h - forgeext run: the daemon that carries the supervisor's policy out
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#ifndef FORGEEXT_RUN_H
#define FORGEEXT_RUN_H

#include "api.h"
#include "call.h"
#include "evfeed.h"
#include "holdkeep.h"
#include "install.h"
#include "machine.h"
#include "netrules.h"
#include "quota.h"
#include "settings.h"

#define RUN_DIR_DEFAULT     "/run/forgefirm/ext"

/* What a service gets. The cap on how many run together is the policy's
 * (SUPER_MAX_RUNNING); these bound each one. */
#define RUN_CPU_PCT         25                  /* of the one core, outside an armed window */
#define RUN_JOB_CPU_PCT     3                   /* inside one, for a service the operator lets run through it */
#define RUN_MEMORY_BYTES    (48LL * 1024 * 1024)
#define RUN_PIDS            32

typedef struct {
    ext_env_t ext;
    machine_cfg_t machine;
    net_env_t net;
    const char *cg_parent;
    const char *run_dir;                        /* status.json */
    const char *holds_dir;                      /* the hold files forgectrl's cooling engine reads */
    const char *api_dir;                        /* one API socket per running service */
    const char *call_dir;                       /* one call socket per running service that has a page */
    int landlock_fs_only;                       /* a kernel older than landlock's TCP rules (tests on a host) */
    int ticks;                                  /* stop after this many seconds; 0 runs until a signal */
} run_cfg_t;

void run_cfg_defaults(run_cfg_t *cfg);

/* Runs until SIGTERM or SIGINT, then stops every service. The exit status. */
int run_daemon(const run_cfg_t *cfg);

#endif
