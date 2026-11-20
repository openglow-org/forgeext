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
#define RUN_SHUTDOWN_GRACE_S 1.0                /* ext.shutdown's time to be read, on the machine */

typedef struct {
    ext_env_t ext;
    machine_cfg_t machine;
    net_env_t net;
    const char *cg_parent;
    const char *run_dir;                        /* status.json */
    const char *holds_dir;                      /* the hold files forgectrl's cooling engine reads */
    const char *senders_dir;                    /* the claims on the Grbl sender forgectrl reads */
#define RUN_SENDERS_DIR_DEFAULT "/run/forgefirm/sender-out"
    const char *api_dir;                        /* one API socket per running service */
    const char *call_dir;                       /* one call socket per running service that has a page */
    int landlock_fs_only;                       /* a kernel older than landlock's TCP rules (tests on a host) */
    int ticks;                                  /* stop after this many seconds; 0 runs until a signal */
    double shutdown_grace_s;                    /* ext.shutdown's time to be read when extensions go off or safe
                                                 * mode begins, the turns running through it: RUN_SHUTDOWN_GRACE_S;
                                                 * a host test holds it open longer. The host's own stop always
                                                 * waits RUN_SHUTDOWN_GRACE_S */
} run_cfg_t;

void run_cfg_defaults(run_cfg_t *cfg);

/* Runs until SIGTERM or SIGINT, then stops every service. The exit status. */
int run_daemon(const run_cfg_t *cfg);

/* <run_dir>/status.json written whole with text, at any size, by a rename
 * from a file beside it: a reader sees the last whole word or this one. 0,
 * or -1 with the file as it was. */
int run_status_file(const char *run_dir, const char *text);

/* A predecessor due to go, booked at its successor's healthy mark: the one
 * the record named, and the stamp of the install that ran healthy. */
typedef struct {
    char id[64], previous[33], stamp[17];
} run_drop_t;

/* The removals put off, after a try at id's predecessor previous for the
 * install stamped stamp: a try the root's lock put off (busy) keeps one
 * entry for the package, the latest in place of an earlier one; a try
 * that ends any other way takes the package's entry out. *n entries in
 * due, at most max. */
void run_drop_due(run_drop_t due[], int *n, int max, const char *id, const char *previous, const char *stamp, int busy);

/* Whether a turn takes up the removals due, after its judgment: only one
 * of a running host whose armed window reads closed (armed 0), with
 * extensions on or inside their grace (enabled, the turn's own inputs).
 * A window open or that cannot be read (armed 1 or -1), extensions off,
 * and the last pass after a TERM (stopping) put them off: a tree walked
 * there would make the next freeze late by its time. */
int run_drops_now(int enabled, int armed, int stopping);

/* The host's word on the armed window, in status.json at the end of every
 * turn; forgectrl's cooling engine reads it before it acknowledges a
 * window. "window" names the open window the host has frozen or held every
 * service for, with no turn since that could have started or thawed one;
 * "quiet" says no service runs and none starts before the file says
 * otherwise.
 *
 * run_window_word: the window a turn leaves named, from the one named
 * before (word), whether the turn was judged (judged: not the last pass
 * after a TERM), and the turn's own inputs (enabled, armed, window). A
 * judged turn that read the window open names it; one that read it closed,
 * or did not judge, names none (0); one that could not read it froze every
 * service and keeps the word it had. */
unsigned long long run_window_word(unsigned long long word, int judged, int enabled, int armed,
                                   unsigned long long window);

/* run_quiet: no service running, and none waiting to start or extensions
 * off (the turn's enabled). run_may_start: a turn starts a service only
 * while the status file in force does not say quiet, so a quiet word on
 * file never stands while a service starts. */
int run_quiet(int running, int waiting, int enabled);
int run_may_start(int may_start, int file_quiet);

/* What a service runs with, as the supervisor compares it (svc_t's
 * conf_wanted and conf_started): its install and the operator's
 * destinations. */
unsigned long long run_conf_digest(const state_pkg_t *p);

/* The record whose predecessor goes when id's service has run healthy:
 * id's in st, when it names a predecessor and is still what the service
 * was started from (started, its conf_started). NULL otherwise: a record
 * written since that start is of an install that has not run, and the
 * predecessor it names is the version still running. */
const state_pkg_t *run_healthy_record(state_t *st, const char *id, unsigned long long started);

#endif
