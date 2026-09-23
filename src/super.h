/*
 * super.h - which services run, when, and frozen or not: the policy
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The supervisor's decisions, apart from what carries them out. It is a
 * step function over the machine's facts and a clock, and everything it
 * does to the world goes through super_ops_t, so the rules can be run
 * against fakes:
 *
 *   Nothing runs unless extensions are on (the master switch, no safe mode).
 *   A service starts only when the machine says it may (the controller up,
 *     motion verified, no diagnostic, no flash), never inside an armed
 *     window, one at a time and SUPER_STAGGER_S apart, and at most
 *     SUPER_MAX_RUNNING together.
 *   While the armed window is open every service is frozen, and thawed
 *     when it closes. A window whose state cannot be read is an open one.
 *     The operator's job_time.run grant lifts the freeze and nothing else:
 *     such a service runs on under job-time limits instead, and falls back
 *     to the freeze when those limits will not take.
 *   A service that cannot be frozen for the window is quarantined, not
 *     left running: the freeze is what keeps a package off the step
 *     stream, and one that will not take is a defect and not a passing
 *     condition. A thaw that fails is said and tried again.
 *   A service that ends is started again after a backoff that doubles from
 *     1 s to 30 s. One that ran SUPER_HEALTHY_S is healthy: its backoff
 *     starts over, and its predecessor version may go. One that ends
 *     SUPER_QUARANTINE_CRASHES times inside SUPER_QUARANTINE_WINDOW_S
 *     without getting that far is quarantined, and stays so until the
 *     operator says otherwise. A start that fails is a crash.
 *   A service that should not run (disabled, removed, quarantined, the
 *     wrong controller mode, extensions off) is stopped; its end is not a
 *     crash.
 *   A service whose version or whose operator's destinations changed is
 *     stopped and started again, outside an armed window; that is not a
 *     crash either.
 */
#ifndef FORGEEXT_SUPER_H
#define FORGEEXT_SUPER_H

#include <stddef.h>
#include <sys/types.h>

#define SUPER_MAX_SERVICES          32
#define SUPER_MAX_RUNNING           4
#define SUPER_STAGGER_S             5.0
#define SUPER_HEALTHY_S             60.0
#define SUPER_BACKOFF_MIN_S         1.0
#define SUPER_BACKOFF_MAX_S         30.0
#define SUPER_QUARANTINE_CRASHES    5
#define SUPER_QUARANTINE_WINDOW_S   600.0
/* Turns a service gets to take the window's posture before it is set
 * aside. A group is frozen in milliseconds; this is for the one that is
 * slow, not for the one that cannot be. */
#define SUPER_POSTURE_TRIES         3

typedef enum { SVC_STOPPED = 0, SVC_RUNNING, SVC_BACKOFF, SVC_QUARANTINED } svc_state_t;

typedef struct {
    char id[64];
    int slot;                           /* the pool account */
    int job_time;                       /* the operator granted job_time.run */
    int hold, hold_required;            /* the operator granted it a hold, and marked it required */
    int pkg_enabled;                    /* enabled by the operator, quarantined or not */
    int mode_grbl, mode_cloud;          /* the controller modes it runs in */
    unsigned long mcodes;               /* the M-codes it answers: bit n for M(CAPS_MCODE_MIN + n) */
    int present;                        /* the package is installed (set by every sync) */
    int wanted;                         /* enabled and not quarantined (from state.json) */

    svc_state_t state;
    pid_t pid;
    int frozen, job_limited, healthy;
    int posture_tries;                  /* turns spent trying to take the open window's posture */
    /* What it runs with, as a digest: its version and the destinations
     * the operator named. The sync sets the one wanted; a start records
     * it; a running service whose two differ is stopped and started again
     * outside an armed window, and that is no crash. */
    unsigned long long conf_wanted, conf_started;
    double started, next_start, backoff_s;
    double crashes[SUPER_QUARANTINE_CRASHES];
    int ncrashes;
    char reason[160];                   /* why it is not running, for the status file */
} svc_t;

typedef struct {
    int enabled;                        /* extensions are on: the master switch, and no safe mode */
    int may_start;                      /* the machine is in a state to take a new process */
    int armed;                          /* 1 open, 0 closed, -1 cannot tell */
    int mode_cloud;                     /* the controller mode now: 1 cloud, 0 grbl, -1 cannot tell */
    const char *off_reason;             /* why enabled is 0, for the status file */
} super_inputs_t;

typedef struct {
    pid_t (*start)(void *ctx, svc_t *s, char *err, size_t elen);    /* the pid, or -1 */
    void (*stop)(void *ctx, svc_t *s);                              /* kill, and take its group and its rules away */
    int (*freeze)(void *ctx, svc_t *s, int on);
    int (*job_limits)(void *ctx, svc_t *s, int on);
    void (*quarantine)(void *ctx, svc_t *s, const char *why);       /* remember it across restarts */
    void (*healthy)(void *ctx, svc_t *s);
    void (*log)(void *ctx, int prio, const char *text);
} super_ops_t;

typedef struct {
    svc_t svc[SUPER_MAX_SERVICES];
    int n;
    double last_start;
    const super_ops_t *ops;
    void *ctx;
} super_t;

void super_init(super_t *sv, const super_ops_t *ops, void *ctx);

/* The service for a package, made when new. NULL when the table is full.
 * A sync clears `present` everywhere, sets each installed package's facts
 * (present, slot, job_time, modes, wanted), and then forgets: a package
 * that is gone is unwanted at once, and leaves the table when it has
 * stopped. */
svc_t *super_service(super_t *sv, const char *id);
void super_sync_begin(super_t *sv);
void super_sync_end(super_t *sv);

void super_tick(super_t *sv, const super_inputs_t *in, double now);
void super_child_exited(super_t *sv, pid_t pid, int status, double now);
void super_stop_all(super_t *sv, const char *why);

/* Set one service aside for a reason of the caller's, as the supervisor
 * sets aside one that keeps ending: it is stopped, it is remembered as
 * quarantined across restarts, and the operator's enable is what lets it
 * out. 0 when there is no such running service. */
int super_quarantine(super_t *sv, const char *id, const char *why);

int super_running(const super_t *sv);
const char *super_state_name(svc_state_t s);

#endif
