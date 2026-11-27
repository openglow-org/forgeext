/*
 * holdkeep.h - the holds packages have on a job: decided here, kept here
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A package with the operator's hold grant may withhold fire, never permit
 * it. The host owns the hold, not the package: a package that is frozen for
 * the job changes nothing about what it said before the job. forgectrl's
 * cooling engine reads one file per package under the holds directory,
 *
 *   {"id": "...", "required": true, "raised": false, "reason": "...", "ts_mono": 1234.567}
 *
 * and takes a file older than two seconds as a host that is not answering:
 * a required hold then stands whatever it last said, an advisory one is
 * dropped. So the files are rewritten twice a second by a thread that does
 * nothing else, and the thread writes only while the main loop is alive
 * (it has spoken within HOLDKEEP_MAIN_S): a turn that takes a few seconds
 * does not pause anybody's job, and a loop that hangs lets every hold go
 * stale, which is the truth.
 *
 * What the host says for a package (hold_decide):
 *
 *   advisory   it runs: what the package last said (nothing yet: clear).
 *              It should run and does not: clear, and the caller is told
 *              the hold was dropped.
 *   required   it runs and has run healthy: what the package last said.
 *              Anything less is a package that cannot speak for itself,
 *              and the host raises the hold in its own words: "the
 *              extension is not running", or, for one that has started and
 *              not yet run healthy, "the extension has only just started".
 *              A package that ends at every start reads as running for a
 *              moment each time, and a required hold must not flicker clear
 *              with it.
 *
 * A package that should not run (disabled, the other controller mode),
 * extensions off, and safe mode have no file at all: those are the
 * operator's exits.
 */
#ifndef FORGEEXT_HOLDKEEP_H
#define FORGEEXT_HOLDKEEP_H

#include <pthread.h>

#define HOLDKEEP_DIR_DEFAULT    "/run/forgefirm/holds"
#define HOLDKEEP_MAX            32
#define HOLDKEEP_PERIOD_MS      500
#define HOLDKEEP_MAIN_S         15.0        /* the main loop's longest honest turn is well under it */
#define HOLDKEEP_REASON_MAX     96

typedef struct {
    char id[64];
    int required, raised;
    char reason[HOLDKEEP_REASON_MAX];
} hold_entry_t;

/* One package's hold. said_raised and said_reason are what the package last
 * told the host. Returns 1 when an advisory hold was dropped because the
 * package is not running. */
int hold_decide(const char *id, int required, int running, int healthy, int said_raised, const char *said_reason,
                hold_entry_t *out);

typedef struct {
    pthread_mutex_t mu;
    pthread_t thread;
    int started, stop;
    char dir[256];
    double main_s;                  /* how long the main loop may be silent */
    double main_seen;               /* when it last spoke (CLOCK_MONOTONIC) */
    hold_entry_t e[HOLDKEEP_MAX];
    int n;
} holdkeep_t;

/* Make the directory and start the thread. What a previous host left stays
 * until the first holdkeep_set() has spoken for it: a required hold that
 * went stale with that host stands until this one says otherwise. 0, or -1
 * with the words. */
int holdkeep_start(holdkeep_t *k, const char *dir, double main_s, char *err, size_t elen);

/* The main loop's word, once a turn: these are the holds, and I am alive.
 * A file whose package is no longer named is removed before this returns. */
void holdkeep_set(holdkeep_t *k, const hold_entry_t *e, int n);

/* Stop the thread. The advisory files are removed; the required ones are
 * left to go stale, because a host that is gone is what a required hold
 * fails closed on, however it went. Turning extensions off and safe mode
 * end them in forgectrl without any host. */
void holdkeep_stop(holdkeep_t *k);

/* A raise that does not wait for the main loop's next turn: the entry the
 * last holdkeep_set() named for id is raised, in these words unless it
 * already stood raised, and its file is written before this returns. Only
 * toward raised, and only for an entry the table already has: which
 * packages have a file (enabled, in this controller mode, extensions on)
 * is the turn's to say, and so is a clear, which must pass hold_decide().
 * 1 when the entry was there, 0 when it was not (nothing is written). */
int holdkeep_raise(holdkeep_t *k, const char *id, const char *reason);

/* A claim taken now (the sender-out files, which share this form): the
 * entry for id is added if the table lacks it, raised, and written before
 * this returns. The next holdkeep_set() keeps it or takes it away. 0, or
 * -1 when the table is full or the keeper is stopping. */
int holdkeep_claim(holdkeep_t *k, const char *id, const char *reason);

/* The required-hold marker of one package (install.h's directory): its
 * name is the package's id, and it holds the controller modes the package
 * runs in, "grbl", "cloud" or "grbl cloud", one line. forgectrl lets a
 * marker go unread while the controller it runs is one the marker does not
 * name; a marker with no modes in it (modes not known) stands in every
 * mode. Written whole (a new file renamed over the old). 0, or -1. */
int holdkeep_marker_write(const char *dir, const char *id, int grbl, int cloud);

#endif
