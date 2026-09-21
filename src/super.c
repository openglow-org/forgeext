/*
 * super.c - which services run, when, and frozen or not: the policy
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#include "super.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>

static void say(super_t *sv, int prio, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void say(super_t *sv, int prio, const char *fmt, ...)
{
    char text[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    if (sv->ops->log)
        sv->ops->log(sv->ctx, prio, text);
}

const char *super_state_name(svc_state_t s)
{
    return s == SVC_RUNNING ? "running" : s == SVC_BACKOFF ? "waiting" : s == SVC_QUARANTINED ? "quarantined" : "stopped";
}

void super_init(super_t *sv, const super_ops_t *ops, void *ctx)
{
    memset(sv, 0, sizeof(*sv));
    sv->ops = ops;
    sv->ctx = ctx;
    sv->last_start = -1e9;
}

svc_t *super_service(super_t *sv, const char *id)
{
    for (int i = 0; i < sv->n; i++)
        if (strcmp(sv->svc[i].id, id) == 0)
            return &sv->svc[i];
    if (sv->n >= SUPER_MAX_SERVICES)
        return NULL;
    svc_t *s = &sv->svc[sv->n++];
    memset(s, 0, sizeof(*s));
    snprintf(s->id, sizeof(s->id), "%s", id);
    s->slot = -1;
    return s;
}

void super_sync_begin(super_t *sv)
{
    for (int i = 0; i < sv->n; i++)
        sv->svc[i].present = 0;
}

void super_sync_end(super_t *sv)
{
    for (int i = 0; i < sv->n;) {
        if (!sv->svc[i].present)
            sv->svc[i].wanted = 0;
        if (!sv->svc[i].present && sv->svc[i].state != SVC_RUNNING) {
            memmove(&sv->svc[i], &sv->svc[i + 1], (size_t)(sv->n - i - 1) * sizeof(sv->svc[0]));
            sv->n--;
        } else {
            i++;
        }
    }
}

int super_running(const super_t *sv)
{
    int n = 0;
    for (int i = 0; i < sv->n; i++)
        n += sv->svc[i].state == SVC_RUNNING;
    return n;
}

static void why(svc_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void why(svc_t *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s->reason, sizeof(s->reason), fmt, ap);
    va_end(ap);
}

/* A deliberate stop: not a crash, and no backoff. */
static void stop(super_t *sv, svc_t *s, const char *reason)
{
    if (s->state == SVC_RUNNING) {
        say(sv, LOG_NOTICE, "%s: stopping (%s)", s->id, reason);
        sv->ops->stop(sv->ctx, s);
    }
    if (s->state != SVC_QUARANTINED)
        s->state = SVC_STOPPED;
    s->pid = 0;
    s->frozen = s->job_limited = 0;
    s->next_start = 0;
    why(s, "%s", reason);
}

void super_stop_all(super_t *sv, const char *reason)
{
    for (int i = 0; i < sv->n; i++)
        stop(sv, &sv->svc[i], reason);
}

/* One end that came too soon. The fifth inside the window quarantines. */
static void crashed(super_t *sv, svc_t *s, double now, const char *how)
{
    int kept = 0;
    for (int i = 0; i < s->ncrashes; i++)
        if (now - s->crashes[i] < SUPER_QUARANTINE_WINDOW_S)
            s->crashes[kept++] = s->crashes[i];
    s->ncrashes = kept;
    if (s->ncrashes < SUPER_QUARANTINE_CRASHES)
        s->crashes[s->ncrashes++] = now;
    s->pid = 0;
    s->frozen = s->job_limited = 0;
    if (s->ncrashes >= SUPER_QUARANTINE_CRASHES) {
        s->state = SVC_QUARANTINED;
        s->wanted = 0;                                  /* until a sync finds the operator has let it out */
        why(s, "quarantined: it ended %d times in %d minutes (%s)", SUPER_QUARANTINE_CRASHES,
            (int)(SUPER_QUARANTINE_WINDOW_S / 60), how);
        say(sv, LOG_ERR, "%s: %s", s->id, s->reason);
        if (sv->ops->quarantine)
            sv->ops->quarantine(sv->ctx, s, s->reason);
        return;
    }
    s->backoff_s = s->backoff_s < SUPER_BACKOFF_MIN_S ? SUPER_BACKOFF_MIN_S : s->backoff_s * 2;
    if (s->backoff_s > SUPER_BACKOFF_MAX_S)
        s->backoff_s = SUPER_BACKOFF_MAX_S;
    s->state = SVC_BACKOFF;
    s->next_start = now + s->backoff_s;
    why(s, "%s; again in %.0f s", how, s->backoff_s);
    say(sv, LOG_WARNING, "%s: %s", s->id, s->reason);
}

void super_child_exited(super_t *sv, pid_t pid, int status, double now)
{
    for (int i = 0; i < sv->n; i++) {
        svc_t *s = &sv->svc[i];
        if (pid <= 0 || s->pid != pid)                  /* a service that was stopped on purpose has no pid to match */
            continue;
        char how[96];
        if (WIFSIGNALED(status))
            snprintf(how, sizeof(how), "it was ended by signal %d after %.0f s", WTERMSIG(status), now - s->started);
        else
            snprintf(how, sizeof(how), "it exited with status %d after %.0f s", WEXITSTATUS(status), now - s->started);
        sv->ops->stop(sv->ctx, s);                      /* its group and its rules go with it */
        /* A run that got as far as healthy cleared the count and the wait
         * when it did, so its end is the first of a new window. */
        crashed(sv, s, now, how);
        s->healthy = 0;
        return;
    }
}

/* A mode that cannot be read stops nobody: nothing new starts either,
 * because a machine that does not answer is not ready for one. */
static int mode_fits(const svc_t *s, const super_inputs_t *in)
{
    if (in->mode_cloud < 0)
        return 1;
    return in->mode_cloud ? s->mode_cloud : s->mode_grbl;
}

void super_tick(super_t *sv, const super_inputs_t *in, double now)
{
    if (!in->enabled) {
        super_stop_all(sv, in->off_reason ? in->off_reason : "extensions are off");
        return;
    }
    int window = in->armed != 0;                        /* open, or cannot tell */
    for (int i = 0; i < sv->n; i++) {
        svc_t *s = &sv->svc[i];
        if (s->state == SVC_QUARANTINED) {
            if (!s->wanted)
                continue;
            s->state = SVC_STOPPED;                     /* the operator took it out of quarantine */
            s->ncrashes = 0;
            s->backoff_s = 0;
        }
        if (!s->wanted) {
            stop(sv, s, "not enabled");
            continue;
        }
        if (!mode_fits(s, in)) {
            stop(sv, s, in->mode_cloud ? "it does not run in cloud mode" : "it does not run in GRBL mode");
            continue;
        }
        if (s->state != SVC_RUNNING)
            continue;
        if (!s->healthy && now - s->started >= SUPER_HEALTHY_S) {
            s->healthy = 1;
            s->backoff_s = 0;
            s->ncrashes = 0;
            if (sv->ops->healthy)
                sv->ops->healthy(sv->ctx, s);
        }
        if (s->job_time) {
            if (window != s->job_limited && sv->ops->job_limits(sv->ctx, s, window) == 0) {
                s->job_limited = window;
                say(sv, LOG_INFO, "%s: %s", s->id, window ? "the armed window is open: job-time limits"
                                                           : "the armed window is closed: its own limits again");
            }
        } else if (window != s->frozen && sv->ops->freeze(sv->ctx, s, window) == 0) {
            s->frozen = window;
            say(sv, LOG_INFO, "%s: %s", s->id, window ? "frozen for the armed window" : "thawed");
        }
    }
    /* Starts: none inside a window, none the machine is not ready for, one
     * per tick, staggered, and under the cap. */
    if (window || !in->may_start || now - sv->last_start < SUPER_STAGGER_S || super_running(sv) >= SUPER_MAX_RUNNING)
        return;
    /* Of those that are due, the one that has ended least lately goes
     * first, so that a package that keeps ending does not take the slots of
     * the ones that would stay up. */
    svc_t *pick = NULL;
    for (int i = 0; i < sv->n; i++) {
        svc_t *s = &sv->svc[i];
        if (!s->wanted || !mode_fits(s, in) || (s->state != SVC_STOPPED && s->state != SVC_BACKOFF) || now < s->next_start)
            continue;
        if (!pick || s->ncrashes < pick->ncrashes)
            pick = s;
    }
    if (!pick)
        return;
    char err[200] = "";
    sv->last_start = now;
    pid_t pid = sv->ops->start(sv->ctx, pick, err, sizeof(err));
    if (pid <= 0) {
        char how[240];
        snprintf(how, sizeof(how), "it did not start (%s)", err);
        crashed(sv, pick, now, how);
        return;
    }
    pick->state = SVC_RUNNING;
    pick->pid = pid;
    pick->started = now;
    pick->frozen = pick->job_limited = pick->healthy = 0;
    pick->reason[0] = '\0';
    say(sv, LOG_NOTICE, "%s: started as ffx%d (pid %d)", pick->id, pick->slot, (int)pid);
}
