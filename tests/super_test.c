/*
 * super_test.c - host test for the supervisor's policy, over fake operations
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Cases: nothing starts while extensions are off, while the machine is
 * not ready, or inside an armed window; starts are one per tick,
 * staggered, and capped; an open window freezes every running service and
 * a closed one thaws it, a window that cannot be read counts as open, and
 * the job_time.run grant trades the freeze for job-time limits; a service
 * that ends is started again after 1, 2, 4, 8 s and is quarantined at its
 * fifth early end, which is remembered and keeps it down until a sync lets
 * it out; ends spread wider than the window never quarantine; a healthy
 * run starts the backoff over, is told once, and its end counts for
 * nothing; a failed start is a crash; a service that is disabled, gone, or
 * in the wrong controller mode is stopped without a crash, and a package
 * that is gone leaves the table; turning extensions off stops everything,
 * and the ends that follow are nobody's crash; and a package that keeps
 * ending does not take the start slots of the ones that would stay up.
 */
#include "../src/super.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static struct {
    int starts, stops, freezes, thaws, limits_on, limits_off, quarantines, healthies;
    int fail_start;
    pid_t next_pid;
    char last_started[64], last_quarantined[64];
} w;

static pid_t op_start(void *ctx, svc_t *s, char *err, size_t elen)
{
    (void)ctx;
    if (w.fail_start) {
        snprintf(err, elen, "exec: No such file or directory");
        return -1;
    }
    w.starts++;
    snprintf(w.last_started, sizeof(w.last_started), "%s", s->id);
    return ++w.next_pid;
}
static void op_stop(void *ctx, svc_t *s) { (void)ctx; (void)s; w.stops++; }
static int op_freeze(void *ctx, svc_t *s, int on) { (void)ctx; (void)s; if (on) w.freezes++; else w.thaws++; return 0; }
static int op_limits(void *ctx, svc_t *s, int on) { (void)ctx; (void)s; if (on) w.limits_on++; else w.limits_off++; return 0; }
static void op_quarantine(void *ctx, svc_t *s, const char *why)
{
    (void)ctx;
    (void)why;
    w.quarantines++;
    snprintf(w.last_quarantined, sizeof(w.last_quarantined), "%s", s->id);
}
static void op_healthy(void *ctx, svc_t *s) { (void)ctx; (void)s; w.healthies++; }
static void op_log(void *ctx, int prio, const char *text) { (void)ctx; (void)prio; (void)text; }

static const super_ops_t ops = { op_start, op_stop, op_freeze, op_limits, op_quarantine, op_healthy, op_log };
static super_t sv;
static const super_inputs_t OFF = { 0, 1, 0, 0, "extensions are off" }, READY = { 1, 1, 0, 0, NULL },
                            NOT_READY = { 1, 0, 0, 0, NULL }, ARMED = { 1, 1, 1, 0, NULL }, UNKNOWN = { 1, 1, -1, 0, NULL },
                            CLOUD = { 1, 1, 0, 1, NULL };

static svc_t *add(const char *id, int slot)
{
    svc_t *s = super_service(&sv, id);
    s->present = s->wanted = s->mode_grbl = s->mode_cloud = 1;
    s->slot = slot;
    return s;
}

static void fresh(void)
{
    memset(&w, 0, sizeof(w));
    w.next_pid = 100;
    super_init(&sv, &ops, NULL);
}

int main(void)
{
    /* off, not ready, armed: no start */
    fresh();
    svc_t *a = add("org.example.a", 0);
    super_tick(&sv, &OFF, 10);
    super_tick(&sv, &NOT_READY, 11);
    super_tick(&sv, &ARMED, 12);
    super_tick(&sv, &UNKNOWN, 13);
    CHECK(w.starts == 0 && a->state == SVC_STOPPED, "a start while off, not ready, armed, or unreadable: %d", w.starts);
    CHECK(strstr(a->reason, "extensions are off") != NULL, "the reason while off: %s", a->reason);

    /* one per tick, staggered, capped */
    svc_t *b = add("org.example.b", 1);
    add("org.example.c", 2);
    add("org.example.d", 3);
    svc_t *e = add("org.example.e", 4);
    super_tick(&sv, &READY, 20);
    CHECK(w.starts == 1 && a->state == SVC_RUNNING && a->pid == 101 && b->state == SVC_STOPPED, "the first tick started %d", w.starts);
    super_tick(&sv, &READY, 21);
    super_tick(&sv, &READY, 24.9);
    CHECK(w.starts == 1, "a second start inside the stagger");
    super_tick(&sv, &READY, 25);
    CHECK(w.starts == 2 && b->state == SVC_RUNNING, "the second start at the stagger");
    super_tick(&sv, &READY, 30);
    super_tick(&sv, &READY, 35);
    super_tick(&sv, &READY, 40);
    super_tick(&sv, &READY, 45);
    CHECK(w.starts == SUPER_MAX_RUNNING && super_running(&sv) == SUPER_MAX_RUNNING && e->state == SVC_STOPPED,
          "the cap: %d started, %d running", w.starts, super_running(&sv));

    /* the armed window */
    b->job_time = 1;
    super_tick(&sv, &ARMED, 50);
    CHECK(w.freezes == 3 && a->frozen && !b->frozen && w.limits_on == 1 && b->job_limited, "armed: %d frozen, %d job-limited",
          w.freezes, w.limits_on);
    super_tick(&sv, &ARMED, 51);
    CHECK(w.freezes == 3 && w.limits_on == 1, "a second armed tick froze again");
    super_tick(&sv, &READY, 52);
    CHECK(w.thaws == 3 && !a->frozen && w.limits_off == 1 && !b->job_limited, "disarmed: %d thawed, %d limits lifted", w.thaws,
          w.limits_off);
    super_tick(&sv, &UNKNOWN, 53);
    CHECK(w.freezes == 6 && a->frozen, "a window that cannot be read did not freeze");
    super_tick(&sv, &READY, 54);

    /* backoff and quarantine */
    fresh();
    a = add("org.example.a", 0);
    double now = 100;
    double waits[] = { 1, 2, 4, 8 };
    super_tick(&sv, &READY, now);
    for (int i = 0; i < 4; i++) {
        super_child_exited(&sv, a->pid, 1 << 8, now + 0.5);
        CHECK(a->state == SVC_BACKOFF && a->backoff_s == waits[i], "after end %d the wait is %.0f s, expected %.0f", i + 1,
              a->backoff_s, waits[i]);
        super_tick(&sv, &READY, a->next_start - 0.01);
        CHECK(a->state == SVC_BACKOFF, "started before its wait was over");
        now = a->next_start + SUPER_STAGGER_S;
        super_tick(&sv, &READY, now);
        CHECK(a->state == SVC_RUNNING, "not started after its wait (end %d)", i + 1);
    }
    CHECK(w.stops == 4, "an ended service's group and rules are taken away each time: %d", w.stops);
    super_child_exited(&sv, a->pid, 9, now + 0.5);
    CHECK(a->state == SVC_QUARANTINED && w.quarantines == 1 && !a->wanted && strstr(a->reason, "quarantined"),
          "the fifth early end: state %s, %d remembered, reason %s", super_state_name(a->state), w.quarantines, a->reason);
    int starts = w.starts;
    super_tick(&sv, &READY, now + 1000);
    CHECK(w.starts == starts && a->state == SVC_QUARANTINED, "a quarantined service was started");
    super_sync_begin(&sv);
    a = add("org.example.a", 0);                        /* the operator let it out: state.json says wanted again */
    super_sync_end(&sv);
    super_tick(&sv, &READY, now + 2000);
    CHECK(a->state == SVC_RUNNING && a->ncrashes == 0, "out of quarantine it did not start");

    /* ends spread wider than the window */
    fresh();
    a = add("org.example.a", 0);
    now = 100;
    for (int i = 0; i < 12; i++) {
        super_tick(&sv, &READY, now);
        CHECK(a->state == SVC_RUNNING, "round %d: not running", i);
        super_child_exited(&sv, a->pid, 1 << 8, now + 1);
        now += SUPER_QUARANTINE_WINDOW_S / 3;
    }
    CHECK(w.quarantines == 0 && a->backoff_s == SUPER_BACKOFF_MAX_S, "slow crashes: %d quarantines, wait %.0f", w.quarantines,
          a->backoff_s);

    /* a healthy run */
    fresh();
    a = add("org.example.a", 0);
    super_tick(&sv, &READY, 100);
    super_child_exited(&sv, a->pid, 1 << 8, 101);
    super_tick(&sv, &READY, 110);
    super_tick(&sv, &READY, 110 + SUPER_HEALTHY_S - 1);
    CHECK(w.healthies == 0, "healthy too soon");
    super_tick(&sv, &READY, 110 + SUPER_HEALTHY_S);
    super_tick(&sv, &READY, 111 + SUPER_HEALTHY_S);
    CHECK(w.healthies == 1 && a->healthy && a->ncrashes == 0, "healthy: told %d times", w.healthies);
    for (int i = 0; i < 8; i++) {
        double t = 1000 + i * 100;
        super_child_exited(&sv, a->pid, 1 << 8, t);
        CHECK(a->state == SVC_BACKOFF && a->backoff_s == SUPER_BACKOFF_MIN_S, "a healthy service's end waits %.0f s", a->backoff_s);
        super_tick(&sv, &READY, t + 10);
        super_tick(&sv, &READY, t + 10 + SUPER_HEALTHY_S);
    }
    CHECK(w.quarantines == 0, "healthy runs that end were quarantined");

    /* a failed start is a crash */
    fresh();
    a = add("org.example.a", 0);
    w.fail_start = 1;
    now = 100;
    for (int i = 0; i < SUPER_QUARANTINE_CRASHES; i++) {
        super_tick(&sv, &READY, now);
        now = (a->next_start > now ? a->next_start : now) + SUPER_STAGGER_S;
    }
    CHECK(a->state == SVC_QUARANTINED && w.quarantines == 1 && strstr(a->reason, "did not start"),
          "five failed starts: %s, %s", super_state_name(a->state), a->reason);

    /* stopped without a crash */
    fresh();
    a = add("org.example.a", 0);
    b = add("org.example.b", 1);
    b->mode_cloud = 0;
    super_tick(&sv, &READY, 100);
    super_tick(&sv, &READY, 110);
    CHECK(super_running(&sv) == 2, "two running");
    super_tick(&sv, &CLOUD, 120);
    CHECK(b->state == SVC_STOPPED && a->state == SVC_RUNNING && w.stops == 1 && strstr(b->reason, "cloud mode"),
          "a GRBL-only service in cloud mode: %s (%s)", super_state_name(b->state), b->reason);
    super_child_exited(&sv, 102, 9, 121);
    CHECK(b->state == SVC_STOPPED && b->ncrashes == 0, "its end was counted as a crash");
    a->wanted = 0;
    super_tick(&sv, &READY, 130);
    CHECK(a->state == SVC_STOPPED && w.stops == 2, "a disabled service was not stopped");
    super_sync_begin(&sv);
    add("org.example.b", 1);
    super_sync_end(&sv);
    CHECK(sv.n == 1 && strcmp(sv.svc[0].id, "org.example.b") == 0, "a package that is gone stayed in the table: %d", sv.n);
    super_tick(&sv, &READY, 140);
    CHECK(sv.svc[0].state == SVC_RUNNING, "back in GRBL mode it did not start");
    super_tick(&sv, &OFF, 150);
    CHECK(super_running(&sv) == 0 && sv.svc[0].ncrashes == 0 && strstr(sv.svc[0].reason, "extensions are off"),
          "extensions off: %d still running", super_running(&sv));

    /* a package that keeps ending does not hold the others up */
    fresh();
    svc_t *crasher = add("org.example.a-crasher", 0);   /* first in the table */
    svc_t *one = add("org.example.b", 1), *two = add("org.example.c", 2);
    now = 100;
    super_tick(&sv, &READY, now);
    CHECK(crasher->state == SVC_RUNNING, "the first in the table starts first");
    super_child_exited(&sv, crasher->pid, 3 << 8, now + 0.1);
    for (int i = 0; i < 2; i++) {
        now += SUPER_STAGGER_S;
        super_tick(&sv, &READY, now);
    }
    CHECK(one->state == SVC_RUNNING && two->state == SVC_RUNNING && crasher->state == SVC_BACKOFF,
          "the two that never ended took the next two slots: %s %s, the crasher %s", super_state_name(one->state),
          super_state_name(two->state), super_state_name(crasher->state));
    now += SUPER_STAGGER_S;
    super_tick(&sv, &READY, now);
    CHECK(crasher->state == SVC_RUNNING, "and then the crasher had its turn");

    printf("%s: super_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
