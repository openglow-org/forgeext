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
 * nothing; a failed start is a crash; a service that is disabled, gone,
 * in the wrong controller mode, or held out by the sync (with the sync's
 * reason) is stopped without a crash, and a package that is gone leaves
 * the table; turning extensions off stops everything,
 * and the ends that follow are nobody's crash; a package that keeps
 * ending does not take the start slots of the ones that would stay up;
 * and, for the window's posture, a freeze that will not take sets the
 * service aside instead of leaving it running, job-time limits that will
 * not take fall back to the freeze the grant lifted (and it is thawed
 * when the window closes), neither taking sets the service aside, and a
 * thaw that fails is tried again. A quarantine whose write fails, for a
 * freeze that will not take or for the fifth early end, holds the service
 * out though every sync says it is wanted: the write is asked for again
 * each tick and said once when it lands; the operator's lift (a new
 * install or an enable, as the sync reads it or as the write finds it)
 * lets the service out, and a destination the operator names does not.
 * A quarantine kept outside the state is taken up for a service that is
 * not running, and refused for one that is.
 */
#include "../src/super.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static struct {
    int starts, stops, freezes, thaws, limits_on, limits_off, quarantines, healthies;
    int fail_start, fail_freeze, fail_limits;
    int write_rc, rewrites;             /* what the quarantine's write answers, and how often it was asked again */
    pid_t next_pid;
    char last_started[64], last_quarantined[64], last_why[160];
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
static int op_freeze(void *ctx, svc_t *s, int on)
{
    (void)ctx;
    (void)s;
    if (w.fail_freeze)
        return -1;
    if (on)
        w.freezes++;
    else
        w.thaws++;
    return 0;
}
static int op_limits(void *ctx, svc_t *s, int on)
{
    (void)ctx;
    (void)s;
    if (w.fail_limits)
        return -1;
    if (on)
        w.limits_on++;
    else
        w.limits_off++;
    return 0;
}
static int op_quarantine(void *ctx, svc_t *s, const char *why, int again)
{
    (void)ctx;
    if (again) {
        w.rewrites++;
        /* As the host's operation answers an ask again: the record it reads
         * where it writes, here the lifts the sync read, lifted since the
         * service was set aside, is nothing to write. */
        return s->lifts != s->aside_lifts ? 1 : w.write_rc;
    }
    w.quarantines++;
    snprintf(w.last_quarantined, sizeof(w.last_quarantined), "%s", s->id);
    snprintf(w.last_why, sizeof(w.last_why), "%s", why ? why : "");
    return w.write_rc;
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

/* One sync of the one service in the table, as run.c makes it: present,
 * wanted as the state says, its lifts, and what it runs with. */
static void sync_one(svc_t *s, int wanted, unsigned long long lifts, unsigned long long conf)
{
    super_sync_begin(&sv);
    s->present = 1;
    s->wanted = wanted;
    s->lifts = lifts;
    s->conf_wanted = conf;
    super_sync_end(&sv);
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
    CHECK(a->state == SVC_STOPPED && w.stops == 2 && strstr(a->reason, "not enabled"),
          "a disabled service was not stopped: %s (%s)", super_state_name(a->state), a->reason);
    /* One the sync holds out, for a manifest it cannot read, is stopped
     * with the sync's reason and not the state's. */
    snprintf(a->held_out, sizeof(a->held_out), "its manifest could not be read (the package has no manifest.json)");
    super_tick(&sv, &READY, 131);
    CHECK(a->state == SVC_STOPPED && strstr(a->reason, "its manifest could not be read"),
          "a service held out by the sync: %s (%s)", super_state_name(a->state), a->reason);
    a->held_out[0] = '\0';
    super_tick(&sv, &READY, 132);
    CHECK(strstr(a->reason, "not enabled"), "held out no longer, the reason is the state's: %s", a->reason);
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

    /* a freeze that will not take: the service is set aside, not left
     * running beside the step stream */
    fresh();
    a = add("org.example.a", 0);
    super_tick(&sv, &READY, 100);
    CHECK(a->state == SVC_RUNNING, "not running before the window");
    w.fail_freeze = 1;
    for (int i = 1; i < SUPER_POSTURE_TRIES; i++) {
        super_tick(&sv, &ARMED, 110 + i);
        CHECK(a->state == SVC_RUNNING && a->posture_tries == i, "turn %d set it aside already: %s (%d)", i,
              super_state_name(a->state), a->posture_tries);
    }
    super_tick(&sv, &ARMED, 110 + SUPER_POSTURE_TRIES);
    CHECK(a->state == SVC_QUARANTINED && !a->frozen && w.quarantines == 1 && w.stops == 1,
          "a freeze that never took: %s, %d quarantined, %d stopped", super_state_name(a->state), w.quarantines, w.stops);
    CHECK(strstr(w.last_why, "could not be frozen") != NULL, "the reason it was set aside: %s", w.last_why);
    w.fail_freeze = 0;
    super_tick(&sv, &READY, 130);
    CHECK(a->state == SVC_QUARANTINED && w.starts == 1, "it started again after the window with no operator");

    /* a freeze that is only slow takes its turn and is not set aside */
    fresh();
    a = add("org.example.a", 0);
    super_tick(&sv, &READY, 100);
    w.fail_freeze = 1;
    super_tick(&sv, &ARMED, 110);
    w.fail_freeze = 0;
    super_tick(&sv, &ARMED, 111);
    CHECK(a->state == SVC_RUNNING && a->frozen && a->posture_tries == 0 && w.quarantines == 0,
          "a slow freeze was set aside: %s, %d tries", super_state_name(a->state), a->posture_tries);

    /* job-time limits that will not take: the freeze the grant lifted
     * stands instead, and it is thawed when the window closes */
    fresh();
    a = add("org.example.a", 0);
    a->job_time = 1;
    super_tick(&sv, &READY, 100);
    w.fail_limits = 1;
    super_tick(&sv, &ARMED, 110);
    CHECK(a->state == SVC_RUNNING && a->frozen && !a->job_limited && w.freezes == 1 && w.quarantines == 0,
          "limits that failed did not fall back to the freeze: frozen %d, %d freezes, %d quarantined", a->frozen,
          w.freezes, w.quarantines);
    super_tick(&sv, &ARMED, 111);
    CHECK(w.freezes == 1, "a second armed tick froze the fallback again");
    super_tick(&sv, &READY, 120);
    CHECK(!a->frozen && w.thaws == 1 && a->state == SVC_RUNNING, "the fallback freeze was not lifted: frozen %d, %d thaws",
          a->frozen, w.thaws);

    /* neither the limits nor the freeze take: nothing holds it off the
     * step stream, so it is set aside */
    fresh();
    a = add("org.example.a", 0);
    a->job_time = 1;
    super_tick(&sv, &READY, 100);
    w.fail_limits = w.fail_freeze = 1;
    for (int i = 0; i < SUPER_POSTURE_TRIES; i++)
        super_tick(&sv, &ARMED, 110 + i);
    CHECK(a->state == SVC_QUARANTINED && w.quarantines == 1, "neither took, and it kept running: %s",
          super_state_name(a->state));
    CHECK(strstr(w.last_why, "limited or frozen") != NULL, "the reason it was set aside: %s", w.last_why);

    /* a thaw that will not take is said, and tried again */
    fresh();
    a = add("org.example.a", 0);
    super_tick(&sv, &READY, 100);
    super_tick(&sv, &ARMED, 110);
    CHECK(a->frozen, "not frozen for the window");
    w.fail_freeze = 1;
    super_tick(&sv, &READY, 120);
    CHECK(a->state == SVC_RUNNING && a->frozen && w.quarantines == 0, "a thaw that failed set it aside: %s",
          super_state_name(a->state));
    w.fail_freeze = 0;
    super_tick(&sv, &READY, 121);
    CHECK(!a->frozen && w.thaws == 1, "the thaw was not tried again: frozen %d, %d thaws", a->frozen, w.thaws);

    /* what it runs with changed: stopped and started again, outside a
     * window, and no crash */
    fresh();
    a = add("org.example.a", 0);
    a->conf_wanted = 1;
    super_tick(&sv, &READY, 100);
    CHECK(a->state == SVC_RUNNING && a->conf_started == 1, "not running with what it was started with");
    a->conf_wanted = 2;
    super_tick(&sv, &ARMED, 110);
    CHECK(a->state == SVC_RUNNING && w.stops == 0, "a restart inside the armed window: %s", super_state_name(a->state));
    super_tick(&sv, &READY, 111);
    CHECK(a->state == SVC_RUNNING && w.stops == 1 && w.starts == 2 && a->conf_started == 2 && a->ncrashes == 0
          && a->backoff_s == 0, "not stopped and started again with what it now runs with, and no crash: %s, %d stops, "
          "%d starts, %d crashes", super_state_name(a->state), w.stops, w.starts, a->ncrashes);
    super_tick(&sv, &READY, 120);
    CHECK(a->state == SVC_RUNNING && w.stops == 1, "a service with nothing changed was stopped");

    /* a quarantine whose write fails holds: the freeze's quarantine, and
     * then every sync says the service is wanted, since the state does not
     * say quarantined; it stays out, and the write is asked again each tick */
    fresh();
    a = add("org.example.a", 0);
    a->lifts = 7;
    w.write_rc = -1;
    super_tick(&sv, &READY, 100);
    w.fail_freeze = 1;
    for (int i = 0; i < SUPER_POSTURE_TRIES; i++)
        super_tick(&sv, &ARMED, 110 + i);
    w.fail_freeze = 0;
    CHECK(a->state == SVC_QUARANTINED && a->unwritten && w.quarantines == 1, "the freeze's quarantine, unwritten: %s %d",
          super_state_name(a->state), a->unwritten);
    for (int i = 0; i < 4; i++) {
        sync_one(a, 1, 7, 0);
        super_tick(&sv, &READY, 200 + i * SUPER_STAGGER_S);
    }
    CHECK(a->state == SVC_QUARANTINED && w.starts == 1 && w.rewrites == 4,
          "an unwritten quarantine let the service out, or was not asked again each tick: %s, %d starts, %d asks",
          super_state_name(a->state), w.starts, w.rewrites);
    /* a destination the operator names lifts nothing */
    sync_one(a, 1, 7, 2);
    super_tick(&sv, &READY, 230);
    CHECK(a->state == SVC_QUARANTINED && a->unwritten && w.starts == 1, "a destination lifted the quarantine: %s, %d starts",
          super_state_name(a->state), w.starts);
    /* the write lands: it stays quarantined, and it is not asked for again */
    w.write_rc = 0;
    sync_one(a, 1, 7, 2);
    super_tick(&sv, &READY, 240);
    sync_one(a, 0, 7, 2);                               /* the state says quarantined now */
    super_tick(&sv, &READY, 250);
    CHECK(a->state == SVC_QUARANTINED && !a->unwritten && w.rewrites == 6 && w.starts == 1,
          "the write landed and it did not stay quarantined, or was asked again: %s, %d asks, %d starts",
          super_state_name(a->state), w.rewrites, w.starts);

    /* the fifth early end, unwritten, holds the same way; the operator's
     * lift, a new install or an enable as the sync reads it, lets it out */
    fresh();
    a = add("org.example.a", 0);
    a->lifts = 7;
    w.write_rc = -1;
    w.fail_start = 1;
    now = 100;
    for (int i = 0; i < SUPER_QUARANTINE_CRASHES; i++) {
        super_tick(&sv, &READY, now);
        now = (a->next_start > now ? a->next_start : now) + SUPER_STAGGER_S;
    }
    w.fail_start = 0;
    CHECK(a->state == SVC_QUARANTINED && a->unwritten, "the crashes' quarantine, unwritten: %s %d",
          super_state_name(a->state), a->unwritten);
    sync_one(a, 1, 7, 0);
    super_tick(&sv, &READY, now + 100);
    CHECK(a->state == SVC_QUARANTINED && w.starts == 0, "an unwritten quarantine for ending let the service out: %s",
          super_state_name(a->state));
    sync_one(a, 1, 8, 0);                               /* installed again, or enabled: the lifts moved */
    super_tick(&sv, &READY, now + 200);
    CHECK(a->state == SVC_RUNNING && !a->unwritten && w.starts == 1, "the operator's lift did not let it out: %s",
          super_state_name(a->state));

    /* the operator's lift that the write finds, newer than the sync's
     * read, lets it out too */
    fresh();
    a = add("org.example.a", 0);
    a->lifts = 7;
    w.write_rc = -1;
    super_tick(&sv, &READY, 100);
    super_quarantine(&sv, "org.example.a", "its data directory holds 2 MiB and it may hold 1");
    CHECK(a->state == SVC_QUARANTINED && a->unwritten, "the measurement's quarantine, unwritten: %s %d",
          super_state_name(a->state), a->unwritten);
    w.write_rc = 1;
    sync_one(a, 1, 7, 0);
    super_tick(&sv, &READY, 200);
    CHECK(a->state == SVC_RUNNING && !a->unwritten && w.starts == 2, "a lift the write found did not let it out: %s",
          super_state_name(a->state));

    /* a quarantine kept outside the state (run.c keeps one whose write
     * failed, to outlive the host) is taken up for a service that is not
     * running, as set aside and unwritten under its lifts, and the first
     * tick asks for its write; one for a service that is running is
     * refused, and the service runs on untouched */
    fresh();
    a = add("org.example.a", 0);
    b = add("org.example.b", 1);
    b->lifts = 7;
    super_tick(&sv, &READY, 10);
    int took = super_take_aside(&sv, "org.example.a", 7, "kept");
    CHECK(took == 1 && a->state == SVC_RUNNING && !a->unwritten && a->wanted && !a->reason[0],
          "a kept record for a running service was taken up: %d, %s (%s)", took, super_state_name(a->state), a->reason);
    took = super_take_aside(&sv, "org.example.b", 7, "kept");
    CHECK(took == 0 && b->state == SVC_QUARANTINED && b->unwritten && b->aside_lifts == 7 && !b->wanted
          && strcmp(b->reason, "kept") == 0, "a kept record for a stopped service was not taken up: %d, %s (%s)", took,
          super_state_name(b->state), b->reason);
    super_tick(&sv, &READY, 20);
    CHECK(w.rewrites == 1 && !b->unwritten && b->state == SVC_QUARANTINED && w.starts == 1,
          "the first tick asked for its write and it stayed aside: %d asks, %s, %d starts", w.rewrites,
          super_state_name(b->state), w.starts);

    printf("%s: super_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
