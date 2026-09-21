/*
 * run.c - forgeext run: the daemon that carries the supervisor's policy out
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * One thread, one loop, one second a turn: read what is installed and what
 * the machine says, let the policy decide (super.c), and do what it asks
 * with the cgroup, the network allowlist, and the launcher. A service's
 * output comes back on a pipe and goes to the log, a line at a time, under
 * the package's name. What every service is doing is written to
 * status.json whenever it changes.
 */
#define _GNU_SOURCE
#include "run.h"

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cgroup.h"
#include "fflog.h"
#include "sandbox.h"
#include "super.h"

#define LOG_LINES_PER_10S   60

typedef struct {
    char id[64];
    int fd;
    char buf[1024];
    size_t used;
    int lines;                                  /* in this ten-second window */
    time_t window;
    int muted;
} logpipe_t;

typedef struct {
    const run_cfg_t *cfg;
    logpipe_t logs[SUPER_MAX_SERVICES];
    char last_status[8192];
    char unreachable[300];                      /* the last word on a root no account can walk to, said once */
    holdkeep_t holds;
    double quota_at;                            /* when the data directories were last measured */
    evfeed_t feed;
    api_t api;
    char dropped[SUPER_MAX_SERVICES][64];       /* the advisory holds dropped at the last turn, each said once */
    int ndropped;
} run_t;

void run_cfg_defaults(run_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    ext_env_defaults(&cfg->ext);
    machine_cfg_defaults(&cfg->machine);
    cfg->cg_parent = CG_PARENT_DEFAULT;
    cfg->run_dir = RUN_DIR_DEFAULT;
    cfg->holds_dir = HOLDKEEP_DIR_DEFAULT;
    cfg->api_dir = API_DIR_DEFAULT;
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- a service's output ---------------------------------------------------- */

static logpipe_t *log_slot(run_t *r, const char *id)
{
    logpipe_t *empty = NULL;
    for (int i = 0; i < SUPER_MAX_SERVICES; i++) {
        if (r->logs[i].fd > 0 && strcmp(r->logs[i].id, id) == 0)
            return &r->logs[i];
        if (r->logs[i].fd <= 0 && !empty)
            empty = &r->logs[i];
    }
    return empty;
}

static void log_line(logpipe_t *l, const char *line)
{
    time_t now = time(NULL);
    if (now - l->window >= 10) {
        if (l->muted)
            fflog(LOG_WARNING, "ext %s: %d lines of its output were not logged", l->id, l->muted);
        l->window = now;
        l->lines = l->muted = 0;
    }
    if (++l->lines > LOG_LINES_PER_10S) {
        l->muted++;
        return;
    }
    fflog(LOG_INFO, "ext %s: %s", l->id, line);
}

static void log_drain(logpipe_t *l)
{
    for (;;) {
        ssize_t k = read(l->fd, l->buf + l->used, sizeof(l->buf) - 1 - l->used);
        if (k <= 0)
            return;
        l->used += (size_t)k;
        l->buf[l->used] = '\0';
        char *start = l->buf, *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';
            for (char *c = start; *c; c++)
                if ((unsigned char)*c < ' ' && *c != '\t')
                    *c = '?';
            if (*start)
                log_line(l, start);
            start = nl + 1;
        }
        l->used = strlen(start);
        memmove(l->buf, start, l->used + 1);
        if (l->used >= sizeof(l->buf) - 1) {            /* a line longer than the buffer: what there is of it */
            log_line(l, l->buf);
            l->used = 0;
        }
    }
}

static void log_close(run_t *r, const char *id)
{
    for (int i = 0; i < SUPER_MAX_SERVICES; i++)
        if (r->logs[i].fd > 0 && strcmp(r->logs[i].id, id) == 0) {
            log_drain(&r->logs[i]);
            close(r->logs[i].fd);
            memset(&r->logs[i], 0, sizeof(r->logs[i]));
        }
}

/* ---- what the policy asks for ------------------------------------------------ */

static const cg_limits_t LIMITS = { RUN_CPU_PCT, RUN_MEMORY_BYTES, RUN_PIDS };
static const cg_limits_t JOB_LIMITS = { RUN_JOB_CPU_PCT, RUN_MEMORY_BYTES, RUN_PIDS };

static int own_dir(const char *path, uid_t uid)
{
    struct stat st;
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    return chown(path, uid, uid) == 0 && chmod(path, 0700) == 0 ? 0 : -1;
}

static pid_t op_start(void *ctx, svc_t *s, char *err, size_t elen)
{
    run_t *r = ctx;
    const run_cfg_t *cfg = r->cfg;
    static manifest_t m;
    static state_t st;
    static net_dest_t dests[NET_MAX_DESTS];
    char pkg[400], data[340], tmp[360], exec[600], resolv[PATH_MAX];
    uid_t uid = (uid_t)(STATE_POOL_UID + s->slot);
    int ndests = 0, listen_port = 0, dns = 0, pfd[2] = { -1, -1 };

    if (s->slot < 0 || s->slot >= STATE_POOL_SIZE)
        return snprintf(err, elen, "it has no account"), -1;
    if (state_load(cfg->ext.root, &st, err, elen) != 0)
        return -1;
    state_pkg_t *p = state_find(&st, s->id);
    if (!p)
        return snprintf(err, elen, "it is not installed"), -1;
    if (ext_check(&cfg->ext, p, err, elen) != 0 || ext_manifest_of(&cfg->ext, s->id, &m, err, elen) != 0)
        return -1;
    if (!manifest_has_service(&m))
        return snprintf(err, elen, "it has no service"), -1;
    if (net_base_ok(&cfg->net, err, elen) != 0)
        return -1;

    sandbox_cfg_t sb;
    memset(&sb, 0, sizeof(sb));
    for (int i = 0; i < m.ncaps; i++) {
        if (strncmp(m.caps[i], "net.outbound:", 13) == 0 && ndests < NET_MAX_DESTS && ndests < SANDBOX_MAX_PORTS - 1
            && caps_outbound_parse(m.caps[i] + 13, dests[ndests].host, sizeof(dests[ndests].host), &dests[ndests].port) == 0) {
            /* A name, not an address: it has a letter, and no colon. */
            dns |= dests[ndests].host[strcspn(dests[ndests].host, "abcdefghijklmnopqrstuvwxyz")] != '\0'
                   && !strchr(dests[ndests].host, ':');
            sb.connect_ports[ndests] = dests[ndests].port;
            ndests++;
        } else if (strncmp(m.caps[i], "net.listen:", 11) == 0) {
            listen_port = atoi(m.caps[i] + 11);
        }
    }
    if (dns)
        sb.connect_ports[ndests] = 53;                  /* a lookup that falls back to TCP */

    snprintf(pkg, sizeof(pkg), "%.255s/pkg/%.63s/%.32s", cfg->ext.root, s->id, p->version);
    snprintf(data, sizeof(data), "%.255s/data/%.63s", cfg->ext.root, s->id);
    snprintf(tmp, sizeof(tmp), "%.339s/tmp", data);
    snprintf(exec, sizeof(exec), "%.399s/%.192s", pkg, m.exec);
    if (own_dir(data, uid) != 0 || own_dir(tmp, uid) != 0)
        return snprintf(err, elen, "cannot make its data directory: %s", strerror(errno)), -1;
    if (cg_create(cfg->cg_parent, s->id, &LIMITS, err, elen) != 0)
        return -1;
    if (net_allow(&cfg->net, uid, dests, ndests, listen_port, dns, err, elen) != 0 || pipe2(pfd, O_CLOEXEC) != 0) {
        if (pfd[0] < 0 && !err[0])
            snprintf(err, elen, "cannot make its log pipe: %s", strerror(errno));
        net_revoke(&cfg->net, uid, NULL, 0);
        cg_destroy(cfg->cg_parent, s->id);
        return -1;
    }

    int a = 0;
    if (m.runtime == RUNTIME_SHELL)
        sb.argv[a++] = "/bin/sh";
    if (m.runtime == RUNTIME_PYTHON) {
        sb.argv[a++] = "/usr/bin/python3";
        sb.argv[a++] = "-B";
    }
    sb.argv[a++] = exec;
    for (int i = 0; i < m.nargs && a < SANDBOX_MAX_ARGV - 1; i++)
        sb.argv[a++] = m.args[i];
    /* Its one way to the machine: the socket is there before the service
     * is, and the broker answers from what the operator granted. */
    static api_who_t who;
    static char api_env[420];
    char api_path[400];
    memset(&who, 0, sizeof(who));
    snprintf(who.id, sizeof(who.id), "%s", s->id);
    snprintf(who.version, sizeof(who.version), "%s", p->version);
    who.uid = uid;
    for (int i = 0; i < m.ncaps && who.ncaps < MANIFEST_MAX_CAPS; i++)
        if (!caps_needs_grant(m.caps[i]) || state_granted(p, m.caps[i]))
            snprintf(who.caps[who.ncaps++], sizeof(who.caps[0]), "%s", m.caps[i]);
    if (api_open(&r->api, &who, api_path, sizeof(api_path), err, elen) != 0) {
        close(pfd[0]);
        close(pfd[1]);
        net_revoke(&cfg->net, uid, NULL, 0);
        cg_destroy(cfg->cg_parent, s->id);
        return -1;
    }
    snprintf(api_env, sizeof(api_env), "FFX_API=%s", api_path);
    sb.env[0] = api_env;
    sb.id = s->id;
    sb.uid = uid;
    sb.gid = (gid_t)uid;
    sb.pkg_dir = pkg;
    sb.data_dir = data;
    sb.bind_port = listen_port;
    sb.log_fd = pfd[1];
    sb.need = SANDBOX_NEED_LANDLOCK_FS | (cfg->landlock_fs_only ? 0 : SANDBOX_NEED_LANDLOCK_NET);
    sb.cg_parent = cfg->cg_parent;
    sb.cg_id = s->id;
    if (dns && realpath("/etc/resolv.conf", resolv) && strncmp(resolv, "/etc/", 5) != 0)
        sb.extra_ro[0] = resolv;                        /* the image keeps it on a tmpfs, behind a link */

    pid_t pid = sandbox_spawn(&sb, err, elen);
    close(pfd[1]);
    logpipe_t *l = pid > 0 ? log_slot(r, s->id) : NULL;
    if (pid <= 0 || !l) {
        close(pfd[0]);
        if (pid > 0)
            snprintf(err, elen, "no room for its log");
        api_close(&r->api, s->id);
        net_revoke(&cfg->net, uid, NULL, 0);
        cg_destroy(cfg->cg_parent, s->id);
        return -1;
    }
    memset(l, 0, sizeof(*l));
    snprintf(l->id, sizeof(l->id), "%s", s->id);
    l->fd = pfd[0];
    fcntl(l->fd, F_SETFL, O_NONBLOCK);
    return pid;
}

static void op_stop(void *ctx, svc_t *s)
{
    run_t *r = ctx;
    char err[200];
    if (cg_destroy(r->cfg->cg_parent, s->id) != 0)
        fflog(LOG_ERR, "%s: its group could not be emptied and removed", s->id);
    if (s->slot >= 0 && net_revoke(&r->cfg->net, (uid_t)(STATE_POOL_UID + s->slot), err, sizeof(err)) != 0)
        fflog(LOG_ERR, "%s: %s", s->id, err);
    api_close(&r->api, s->id);
    if (s->pid > 0)
        waitpid(s->pid, NULL, 0);                       /* killed with its group; an ended one is already reaped */
    log_close(r, s->id);
}

static int op_freeze(void *ctx, svc_t *s, int on)
{
    run_t *r = ctx;
    return cg_freeze(r->cfg->cg_parent, s->id, on);
}

static int op_job_limits(void *ctx, svc_t *s, int on)
{
    run_t *r = ctx;
    return cg_limits(r->cfg->cg_parent, s->id, on ? &JOB_LIMITS : &LIMITS, NULL, 0);
}

static void op_quarantine(void *ctx, svc_t *s, const char *why)
{
    run_t *r = ctx;
    char err[200];
    (void)why;
    if (ext_set_quarantined(&r->cfg->ext, s->id, 1, err, sizeof(err)) != 0)
        fflog(LOG_ERR, "%s: the quarantine could not be written: %s", s->id, err);
}

static void op_healthy(void *ctx, svc_t *s)
{
    run_t *r = ctx;
    char err[200];
    if (ext_drop_previous(&r->cfg->ext, s->id, err, sizeof(err)) != 0)
        fflog(LOG_WARNING, "%s: its previous version could not be removed: %s", s->id, err);
}

static void op_log(void *ctx, int prio, const char *text)
{
    (void)ctx;
    fflog(prio, "%s", text);
}

static const super_ops_t OPS = { op_start, op_stop, op_freeze, op_job_limits, op_quarantine, op_healthy, op_log };

/* ---- the storage quota --------------------------------------------------------- */

/* Each running service's data directory, measured on its own slow
 * cadence. A service over what its manifest asked for is quarantined:
 * stopped, remembered, and shown with the reason. The host does not
 * delete a package's data - that is the operator's to do, by removing
 * the package or by clearing the directory and enabling it again. */
static void quota_turn(run_t *r, super_t *sv, double now)
{
    if (now - r->quota_at < QUOTA_EVERY_S)
        return;
    r->quota_at = now;
    for (int i = 0; i < sv->n; i++) {
        svc_t *s = &sv->svc[i];
        manifest_t m;
        char data[420], err[300];
        if (s->state != SVC_RUNNING)
            continue;
        if (ext_manifest_of(&r->cfg->ext, s->id, &m, err, sizeof(err)) != 0)
            continue;
        snprintf(data, sizeof(data), "%.255s/data/%.63s", r->cfg->ext.root, s->id);
        long long used = quota_dir_bytes(data), may = quota_of(&m);
        if (used < 0 || used <= may)
            continue;
        fflog(LOG_WARNING, "%s: its data directory holds %lld MiB and it may hold %lld: set aside",
              s->id, used >> 20, may >> 20);
        /* The reason is built here and not in s->reason: the supervisor
         * stops the service first, which writes its own words there, and
         * a reason that pointed at that buffer would be gone by the time
         * it was copied back. */
        char why[160];
        snprintf(why, sizeof(why),
                 "its data directory holds %lld MiB and it may hold %lld: remove the package, or clear "
                 "its data and enable it again", used >> 20, may >> 20);
        super_quarantine(sv, s->id, why);
    }
}

/* ---- motion ------------------------------------------------------------------- */

/* One JSON answer into the broker's buffer: the status, or 500 when it
 * does not fit. */
static int say_json(char *out, size_t olen, int status, json_t *j)
{
    char *text = j ? json_dumps(j, JSON_COMPACT) : NULL;
    json_decref(j);
    if (!text || strlen(text) >= olen) {
        free(text);
        snprintf(out, olen, "{\"error\":\"the answer did not fit\"}");
        return 500;
    }
    snprintf(out, olen, "%s", text);
    free(text);
    return status;
}

/* One motion request on a package's behalf, with the host's own
 * credential. The machine judges it again - its bounds, its mode, its
 * lease, and the sender at the controller port who always wins - and
 * whatever it says is what the package is told. */
static int motion_call(void *ctx, const char *path, char *out, size_t olen)
{
    const run_cfg_t *cfg = ctx;
    char answer[2048] = "";
    int rc = machine_post(&cfg->machine, path, answer, sizeof(answer));
    if (rc == 0) {
        snprintf(out, olen, "%s", answer[0] ? answer : "{\"ok\":true}");
        return 200;
    }
    int status = rc < -1 ? -rc : 502;
    json_t *j = answer[0] ? json_loads(answer, 0, NULL) : NULL;
    const char *why = j ? json_string_value(json_object_get(j, "error")) : NULL;
    if (!why)
        why = j ? json_string_value(json_object_get(j, "message")) : NULL;
    char words[240];
    snprintf(words, sizeof(words), "%s", why ? why : (answer[0] ? answer : "the machine did not answer"));
    for (char *p = words; *p; p++)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
            *p = ' ';
    json_decref(j);
    return say_json(out, olen, status, json_pack("{s:s}", "error", words));
}

/* ---- the cameras --------------------------------------------------------------- */

/* One frame for a package, from forgectrl's own camera route. It is
 * always asked for as a background capture: a package is never the
 * person standing at the machine, so it yields to an operator who is
 * watching rather than stuttering their stream. Runs on the broker's
 * camera thread. */
static int camera_call(void *ctx, const char *cam, int full, int quality,
                       unsigned char **jpeg, size_t *len, char *ctype, size_t clen,
                       char *out, size_t olen)
{
    const run_cfg_t *cfg = ctx;
    char path[160];
    int n = snprintf(path, sizeof(path), "/cam/snapshot?cam=%.8s&res=%s&background=1",
                     cam, full ? "full" : "half");
    if (quality > 0 && n > 0 && (size_t)n < sizeof(path))
        snprintf(path + n, sizeof(path) - (size_t)n, "&q=%d", quality);

    int rc = machine_get_blob(&cfg->machine, path, jpeg, len, ctype, clen);
    if (rc == 0 && *len > 2 && (*jpeg)[0] == 0xff && (*jpeg)[1] == 0xd8)
        return 200;
    if (rc == 0) {
        /* A 200 that is not a JPEG is not passed on as one. */
        free(*jpeg);
        *jpeg = NULL;
        *len = 0;
        snprintf(out, olen, "{\"error\":\"the machine's answer was not a frame\"}");
        return 502;
    }
    /* The machine's own refusal, in its own words: the lid is open, or
     * somebody is watching. It answers a refusal as plain text on this
     * route and as JSON on others, so both are read and whichever it
     * sent is what the package is told. */
    int status = rc < -1 ? -rc : 502;
    char words[200] = "";
    json_t *j = *jpeg && *len ? json_loadb((const char *)*jpeg, *len, 0, NULL) : NULL;
    const char *why = j ? json_string_value(json_object_get(j, "error")) : NULL;
    if (!why)
        why = j ? json_string_value(json_object_get(j, "message")) : NULL;
    if (why) {
        snprintf(words, sizeof(words), "%s", why);
    } else if (*jpeg && *len) {
        /* Plain text, as far as it is printable: what the machine said
         * goes on, and nothing that is not text does. */
        size_t n = *len < sizeof(words) - 1 ? *len : sizeof(words) - 1;
        size_t k = 0;
        for (size_t i = 0; i < n; i++) {
            unsigned char ch = (*jpeg)[i];
            if (ch >= 0x20 && ch < 0x7f)
                words[k++] = (char)ch;
            else if (ch == '\n' || ch == '\t')
                words[k++] = ' ';
        }
        words[k] = '\0';
    }
    say_json(out, olen, status, json_pack("{s:s}", "error",
                                          words[0] ? words : "the machine did not answer the camera"));
    json_decref(j);
    free(*jpeg);
    *jpeg = NULL;
    *len = 0;
    return status;
}

/* ---- a package's own settings ------------------------------------------------- */

/* The broker's way to a package's own settings. The schema is the
 * package's installed manifest, read afresh each time: an update that
 * changes the schema changes what its settings are from that moment, and
 * the host never holds a schema the package no longer ships. */
static int settings_call(void *ctx, const char *id, const char *patch, size_t plen, char *out, size_t olen)
{
    const run_cfg_t *cfg = ctx;
    manifest_t m;
    char err[300];

    if (ext_manifest_of(&cfg->ext, id, &m, err, sizeof(err)) != 0)
        return say_json(out, olen, 502, json_pack("{s:s}", "error", err));
    if (m.nsettings == 0)
        return say_json(out, olen, 404, json_pack("{s:s}", "error", "this package declares no settings"));
    if (patch) {
        json_error_t je;
        json_t *body = json_loadb(patch, plen, JSON_REJECT_DUPLICATES, &je);
        int rc = body ? settings_write(cfg->ext.root, id, &m, body, err, sizeof(err))
                      : (snprintf(err, sizeof(err), "the body is a JSON object of settings"), -1);
        json_decref(body);
        if (rc != 0)
            return say_json(out, olen, 400, json_pack("{s:s}", "error", err));
        fflog(LOG_NOTICE, "%s: it changed its own settings", id);
    }
    return say_json(out, olen, 200,
                        json_pack("{s:o, s:o}", "settings", settings_read(cfg->ext.root, id, &m),
                                  "schema", settings_schema_json(&m)));
}

/* ---- one turn ---------------------------------------------------------------- */

/* The holds, as they stand after this turn's policy. A package that is
 * enabled and runs in this controller mode has a file while extensions are
 * on; every other case has none, and that is the operator's exit. The
 * package's own word arrives over its API socket (POST /v0/hold) and
 * starts clear with every start of its service. */
static void holds_turn(run_t *r, const super_t *sv, const super_inputs_t *in)
{
    static hold_entry_t e[HOLDKEEP_MAX];
    char now_dropped[SUPER_MAX_SERVICES][64];
    int n = 0, nd = 0;
    for (int i = 0; in->enabled && i < sv->n && n < HOLDKEEP_MAX; i++) {
        const svc_t *s = &sv->svc[i];
        int mode_ok = in->mode_cloud < 0 ? 1 : in->mode_cloud ? s->mode_cloud : s->mode_grbl;
        if (!s->present || !s->hold || !s->pkg_enabled || !mode_ok)
            continue;
        api_hold_t said;
        api_hold_said(&r->api, s->id, &said);
        if (hold_decide(s->id, s->hold_required, s->state == SVC_RUNNING, s->healthy, said.raised, said.reason, &e[n]))
            snprintf(now_dropped[nd++], sizeof(now_dropped[0]), "%s", s->id);
        n++;
    }
    holdkeep_set(&r->holds, e, n);
    for (int i = 0; i < nd; i++) {
        int said = 0;
        for (int k = 0; k < r->ndropped; k++)
            said |= strcmp(r->dropped[k], now_dropped[i]) == 0;
        if (!said)
            fflog(LOG_WARNING, "%s: its advisory hold is dropped while it is not running", now_dropped[i]);
    }
    memcpy(r->dropped, now_dropped, sizeof(now_dropped[0]) * (size_t)nd);
    r->ndropped = nd;
}

/* What is installed, into the policy's table. */
static void sync_installed(run_t *r, super_t *sv)
{
    static state_t st;
    static manifest_t m;
    char err[300];
    if (state_load(r->cfg->ext.root, &st, err, sizeof(err)) != 0) {
        fflog(LOG_ERR, "%s: nothing is changed until it reads", err);
        return;
    }
    super_sync_begin(sv);
    for (int i = 0; i < st.n; i++) {
        const state_pkg_t *p = &st.pkgs[i];
        if (p->slot < 0)
            continue;                                   /* nothing of it runs on the machine */
        svc_t *s = super_service(sv, p->id);
        if (!s)
            continue;
        s->present = 1;
        s->slot = p->slot;
        s->job_time = state_granted(p, "job_time.run");
        s->hold = state_granted(p, "hold");
        s->hold_required = s->hold && p->hold_required;
        s->pkg_enabled = p->enabled;
        if (s->state != SVC_RUNNING && ext_manifest_of(&r->cfg->ext, p->id, &m, err, sizeof(err)) == 0) {
            s->mode_grbl = m.mode_grbl;
            s->mode_cloud = m.mode_cloud;
        }
        s->wanted = p->enabled && !p->quarantined;
        if (p->quarantined && s->state != SVC_RUNNING && s->state != SVC_QUARANTINED) {
            s->state = SVC_QUARANTINED;
            if (!s->reason[0])
                snprintf(s->reason, sizeof(s->reason), "quarantined");
        }
    }
    super_sync_end(sv);
    if (ext_required_holds_sync(&r->cfg->ext, &st) != 0)
        fflog(LOG_WARNING, "the required holds under %s could not be made to match the state", r->cfg->ext.root);
}

static void write_status(run_t *r, const super_t *sv, const machine_t *mc)
{
    json_t *top = json_object(), *list = json_array();
    /* The file is written when it changes and outlives a host that was
     * killed: the pid says whose word it is. */
    json_object_set_new(top, "pid", json_integer(getpid()));
    json_object_set_new(top, "enabled", json_boolean(mc->enabled));
    json_object_set_new(top, "off_reason", json_string(mc->off_reason));
    json_object_set_new(top, "armed", mc->armed < 0 ? json_null() : json_boolean(mc->armed));
    json_object_set_new(top, "not_ready", json_string(mc->not_ready));
    json_object_set_new(top, "events", json_pack("{s:b, s:i}", "connected", evfeed_connected(&r->feed),
                                                 "wanted", api_events_wanted(&r->api)));
    for (int i = 0; i < sv->n; i++) {
        const svc_t *s = &sv->svc[i];
        json_t *j = json_object();
        json_object_set_new(j, "id", json_string(s->id));
        json_object_set_new(j, "state", json_string(super_state_name(s->state)));
        json_object_set_new(j, "account", json_sprintf("ffx%d", s->slot));
        json_object_set_new(j, "pid", json_integer(s->state == SVC_RUNNING ? s->pid : 0));
        json_object_set_new(j, "frozen", json_boolean(s->frozen));
        json_object_set_new(j, "job_limited", json_boolean(s->job_limited));
        json_object_set_new(j, "healthy", json_boolean(s->healthy));
        if (s->hold)
            json_object_set_new(j, "hold", json_string(s->hold_required ? "required" : "advisory"));
        json_object_set_new(j, "reason", json_string(s->reason));
        json_array_append_new(list, j);
    }
    json_object_set_new(top, "services", list);
    char *text = json_dumps(top, JSON_INDENT(1) | JSON_SORT_KEYS);
    json_decref(top);
    if (!text)
        return;
    if (strlen(text) < sizeof(r->last_status) && strcmp(text, r->last_status) != 0) {
        char path[400], tmp[420];
        snprintf(path, sizeof(path), "%.380s/status.json", r->cfg->run_dir);
        snprintf(tmp, sizeof(tmp), "%.380s/status.json.new", r->cfg->run_dir);
        FILE *f = fopen(tmp, "we");
        if (f) {
            fputs(text, f);
            fputc('\n', f);
            if (fclose(f) == 0 && rename(tmp, path) == 0)
                snprintf(r->last_status, sizeof(r->last_status), "%s", text);
        }
    }
    free(text);
}

int run_daemon(const run_cfg_t *cfg)
{
    static run_t r;
    static super_t sv;
    char err[300];
    sigset_t mask;

    memset(&r, 0, sizeof(r));
    r.cfg = cfg;
    if (geteuid() != 0) {
        fprintf(stderr, "forgeext run: needs root\n");
        return 2;
    }
    if (ext_root_prepare(&cfg->ext, err, sizeof(err)) != 0 || cg_ready(cfg->cg_parent, err, sizeof(err)) != 0) {
        fflog(LOG_ERR, "not starting: %s", err);
        fprintf(stderr, "forgeext run: %s\n", err);
        return 1;
    }
    if (mkdir(cfg->run_dir, 0755) != 0 && errno != EEXIST) {
        fflog(LOG_ERR, "not starting: cannot make %s: %s", cfg->run_dir, strerror(errno));
        return 1;
    }
    /* One daemon: a second one would sweep the first one's services. The
     * lock is held until the process ends, however it ends. */
    char lockpath[PATH_MAX];
    snprintf(lockpath, sizeof(lockpath), "%.4000s/daemon.lock", cfg->run_dir);
    int lfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || flock(lfd, LOCK_EX | LOCK_NB) != 0) {
        fflog(LOG_ERR, "not starting: another extension host holds %s", lockpath);
        fprintf(stderr, "forgeext run: another extension host is running\n");
        if (lfd >= 0)
            close(lfd);
        return 1;
    }
    /* A daemon that was killed left its services running, thawed, with
     * their ways out open, and nobody to freeze them when a job arms.
     * Nothing this one did not start runs under it. */
    int groups = cg_sweep(cfg->cg_parent);
    int chains = net_sweep(&cfg->net, err, sizeof(err));
    if (groups < 0) {
        fflog(LOG_ERR, "not starting: a group under %s could not be emptied and removed", cfg->cg_parent);
        close(lfd);
        return 1;
    }
    if (groups > 0 || chains > 0)
        fflog(LOG_WARNING, "a previous extension host left %d group(s) and %d allowlist chain(s): removed", groups,
              chains > 0 ? chains : 0);
    if (chains < 0)
        fflog(LOG_WARNING, "the allowlist could not be swept (%s): a start replaces its own account's chain", err);
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    signal(SIGPIPE, SIG_IGN);
    int sfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sfd < 0)
        return 1;
    if (holdkeep_start(&r.holds, cfg->holds_dir, HOLDKEEP_MAIN_S, err, sizeof(err)) != 0) {
        fflog(LOG_ERR, "not starting: %s", err);
        close(lfd);
        return 1;
    }
    if (evfeed_start(&r.feed, &cfg->machine, err, sizeof(err)) != 0) {
        fflog(LOG_ERR, "not starting: %s", err);
        holdkeep_stop(&r.holds);
        close(lfd);
        return 1;
    }
    if (api_start(&r.api, cfg->api_dir, &cfg->machine, &r.feed, settings_call, (void *)cfg,
                  camera_call, (void *)cfg, motion_call, (void *)cfg, err, sizeof(err)) != 0) {
        fflog(LOG_ERR, "not starting: %s", err);
        evfeed_stop(&r.feed);
        holdkeep_stop(&r.holds);
        close(lfd);
        return 1;
    }
    super_init(&sv, &OPS, &r);
    fflog(LOG_NOTICE, "started: extension root %s, groups under %s", cfg->ext.root, cfg->cg_parent);

    int stopping = 0, turns = 0;
    double next = mono();
    while (!stopping) {
        struct pollfd fds[SUPER_MAX_SERVICES + 1];
        logpipe_t *who[SUPER_MAX_SERVICES + 1];
        int n = 0;
        fds[n].fd = sfd;
        fds[n++].events = POLLIN;
        for (int i = 0; i < SUPER_MAX_SERVICES; i++)
            if (r.logs[i].fd > 0) {
                who[n] = &r.logs[i];
                fds[n].fd = r.logs[i].fd;
                fds[n++].events = POLLIN;
            }
        double left = next - mono();
        poll(fds, (nfds_t)n, left > 0 ? (int)(left * 1000) + 1 : 0);
        for (int i = 1; i < n; i++)
            if (fds[i].revents & (POLLIN | POLLHUP))
                log_drain(who[i]);
        struct signalfd_siginfo si;
        while (read(sfd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
            if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT)
                stopping = 1;
        }
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
            super_child_exited(&sv, pid, status, mono());
        if (mono() < next && !stopping)
            continue;
        next = mono() + 1.0;

        machine_t mc;
        int waiting = 0;
        sync_installed(&r, &sv);
        for (int i = 0; i < sv.n; i++)
            waiting |= sv.svc[i].wanted && sv.svc[i].state != SVC_RUNNING;
        machine_read(&cfg->machine, &mc, waiting);
        /* A service whose account cannot walk to its package would end at
         * once, five times, and be quarantined for a fault that is the
         * machine's: it is the machine that is not ready. */
        if (mc.may_start) {
            if (ext_root_reachable(&cfg->ext, err, sizeof(err)) != 0) {
                mc.may_start = 0;
                snprintf(mc.not_ready, sizeof(mc.not_ready), "%.95s", err);
                if (strcmp(err, r.unreachable) != 0)
                    fflog(LOG_ERR, "no service can start: %s", err);
                snprintf(r.unreachable, sizeof(r.unreachable), "%s", err);
            } else {
                r.unreachable[0] = '\0';
            }
        }
        super_inputs_t in = { mc.enabled, mc.may_start, mc.armed, mc.mode_cloud, mc.off_reason };
        if (!stopping)
            super_tick(&sv, &in, mono());
        quota_turn(&r, &sv, mono());
        holds_turn(&r, &sv, &in);
        /* The machine's stream is held while somebody reads it and let go
         * when nobody does: forgectrl samples its own state only while a
         * stream is open. */
        evfeed_want(&r.feed, mc.enabled ? api_events_wanted(&r.api) : 0);
        write_status(&r, &sv, &mc);
        if (cfg->ticks && ++turns >= cfg->ticks)
            stopping = 1;
    }
    super_stop_all(&sv, "the extension host is stopping");
    holdkeep_stop(&r.holds);
    api_stop(&r.api);
    evfeed_stop(&r.feed);
    machine_t off;
    memset(&off, 0, sizeof(off));
    snprintf(off.off_reason, sizeof(off.off_reason), "the extension host is not running");
    off.armed = -1;
    write_status(&r, &sv, &off);
    fflog(LOG_NOTICE, "stopped");
    close(sfd);
    close(lfd);
    return 0;
}
