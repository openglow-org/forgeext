/*
 * settings_test.c - host test: a package's own settings, schema and store
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Two halves. The schema, as the manifest parser reads it: every type,
 * every way of declaring one wrong, and a default a package's own schema
 * would refuse. The store, against a real directory: defaults before
 * anybody sets anything, a patch applied whole or not at all, a value
 * the schema no longer takes passed over, and the file's mode; a change
 * waiting on the package's lock keeps the other writer's value; and
 * writes the disk refuses, before their temporary file and after it,
 * leave no descriptor open and no lock held.
 */
#include "../src/manifest.h"
#include "../src/settings.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); \
                              fflush(stdout); } } while (0)

static char root[128];

/* The descriptors this process holds now. */
static int open_fds(void)
{
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL)
        n += e->d_name[0] != '.';
    if (d)
        closedir(d);
    return n;
}

/* A manifest with the settings block given, parsed. 0 on success. */
static int parse_with(const char *settings_json, manifest_t *m, char *err, size_t elen)
{
    char text[4096];
    snprintf(text, sizeof(text),
             "{\"manifest\":1,\"id\":\"org.example.s\",\"name\":\"S\",\"version\":\"1.0.0\","
             "\"author\":\"a\",\"license\":\"MIT\",\"api\":\"0.1\",\"runtime\":\"python\","
             "\"service\":{\"exec\":\"bin/s.py\"},\"capabilities\":[\"settings.own\"]%s%s}",
             settings_json ? ",\"settings\":" : "", settings_json ? settings_json : "");
    return manifest_parse(text, strlen(text), m, err, elen);
}

static const char *GOOD =
    "{\"webhook\":{\"type\":\"string\",\"default\":\"\",\"max\":40,\"label\":\"Where to post\"},"
    "\"threshold\":{\"type\":\"number\",\"default\":40,\"min\":0,\"max\":100},"
    "\"loud\":{\"type\":\"bool\",\"default\":false},"
    "\"when\":{\"type\":\"choice\",\"default\":\"end\",\"choices\":[\"start\",\"end\",\"never\"]}}";

/* JSON_DECODE_ANY: a setting's value is often a bare number, string or
 * bool, and without it jansson takes only an array or an object - which
 * would hand every case below a NULL and refuse it for the wrong
 * reason, the good ones and the bad ones alike. */
static json_t *obj(const char *text);

enum { REFUSE_FULL, REFUSE_NO_ENTRY };

/* Fifty writes the disk refuses, in a child with a deadline: each leaves
 * no descriptor open, and none keeps the package's lock from the next one
 * (a lock left held makes the next write wait for it, and the alarm ends
 * the child). 0 when all fifty were refused and the descriptor table is
 * as it was, 1 when not, 128 plus the signal that ended the child. */
static int refused_writes(const manifest_t *m, int how)
{
    char dir[200];
    snprintf(dir, sizeof(dir), "%s/%s", root, SETTINGS_DIR);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        struct rlimit was, rl;
        getrlimit(RLIMIT_FSIZE, &was);
        rl = was;
        if (how == REFUSE_FULL) {
            rl.rlim_cur = 0;
            signal(SIGXFSZ, SIG_IGN);
            if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
                _exit(3);
        } else if (chmod(dir, 0500) != 0) {
            _exit(3);
        }
        char err[400];
        int before = open_fds(), refused = 0;
        for (int i = 0; i < 50; i++) {
            json_t *patch = obj("{\"threshold\": 20}");
            refused += settings_write(root, "org.example.s", m, patch, err, sizeof(err)) != 0;
            json_decref(patch);
        }
        setrlimit(RLIMIT_FSIZE, &was);                  /* for the words below, which go to a file */
        printf("  %d of 50 refused (%s): %d descriptors, %d before\n", refused, err, open_fds(), before);
        fflush(stdout);
        _exit(refused == 50 && open_fds() == before ? 0 : 1);
    }
    int st = -1;
    if (pid > 0)
        waitpid(pid, &st, 0);
    chmod(dir, 0700);
    return pid < 0 ? -1 : WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1;
}

static json_t *obj(const char *text)
{
    return json_loads(text, JSON_DECODE_ANY, NULL);
}

int main(void)
{
    manifest_t m;
    char err[400];

    /* A root of this run's own: a killed run's is never taken up again. */
    snprintf(root, sizeof(root), "/tmp/ffx-settings-test.XXXXXX");
    if (!mkdtemp(root)) {
        printf("FAIL: no directory for the test: %s\n", strerror(errno));
        return 1;
    }

    /* ---- the schema ---- */
    CHECK(parse_with(NULL, &m, err, sizeof(err)) == 0 && m.nsettings == 0,
          "a manifest with no settings block: %s", err);
    CHECK(parse_with(GOOD, &m, err, sizeof(err)) == 0 && m.nsettings == 4, "the good schema: %s", err);
    const setting_t *t = manifest_setting(&m, "webhook");
    CHECK(t && t->type == SETTING_STRING && t->text_max == 40 && !strcmp(t->label, "Where to post"),
          "the string setting: max %zu label %s", t ? t->text_max : 0, t ? t->label : "");
    t = manifest_setting(&m, "threshold");
    CHECK(t && t->type == SETTING_NUMBER && t->has_min && t->has_max && t->min == 0 && t->max == 100,
          "the number setting");
    t = manifest_setting(&m, "loud");
    CHECK(t && t->type == SETTING_BOOL && t->boolean == 0, "the bool setting");
    t = manifest_setting(&m, "when");
    CHECK(t && t->type == SETTING_CHOICE && t->nchoices == 3 && !strcmp(t->text, "end"), "the choice setting");
    CHECK(manifest_setting(&m, "nothere") == NULL, "a setting that is not declared");
    /* A label the manifest leaves out is the name. */
    CHECK(parse_with("{\"x\":{\"type\":\"bool\",\"default\":true}}", &m, err, sizeof(err)) == 0
          && !strcmp(m.settings[0].label, "x"), "a setting with no label is labeled by its name");
    /* A string with no max takes the longest the schema allows. */
    CHECK(parse_with("{\"x\":{\"type\":\"string\",\"default\":\"\"}}", &m, err, sizeof(err)) == 0
          && m.settings[0].text_max == SETTING_TEXT_MAX - 1, "a string with no max: %zu", m.settings[0].text_max);

    static const struct { const char *json, *name; } bad[] = {
        { "[]", "a settings block that is not an object" },
        { "{\"x\":{\"type\":\"string\"}}", "no default at all" },
        { "{\"x\":{\"type\":\"colour\",\"default\":\"red\"}}", "a type there is none of" },
        { "{\"x\":{\"default\":\"red\"}}", "no type at all" },
        { "{\"X\":{\"type\":\"bool\",\"default\":true}}", "a name with a capital" },
        { "{\"1x\":{\"type\":\"bool\",\"default\":true}}", "a name starting with a digit" },
        { "{\"x-y\":{\"type\":\"bool\",\"default\":true}}", "a name with a dash" },
        { "{\"\":{\"type\":\"bool\",\"default\":true}}", "a name that is empty" },
        { "{\"x\":{\"type\":\"bool\",\"default\":1}}", "a bool defaulting to a number" },
        { "{\"x\":{\"type\":\"number\",\"default\":\"4\"}}", "a number defaulting to a string" },
        { "{\"x\":{\"type\":\"number\",\"default\":5,\"min\":10}}", "a default below its own min" },
        { "{\"x\":{\"type\":\"number\",\"default\":5,\"max\":1}}", "a default above its own max" },
        { "{\"x\":{\"type\":\"number\",\"default\":5,\"min\":9,\"max\":1}}", "a min above its max" },
        { "{\"x\":{\"type\":\"string\",\"default\":\"abc\",\"max\":2}}", "a default longer than its own max" },
        { "{\"x\":{\"type\":\"string\",\"default\":\"\",\"min\":1}}", "a min on a string" },
        { "{\"x\":{\"type\":\"bool\",\"default\":true,\"max\":4}}", "a max on a bool" },
        { "{\"x\":{\"type\":\"string\",\"default\":\"\",\"choices\":[\"a\",\"b\"]}}", "choices on a string" },
        { "{\"x\":{\"type\":\"choice\",\"default\":\"a\"}}", "a choice with no choices" },
        { "{\"x\":{\"type\":\"choice\",\"default\":\"a\",\"choices\":[\"a\"]}}", "a choice with one choice" },
        { "{\"x\":{\"type\":\"choice\",\"default\":\"c\",\"choices\":[\"a\",\"b\"]}}", "a default outside its choices" },
        { "{\"x\":{\"type\":\"choice\",\"default\":\"a\",\"choices\":[\"a\",\"a\"]}}", "a choice named twice" },
        { "{\"x\":{\"type\":\"bool\",\"default\":true,\"step\":1}}", "a key the schema does not have" },
        { "{\"x\":\"bool\"}", "a setting that is not an object" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        CHECK(parse_with(bad[i].json, &m, err, sizeof(err)) != 0 && err[0],
              "%s was taken", bad[i].name);
    }
    {   /* More settings than the schema holds. */
        char many[3072] = "{";
        for (int i = 0; i <= MANIFEST_MAX_SETTINGS; i++)
            snprintf(many + strlen(many), sizeof(many) - strlen(many),
                     "%s\"k%d\":{\"type\":\"bool\",\"default\":true}", i ? "," : "", i);
        strcat(many, "}");
        CHECK(parse_with(many, &m, err, sizeof(err)) != 0, "%d settings were taken", MANIFEST_MAX_SETTINGS + 1);
    }

    /* ---- one value against its setting ---- */
    parse_with(GOOD, &m, err, sizeof(err));
    static const struct { const char *key, *value, *name; int ok; } vals[] = {
        { "threshold", "50", "a number inside its bounds", 1 },
        { "threshold", "0", "a number at its min", 1 },
        { "threshold", "100", "a number at its max", 1 },
        { "threshold", "-1", "a number below its min", 0 },
        { "threshold", "101", "a number above its max", 0 },
        { "threshold", "\"50\"", "a number as a string", 0 },
        { "threshold", "true", "a number as a bool", 0 },
        { "loud", "true", "a bool", 1 },
        { "loud", "1", "a bool as a number", 0 },
        { "when", "\"start\"", "a choice that is one", 1 },
        { "when", "\"sometimes\"", "a choice that is not", 0 },
        { "when", "4", "a choice as a number", 0 },
        { "webhook", "\"https://example.test/x\"", "a string inside its max", 1 },
        { "webhook", "\"0123456789012345678901234567890123456789\"", "a string at its max", 1 },
        { "webhook", "\"01234567890123456789012345678901234567890\"", "a string one past its max", 0 },
        { "webhook", "\"two\\nlines\"", "a string with a line end", 0 },
        { "webhook", "[]", "a string as an array", 0 },
        { "webhook", "null", "a value that is null", 0 },
    };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        json_t *v = obj(vals[i].value);
        CHECK(v != NULL, "the test's own value does not read: %s", vals[i].value);
        int rc = setting_value_ok(manifest_setting(&m, vals[i].key), v, err, sizeof(err));
        CHECK((rc == 0) == (vals[i].ok != 0) && (rc == 0 || err[0]), "%s: %s", vals[i].name,
              rc == 0 ? "taken" : err);
        json_decref(v);
    }

    /* ---- the store ---- */
    json_t *now = settings_read(root, "org.example.s", &m);
    CHECK(json_object_size(now) == 4 && json_is_string(json_object_get(now, "webhook"))
          && json_number_value(json_object_get(now, "threshold")) == 40
          && json_is_false(json_object_get(now, "loud"))
          && !strcmp(json_string_value(json_object_get(now, "when")), "end"),
          "before anything is set, every key is its default");
    json_decref(now);

    json_t *patch = obj("{\"threshold\": 70, \"loud\": true}");
    CHECK(settings_write(root, "org.example.s", &m, patch, err, sizeof(err)) == 0, "a good patch: %s", err);
    json_decref(patch);
    now = settings_read(root, "org.example.s", &m);
    CHECK(json_number_value(json_object_get(now, "threshold")) == 70
          && json_is_true(json_object_get(now, "loud"))
          && !strcmp(json_string_value(json_object_get(now, "when")), "end"),
          "what was set is set, and what was not keeps its default");
    json_decref(now);

    /* A later patch leaves alone what it does not name: settings are kept,
     * not replaced wholesale. Reading back only proves this after a second
     * patch, because an unset key reads as its default either way. */
    patch = obj("{\"when\": \"never\"}");
    CHECK(settings_write(root, "org.example.s", &m, patch, err, sizeof(err)) == 0, "a second patch: %s", err);
    json_decref(patch);
    now = settings_read(root, "org.example.s", &m);
    CHECK(json_number_value(json_object_get(now, "threshold")) == 70
          && json_is_true(json_object_get(now, "loud"))
          && !strcmp(json_string_value(json_object_get(now, "when")), "never"),
          "a second patch kept what the first one set: %s", json_dumps(now, JSON_COMPACT));
    json_decref(now);

    /* Two writers, the broker and the command line: each read, change and
     * write is made under the package's own lock, through a temporary
     * file of its own. A writer that holds the lock holds the other off
     * until it lets go; and a name another writer's temporary file once
     * had is no obstacle. */
    {
        char lockp[640], stale[640], store[600];
        snprintf(store, sizeof(store), "%s/%s/org.example.s.json", root, SETTINGS_DIR);
        snprintf(lockp, sizeof(lockp), "%.600s.lock", store);
        snprintf(stale, sizeof(stale), "%.600s.new", store);
        CHECK(mkdir(stale, 0700) == 0, "a directory where a fixed temporary name would go");
        int lk = open(lockp, O_RDWR | O_CREAT, 0600);
        CHECK(lk >= 0 && flock(lk, LOCK_EX) == 0, "the test holds the package's lock");
        int pfd[2];
        CHECK(pipe(pfd) == 0, "a pipe");
        pid_t child = fork();
        if (child == 0) {
            json_t *p3 = obj("{\"threshold\": 30}");
            char e3[200];
            int rc = settings_write(root, "org.example.s", &m, p3, e3, sizeof(e3));
            if (write(pfd[1], rc == 0 ? "y" : "n", 1) != 1)
                _exit(2);
            _exit(rc == 0 ? 0 : 1);
        }
        struct pollfd pw = { .fd = pfd[0], .events = POLLIN };
        CHECK(poll(&pw, 1, 1000) == 0, "a write went ahead while another held the package's lock");
        /* The holder changes the file before it lets go: the waiting
         * write reads it under the lock, after this, and keeps it. */
        FILE *sf = fopen(store, "w");
        CHECK(sf && fputs("{\"loud\": true, \"threshold\": 70, \"webhook\": \"\", \"when\": \"start\"}\n", sf) >= 0,
              "the holder's own write");
        if (sf)
            fclose(sf);
        flock(lk, LOCK_UN);
        char said = 0;
        CHECK(poll(&pw, 1, 5000) == 1 && read(pfd[0], &said, 1) == 1 && said == 'y',
              "let go, the waiting write did not finish, or failed (%c)", said ? said : '-');
        waitpid(child, NULL, 0);
        close(lk);
        close(pfd[0]);
        close(pfd[1]);
        now = settings_read(root, "org.example.s", &m);
        CHECK(json_number_value(json_object_get(now, "threshold")) == 30
              && !strcmp(json_string_value(json_object_get(now, "when")), "start"),
              "the write after the wait kept what the holder wrote before it let go: %s", json_dumps(now, JSON_COMPACT));
        json_decref(now);
        rmdir(stale);
        patch = obj("{\"threshold\": 70, \"when\": \"never\"}");    /* back as the cases below expect them */
        CHECK(settings_write(root, "org.example.s", &m, patch, err, sizeof(err)) == 0, "the threshold back: %s", err);
        json_decref(patch);
    }

    /* A write the disk refuses leaves no descriptor open and its lock let
     * go: the broker's thread may be refused this way at a package's rate,
     * for as long as the disk stays full. Refused once the temporary file
     * is written (a full /data, here RLIMIT_FSIZE 0), and before it can be
     * made (no room for a new entry, here a settings directory the account
     * may not write in; root writes there all the same). */
    {
        int rc = refused_writes(&m, REFUSE_FULL);
        CHECK(rc == 0, "50 writes refused at a full disk: %s", rc == 1 ? "a descriptor left open"
              : rc == 128 + SIGALRM ? "a lock left held: the next write waited for it" : "the child could not run");
        if (geteuid() != 0) {
            rc = refused_writes(&m, REFUSE_NO_ENTRY);
            CHECK(rc == 0, "50 writes refused before their temporary file: %s", rc == 1 ? "a descriptor left open"
                  : rc == 128 + SIGALRM ? "a lock left held: the next write waited for it" : "the child could not run");
        } else {
            printf("note: as root the settings directory takes a new entry whatever its mode; the refusal before the "
                   "temporary file is the unprivileged run's\n");
        }
    }

    {   /* The file is the host's alone. */
        char p[256];
        struct stat st;
        snprintf(p, sizeof(p), "%s/%s/org.example.s.json", root, SETTINGS_DIR);
        CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600, "the store's mode is %04o",
              stat(p, &st) == 0 ? st.st_mode & 0777 : 0);
    }

    /* A patch is all or nothing. */
    static const struct { const char *json, *name; } bad_patch[] = {
        { "{\"threshold\": 500}", "a value outside its bounds" },
        { "{\"nothere\": 1}", "a key the package does not declare" },
        { "{\"threshold\": 50, \"nothere\": 1}", "one good key beside one bad" },
        { "{\"threshold\": 50, \"loud\": 7}", "one good key beside one bad value" },
        { "{}", "a patch naming nothing" },
        { "[1]", "a patch that is not an object" },
    };
    for (size_t i = 0; i < sizeof(bad_patch) / sizeof(bad_patch[0]); i++) {
        json_t *p2 = obj(bad_patch[i].json);
        err[0] = '\0';
        int rc = settings_write(root, "org.example.s", &m, p2 ? p2 : json_null(), err, sizeof(err));
        json_decref(p2);
        now = settings_read(root, "org.example.s", &m);
        CHECK(rc != 0 && err[0] && json_number_value(json_object_get(now, "threshold")) == 70
              && json_is_true(json_object_get(now, "loud")),
              "%s: rc %d, and the values are now %s", bad_patch[i].name, rc, json_dumps(now, JSON_COMPACT));
        json_decref(now);
    }

    /* A schema that changed under the values: what no longer fits, and
     * what is no longer declared, are passed over. */
    {
        manifest_t m2;
        CHECK(parse_with("{\"threshold\":{\"type\":\"number\",\"default\":5,\"min\":0,\"max\":10},"
                         "\"fresh\":{\"type\":\"bool\",\"default\":true}}", &m2, err, sizeof(err)) == 0,
              "the changed schema: %s", err);
        now = settings_read(root, "org.example.s", &m2);
        CHECK(json_object_size(now) == 2 && json_number_value(json_object_get(now, "threshold")) == 5
              && json_is_true(json_object_get(now, "fresh")) && !json_object_get(now, "loud"),
              "a value the new schema refuses goes back to its default, and a key it dropped is gone: %s",
              json_dumps(now, JSON_COMPACT));
        json_decref(now);
    }

    /* The package is removed: its values go. */
    settings_forget(root, "org.example.s");
    now = settings_read(root, "org.example.s", &m);
    CHECK(json_number_value(json_object_get(now, "threshold")) == 40, "the values outlived the package");
    json_decref(now);

    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
        if (system(cmd)) { }
    }
    printf("%s: settings_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
