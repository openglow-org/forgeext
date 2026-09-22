/*
 * api_test.c - host test: the capability broker's judgment of a request
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * api_dispatch() over requests read by httpreq_parse() and a fake machine:
 * what a package may use is what the operator granted, the machine is
 * never asked for a package that may not read it, what the machine says
 * goes on only as a JSON object, and a package's word on its hold is taken
 * in one closed form. The events poll is judged here too: the capability,
 * the body's form, what comes back after a sequence number, and when the
 * broker is told to make the request wait instead of answering it. The
 * sockets and the thread are run_test.py's.
 */
#include "../src/api.h"

#include <jansson.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static int asked;
static char asked_path[64];
static const char *machine_says = "{\"mode\": \"grbl\", \"controller\": \"running\"}";

static int fake_machine(void *ctx, const char *path, char *out, size_t olen)
{
    (void)ctx;
    asked++;
    snprintf(asked_path, sizeof(asked_path), "%s", path);
    if (!machine_says)
        return -1;
    snprintf(out, olen, "%s", machine_says);
    return 0;
}

static char body[API_BODY_MAX];
static evfeed_t feed;
static api_park_t park;

/* The settings side, faked: what the broker asked for, and a fixed answer. */
static int set_calls;
static char set_id[64], set_patch[256];
static int set_status = 200;

static int fake_camera(void *ctx, const char *cam, int full, int quality, unsigned char **jpeg,
                       size_t *len, char *ctype, size_t clen, char *out, size_t olen)
{
    (void)ctx; (void)cam; (void)full; (void)quality; (void)jpeg; (void)len;
    (void)ctype; (void)clen; (void)out; (void)olen;
    return 200;                                     /* the broker never calls it in this test */
}

static int fake_settings(void *ctx, const char *id, const char *patch, size_t plen, char *out, size_t olen)
{
    (void)ctx;
    set_calls++;
    snprintf(set_id, sizeof(set_id), "%s", id);
    snprintf(set_patch, sizeof(set_patch), "%.*s", patch ? (int)plen : 0, patch ? patch : "");
    snprintf(out, olen, set_status == 200 ? "{\"settings\":{\"loud\":true},\"schema\":[]}"
                                          : "{\"error\":\"no\"}");
    return set_status;
}

static api_world_t world;
static api_shot_t shot;

/* The motion side, faked: the path the broker would have sent. */
static int motion_calls;
static char motion_path[256];

/* The job side, faked: what the broker would have handed the machine. */
static int job_calls;
static char job_id[64], job_program[200], job_fields[160];

static int fake_job(void *ctx, const char *id, const char *program, const char *fields,
                    char *out, size_t olen)
{
    (void)ctx;
    job_calls++;
    snprintf(job_id, sizeof(job_id), "%s", id);
    snprintf(job_program, sizeof(job_program), "%s", program ? program : "(abort)");
    snprintf(job_fields, sizeof(job_fields), "%s", fields ? fields : "");
    snprintf(out, olen, "{\"ok\":true}");
    return 200;
}

static int fake_motion(void *ctx, const char *path, char *out, size_t olen)
{
    (void)ctx;
    motion_calls++;
    snprintf(motion_path, sizeof(motion_path), "%s", path);
    snprintf(out, olen, "{\"ok\":true}");
    return 200;
}

static int call(const api_who_t *who, api_hold_t *hold, const char *text)
{
    httpreq_t req;
    const char *why;
    memset(&park, 0, sizeof(park));
    if (httpreq_parse(text, strlen(text), &req, &why) != 1) {
        CHECK(0, "the test's own request does not read: %.40s", text);
        return 0;
    }
    return api_dispatch(who, hold, &req, &world, &park, &shot, body, sizeof(body));
}

static int post_events(const api_who_t *who, api_hold_t *hold, const char *json, const char *type)
{
    char text[512];
    snprintf(text, sizeof(text), "POST /v0/events HTTP/1.1\r\n%s%s%sContent-Length: %zu\r\n\r\n%s",
             type ? "Content-Type: " : "", type ? type : "", type ? "\r\n" : "", strlen(json), json);
    return call(who, hold, text);
}

static int post_hold(const api_who_t *who, api_hold_t *hold, const char *json, const char *type)
{
    char text[1024];
    snprintf(text, sizeof(text), "POST /v0/hold HTTP/1.1\r\n%s%s%sContent-Length: %zu\r\n\r\n%s", type ? "Content-Type: " : "",
             type ? type : "", type ? "\r\n" : "", strlen(json), json);
    return call(who, hold, text);
}

static const char *error_words(void)
{
    static char words[256];
    json_t *j = json_loads(body, 0, NULL);
    snprintf(words, sizeof(words), "%s", json_string_value(json_object_get(j, "error")) ? json_string_value(json_object_get(j, "error")) : "");
    json_decref(j);
    return words;
}

int main(void)
{
    world.machine = fake_machine;
    world.settings = fake_settings;
    world.camera = fake_camera;
    world.motion = fake_motion;
    world.job = fake_job;
    world.feed = &feed;
    api_who_t reader = { .id = "org.example.reader", .version = "1.2.0", .uid = 800, .caps = { "machine.read", "events" }, .ncaps = 2 };
    api_who_t holder = { .id = "org.example.badge", .version = "1.0.0", .uid = 801, .caps = { "hold" }, .ncaps = 1 };
    api_who_t nobody = { .id = "org.example.plain", .version = "1.0.0", .uid = 802, .ncaps = 0 };
    api_hold_t hold = { 0, "" };
    int rc;

    /* Who the host takes the caller for. */
    rc = call(&reader, &hold, "GET /v0/self HTTP/1.1\r\n\r\n");
    json_t *j = json_loads(body, 0, NULL);
    CHECK(rc == 200 && j && !strcmp(json_string_value(json_object_get(j, "id")), "org.example.reader") &&
          !strcmp(json_string_value(json_object_get(j, "version")), "1.2.0") &&
          !strcmp(json_string_value(json_object_get(j, "api")), API_VERSION) &&
          json_array_size(json_object_get(j, "capabilities")) == 2, "GET /v0/self: %d %s", rc, body);
    json_decref(j);
    CHECK(call(&reader, &hold, "POST /v0/self HTTP/1.1\r\nContent-Length: 0\r\n\r\n") == 405, "POST /v0/self");

    /* The machine: only for a package that may read it, and only the three routes. */
    asked = 0;
    rc = call(&reader, &hold, "GET /v0/machine/mode HTTP/1.1\r\n\r\n");
    CHECK(rc == 200 && asked == 1 && !strcmp(asked_path, "/mode") && !strcmp(body, machine_says), "the mode, relayed: %d %s", rc, body);
    call(&reader, &hold, "GET /v0/machine/cool HTTP/1.1\r\n\r\n");
    CHECK(!strcmp(asked_path, "/cool/status"), "cool asks forgectrl for %s", asked_path);
    call(&reader, &hold, "GET /v0/machine/status HTTP/1.1\r\n\r\n");
    CHECK(!strcmp(asked_path, "/status"), "status asks forgectrl for %s", asked_path);
    asked = 0;
    rc = call(&holder, &hold, "GET /v0/machine/mode HTTP/1.1\r\n\r\n");
    CHECK(rc == 403 && asked == 0 && strstr(error_words(), "machine.read"), "without machine.read: %d, the machine asked %d times", rc, asked);
    rc = call(&reader, &hold, "GET /v0/machine/settings HTTP/1.1\r\n\r\n");
    CHECK(rc == 404 && asked == 0, "a machine route the API does not have: %d", rc);
    rc = call(&reader, &hold, "GET /v0/machine/mode/ HTTP/1.1\r\n\r\n");
    CHECK(rc == 404 && asked == 0, "a trailing slash is another path: %d", rc);
    rc = call(&reader, &hold, "POST /v0/machine/mode HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    CHECK(rc == 405 && asked == 0, "the machine is not written through the API: %d", rc);
    machine_says = NULL;
    CHECK(call(&reader, &hold, "GET /v0/machine/mode HTTP/1.1\r\n\r\n") == 502, "forgectrl does not answer: 502");
    machine_says = "<html>not JSON</html>";
    rc = call(&reader, &hold, "GET /v0/machine/mode HTTP/1.1\r\n\r\n");
    CHECK(rc == 502 && !strstr(body, "html"), "what is not a JSON object does not go on: %d %s", rc, body);
    machine_says = "[1, 2]";
    CHECK(call(&reader, &hold, "GET /v0/machine/mode HTTP/1.1\r\n\r\n") == 502, "a JSON array is not an object");
    machine_says = "{\"mode\": \"grbl\"}";

    /* The hold: only with the grant, in one closed form. */
    rc = call(&reader, &hold, "GET /v0/hold HTTP/1.1\r\n\r\n");
    CHECK(rc == 403 && strstr(error_words(), "did not grant"), "GET /v0/hold without the grant: %d", rc);
    rc = post_hold(&nobody, &hold, "{\"raised\": true}", "application/json");
    CHECK(rc == 403 && !hold.raised, "POST /v0/hold without the grant: %d, raised %d", rc, hold.raised);
    rc = call(&holder, &hold, "GET /v0/hold HTTP/1.1\r\n\r\n");
    CHECK(rc == 200 && !strcmp(body, "{\"raised\":false,\"reason\":\"\"}"), "a hold starts clear: %s", body);
    rc = post_hold(&holder, &hold, "{\"raised\": true, \"reason\": \"no badge presented\"}", "application/json");
    CHECK(rc == 200 && hold.raised && !strcmp(hold.reason, "no badge presented") && strstr(body, "no badge presented"),
          "raised with its words: %d %s", rc, body);
    rc = post_hold(&holder, &hold, "{\"raised\": true}", "application/json; charset=utf-8");
    CHECK(rc == 200 && hold.raised && !hold.reason[0], "raised with no words");
    post_hold(&holder, &hold, "{\"raised\": true, \"reason\": \"again\"}", "application/json");
    rc = post_hold(&holder, &hold, "{\"raised\": false, \"reason\": \"left over\"}", "application/json");
    CHECK(rc == 200 && !hold.raised && !hold.reason[0], "cleared: the words go with it");

    /* What is refused leaves the hold as it was. */
    post_hold(&holder, &hold, "{\"raised\": true, \"reason\": \"standing\"}", "application/json");
    static const struct { const char *json, *type, *name; int code; } bad[] = {
        { "{\"raised\": false}", NULL, "no content type", 415 },
        { "{\"raised\": false}", "text/plain", "another content type", 415 },
        { "{\"raised\": fal", "application/json", "cut-off JSON", 400 },
        { "[false]", "application/json", "an array", 400 },
        { "{}", "application/json", "no raised at all", 400 },
        { "{\"raised\": 0}", "application/json", "raised as a number", 400 },
        { "{\"raised\": false, \"required\": false}", "application/json", "a key the form does not have", 400 },
        { "{\"raised\": false, \"raised\": true}", "application/json", "a key twice", 400 },
        { "{\"raised\": true, \"reason\": 5}", "application/json", "a reason that is no string", 400 },
        { "{\"raised\": true, \"reason\": \"a \\\"quote\\\"\"}", "application/json", "a quote in the reason", 400 },
        { "{\"raised\": true, \"reason\": \"a \\\\ slash\"}", "application/json", "a backslash in the reason", 400 },
        { "{\"raised\": true, \"reason\": \"two\\nlines\"}", "application/json", "a line end in the reason", 400 },
        { "{\"raised\": true, \"reason\": \"caf\\u00e9\"}", "application/json", "a reason that is not ASCII", 400 },
        { "{\"raised\": true, \"reason\": \"nul\\u0000here\"}", "application/json", "a NUL in the reason", 400 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        rc = post_hold(&holder, &hold, bad[i].json, bad[i].type);
        CHECK(rc == bad[i].code && hold.raised && !strcmp(hold.reason, "standing") && error_words()[0],
              "%s: %d (expected %d), the hold now %d \"%s\"", bad[i].name, rc, bad[i].code, hold.raised, hold.reason);
    }
    {
        char longjson[400] = "{\"raised\": true, \"reason\": \"";
        memset(longjson + strlen(longjson), 'x', 96);
        strcat(longjson, "\"}");
        rc = post_hold(&holder, &hold, longjson, "application/json");
        CHECK(rc == 400 && !strcmp(hold.reason, "standing"), "a reason of 96 bytes: %d", rc);
    }

    /* The events poll. */
    pthread_mutex_init(&feed.mu, NULL);
    pthread_cond_init(&feed.news, NULL);
    rc = post_events(&holder, &hold, "{}", "application/json");
    CHECK(rc == 403 && strstr(error_words(), "events"), "the poll without the capability: %d", rc);
    CHECK(call(&reader, &hold, "GET /v0/events HTTP/1.1\r\n\r\n") == 405, "the poll is a POST");
    rc = post_events(&reader, &hold, "{}", NULL);
    CHECK(rc == 415, "the poll takes JSON: %d", rc);

    /* An empty feed: where the present is, and nothing replayed. */
    rc = post_events(&reader, &hold, "{}", "application/json");
    j = json_loads(body, 0, NULL);
    CHECK(rc == 200 && j && json_integer_value(json_object_get(j, "next")) == 0 &&
          json_array_size(json_object_get(j, "events")) == 0 &&
          json_integer_value(json_object_get(j, "dropped")) == 0, "an empty feed: %d %s", rc, body);
    json_decref(j);

    evfeed_add(&feed, "lid", "{\"open\":true}");
    evfeed_add(&feed, "cooling.verdict", "{\"verdict\":\"OK\"}");
    /* No since at all asks where the present is; since 0 is the
     * beginning of what is held, and the two are different questions. */
    rc = post_events(&reader, &hold, "{}", "application/json");
    j = json_loads(body, 0, NULL);
    CHECK(rc == 200 && json_integer_value(json_object_get(j, "next")) == 2 &&
          json_array_size(json_object_get(j, "events")) == 0,
          "no since is the present, not the past: %s", body);
    json_decref(j);
    rc = post_events(&reader, &hold, "{\"since\": 0}", "application/json");
    j = json_loads(body, 0, NULL);
    CHECK(rc == 200 && json_array_size(json_object_get(j, "events")) == 2 &&
          json_integer_value(json_object_get(j, "next")) == 2,
          "since 0 is what a reader that was there from the start is owed: %s", body);
    json_decref(j);
    rc = post_events(&reader, &hold, "{\"since\": 1}", "application/json");
    j = json_loads(body, 0, NULL);
    json_t *list = json_object_get(j, "events"), *one = json_array_get(list, 0);
    CHECK(rc == 200 && json_array_size(list) == 1 && json_integer_value(json_object_get(j, "next")) == 2 &&
          !strcmp(json_string_value(json_object_get(one, "event")), "cooling.verdict") &&
          json_integer_value(json_object_get(one, "seq")) == 2,
          "what came after 1: %s", body);
    CHECK(!strcmp(json_string_value(json_object_get(json_object_get(one, "data"), "verdict")), "OK"),
          "the event's data is the machine's JSON, not a string: %s", body);
    json_decref(j);

    /* A reader a whole ring behind is told, and handed what is still there. */
    for (int i = 0; i < EVFEED_RING + 10; i++)
        evfeed_add(&feed, "telemetry.tick", "{}");
    rc = post_events(&reader, &hold, "{\"since\": 1}", "application/json");
    j = json_loads(body, 0, NULL);
    CHECK(rc == 200 && json_integer_value(json_object_get(j, "dropped")) > 0 &&
          json_array_size(json_object_get(j, "events")) == API_EVENTS_MAX,
          "a slow reader is told what it lost: %s", body);
    json_decref(j);

    /* A poll with nothing to say waits; one with something does not. */
    rc = post_events(&reader, &hold, "{\"since\": 76, \"wait\": 20}", "application/json");
    CHECK(rc == API_PARK && park.since == 76 && park.seconds == 20, "the poll waits: %d, %lu for %.0fs",
          rc, park.since, park.seconds);
    rc = post_events(&reader, &hold, "{\"since\": 76, \"wait\": 9000}", "application/json");
    CHECK(rc == API_PARK && park.seconds == API_EVENTS_WAIT_MAX, "a wait longer than the cap is capped: %.0f", park.seconds);
    rc = post_events(&reader, &hold, "{\"since\": 10, \"wait\": 20}", "application/json");
    CHECK(rc == 200, "a poll that has something to say does not wait: %d", rc);
    rc = post_events(&reader, &hold, "{\"wait\": 20}", "application/json");
    CHECK(rc == 200, "asking where the present is never waits: %d", rc);
    rc = post_events(&reader, &hold, "{\"since\": 500, \"wait\": 20}", "application/json");
    CHECK(rc == 200 && strstr(body, "\"events\":[]") && strstr(body, "\"next\":76"),
          "a feed that started over says so at once, not after the wait: %d %s", rc, body);

    static const struct { const char *json, *name; } badpoll[] = {
        { "{\"since\": -1}", "a place before the first" },
        { "{\"since\": \"2\"}", "a place that is a string" },
        { "{\"wait\": -5}", "a wait that is negative" },
        { "{\"since\": 1, \"limit\": 4}", "a key the form does not have" },
        { "{\"since\": 1, \"since\": 2}", "a key twice" },
        { "[1]", "an array" },
        { "{\"since\": 1", "cut-off JSON" },
    };
    for (size_t i = 0; i < sizeof(badpoll) / sizeof(badpoll[0]); i++) {
        rc = post_events(&reader, &hold, badpoll[i].json, "application/json");
        CHECK(rc == 400 && error_words()[0], "%s: %d", badpoll[i].name, rc);
    }

    /* A package's own settings: the capability, and what the broker hands on. */
    api_who_t setter = { .id = "org.example.setter", .version = "1.0.0", .uid = 803,
                         .caps = { "settings.own" }, .ncaps = 1 };
    set_calls = 0;
    rc = call(&reader, &hold, "GET /v0/settings HTTP/1.1\r\n\r\n");
    CHECK(rc == 403 && set_calls == 0 && strstr(error_words(), "settings.own"),
          "settings without the capability: %d, asked %d times", rc, set_calls);
    rc = call(&setter, &hold, "GET /v0/settings HTTP/1.1\r\n\r\n");
    CHECK(rc == 200 && set_calls == 1 && !strcmp(set_id, "org.example.setter") && !set_patch[0]
          && strstr(body, "loud"), "the read: %d %s", rc, body);
    {
        const char *patch = "{\"loud\": true}";
        char text[256];
        snprintf(text, sizeof(text), "POST /v0/settings HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(patch), patch);
        rc = call(&setter, &hold, text);
        CHECK(rc == 200 && set_calls == 2 && !strcmp(set_patch, patch),
              "the patch reaches the host as it was sent: %d %s", rc, set_patch);
        snprintf(text, sizeof(text), "POST /v0/settings HTTP/1.1\r\nContent-Length: %zu\r\n\r\n%s",
                 strlen(patch), patch);
        rc = call(&setter, &hold, text);
        CHECK(rc == 415 && set_calls == 2, "a patch that is not JSON: %d, asked %d times", rc, set_calls);
        set_status = 400;
        snprintf(text, sizeof(text), "POST /v0/settings HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(patch), patch);
        rc = call(&setter, &hold, text);
        CHECK(rc == 400 && strstr(body, "\"error\""), "the host's refusal is passed on whole: %d %s", rc, body);
        set_status = 200;
    }
    world.settings = NULL;
    rc = call(&setter, &hold, "GET /v0/settings HTTP/1.1\r\n\r\n");
    CHECK(rc == 502, "with no way to the settings: %d", rc);
    world.settings = fake_settings;

    /* A camera: the capability is the one for the camera it asked for. */
    api_who_t looker = { .id = "org.example.looker", .version = "1.0.0", .uid = 804,
                         .caps = { "camera.lid" }, .ncaps = 1 };
    {
        char text[400];
        const char *want = "{\"camera\": \"lid\", \"resolution\": \"half\"}";
        snprintf(text, sizeof(text), "POST /v0/camera HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(want), want);
        rc = call(&looker, &hold, text);
        CHECK(rc == API_SHOOT && !strcmp(shot.cam, "lid") && shot.full == 0,
              "the lid camera, asked for by a package that holds it: %d %s", rc, shot.cam);

        want = "{\"camera\": \"lid\", \"resolution\": \"full\", \"quality\": 80}";
        snprintf(text, sizeof(text), "POST /v0/camera HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(want), want);
        rc = call(&looker, &hold, text);
        CHECK(rc == API_SHOOT && shot.full == 1 && shot.quality == 80,
              "the whole frame at a quality it named: %d full %d q %d", rc, shot.full, shot.quality);

        /* The head camera is a capability of its own. */
        want = "{\"camera\": \"head\"}";
        snprintf(text, sizeof(text), "POST /v0/camera HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(want), want);
        rc = call(&looker, &hold, text);
        CHECK(rc == 403 && strstr(error_words(), "camera"),
              "the head camera, held by a package that holds only the lid's: %d", rc);
        rc = call(&reader, &hold, text);
        CHECK(rc == 403, "a camera at all, without either capability: %d", rc);

        CHECK(call(&looker, &hold, "GET /v0/camera HTTP/1.1\r\n\r\n") == 405, "a camera is a POST");

        static const struct { const char *json, *name; } badshot[] = {
            { "{}", "no camera named" },
            { "{\"camera\": \"bed\"}", "a camera there is none of" },
            { "{\"camera\": \"lid\", \"resolution\": \"huge\"}", "a resolution there is none of" },
            { "{\"camera\": \"lid\", \"quality\": 0}", "a quality below the range" },
            { "{\"camera\": \"lid\", \"quality\": 101}", "a quality above the range" },
            { "{\"camera\": \"lid\", \"lamp\": 500}", "a key the form does not have" },
            { "{\"camera\": \"lid\", \"camera\": \"head\"}", "a key twice" },
            { "[\"lid\"]", "an array" },
        };
        for (size_t i = 0; i < sizeof(badshot) / sizeof(badshot[0]); i++) {
            snprintf(text, sizeof(text), "POST /v0/camera HTTP/1.1\r\nContent-Type: application/json\r\n"
                                         "Content-Length: %zu\r\n\r\n%s",
                     strlen(badshot[i].json), badshot[i].json);
            rc = call(&looker, &hold, text);
            CHECK(rc == 400 && error_words()[0], "%s: %d", badshot[i].name, rc);
        }
        world.camera = NULL;
        const char *want2 = "{\"camera\": \"lid\"}";
        snprintf(text, sizeof(text), "POST /v0/camera HTTP/1.1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: %zu\r\n\r\n%s", strlen(want2), want2);
        CHECK(call(&looker, &hold, text) == 502, "with no way to the cameras");
        world.camera = fake_camera;
    }

    /* A jog: the one call that moves the machine. */
    api_who_t jogger = { .id = "org.example.jogger", .version = "1.0.0", .uid = 805,
                         .caps = { "motion.jog" }, .ncaps = 1 };
    {
        char text[400];
        #define JOG(who_, json_) (snprintf(text, sizeof(text), \
            "POST /v0/motion/jog HTTP/1.1\r\nContent-Type: application/json\r\n" \
            "Content-Length: %zu\r\n\r\n%s", strlen(json_), json_), call(who_, &hold, text))

        motion_calls = 0;
        rc = JOG(&reader, "{\"x\": 10}");
        CHECK(rc == 403 && motion_calls == 0 && strstr(error_words(), "motion.jog"),
              "a jog without the capability: %d, the machine asked %d times", rc, motion_calls);

        rc = JOG(&jogger, "{\"x\": 10, \"y\": -5, \"feed\": 2000}");
        CHECK(rc == 200 && motion_calls == 1 && strstr(motion_path, "x=10.000")
              && strstr(motion_path, "y=-5.000") && strstr(motion_path, "feed=2000.000"),
              "a jog inside the bounds: %d %s", rc, motion_path);

        /* The bounds, each one at its edge and just past it. */
        static const struct { const char *json, *name; int ok; } jogs[] = {
            { "{\"x\": 100}", "X at its bound", 1 },
            { "{\"x\": 100.1}", "X past its bound", 0 },
            { "{\"x\": -100.1}", "X past its bound the other way", 0 },
            { "{\"y\": 100}", "Y at its bound", 1 },
            { "{\"y\": 101}", "Y past its bound", 0 },
            { "{\"z\": 5}", "Z at its bound", 1 },
            { "{\"z\": 5.5}", "Z past its bound", 0 },
            { "{\"x\": 1, \"feed\": 10}", "the slowest feed", 1 },
            { "{\"x\": 1, \"feed\": 9}", "a feed below the floor", 0 },
            { "{\"x\": 1, \"feed\": 12000}", "the fastest feed", 1 },
            { "{\"x\": 1, \"feed\": 12001}", "a feed above the ceiling", 0 },
            { "{\"x\": 0, \"y\": 0, \"z\": 0}", "a jog that moves nothing", 0 },
            { "{}", "a jog that names nothing", 0 },
            { "{\"x\": \"10\"}", "an axis that is a string", 0 },
            { "{\"x\": true}", "an axis that is a bool", 0 },
            { "{\"a\": 10}", "an axis there is none of", 0 },
            { "{\"x\": 10, \"laser\": 1}", "a key the form does not have", 0 },
            { "{\"x\": 1, \"x\": 2}", "a key twice", 0 },
            { "[10]", "an array", 0 },
        };
        for (size_t i = 0; i < sizeof(jogs) / sizeof(jogs[0]); i++) {
            int before = motion_calls;
            rc = JOG(&jogger, jogs[i].json);
            if (jogs[i].ok) {
                CHECK(rc == 200 && motion_calls == before + 1, "%s: %d", jogs[i].name, rc);
            } else {
                CHECK(rc == 400 && motion_calls == before && error_words()[0],
                      "%s: %d, and the machine was asked %d times", jogs[i].name, rc,
                      motion_calls - before);
            }
        }

        CHECK(call(&jogger, &hold, "GET /v0/motion/jog HTTP/1.1\r\n\r\n") == 405, "a jog is a POST");
        rc = call(&jogger, &hold, "POST /v0/motion/cancel HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        CHECK(rc == 200 && strstr(motion_path, "/motion/cancel"), "a cancel: %d %s", rc, motion_path);
        rc = call(&reader, &hold, "POST /v0/motion/cancel HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        CHECK(rc == 403, "a cancel without the capability: %d", rc);
        world.motion = NULL;
        rc = JOG(&jogger, "{\"x\": 1}");
        CHECK(rc == 502, "with no way to the machine's motion: %d", rc);
        world.motion = fake_motion;
        #undef JOG
    }

    /* A job: the one call that runs a program. */
    api_who_t runner = { .id = "org.example.runner", .version = "1.0.0", .uid = 806,
                         .caps = { "motion.job" }, .ncaps = 1 };
    {
        char text[400];
        #define JOB(who_, json_) (snprintf(text, sizeof(text), \
            "POST /v0/motion/job HTTP/1.1\r\nContent-Type: application/json\r\n" \
            "Content-Length: %zu\r\n\r\n%s", strlen(json_), json_), call(who_, &hold, text))

        job_calls = 0;
        rc = JOB(&jogger, "{\"program\": \"j.gcode\"}");
        CHECK(rc == 403 && job_calls == 0 && strstr(error_words(), "motion.job"),
              "a job without the capability: %d, the machine asked %d times", rc, job_calls);

        rc = JOB(&runner, "{\"program\": \"j.gcode\", \"lit_within_s\": 30, \"timeout_s\": 600}");
        CHECK(rc == 200 && job_calls == 1 && !strcmp(job_program, "j.gcode")
              && strstr(job_fields, "lit_within_s=30") && strstr(job_fields, "timeout_s=600"),
              "a job with its bounds: %d %s %s", rc, job_program, job_fields);
        /* Who the job is from is the host's word: the id, never a name
         * the package chose. */
        CHECK(!strcmp(job_id, "org.example.runner"), "the job was not named for the package: %s", job_id);

        static const struct { const char *json, *name; } badjobs[] = {
            { "{}", "a job that names no program" },
            { "{\"program\": 7}", "a program that is not a string" },
            { "{\"program\": \"j.gcode\", \"name\": \"someone-else\"}", "a package naming the sender itself" },
            { "{\"program\": \"j.gcode\", \"unlock\": \"1\"}", "a key the form does not have" },
            { "{\"program\": \"j.gcode\", \"lit_within_s\": 5000}", "a lit window past its bound" },
            { "{\"program\": \"j.gcode\", \"timeout_s\": -1}", "a timeout below zero" },
            { "{\"program\": \"j.gcode\", \"program\": \"k.gcode\"}", "a key twice" },
            { "[\"j.gcode\"]", "an array" },
        };
        for (size_t i = 0; i < sizeof(badjobs) / sizeof(badjobs[0]); i++) {
            int before = job_calls;
            rc = JOB(&runner, badjobs[i].json);
            CHECK(rc == 400 && job_calls == before && error_words()[0],
                  "%s: %d, and the machine was asked %d times", badjobs[i].name, rc, job_calls - before);
        }

        CHECK(call(&runner, &hold, "GET /v0/motion/job HTTP/1.1\r\n\r\n") == 405, "a job is a POST");
        rc = call(&runner, &hold, "POST /v0/motion/job/abort HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        CHECK(rc == 200 && !strcmp(job_program, "(abort)"), "an abort: %d %s", rc, job_program);
        rc = call(&jogger, &hold, "POST /v0/motion/job/abort HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        CHECK(rc == 403, "an abort without the capability: %d", rc);
        world.job = NULL;
        rc = JOB(&runner, "{\"program\": \"j.gcode\"}");
        CHECK(rc == 502, "with no way to the machine's job route: %d", rc);
        world.job = fake_job;
        #undef JOB
    }

    /* Everything else. */
    CHECK(call(&reader, &hold, "GET / HTTP/1.1\r\n\r\n") == 404, "the root");
    CHECK(call(&reader, &hold, "GET /v1/self HTTP/1.1\r\n\r\n") == 404, "another version of the API");
    CHECK(call(&reader, &hold, "GET /v0/cameras HTTP/1.1\r\n\r\n") == 404, "a path the API does not have");

    printf("%s: api_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
