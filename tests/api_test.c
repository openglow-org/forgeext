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
 * in one closed form. The sockets and the thread are run_test.py's.
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

static int call(const api_who_t *who, api_hold_t *hold, const char *text)
{
    httpreq_t req;
    const char *why;
    if (httpreq_parse(text, strlen(text), &req, &why) != 1) {
        CHECK(0, "the test's own request does not read: %.40s", text);
        return 0;
    }
    return api_dispatch(who, hold, &req, fake_machine, NULL, body, sizeof(body));
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

    /* Everything else. */
    CHECK(call(&reader, &hold, "GET / HTTP/1.1\r\n\r\n") == 404, "the root");
    CHECK(call(&reader, &hold, "GET /v1/self HTTP/1.1\r\n\r\n") == 404, "another version of the API");
    CHECK(call(&reader, &hold, "GET /v0/settings HTTP/1.1\r\n\r\n") == 404, "a path the API does not have");

    printf("%s: api_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
