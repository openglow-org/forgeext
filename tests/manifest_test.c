/*
 * manifest_test.c - host test for the manifest parser
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Cases: a whole manifest parses into every field; the smallest one a
 * data package needs parses with its defaults; and each way of being
 * wrong is refused in words that name the fault: not JSON, a duplicate
 * key, an unknown key, a wrong schema number, a bad id, a bad version,
 * another API, a service where none runs and none where one must, an
 * entry point that leaves the package, a capability that is unknown,
 * privileged, listed twice, or a service's on a package with none, a
 * data package that asks for anything, modes that are empty or doubled,
 * a conflict with itself. Versions order the way semantic versions do.
 */
#include "../src/manifest.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static char err[512];
static manifest_t m;

static int parses(const char *text)
{
    return manifest_parse(text, strlen(text), &m, err, sizeof(err)) == 0;
}

static int refused_with(const char *text, const char *words)
{
    return manifest_parse(text, strlen(text), &m, err, sizeof(err)) != 0 && strstr(err, words) != NULL;
}

/* A service manifest with one field replaced: `"key": value` swapped in
 * by the caller through the two %s. */
#define BASE_HEAD "{\"manifest\":1,\"id\":\"org.example.notify\",\"name\":\"Notify\",\"version\":\"1.2.3\"," \
                  "\"author\":\"Someone\",\"license\":\"MIT\",\"api\":\"0.1\","
#define SERVICE   "\"runtime\":\"python\",\"service\":{\"exec\":\"bin/run.py\",\"args\":[\"--quiet\"]},"

int main(void)
{
    CHECK(parses(BASE_HEAD SERVICE
                 "\"description\":\"Tells you when a job ends\",\"homepage\":\"https://example.org/notify\","
                 "\"core\":{\"min\":\"0.0.7\"},\"modes\":[\"grbl\"],"
                 "\"capabilities\":[\"events\",\"machine.read\",\"net.outbound:mqtt.example.org:8883\",\"storage:8\",\"hold\"],"
                 "\"conflicts\":[\"org.example.other\"]}"), "the whole manifest: %s", err);
    CHECK(strcmp(m.id, "org.example.notify") == 0 && strcmp(m.version, "1.2.3") == 0 && m.runtime == RUNTIME_PYTHON
          && strcmp(m.exec, "bin/run.py") == 0 && m.nargs == 1 && strcmp(m.args[0], "--quiet") == 0
          && m.mode_grbl && !m.mode_cloud && m.ncaps == 5 && manifest_has_cap(&m, "hold") && m.nconflicts == 1
          && strcmp(m.core_min, "0.0.7") == 0 && m.api_major == 0 && m.api_minor == 1
          && manifest_has_service(&m), "the whole manifest's fields");

    CHECK(parses("{\"manifest\":1,\"id\":\"org.example.theme\",\"name\":\"Theme\",\"version\":\"0.1.0\","
                 "\"author\":\"A\",\"license\":\"CC0-1.0\",\"api\":\"0.1\",\"runtime\":\"data\",\"capabilities\":[]}"),
          "the smallest data package: %s", err);
    CHECK(m.mode_grbl && m.mode_cloud && m.ncaps == 0 && !manifest_has_service(&m) && !m.exec[0],
          "the smallest data package's defaults");

    CHECK(refused_with("not json", "not JSON"), "not JSON -> %s", err);
    CHECK(refused_with("[1]", "not a JSON object"), "an array -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"id\":\"org.example.twice\",\"runtime\":\"data\",\"capabilities\":[]}", "not JSON"),
          "a duplicate key -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"data\",\"capabilities\":[],\"kind\":\"runner-fd\"}", "unknown key \"kind\""),
          "an unknown key -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"data\",\"capabilities\":[],\"provider\":{}}", "unknown key"),
          "a provider key -> %s", err);
    CHECK(refused_with("{\"manifest\":2,\"id\":\"a.b\"}", "schema number"), "schema 2 -> %s", err);
    CHECK(refused_with("{\"manifest\":1,\"id\":\"notify\",\"name\":\"N\",\"version\":\"1.0.0\"}", "reverse-DNS"),
          "a one-label id -> %s", err);
    CHECK(refused_with("{\"manifest\":1,\"id\":\"Org.Example.x\",\"name\":\"N\"}", "reverse-DNS"), "an uppercase id -> %s", err);
    CHECK(refused_with("{\"manifest\":1,\"id\":\"org.example/../x\",\"name\":\"N\"}", "reverse-DNS"), "a path in the id -> %s", err);
    CHECK(!manifest_id_ok("org..x") && !manifest_id_ok("org.x-") && !manifest_id_ok(".org.x") && !manifest_id_ok("org.9x")
          && manifest_id_ok("org.x9") && manifest_id_ok("io.github.some-one.tool"), "id forms");
    CHECK(refused_with("{\"manifest\":1,\"id\":\"org.example.x\",\"name\":\"N\",\"version\":\"1.0\"}", "MAJOR.MINOR.PATCH"),
          "a two-part version -> %s", err);
    CHECK(refused_with("{\"manifest\":1,\"id\":\"org.example.x\",\"name\":\"N\",\"version\":\"01.0.0\"}", "MAJOR.MINOR.PATCH"),
          "a leading zero -> %s", err);
    CHECK(refused_with("{\"manifest\":1,\"id\":\"org.example.x\",\"name\":\"a\\u0007b\",\"version\":\"1.0.0\"}",
                       "control character"), "a bell in the name -> %s", err);

#define HEAD_NO_API "{\"manifest\":1,\"id\":\"org.example.notify\",\"name\":\"N\",\"version\":\"1.0.0\",\"author\":\"A\",\"license\":\"MIT\","
    CHECK(refused_with(HEAD_NO_API "\"api\":\"0.2\",\"runtime\":\"data\",\"capabilities\":[]}", "this firmware serves 0.1"),
          "API 0.2 -> %s", err);
    CHECK(refused_with(HEAD_NO_API "\"api\":\"1.0\",\"runtime\":\"data\",\"capabilities\":[]}", "this firmware serves 0.1"),
          "API 1.0 -> %s", err);
    CHECK(refused_with(HEAD_NO_API "\"api\":\"0.1.0\",\"runtime\":\"data\",\"capabilities\":[]}", "MAJOR.MINOR"),
          "a three-part API -> %s", err);
    CHECK(refused_with(HEAD_NO_API "\"runtime\":\"data\",\"capabilities\":[]}", "\"api\" is missing"), "no API -> %s", err);

    CHECK(refused_with(BASE_HEAD "\"runtime\":\"lua\",\"capabilities\":[]}", "data, ui, shell, native, python"),
          "runtime lua -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"data\",\"service\":{\"exec\":\"x\"},\"capabilities\":[]}", "has no \"service\""),
          "a data package with a service -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"shell\",\"capabilities\":[]}", "needs a \"service\""),
          "a shell package with no service -> %s", err);
    static const char *const bad_exec[] = { "/bin/sh", "../run.sh", "bin/../../run.sh", "bin//run.sh", "./run.sh",
                                            "bin/run me.sh", "bin\\\\run.sh", "" };
    for (size_t i = 0; i < sizeof(bad_exec) / sizeof(bad_exec[0]); i++) {
        char text[1024];
        snprintf(text, sizeof(text), BASE_HEAD "\"runtime\":\"shell\",\"service\":{\"exec\":\"%s\"},\"capabilities\":[]}",
                 bad_exec[i]);
        CHECK(manifest_parse(text, strlen(text), &m, err, sizeof(err)) != 0, "exec \"%s\" was taken", bad_exec[i]);
    }
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"shell\",\"service\":{\"exec\":\"run.sh\",\"user\":\"root\"},\"capabilities\":[]}",
                       "unknown key \"user\""), "a service that names a user -> %s", err);

    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[\"role:homing\"]}", "part of the firmware"), "role:homing -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[\"role:controller\"]}", "part of the firmware"),
          "role:controller -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[\"cnc.write\"]}", "is not a capability"), "cnc.write -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[\"events\",\"events\"]}", "listed twice"), "events twice -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[\"storage:8\",\"storage:16\"]}", "asked for twice"),
          "storage twice -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[7]}", "is not a string"), "a number -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":\"events\"}", "is an array"), "a string for the list -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"modes\":[\"grbl\"]}", "\"capabilities\" is missing"), "no capabilities -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"data\",\"capabilities\":[\"events\"]}", "holds no capability"),
          "a data package with a capability -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"ui\",\"capabilities\":[\"ui\",\"hold\"]}", "belongs to a service"),
          "a UI package with a hold -> %s", err);
    CHECK(refused_with(BASE_HEAD "\"runtime\":\"ui\",\"capabilities\":[\"net.outbound:a.example:1\"]}", "belongs to a service"),
          "a UI package with a destination -> %s", err);
    CHECK(parses(BASE_HEAD "\"runtime\":\"ui\",\"capabilities\":[\"ui\",\"camera.lid\",\"motion.jog\"]}"),
          "a UI package with what its page uses: %s", err);

    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[],\"modes\":[]}", "grbl, cloud, or both"), "empty modes -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[],\"modes\":[\"grbl\",\"grbl\"]}", "each once"), "grbl twice -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[],\"modes\":[\"factory\"]}", "grbl, cloud, or both"),
          "mode factory -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[],\"conflicts\":[\"org.example.notify\"]}", "with itself"),
          "a conflict with itself -> %s", err);
    CHECK(refused_with(BASE_HEAD SERVICE "\"capabilities\":[],\"core\":{\"min\":\"0.1.0\",\"max\":\"0.0.9\"}}", "above"),
          "core min above max -> %s", err);

    CHECK(manifest_version_cmp("1.2.3", "1.2.3") == 0 && manifest_version_cmp("1.2.3", "1.2.10") < 0
          && manifest_version_cmp("1.10.0", "1.9.9") > 0 && manifest_version_cmp("2.0.0-rc1", "2.0.0") < 0
          && manifest_version_cmp("2.0.0", "2.0.0-rc1") > 0 && manifest_version_cmp("2.0.0-a", "2.0.0-b") < 0,
          "version order");
    CHECK(manifest_id_reserved("org.openglow.align") && manifest_id_reserved("org.forgefirm.x")
          && !manifest_id_reserved("org.openglowfan.x") && !manifest_id_reserved("com.example.x"), "the reserved namespace");

    static char big[MANIFEST_MAX_BYTES + 64];
    memset(big, ' ', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    CHECK(refused_with(big, "larger than"), "an oversized manifest -> %s", err);

    printf("%s: manifest_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
