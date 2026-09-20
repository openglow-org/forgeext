/*
 * caps_test.c - host test for the closed capability list
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Cases: every offered capability passes in its own spelling and nothing
 * else does; the two privileged roles are refused by name and every other
 * role with them; a capability that is known and not offered says so; the
 * four that need the operator's own grant are exactly those four; an
 * argument is held to its form (a destination never names the machine
 * itself, a listening port is never the firmware's, a quota has a
 * ceiling); a bare capability takes no argument and a parameterized one
 * is never bare.
 */
#include "../src/caps.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static char why[256];

static int ok(const char *cap)
{
    return caps_check(cap, why, sizeof(why)) == 0;
}

static int refused_with(const char *cap, const char *words)
{
    return caps_check(cap, why, sizeof(why)) != 0 && strstr(why, words) != NULL;
}

int main(void)
{
    static const char *const good[] = {
        "machine.read", "events", "settings.own", "camera.lid", "camera.head", "motion.jog", "motion.job",
        "hold", "job_time.run", "ui", "net.outbound:mqtt.example.org:8883", "net.outbound:192.168.1.20:1883",
        "net.outbound:[2001:db8::1]:443", "net.listen:8123", "storage:16", "storage:256",
    };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        CHECK(ok(good[i]), "%s refused: %s", good[i], why);

    CHECK(refused_with("role:homing", "part of the firmware"), "role:homing -> %s", why);
    CHECK(refused_with("role:controller", "part of the firmware"), "role:controller -> %s", why);
    CHECK(refused_with("role:focus", "no package provides a role"), "role:focus -> %s", why);
    CHECK(refused_with("role", "no package provides a role"), "role -> %s", why);
    CHECK(refused_with("runner-fd", "is not a capability"), "runner-fd -> %s", why);
    CHECK(refused_with("pulse.fd", "is not a capability"), "pulse.fd -> %s", why);
    CHECK(refused_with("motion.offsets", "not offered"), "motion.offsets -> %s", why);
    CHECK(refused_with("wizard", "not offered"), "wizard -> %s", why);
    CHECK(refused_with("mcode:101", "not offered"), "mcode:101 -> %s", why);

    int needs = 0;
    for (size_t i = 0; i < caps_count(); i++)
        needs += caps_at(i)->explicit_grant;
    CHECK(needs == 4, "%d capabilities need the operator's grant, expected 4", needs);
    CHECK(caps_needs_grant("hold") && caps_needs_grant("job_time.run") && caps_needs_grant("motion.job")
          && caps_needs_grant("motion.offsets"), "one of the four does not need a grant");
    CHECK(!caps_needs_grant("machine.read") && !caps_needs_grant("net.outbound:a.example:1")
          && !caps_needs_grant("nonsense"), "a plain capability needs a grant");

    CHECK(refused_with("machine.read:all", "takes no argument"), "machine.read:all -> %s", why);
    CHECK(refused_with("storage", "needs an argument"), "storage -> %s", why);
    CHECK(refused_with("storage:", "needs an argument"), "storage: -> %s", why);
    CHECK(refused_with("storage:0", "1 to 256"), "storage:0 -> %s", why);
    CHECK(refused_with("storage:257", "1 to 256"), "storage:257 -> %s", why);
    CHECK(refused_with("storage:016", "1 to 256"), "storage:016 -> %s", why);
    CHECK(refused_with("storage:16MiB", "1 to 256"), "storage:16MiB -> %s", why);
    CHECK(refused_with("net.listen:80", "1024 to 65535"), "net.listen:80 -> %s", why);
    CHECK(refused_with("net.listen:23", "1024 to 65535"), "net.listen:23 -> %s", why);
    CHECK(refused_with("net.listen:8090", "the firmware's own"), "net.listen:8090 -> %s", why);
    CHECK(refused_with("net.listen:65536", "1024 to 65535"), "net.listen:65536 -> %s", why);
    CHECK(refused_with("net.outbound:example.org", "host:port"), "no port -> %s", why);
    CHECK(refused_with("net.outbound:example.org:0", "host:port"), "port 0 -> %s", why);
    CHECK(refused_with("net.outbound:Example.org:443", "host:port"), "uppercase host -> %s", why);
    CHECK(refused_with("net.outbound:exa mple.org:443", "no space"), "a space -> %s", why);
    CHECK(refused_with("net.outbound:-bad.example:443", "host:port"), "a label starting with - -> %s", why);
    CHECK(refused_with("net.outbound:*:443", "host:port"), "a wildcard -> %s", why);
    CHECK(refused_with("net.outbound:localhost:23", "the machine itself"), "localhost -> %s", why);
    CHECK(refused_with("net.outbound:127.0.0.1:443", "the machine itself"), "127.0.0.1 -> %s", why);
    CHECK(refused_with("net.outbound:[::1]:80", "the machine itself"), "::1 -> %s", why);
    CHECK(refused_with("", "1 to"), "the empty string -> %s", why);

    char host[64];
    int port = 0;
    CHECK(caps_outbound_parse("[2001:db8::1]:443", host, sizeof(host), &port) == 0
          && strcmp(host, "2001:db8::1") == 0 && port == 443, "the bracketed form parsed to %s %d", host, port);
    CHECK(caps_outbound_parse("mqtt.example.org:8883", host, sizeof(host), &port) == 0
          && strcmp(host, "mqtt.example.org") == 0 && port == 8883, "the name form parsed to %s %d", host, port);

    printf("%s: caps_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
