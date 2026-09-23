/*
 * state_test.c - host test for state.json
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Cases: a root with no file is an empty state; what is saved is what
 * loads, field for field; the pool hands out the lowest free account and
 * none past the thirty-second; removal frees the account; and a file this
 * daemon did not write is refused whole: another schema, an id that is
 * not one, a tier that does not exist, a key on an unverified package or
 * none on a signed one, an account outside the pool, two packages on one
 * account, a grant for a capability that needs none.
 */
#include "../src/state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static char root[64] = "/tmp/forgeext-state.XXXXXX";
static char err[512];

static void put(const char *text)
{
    char p[128];
    snprintf(p, sizeof(p), "%s/state.json", root);
    FILE *f = fopen(p, "w");
    fputs(text, f);
    fclose(f);
}

static int refused_with(const char *text, const char *words)
{
    static state_t s;
    put(text);
    return state_load(root, &s, err, sizeof(err)) != 0 && strstr(err, words) != NULL && s.n == 0;
}

#define KEY64 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

int main(void)
{
    static state_t s, t;
    char cmd[320];

    if (!mkdtemp(root))
        return 2;
    CHECK(state_load(root, &s, err, sizeof(err)) == 0 && s.n == 0, "an empty root: %s", err);

    state_pkg_t *a = state_add(&s, "org.example.notify");
    snprintf(a->version, sizeof(a->version), "1.2.3");
    snprintf(a->previous, sizeof(a->previous), "1.2.2");
    a->tier = TIER_COMMUNITY;
    snprintf(a->key_id, sizeof(a->key_id), KEY64);
    a->slot = state_slot_free(&s);
    a->enabled = 1;
    snprintf(a->grants[a->ngrants++], CAP_MAX_LEN, "hold");
    snprintf(a->grants[a->ngrants++], CAP_MAX_LEN, "motion.job");
    snprintf(a->dests[a->ndests++], CAP_MAX_LEN, "plug.lan:80");
    snprintf(a->dests[a->ndests++], CAP_MAX_LEN, "[2001:db8::7]:1883");
    state_pkg_t *b = state_add(&s, "org.example.theme");
    snprintf(b->version, sizeof(b->version), "0.1.0");
    b->tier = TIER_UNVERIFIED;
    b->quarantined = 1;
    CHECK(a->slot == 0 && b->slot == -1, "accounts: %d and %d", a->slot, b->slot);
    CHECK(state_add(&s, "not an id") == NULL, "a bad id was added");
    CHECK(state_save(root, &s, err, sizeof(err)) == 0, "save: %s", err);
    CHECK(state_load(root, &t, err, sizeof(err)) == 0 && t.n == 2, "load: %s", err);
    state_pkg_t *la = state_find(&t, "org.example.notify"), *lb = state_find(&t, "org.example.theme");
    CHECK(la && lb, "both packages came back");
    if (la && lb) {
        CHECK(strcmp(la->version, "1.2.3") == 0 && strcmp(la->previous, "1.2.2") == 0 && la->tier == TIER_COMMUNITY
              && strcmp(la->key_id, KEY64) == 0 && la->slot == 0 && la->enabled && !la->quarantined && la->ngrants == 2
              && state_granted(la, "hold") && state_granted(la, "motion.job") && !state_granted(la, "job_time.run"),
              "the service package's fields");
        CHECK(la->ndests == 2 && strcmp(la->dests[0], "plug.lan:80") == 0 && strcmp(la->dests[1], "[2001:db8::7]:1883") == 0,
              "the operator's destinations, in order: %d", la->ndests);
        CHECK(lb->tier == TIER_UNVERIFIED && !lb->key_id[0] && lb->slot == -1 && !lb->enabled && lb->quarantined
              && lb->ngrants == 0 && lb->ndests == 0, "the data package's fields");
    }
    snprintf(cmd, sizeof(cmd), "test \"$(stat -c %%a %s/state.json)\" = 600 && ! test -e %s/state.json.new", root, root);
    CHECK(system(cmd) == 0, "state.json is not 0600, or its temporary file stayed");

    for (int i = 1; i < STATE_POOL_SIZE; i++) {
        char id[64];
        snprintf(id, sizeof(id), "org.example.svc%d", i);
        state_pkg_t *p = state_add(&t, id);
        p->slot = state_slot_free(&t);
        CHECK(p->slot == i, "service %d got account %d", i, p->slot);
    }
    CHECK(state_slot_free(&t) == -1, "a thirty-third account was handed out");
    state_remove(&t, "org.example.svc7");
    CHECK(state_slot_free(&t) == 7 && !state_find(&t, "org.example.svc7"), "removal did not free account 7");

#define PKG(fields) "{\"state\":1,\"packages\":{\"org.example.x\":{" fields "}}}"
#define GOOD "\"version\":\"1.0.0\",\"previous\":\"\",\"enabled\":true,\"quarantined\":false,"
    CHECK(refused_with("{\"state\":2,\"packages\":{}}", "schema 1"), "schema 2 -> %s", err);
    CHECK(refused_with("{\"state\":1}", "schema 1"), "no packages -> %s", err);
    CHECK(refused_with("{\"state\":1,\"packages\":{\"../x\":{}}}", "does not read"), "a path as an id -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"root\",\"key\":\"\",\"slot\":-1,\"grants\":[]"), "does not read"), "tier root -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"" KEY64 "\",\"slot\":-1,\"grants\":[]"), "does not read"),
          "a key on an unverified package -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"official\",\"key\":\"\",\"slot\":-1,\"grants\":[]"), "does not read"),
          "no key on an official package -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":32,\"grants\":[]"), "does not read"),
          "account 32 -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":0,\"grants\":[\"machine.read\"]"), "does not read"),
          "a grant for machine.read -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":0,\"grants\":[\"role:homing\"]"), "does not read"),
          "a grant for role:homing -> %s", err);
    CHECK(refused_with("{\"state\":1,\"packages\":{"
                       "\"org.example.x\":{" GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":3,\"grants\":[]},"
                       "\"org.example.y\":{" GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":3,\"grants\":[]}}}",
                       "two packages hold account ffx3"), "one account twice -> %s", err);
    CHECK(refused_with("{\"state\":1,\"packages\":{", "does not read"), "a file cut short -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":0,\"grants\":[],\"destinations\":[\"plug.lan\"]"),
                       "does not read"), "a destination with no port -> %s", err);
    CHECK(refused_with(PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":0,\"grants\":[],\"destinations\":\"plug.lan:80\""),
                       "does not read"), "destinations that are not a list -> %s", err);
    /* A state written before the operator could name destinations has none. */
    snprintf(cmd, sizeof(cmd), "printf '%%s' '" PKG(GOOD "\"tier\":\"unverified\",\"key\":\"\",\"slot\":0,\"grants\":[]")
             "' > %s/state.json", root);
    CHECK(system(cmd) == 0 && state_load(root, &s, err, sizeof(err)) == 0 && s.n == 1 && s.pkgs[0].ndests == 0,
          "a state with no destinations key: %s", err);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
    if (system(cmd) != 0)
        fails++;
    printf("%s: state_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
