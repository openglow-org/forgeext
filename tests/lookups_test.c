/*
 * lookups_test.c - host test for the answers table the allowlist's names are looked up in
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * net_lookups over a stand-in resolver that answers a name only when the
 * test lets it, and a clock the test sets: no network, no nft, no root.
 * Cases: an answer is used for 30 s and asked again after; a table of 32
 * fresh answers refuses a 33rd name without asking the resolver; a full
 * table refuses a new name while its one lookup under way is 59 s old, and
 * gives that slot to it at 61 s; the let-go lookup's late answer is
 * discarded and the new name's own kept; a name whose lookup is under way
 * is not asked again, even 70 s on; and with 32 lookups inside the
 * resolver a 33rd name is refused without asking, though a slot could be
 * let go, each lookup on a stack of NET_LOOKUP_STACK; and a lookup that
 * was let go still counts toward the 32 until it returns.
 *
 * And the route table an IPv6 answer is judged against (net_on_link6),
 * over a table of the test's own: which routes say on-link, a prefix that
 * ends inside a hex digit, a table that cannot be read or not to its end,
 * and no table at all.
 */
#define _GNU_SOURCE
#include "../src/netrules.h"

#include <dirent.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

/* The stand-in resolver's names: each answers addr once the test lets it
 * (held 0), and counts how often it was asked. */
typedef struct {
    char host[64], addr[64];
    int held, asked;
    size_t stack;                       /* the stack of the thread that asked it last */
} name_t;

#define MAX_NAMES 256
static name_t names[MAX_NAMES];
static int nnames;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static double clock_s;
static char err[256];

static double fake_now(void)
{
    pthread_mutex_lock(&mu);
    double t = clock_s;
    pthread_mutex_unlock(&mu);
    return t;
}

static name_t *name_of(const char *host)               /* under mu */
{
    for (int i = 0; i < nnames; i++)
        if (strcmp(names[i].host, host) == 0)
            return &names[i];
    return NULL;
}

static int fake_resolve(const char *host, struct addrinfo **res)
{
    char addr[64] = "";
    pthread_attr_t ta;
    size_t stack = 0;
    if (pthread_getattr_np(pthread_self(), &ta) == 0) {
        pthread_attr_getstacksize(&ta, &stack);
        pthread_attr_destroy(&ta);
    }
    pthread_mutex_lock(&mu);
    name_t *n = name_of(host);
    if (n) {
        n->asked++;
        n->stack = stack;
        pthread_cond_broadcast(&cv);
        while (n->held)
            pthread_cond_wait(&cv, &mu);
        snprintf(addr, sizeof(addr), "%s", n->addr);
    }
    pthread_mutex_unlock(&mu);
    if (!addr[0])
        return EAI_NONAME;
    struct addrinfo hints = { .ai_flags = AI_NUMERICHOST, .ai_socktype = SOCK_STREAM };
    return getaddrinfo(addr, NULL, &hints, res);
}

static void add_name(const char *host, const char *addr, int held)
{
    pthread_mutex_lock(&mu);
    if (nnames < MAX_NAMES) {
        name_t *n = &names[nnames++];
        snprintf(n->host, sizeof(n->host), "%s", host);
        snprintf(n->addr, sizeof(n->addr), "%s", addr);
        n->held = held;
    }
    pthread_mutex_unlock(&mu);
}

static void let_go(const char *host)
{
    pthread_mutex_lock(&mu);
    name_t *n = name_of(host);
    if (n)
        n->held = 0;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
}

static int asked(const char *host)
{
    pthread_mutex_lock(&mu);
    name_t *n = name_of(host);
    int k = n ? n->asked : -1;
    pthread_mutex_unlock(&mu);
    return k;
}

/* Until the resolver has been asked host this many times (10 s at most). */
static int wait_asked(const char *host, int times)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    pthread_mutex_lock(&mu);
    name_t *n = name_of(host);
    int rc = 0;
    while (n && n->asked < times && rc == 0)
        rc = pthread_cond_timedwait(&cv, &mu, &until);
    int ok = n && n->asked >= times;
    pthread_mutex_unlock(&mu);
    return ok;
}

/* This process's threads but the main one: the lookups still running. */
static int lookup_threads(void)
{
    DIR *d = opendir("/proc/self/task");
    int n = -1;
    for (struct dirent *e; d && (e = readdir(d));)
        n += e->d_name[0] != '.';
    if (d)
        closedir(d);
    return n;
}

/* Until exactly n lookup threads are left (10 s at most): a thread that has
 * ended has made its write to the table. */
static int wait_threads(int n)
{
    for (int i = 0; i < 10000; i++) {
        if (lookup_threads() == n)
            return 1;
        struct timespec ms = { 0, 1000000 };
        nanosleep(&ms, NULL);
    }
    return 0;
}

/* One start's try for host at time t: net_lookups' answer, its words in err. */
static int look(const char *host, double t)
{
    net_dest_t d = { .port = 443 };
    snprintf(d.host, sizeof(d.host), "%s", host);
    pthread_mutex_lock(&mu);
    clock_s = t;
    pthread_mutex_unlock(&mu);
    err[0] = '\0';
    return net_lookups(&d, 1, err, sizeof(err));
}

/* The same, tried until host's lookup has ended (10 s at most). */
static int answered(const char *host, double t)
{
    int rc = NET_PENDING;
    for (int i = 0; i < 10000 && (rc = look(host, t)) == NET_PENDING; i++) {
        struct timespec ms = { 0, 1000000 };
        nanosleep(&ms, NULL);
    }
    return rc;
}

/* Each case starts far from the last one's, with every answer it left old. */
static double next_case(void)
{
    static double at;
    return at += 1000;
}

static void an_answer_lapses(void)
{
    double t = next_case();
    add_name("lapse.test", "198.51.100.10", 0);
    CHECK(answered("lapse.test", t) == 0 && asked("lapse.test") == 1, "lapse.test answered once: %s", err);
    CHECK(look("lapse.test", t + 29) == 0 && asked("lapse.test") == 1,
          "at 29 s the answer is used and the name not asked again: asked %d times", asked("lapse.test"));
    CHECK(answered("lapse.test", t + 31) == 0 && asked("lapse.test") == 2,
          "at 31 s the name is asked again: asked %d times", asked("lapse.test"));
    CHECK(wait_threads(0), "the lookups ended: %d left", lookup_threads());
}

static void a_full_table(void)
{
    double t = next_case();
    char host[64];
    int all = 1;
    for (int i = 0; i < NET_LOOKUPS_MAX; i++) {
        snprintf(host, sizeof(host), "full%d.test", i);
        add_name(host, "198.51.100.11", 0);
        look(host, t);
    }
    for (int i = 0; i < NET_LOOKUPS_MAX; i++) {
        snprintf(host, sizeof(host), "full%d.test", i);
        all &= answered(host, t) == 0;
    }
    CHECK(all, "32 names answered");
    add_name("extra.test", "198.51.100.12", 0);
    int rc = look("extra.test", t + 10);
    CHECK(rc == -1 && asked("extra.test") == 0,
          "32 fresh answers: a 33rd name refused without asking -> %d (%s), asked %d times", rc, err,
          asked("extra.test"));
    CHECK(wait_threads(0), "the lookups ended: %d left", lookup_threads());
}

static void a_lookup_let_go(void)
{
    double t = next_case();
    char host[64];
    int all = 1;
    /* Its late answer would be this machine: discarded, it is never seen. */
    add_name("stuck.test", "127.0.0.1", 1);
    CHECK(look("stuck.test", t) == NET_PENDING && wait_asked("stuck.test", 1), "stuck.test under way: %s", err);
    for (int i = 0; i < NET_LOOKUPS_MAX - 1; i++) {
        snprintf(host, sizeof(host), "busy%d.test", i);
        add_name(host, "198.51.100.13", 0);
        all &= answered(host, t + 40) == 0;
    }
    CHECK(all, "31 names answered at 40 s");
    add_name("late.test", "198.51.100.14", 1);
    int rc = look("late.test", t + 59);
    CHECK(rc == -1 && asked("late.test") == 0,
          "at 59 s a full table refuses late.test without asking -> %d (%s), asked %d times", rc, err,
          asked("late.test"));
    rc = look("late.test", t + 61);
    CHECK(rc == NET_PENDING && wait_asked("late.test", 1),
          "at 61 s stuck.test's slot is given to late.test, and late.test asked -> %d (%s)", rc, err);
    let_go("stuck.test");
    CHECK(wait_threads(1), "stuck.test's lookup ended: %d left", lookup_threads());
    rc = look("late.test", t + 62);
    CHECK(rc == NET_PENDING, "stuck.test's late answer is discarded, late.test still being looked up -> %d (%s)", rc,
          err);
    let_go("late.test");
    rc = answered("late.test", t + 62);
    CHECK(rc == 0, "late.test's own answer is kept -> %d (%s)", rc, err);
    CHECK(wait_threads(0), "the lookups ended: %d left", lookup_threads());
}

static void no_second_lookup(void)
{
    double t = next_case();
    add_name("hung.test", "198.51.100.15", 1);
    CHECK(look("hung.test", t) == NET_PENDING && wait_asked("hung.test", 1), "hung.test under way: %s", err);
    int rc = look("hung.test", t + 70);
    CHECK(rc == -1, "at 70 s, still under way: not answered, and not asked again -> %d (%s)", rc, err);
    let_go("hung.test");
    CHECK(wait_threads(0) && asked("hung.test") == 1, "hung.test asked %d times, %d lookups left", asked("hung.test"),
          lookup_threads());
}

static void the_thread_cap(void)
{
    double t = next_case();
    char host[64];
    int all = 1;
    for (int i = 0; i < NET_LOOKUPS_MAX; i++) {
        snprintf(host, sizeof(host), "held%d.test", i);
        add_name(host, "198.51.100.16", 1);
        all &= look(host, t) == NET_PENDING && wait_asked(host, 1);
    }
    CHECK(all && lookup_threads() == NET_LOOKUPS_MAX, "32 lookups inside the resolver: %d", lookup_threads());
    pthread_mutex_lock(&mu);
    size_t stack = name_of("held0.test")->stack;
    pthread_mutex_unlock(&mu);
    CHECK(stack == NET_LOOKUP_STACK, "a lookup's stack: %zu bytes, expected %d", stack, NET_LOOKUP_STACK);
    add_name("capped.test", "198.51.100.17", 0);
    int rc = look("capped.test", t + 61);
    CHECK(rc == -1 && asked("capped.test") == 0,
          "at 61 s, with 32 lookups inside the resolver, a 33rd name refused without asking -> %d (%s), asked %d "
          "times", rc, err, asked("capped.test"));
    for (int i = 0; i < NET_LOOKUPS_MAX; i++) {
        snprintf(host, sizeof(host), "held%d.test", i);
        let_go(host);
    }
    CHECK(wait_threads(0), "the lookups ended: %d left", lookup_threads());
}

/* The cap counts a lookup that was let go, not only a slot still asking:
 * 31 names held, one answered and fresh, a new name takes a let-go slot at
 * 61 s, and a further one would be a 33rd thread. */
static void the_cap_counts_let_go(void)
{
    double t = next_case();
    char host[64];
    for (int i = 0; i < NET_LOOKUPS_MAX - 1; i++) {
        snprintf(host, sizeof(host), "kept%d.test", i);
        add_name(host, "198.51.100.20", 1);
        look(host, t);
        wait_asked(host, 1);
    }
    add_name("fresh.test", "198.51.100.21", 0);
    CHECK(answered("fresh.test", t + 50) == 0, "a fresh answer keeps one slot: %s", err);
    add_name("one.test", "198.51.100.22", 1);
    CHECK(look("one.test", t + 61) == NET_PENDING && wait_asked("one.test", 1) && lookup_threads() == NET_LOOKUPS_MAX,
          "at 61 s one.test takes a slot let go: %d lookups inside the resolver (%s)", lookup_threads(), err);
    add_name("two.test", "198.51.100.23", 1);
    int rc = look("two.test", t + 61);
    CHECK(rc == -1 && asked("two.test") == 0,
          "31 still asking and one let go, 32 lookups inside the resolver: a further name refused without asking "
          "-> %d (%s), asked %d times, %d threads", rc, err, asked("two.test"), lookup_threads());
    for (int i = 0; i < NET_LOOKUPS_MAX - 1; i++) {
        snprintf(host, sizeof(host), "kept%d.test", i);
        let_go(host);
    }
    let_go("one.test");
    let_go("two.test");
    CHECK(wait_threads(0), "the lookups ended: %d left", lookup_threads());
}

/* The route table's reading. Flags as the kernel prints them: 1 up, 2
 * gateway, 0x200 reject, 0x00100000 anycast, 0x80000000 local. */
static void the_route_table(void)
{
#define NET6(group) "20010db8" group "00000000000000000000"
    static const struct {
        const char *dest;
        unsigned plen, flags;
        const char *dev;
    } routes[] = {
        { NET6("000a"), 64, 0x3, "eth0" },              { NET6("000b"), 64, 0x201, "eth0" },
        { NET6("000c"), 64, 0x80000001U, "eth0" },      { NET6("00c1"), 64, 0x00100001, "eth0" },
        { NET6("000d"), 64, 0x0, "eth0" },              { NET6("000e"), 64, 0x1, "lo" },
        { "20010db80011", 64, 0x1, "eth0" },            /* a destination cut short: no route */
        { "00000000000000000000000000000000", 0, 0x1, "eth0" },
        { "ff000000000000000000000000000000", 8, 0x1, "eth0" },
        { "20010db8001000080000000000000000", 61, 0x1, "eth0" },
        { NET6("0012"), 64, 0x1, "eth0" },
    };
    static const struct {
        const char *addr;
        int want;
        const char *what;
    } asks[] = {
        { "2001:db8:a::1", 0, "a route through a gateway" },
        { "2001:db8:b::1", 0, "a reject route" },
        { "2001:db8:c::1", 0, "this machine's own address (local)" },
        { "2001:db8:c1::1", 0, "this machine's own anycast address" },
        { "2001:db8:d::1", 0, "a route that is not up" },
        { "2001:db8:e::1", 0, "a route on lo" },
        { "2001:db8:f::1", 0, "a default route with no gateway (0 bits)" },
        { "ff02::1", 0, "the multicast route" },
        { "2001:db8:10:f::1", 1, "the last /64 of an on-link /61" },
        { "2001:db8:10:7::1", 0, "the /64 below an on-link /61" },
        { "2001:db8:11::1", 0, "a line that is no route" },
        { "2001:db8:12::1", 1, "an on-link /64, after lines that are no route" },
    };
    char path[] = "/tmp/lookups_test.XXXXXX", none[64];
    int fd = mkstemp(path);
    FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
    CHECK(f != NULL, "a route table of the test's own");
    if (!f)
        return;
    fprintf(f, "not a route\n");
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++)
        fprintf(f, "%s %02x %032x 00 %032x 00000100 00000001 00000000 %08x %8s\n", routes[i].dest, routes[i].plen, 0, 0,
                routes[i].flags, routes[i].dev);
    fclose(f);
    for (size_t i = 0; i < sizeof(asks) / sizeof(asks[0]); i++) {
        int got = net_on_link6(path, asks[i].addr);
        CHECK(got == asks[i].want, "%s: %s on-link -> %d, expected %d", asks[i].what, asks[i].addr, got, asks[i].want);
    }
    /* The careful answer for a table that cannot be read (its path runs
     * through a file) or not to its end (a directory opens and does not
     * read); no table at all is a kernel with no IPv6. */
    snprintf(none, sizeof(none), "%s/routes", path);
    CHECK(net_on_link6(none, "2001:db8:f::1") == 1, "a route table that does not open is the careful answer");
    CHECK(net_on_link6("/tmp", "2001:db8:f::1") == 1, "a route table that does not read is the careful answer");
    unlink(path);
    CHECK(net_on_link6(path, "2001:db8:12::1") == 0, "no route table: nothing is on-link");
#undef NET6
}

int main(void)
{
    the_route_table();
    net_lookup_seams(fake_resolve, fake_now);
    an_answer_lapses();
    a_full_table();
    a_lookup_let_go();
    no_second_lookup();
    the_thread_cap();
    the_cap_counts_let_go();
    net_lookup_seams(NULL, NULL);
    printf("%s: lookups_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
