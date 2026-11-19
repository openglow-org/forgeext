/*
 * netrules.c - a running package's way through the image's deny rules
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "netrules.h"
#include "sandbox.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NFT_DEFAULT   "/usr/sbin/nft"
#define NFT_TIMEOUT_S 20
#define SCRIPT_MAX    16384

static int fail(char *err, size_t elen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t elen, const char *fmt, ...)
{
    if (err && elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, elen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* Runs nft with argv (argv[0] replaced by the binary), `input` on its
 * stdin when not NULL, its stdout and stderr together into out. The exit
 * status, or -1. No shell. NFT_TIMEOUT_S is a timeout, so it rides
 * CLOCK_MONOTONIC and no step of the wall clock moves it. */
static int nft_run(const net_env_t *env, const char *const argv_in[], const char *input, char *out, size_t olen)
{
    const char *argv[16];
    int n = 0, in_pipe[2] = { -1, -1 }, out_pipe[2];
    argv[n++] = env && env->nft ? env->nft : NFT_DEFAULT;
    for (int i = 1; argv_in[i] && n < 15; i++)
        argv[n++] = argv_in[i];
    argv[n] = NULL;
    if (out && olen)
        out[0] = '\0';
    if (pipe2(out_pipe, O_CLOEXEC) != 0)
        return -1;
    if (input && pipe2(in_pipe, O_CLOEXEC) != 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        if (input) {
            close(in_pipe[0]);
            close(in_pipe[1]);
        }
        return -1;
    }
    if (pid == 0) {
        int null = open("/dev/null", O_RDONLY);
        dup2(input ? in_pipe[0] : null, 0);
        dup2(out_pipe[1], 1);
        dup2(out_pipe[1], 2);
        sandbox_signals_default();
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(out_pipe[1]);
    if (input) {
        close(in_pipe[0]);
        size_t len = strlen(input), off = 0;
        /* nft may exit on the first rule it will not take, leaving the
         * rest of the script with nowhere to go. The write's own result is
         * what is checked; SIGPIPE is ignored for the whole program in
         * main(). */
        while (off < len) {
            ssize_t k = write(in_pipe[1], input + off, len - off);
            if (k <= 0)
                break;
            off += (size_t)k;
        }
        close(in_pipe[1]);
    }
    size_t got = 0;
    double end = mono() + NFT_TIMEOUT_S;
    int timed_out = 0;
    for (;;) {
        struct pollfd p = { .fd = out_pipe[0], .events = POLLIN };
        int left = (int)((end - mono()) * 1000);
        if (left <= 0) {
            timed_out = 1;
            break;
        }
        int r = poll(&p, 1, left);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            timed_out = r == 0;
            break;
        }
        char buf[1024];
        ssize_t k = read(out_pipe[0], buf, sizeof(buf));
        if (k <= 0)
            break;
        if (out && got + 1 < olen) {
            size_t take = (size_t)k < olen - 1 - got ? (size_t)k : olen - 1 - got;
            memcpy(out + got, buf, take);
            got += take;
            out[got] = '\0';
        }
    }
    close(out_pipe[0]);
    if (timed_out)
        kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    return timed_out || !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
}

/* The text between "chain <name> {" and its closing brace, or NULL. */
static const char *chain_of(const char *table, const char *name, char *out, size_t olen)
{
    char head[64];
    snprintf(head, sizeof(head), "chain %s {", name);
    const char *p = strstr(table, head);
    if (!p)
        return NULL;
    p += strlen(head);
    size_t n = strcspn(p, "}");
    if (n >= olen)
        n = olen - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

int net_base_ok(const net_env_t *env, char *err, size_t elen)
{
    char table[8192], chain[2048], want[64];
    const char *argv[] = { "", "list", "table", "inet", "ffx", NULL };
    if (nft_run(env, argv, NULL, table, sizeof(table)) != 0)
        return fail(err, elen, "table inet ffx is not loaded: the image's deny rules are missing");
    if (!strstr(table, "map allow {"))
        return fail(err, elen, "table inet ffx has no allow map: it is not the image's");
    if (!chain_of(table, "output", chain, sizeof(chain)) || !strstr(chain, "hook output") || !strstr(chain, "policy accept"))
        return fail(err, elen, "table inet ffx has no filter on the output hook: it is not the image's");
    snprintf(want, sizeof(want), "meta skuid %d-%d jump pool", NET_POOL_FIRST, NET_POOL_LAST);
    if (!strstr(chain, want))
        return fail(err, elen, "table inet ffx does not send the account pool (%d-%d) to its refusal", NET_POOL_FIRST,
                    NET_POOL_LAST);
    if (!chain_of(table, "pool", chain, sizeof(chain)))
        return fail(err, elen, "table inet ffx has no pool chain: it is not the image's");
    const char *lo = strstr(chain, "oifname \"lo\" jump refuse"), *map = strstr(chain, "vmap @allow");
    if (!lo || !map || lo > map)
        return fail(err, elen, "table inet ffx does not refuse the machine itself ahead of the allow map");
    if (!strstr(map, "jump refuse"))
        return fail(err, elen, "table inet ffx does not refuse what the allow map lets fall through");
    if (!chain_of(table, "refuse", chain, sizeof(chain)) || !strstr(chain, "reject with tcp reset") || !strstr(chain, "drop"))
        return fail(err, elen, "table inet ffx's refusal does not refuse");
    return 0;
}

int net_sweep(const net_env_t *env, char *err, size_t elen)
{
    /* The chain names alone: the rules of 32 accounts would not fit a
     * buffer worth having. */
    static char text[16384];
    const char *argv[] = { "", "list", "chains", "inet", NULL };
    if (nft_run(env, argv, NULL, text, sizeof(text)) != 0)
        return fail(err, elen, "the chains of table inet ffx cannot be listed");
    int n = 0;
    for (const char *p = text; (p = strstr(p, "chain u")) != NULL;) {
        p += strlen("chain u");
        char *end;
        unsigned long uid = strtoul(p, &end, 10);
        if (end == p || *end != ' ' || uid < NET_POOL_FIRST || uid > NET_POOL_LAST)
            continue;
        if (net_revoke(env, (uid_t)uid, err, elen) != 0)
            return -1;
        n++;
    }
    return n;
}

/* The local-use NAT64 prefix, 64:ff9b:1::/48: a network's own translator,
 * at a prefix length of its choosing. */
static const unsigned char nat64_local[6] = { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01 };

/* The IPv4 addresses an IPv6 one may carry, as the two judgments below
 * read it, into a4: their count, 0 for none. *whole says what they are:
 * 1, each a whole address the form carries:
 *   in bytes 12 to 15: mapped (::ffff:a.b.c.d), compatible (::a.b.c.d),
 *     translated (::ffff:0:a.b.c.d), the well-known NAT64 prefix
 *     (64:ff9b::/96), and an ISATAP interface identifier
 *     (..:0:5efe:a.b.c.d and ..:200:5efe:a.b.c.d, under any prefix);
 *   in bytes 2 to 5: 6to4 (2002::/16). A 6to4 address may have an ISATAP
 *     interface identifier too, and then carries two: both are given.
 * 0, the four places of the local-use NAT64 prefix: the address at each
 *   place a translator of that prefix may keep it (a /48, /56, /64 or /96
 *   prefix; bytes 6-7 and 9-10, 7 and 9-11, 9-12, 12-15), since the
 *   translator's choice cannot be known from here. An ISATAP interface
 *   identifier under that prefix has its address at the last of them. */
#define EMBEDDED_MAX 4

static int embedded_v4(const struct in6_addr *a6, struct in_addr a4[EMBEDDED_MAX], int *whole)
{
    static const unsigned char nat64[12] = { 0x00, 0x64, 0xff, 0x9b };
    static const unsigned char translated[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0 };
    static const unsigned char places[EMBEDDED_MAX][4] = { { 6, 7, 9, 10 }, { 7, 9, 10, 11 }, { 9, 10, 11, 12 },
                                                           { 12, 13, 14, 15 } };
    const unsigned char *b = a6->s6_addr;
    *whole = 0;
    if (memcmp(b, nat64_local, sizeof(nat64_local)) == 0) {
        for (int i = 0; i < EMBEDDED_MAX; i++) {
            unsigned char raw[4];
            for (int k = 0; k < 4; k++)
                raw[k] = b[places[i][k]];
            memcpy(&a4[i], raw, 4);
        }
        return EMBEDDED_MAX;
    }
    *whole = 1;
    int n = 0;
    int isatap = (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5e && b[11] == 0xfe;
    if (IN6_IS_ADDR_V4MAPPED(a6) || IN6_IS_ADDR_V4COMPAT(a6) || memcmp(b, nat64, 12) == 0
        || memcmp(b, translated, 12) == 0 || isatap)
        memcpy(&a4[n++], &b[12], 4);
    if (b[0] == 0x20 && b[1] == 0x02)
        memcpy(&a4[n++], &b[2], 4);
    return n;
}

static int v4_is_self_shaped(const struct in_addr *a)
{
    uint32_t h = ntohl(a->s_addr);
    return h == 0 || (h >> 24) == 127 || (h >> 28) == 14 || h == 0xffffffffU;
}

/* Is raw (an in_addr or an in6_addr) the address of one of this machine's
 * interfaces? 1 too when that cannot be told: the careful answer. */
static int on_interface(int family, const void *raw)
{
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return 1;
    int self = 0;
    for (struct ifaddrs *i = list; i && !self; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != family)
            continue;
        if (family == AF_INET)
            self = memcmp(&((struct sockaddr_in *)i->ifa_addr)->sin_addr, raw, sizeof(struct in_addr)) == 0;
        else
            self = memcmp(&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, raw, sizeof(struct in6_addr)) == 0;
    }
    freeifaddrs(list);
    return self;
}

int net_addr_is_self(const char *addr)
{
    struct in_addr a4, in6[EMBEDDED_MAX];
    struct in6_addr a6;
    if (inet_pton(AF_INET, addr, &a4) == 1)
        return v4_is_self_shaped(&a4) || on_interface(AF_INET, &a4);
    if (inet_pton(AF_INET6, addr, &a6) != 1)
        return -1;
    if (IN6_IS_ADDR_UNSPECIFIED(&a6) || IN6_IS_ADDR_LOOPBACK(&a6) || IN6_IS_ADDR_MULTICAST(&a6))
        return 1;
    /* The machine inside an IPv6 address (a translator, a 6to4 relay or an
     * ISATAP router carries it back in) is the machine. Each whole carried
     * address is judged as an IPv4 destination would be. Of the four places
     * of the local-use NAT64 prefix at most one is an address at all, so
     * each is asked only whether it is loopback or an interface's own. */
    int whole, n = embedded_v4(&a6, in6, &whole);
    for (int i = 0; i < n; i++) {
        char text[INET_ADDRSTRLEN];
        if (!whole ? (ntohl(in6[i].s_addr) >> 24) == 127 || on_interface(AF_INET, &in6[i])
                   : !inet_ntop(AF_INET, &in6[i], text, sizeof(text)) || net_addr_is_self(text) != 0)
            return 1;
    }
    return on_interface(AF_INET6, &a6);
}

/* The route table's flags, as /proc/net/ipv6_route prints them. */
#define ROUTE_UP      0x00000001U
#define ROUTE_GATEWAY 0x00000002U
#define ROUTE_REJECT  0x00000200U
#define ROUTE_ANYCAST 0x00100000U
#define ROUTE_LOCAL   0x80000000U

/* Is an IPv6 address on a link of this machine's, as the route table at
 * path holds it: inside a prefix that is reached with no router (an
 * address configured with its prefix, or a prefix a router announced as
 * on-link beside an address of /128)? 1 too when the table cannot be
 * read, or not to its end; a kernel with no IPv6 has none. */
static int v6_on_link(const char *path, const struct in6_addr *a6)
{
    FILE *f = fopen(path, "re");
    if (!f)
        return errno != ENOENT;
    char line[256], dest[33], dev[32];
    unsigned plen, flags;
    int local = 0;
    while (!local && fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%32[0-9a-f] %x %*32[0-9a-f] %*x %*32[0-9a-f] %*x %*x %*x %x %31s", dest, &plen, &flags, dev) != 4
            || strlen(dest) != 32)
            continue;
        if (!(flags & ROUTE_UP) || (flags & (ROUTE_GATEWAY | ROUTE_REJECT | ROUTE_ANYCAST | ROUTE_LOCAL)) || plen < 1
            || plen > 128 || strcmp(dev, "lo") == 0 || strncmp(dest, "ff", 2) == 0)
            continue;                                   /* through a router, refused, this machine's own, or multicast */
        unsigned same = 1;
        for (unsigned bit = 0; bit < plen && same; bit += 4) {
            unsigned digit = dest[bit / 4] <= '9' ? (unsigned)(dest[bit / 4] - '0') : (unsigned)(dest[bit / 4] - 'a') + 10;
            unsigned mine = (a6->s6_addr[bit / 8] >> (bit % 8 ? 0 : 4)) & 0xfU;
            unsigned mask = plen - bit >= 4 ? 0xfU : (0xfU << (4 - (plen - bit))) & 0xfU;
            same = (digit & mask) == (mine & mask);
        }
        local = (int)same;
    }
    if (ferror(f))
        local = 1;
    fclose(f);
    return local;
}

int net_on_link6(const char *routes, const char *addr)
{
    struct in6_addr a6;
    if (inet_pton(AF_INET6, addr, &a6) != 1)
        return -1;
    return v6_on_link(routes ? routes : NET_ROUTES6, &a6);
}

/* Is a numeric address one of a network that is somebody's own: private,
 * link-local, carrier-grade NAT, unique local, behind a network's own
 * NAT64 translator (the local-use prefix, whole), or on a subnet or an
 * on-link prefix of one of this machine's interfaces? A name is the
 * name's owner's to answer, so a name a manifest gives never leads there;
 * the address itself may (the operator, or a manifest, named that host
 * outright), and so may a name the operator typed (the operator chose
 * that host). */
static int addr_is_local_net(const char *addr)
{
    struct in_addr a4, in6[EMBEDDED_MAX];
    struct in6_addr a6;
    int family;
    if (inet_pton(AF_INET, addr, &a4) == 1) {
        uint32_t h = ntohl(a4.s_addr);
        if ((h >> 24) == 10 || (h >> 20) == 0xac1 || (h >> 16) == 0xc0a8 || (h >> 16) == 0xa9fe || (h >> 22) == 0x191)
            return 1;                                   /* 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 */
        family = AF_INET;
    } else if (inet_pton(AF_INET6, addr, &a6) == 1) {
        if ((a6.s6_addr[0] & 0xfe) == 0xfc || (a6.s6_addr[0] == 0xfe && (a6.s6_addr[1] & 0xc0) == 0x80)
            || memcmp(a6.s6_addr, nat64_local, sizeof(nat64_local)) == 0)
            return 1;                                   /* fc00::/7, fe80::/10, 64:ff9b:1::/48 */
        /* An IPv4 address inside an IPv6 one is judged as that IPv4
         * address, and each of two as itself. */
        int whole, n = embedded_v4(&a6, in6, &whole);
        for (int i = 0; i < n; i++) {
            char text[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &in6[i], text, sizeof(text)) || addr_is_local_net(text))
                return 1;
        }
        family = AF_INET6;
    } else {
        return 1;
    }
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return 1;                                       /* cannot tell: the careful answer */
    int local = 0;
    for (struct ifaddrs *i = list; i && !local; i = i->ifa_next) {
        if (!i->ifa_addr || !i->ifa_netmask || i->ifa_addr->sa_family != family)
            continue;
        if (family == AF_INET) {
            uint32_t mine = ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr;
            uint32_t mask = ((struct sockaddr_in *)i->ifa_netmask)->sin_addr.s_addr;
            local = mask && (mine & mask) == (a4.s_addr & mask);
        } else {
            const unsigned char *mine = ((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr.s6_addr;
            const unsigned char *mask = ((struct sockaddr_in6 *)i->ifa_netmask)->sin6_addr.s6_addr;
            int same = 0;
            for (int k = 0; k < 16; k++) {
                same |= mask[k];
                if ((mine[k] & mask[k]) != (a6.s6_addr[k] & mask[k])) {
                    same = 0;
                    break;
                }
            }
            local = same;
        }
    }
    freeifaddrs(list);
    return local || (family == AF_INET6 && v6_on_link(NET_ROUTES6, &a6));
}

static int append(char *script, size_t *used, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int append(char *script, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(script + *used, SCRIPT_MAX - *used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= SCRIPT_MAX - *used)
        return -1;
    *used += (size_t)n;
    return 0;
}

/* The answers to the names that starts ask for. Each name is looked up on
 * a thread of its own and nobody waits for it: a start whose names are
 * not answered yet is put off, and a later one is made from the stored
 * answer, so a resolver that is slow or never answers holds no turn. Each
 * lookup has its own NET_RESOLVE_S from the moment it was asked; past that
 * with no answer, the resolver did not answer that name, and an answer
 * that comes later is still taken. A name whose lookup is still under way
 * is not asked again while it holds its slot: it stays one the resolver
 * did not answer until its thread returns. An answer, addresses or a
 * refusal, is used for NET_ANSWER_S and then asked again. A slot whose
 * lookup has been under way NET_LOOKUP_STALE_S may be given to another
 * name when no other slot is free; that thread still counts until it
 * returns, and its answer is discarded. At most NET_LOOKUPS_MAX threads
 * are inside the resolver at once, let-go ones included, each on a stack
 * of NET_LOOKUP_STACK; a name asked past that is refused without asking. */
enum { ASK_FREE, ASK_ASKED, ASK_ANSWERED };

typedef struct {
    char host[256];
    int state;
    unsigned gen;                   /* which lookup a thread's answer is for */
    double asked, answered;         /* CLOCK_MONOTONIC */
    int rc, n;                      /* 0 and the addresses, or an EAI_* code */
    char addrs[NET_MAX_ADDRS][INET6_ADDRSTRLEN];
    int families[NET_MAX_ADDRS];
} answer_t;

static answer_t answers[NET_LOOKUPS_MAX];
static unsigned answers_gen;
static int lookups_live;                /* threads inside the resolver, let-go ones included */
static pthread_mutex_t answers_mu = PTHREAD_MUTEX_INITIALIZER;

static int resolve_default(const char *host, struct addrinfo **res)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    return getaddrinfo(host, NULL, &hints, res);
}

static net_resolver_fn resolver = resolve_default;
static double (*clock_now)(void) = mono;

void net_lookup_seams(net_resolver_fn resolve, double (*now)(void))
{
    pthread_mutex_lock(&answers_mu);
    resolver = resolve ? resolve : resolve_default;
    clock_now = now ? now : mono;
    pthread_mutex_unlock(&answers_mu);
}

typedef struct {
    int slot;
    unsigned gen;
    char host[256];
} asking_t;

static void *lookup_run(void *arg)
{
    asking_t *a = arg;
    struct addrinfo *res = NULL;
    pthread_mutex_lock(&answers_mu);
    net_resolver_fn resolve = resolver;
    pthread_mutex_unlock(&answers_mu);
    int rc = resolve(a->host, &res);
    pthread_mutex_lock(&answers_mu);
    lookups_live--;
    answer_t *s = &answers[a->slot];
    if (s->state == ASK_ASKED && s->gen == a->gen) {    /* still the lookup this thread was asked for */
        s->n = 0;
        for (struct addrinfo *r = rc == 0 ? res : NULL; r && s->n < NET_MAX_ADDRS; r = r->ai_next) {
            char text[INET6_ADDRSTRLEN];
            const void *raw = r->ai_family == AF_INET ? (const void *)&((struct sockaddr_in *)r->ai_addr)->sin_addr
                            : r->ai_family == AF_INET6 ? (const void *)&((struct sockaddr_in6 *)r->ai_addr)->sin6_addr
                                                       : NULL;
            if (!raw || !inet_ntop(r->ai_family, raw, text, sizeof(text)))
                continue;
            int seen = 0;
            for (int i = 0; i < s->n; i++)
                seen |= strcmp(s->addrs[i], text) == 0;
            if (!seen) {
                snprintf(s->addrs[s->n], INET6_ADDRSTRLEN, "%s", text);
                s->families[s->n++] = r->ai_family;
            }
        }
        s->rc = rc != 0 ? rc : s->n == 0 ? EAI_NONAME : 0;
        s->state = ASK_ANSWERED;
        s->answered = clock_now();
    }
    pthread_mutex_unlock(&answers_mu);
    if (res)
        freeaddrinfo(res);
    free(a);
    return NULL;
}

/* The slot that holds host's lookup, asked now when there is none or its
 * answer is old. Under answers_mu. ASK_NO_SLOT when every slot holds a
 * lookup under way or an answer still in use, ASK_NO_THREAD when
 * NET_LOOKUPS_MAX lookups are inside the resolver. */
enum { ASK_NO_SLOT = -1, ASK_NO_THREAD = -2 };

static int ask_locked(const char *host, double now)
{
    int at = -1;
    for (int i = 0; i < NET_LOOKUPS_MAX && at < 0; i++)
        if (answers[i].state != ASK_FREE && strcmp(answers[i].host, host) == 0)
            at = i;
    if (at >= 0) {
        const answer_t *s = &answers[at];
        if (s->state == ASK_ASKED || now - s->answered < NET_ANSWER_S)
            return at;                                  /* under way (never asked twice), or an answer in use */
    } else {
        /* A free slot, else the oldest answer, else a lookup let go. */
        for (int i = 0; i < NET_LOOKUPS_MAX && at < 0; i++)
            if (answers[i].state == ASK_FREE)
                at = i;
        for (int i = 0; i < NET_LOOKUPS_MAX && at < 0; i++)
            if (answers[i].state == ASK_ANSWERED && now - answers[i].answered >= NET_ANSWER_S)
                at = i;
        for (int i = 0; i < NET_LOOKUPS_MAX && at < 0; i++)
            if (answers[i].state == ASK_ASKED && now - answers[i].asked >= NET_LOOKUP_STALE_S)
                at = i;
        if (at < 0)
            return ASK_NO_SLOT;
    }
    if (lookups_live >= NET_LOOKUPS_MAX)
        return ASK_NO_THREAD;
    answer_t *s = &answers[at];
    memset(s, 0, sizeof(*s));
    snprintf(s->host, sizeof(s->host), "%s", host);
    s->state = ASK_ASKED;
    s->gen = ++answers_gen;
    s->asked = now;
    asking_t *a = malloc(sizeof(*a));
    pthread_attr_t ta;
    pthread_t t;
    int started = 0;
    if (a) {
        a->slot = at;
        a->gen = s->gen;
        snprintf(a->host, sizeof(a->host), "%s", host);
        pthread_attr_init(&ta);
        pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&ta, NET_LOOKUP_STACK);
        started = pthread_create(&t, &ta, lookup_run, a) == 0;
        pthread_attr_destroy(&ta);
        lookups_live += started;
    }
    if (!started) {
        free(a);
        s->state = ASK_ANSWERED;
        s->rc = EAI_SYSTEM;
        s->answered = now;
    }
    return at;
}

static int is_name(const char *host)
{
    unsigned char raw[sizeof(struct in6_addr)];
    return inet_pton(AF_INET, host, raw) != 1 && inet_pton(AF_INET6, host, raw) != 1;
}

/* What a start may know of one destination now: its numeric addresses,
 * each judged (the count), NET_PENDING while its name's lookup is under
 * way inside its own NET_RESOLVE_S, or -1 with words. A name the operator
 * typed may lead into the machine's own network, where the operator chose
 * that host; one a manifest names may not. Neither may be this machine. */
static int dest_addrs(const net_dest_t *d, char addrs[][INET6_ADDRSTRLEN], int families[], char *err, size_t elen)
{
    int n = 0, by_name = is_name(d->host);
    if (!by_name) {
        unsigned char raw[sizeof(struct in6_addr)];
        families[0] = inet_pton(AF_INET, d->host, raw) == 1 ? AF_INET : AF_INET6;
        snprintf(addrs[0], INET6_ADDRSTRLEN, "%.45s", d->host);
        n = 1;
    } else {
        pthread_mutex_lock(&answers_mu);
        double now = clock_now();
        int at = ask_locked(d->host, now);
        const answer_t *s = at >= 0 ? &answers[at] : NULL;
        int rc = at == ASK_NO_THREAD ? fail(err, elen, "cannot resolve %s: %d lookups are under way already", d->host,
                                            NET_LOOKUPS_MAX)
               : !s ? fail(err, elen, "cannot resolve %s: %d names are being looked up already", d->host, NET_LOOKUPS_MAX)
               : s->state == ASK_ASKED && now - s->asked < NET_RESOLVE_S
                   ? (fail(err, elen, "looking up %s", d->host), NET_PENDING)
               : s->state == ASK_ASKED ? fail(err, elen, "cannot resolve %s: the resolver did not answer in %d s", d->host,
                                              NET_RESOLVE_S)
               : s->rc != 0 ? fail(err, elen, "cannot resolve %s: %s", d->host, gai_strerror(s->rc))
                            : 0;
        if (rc == 0) {
            n = s->n;
            for (int i = 0; i < n; i++) {
                snprintf(addrs[i], INET6_ADDRSTRLEN, "%s", s->addrs[i]);
                families[i] = s->families[i];
            }
        }
        pthread_mutex_unlock(&answers_mu);
        if (rc != 0)
            return rc;
    }
    for (int i = 0; i < n; i++) {
        if (net_addr_is_self(addrs[i]) != 0)
            return fail(err, elen, "%s is this machine (%s): no package's destination", d->host, addrs[i]);
        if (by_name && !d->typed && addr_is_local_net(addrs[i]))
            return fail(err, elen, "%s answers %s, a private or local address: name the address itself", d->host,
                        addrs[i]);
    }
    return n;
}

int net_lookups(const net_dest_t *dests, int ndests, char *err, size_t elen)
{
    char addrs[NET_MAX_ADDRS][INET6_ADDRSTRLEN];
    int families[NET_MAX_ADDRS], rc = 0;
    /* Every name asked first, so that the lookups run side by side. */
    pthread_mutex_lock(&answers_mu);
    double now = clock_now();
    for (int i = 0; i < ndests && i < NET_MAX_DESTS; i++)
        if (is_name(dests[i].host))
            ask_locked(dests[i].host, now);
    pthread_mutex_unlock(&answers_mu);
    for (int i = 0; i < ndests && i < NET_MAX_DESTS && rc == 0; i++) {
        int n = dest_addrs(&dests[i], addrs, families, err, elen);
        rc = n == NET_PENDING ? NET_PENDING : n < 0 ? -1 : 0;
    }
    return rc;
}

int net_lookups_wait(const net_dest_t *dests, int ndests, char *err, size_t elen)
{
    int rc;
    while ((rc = net_lookups(dests, ndests, err, elen)) == NET_PENDING) {
        struct timespec nap = { 0, 50 * 1000 * 1000 };
        nanosleep(&nap, NULL);
    }
    return rc;
}

/* The resolvers of /etc/resolv.conf that are not this machine. */
static int resolvers(char addrs[][INET6_ADDRSTRLEN], int families[], int max)
{
    FILE *f = fopen("/etc/resolv.conf", "re");
    char line[256], word[INET6_ADDRSTRLEN + 16];
    int n = 0;
    while (f && n < max && fgets(line, sizeof(line), f)) {
        if (sscanf(line, " nameserver %61s", word) != 1)
            continue;
        word[strcspn(word, "%")] = '\0';                /* a scoped link-local resolver: not one a rule can name */
        struct in6_addr a6;
        struct in_addr a4;
        int fam = inet_pton(AF_INET, word, &a4) == 1 ? AF_INET : inet_pton(AF_INET6, word, &a6) == 1 ? AF_INET6 : 0;
        if (!fam || net_addr_is_self(word) != 0)
            continue;
        snprintf(addrs[n], INET6_ADDRSTRLEN, "%.45s", word);
        families[n++] = fam;
    }
    if (f)
        fclose(f);
    return n;
}

int net_allow(const net_env_t *env, uid_t uid, const net_dest_t *dests, int ndests, int listen_port, int dns,
              char *err, size_t elen)
{
    char addrs[NET_MAX_ADDRS][INET6_ADDRSTRLEN], out[512];
    int families[NET_MAX_ADDRS];
    size_t used = 0;

    if (uid < NET_POOL_FIRST || uid > NET_POOL_LAST)
        return fail(err, elen, "account %u is not one of the pool's", (unsigned)uid);
    if (ndests < 0 || ndests > NET_MAX_DESTS || listen_port < 0 || listen_port > 65535)
        return fail(err, elen, "a package has at most %d destinations", NET_MAX_DESTS);
    char *script = malloc(SCRIPT_MAX);
    if (!script)
        return fail(err, elen, "out of memory");
    int rc = append(script, &used, "add chain inet ffx u%u\nflush chain inet ffx u%u\n", (unsigned)uid, (unsigned)uid);
    for (int i = 0; i < ndests && rc == 0; i++) {
        if (dests[i].port < 1 || dests[i].port > 65535) {
            rc = fail(err, elen, "%s: port %d is not a port", dests[i].host, dests[i].port);
            break;
        }
        int n = dest_addrs(&dests[i], addrs, families, err, elen);
        if (n < 0) {
            rc = n == NET_PENDING ? NET_PENDING : -1;
            break;
        }
        for (int k = 0; k < n && rc == 0; k++)
            rc = append(script, &used, "add rule inet ffx u%u %s daddr %s tcp dport %d accept\n", (unsigned)uid,
                        families[k] == AF_INET ? "ip" : "ip6", addrs[k], dests[i].port);
        if (rc != 0 && !(err && err[0]))
            fail(err, elen, "the package's destinations do not fit one rule set");
    }
    if (rc == 0 && dns) {
        int n = resolvers(addrs, families, NET_MAX_ADDRS);
        for (int k = 0; k < n && rc == 0; k++)
            rc = append(script, &used, "add rule inet ffx u%u %s daddr %s udp dport 53 accept\n"
                                       "add rule inet ffx u%u %s daddr %s tcp dport 53 accept\n",
                        (unsigned)uid, families[k] == AF_INET ? "ip" : "ip6", addrs[k],
                        (unsigned)uid, families[k] == AF_INET ? "ip" : "ip6", addrs[k]);
    }
    /* A listening port is answered from, never dialed out of. The rule
     * matches the source port, so on its own it would let the account
     * reach any destination at all by binding a connection to that port -
     * which is the declared-destination promise undone by a capability
     * that has nothing to do with it. The flags tell the two apart with
     * no connection tracking (the image's kernel builds none): a lone SYN
     * is a connection this account is opening and is refused, and every
     * other segment - the SYN-ACK that answers a caller, and the rest of
     * that conversation - is its listener speaking and is let out. */
    if (rc == 0 && listen_port)
        rc = append(script, &used,
                    "add rule inet ffx u%u tcp sport %d tcp flags & (fin|syn|rst|ack) != syn accept\n",
                    (unsigned)uid, listen_port);
    if (rc == 0)
        rc = append(script, &used, "add element inet ffx allow { %u : jump u%u }\n", (unsigned)uid, (unsigned)uid);
    if (rc == 0) {
        const char *argv[] = { "", "-f", "-", NULL };
        if (nft_run(env, argv, script, out, sizeof(out)) != 0) {
            out[strcspn(out, "\n")] = '\0';
            rc = fail(err, elen, "nft did not take the package's rules: %.200s", out);
        }
    }
    free(script);
    return rc;
}

int net_revoke(const net_env_t *env, uid_t uid, char *err, size_t elen)
{
    char chain[32], element[32];
    if (uid < NET_POOL_FIRST || uid > NET_POOL_LAST)
        return fail(err, elen, "account %u is not one of the pool's", (unsigned)uid);
    snprintf(chain, sizeof(chain), "u%u", (unsigned)uid);
    snprintf(element, sizeof(element), "{ %u }", (unsigned)uid);
    /* The element first: a chain the map still names cannot be deleted.
     * Each step may find nothing to do. */
    const char *del_el[] = { "", "delete", "element", "inet", "ffx", "allow", element, NULL };
    const char *flush[] = { "", "flush", "chain", "inet", "ffx", chain, NULL };
    const char *del_ch[] = { "", "delete", "chain", "inet", "ffx", chain, NULL };
    const char *list[] = { "", "list", "chain", "inet", "ffx", chain, NULL };
    nft_run(env, del_el, NULL, NULL, 0);
    nft_run(env, flush, NULL, NULL, 0);
    nft_run(env, del_ch, NULL, NULL, 0);
    if (nft_run(env, list, NULL, NULL, 0) == 0)
        return fail(err, elen, "the chain of account %u could not be removed", (unsigned)uid);
    return 0;
}
