/*
 * netrules.c - a running package's way through the image's deny rules
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "netrules.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
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

/* Runs nft with argv (argv[0] replaced by the binary), `input` on its
 * stdin when not NULL, its stdout and stderr together into out. The exit
 * status, or -1. No shell. */
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
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(out_pipe[1]);
    if (input) {
        close(in_pipe[0]);
        size_t len = strlen(input), off = 0;
        signal(SIGPIPE, SIG_IGN);
        while (off < len) {
            ssize_t k = write(in_pipe[1], input + off, len - off);
            if (k <= 0)
                break;
            off += (size_t)k;
        }
        close(in_pipe[1]);
    }
    size_t got = 0;
    time_t end = time(NULL) + NFT_TIMEOUT_S;
    int timed_out = 0;
    for (;;) {
        struct pollfd p = { .fd = out_pipe[0], .events = POLLIN };
        int left = (int)(end - time(NULL));
        if (left <= 0) {
            timed_out = 1;
            break;
        }
        int r = poll(&p, 1, left * 1000);
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

static int v4_is_self_shaped(const struct in_addr *a)
{
    uint32_t h = ntohl(a->s_addr);
    return h == 0 || (h >> 24) == 127 || (h >> 28) == 14 || h == 0xffffffffU;
}

int net_addr_is_self(const char *addr)
{
    struct in_addr a4;
    struct in6_addr a6;
    int family;
    if (inet_pton(AF_INET, addr, &a4) == 1) {
        family = AF_INET;
        if (v4_is_self_shaped(&a4))
            return 1;
    } else if (inet_pton(AF_INET6, addr, &a6) == 1) {
        family = AF_INET6;
        if (IN6_IS_ADDR_UNSPECIFIED(&a6) || IN6_IS_ADDR_LOOPBACK(&a6) || IN6_IS_ADDR_MULTICAST(&a6))
            return 1;
        if (IN6_IS_ADDR_V4MAPPED(&a6) || IN6_IS_ADDR_V4COMPAT(&a6)) {
            memcpy(&a4, &a6.s6_addr[12], 4);
            char text[INET_ADDRSTRLEN];
            return inet_ntop(AF_INET, &a4, text, sizeof(text)) ? net_addr_is_self(text) : 1;
        }
    } else {
        return -1;
    }
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return 1;                           /* cannot tell: the careful answer */
    int self = 0;
    for (struct ifaddrs *i = list; i && !self; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != family)
            continue;
        if (family == AF_INET)
            self = ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr == a4.s_addr;
        else
            self = memcmp(&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, &a6, sizeof(a6)) == 0;
    }
    freeifaddrs(list);
    return self;
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

/* The numeric addresses of one declared destination, each judged. */
static int resolve(const net_dest_t *d, char addrs[][INET6_ADDRSTRLEN], int families[], char *err, size_t elen)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    int rc = getaddrinfo(d->host, NULL, &hints, &res), n = 0;
    if (rc != 0 || !res) {
        fail(err, elen, "cannot resolve %s: %s", d->host, rc ? gai_strerror(rc) : "no address");
        return -1;
    }
    for (struct addrinfo *a = res; a && n < NET_MAX_ADDRS; a = a->ai_next) {
        char text[INET6_ADDRSTRLEN];
        const void *raw = a->ai_family == AF_INET ? (const void *)&((struct sockaddr_in *)a->ai_addr)->sin_addr
                        : a->ai_family == AF_INET6 ? (const void *)&((struct sockaddr_in6 *)a->ai_addr)->sin6_addr : NULL;
        if (!raw || !inet_ntop(a->ai_family, raw, text, sizeof(text)))
            continue;
        if (net_addr_is_self(text) != 0) {
            freeaddrinfo(res);
            fail(err, elen, "%s is this machine (%s): no package's destination", d->host, text);
            return -1;
        }
        int seen = 0;
        for (int i = 0; i < n; i++)
            seen |= strcmp(addrs[i], text) == 0;
        if (!seen) {
            snprintf(addrs[n], INET6_ADDRSTRLEN, "%s", text);
            families[n++] = a->ai_family;
        }
    }
    freeaddrinfo(res);
    if (n == 0)
        return fail(err, elen, "cannot resolve %s: no address", d->host);
    return n;
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
        int n = resolve(&dests[i], addrs, families, err, elen);
        if (n < 0) {
            rc = -1;
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
