/*
 * netrules.h - a running package's way through the image's deny rules
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The image loads table inet ffx before the network starts: every packet
 * a pool account sends is refused, the machine's own addresses before
 * anything else (forgefirm-sandbox, ffx.nft). The one way through is the
 * table's `allow` map, account -> a chain of that package's destinations.
 * This file is the only writer of that map: it holds the table to its
 * shape before any service starts, resolves a package's declared
 * destinations to addresses, writes its chain and its map element in one
 * nft transaction, and takes both away when the service stops.
 *
 * A rule names an address, never a name: what was resolved and judged is
 * what is allowed. A declared destination that resolves to this machine
 * is refused here in words; the table would refuse it anyway.
 */
#ifndef FORGEEXT_NETRULES_H
#define FORGEEXT_NETRULES_H

#include <stddef.h>
#include <sys/types.h>

#define NET_MAX_DESTS   16
#define NET_MAX_ADDRS   8           /* per destination */
#define NET_RESOLVE_S   5           /* one name's own lookup: past it with no answer, the resolver did not
                                     * answer that name */
#define NET_ANSWER_S    30          /* an answer, addresses or a refusal, is used this long, then asked again */
#define NET_LOOKUPS_MAX 32          /* names answered or being looked up at once */
#define NET_LOOKUP_STALE_S 60       /* a lookup still under way this long may give its slot to another name */
#define NET_LOOKUP_STACK (256 * 1024) /* each lookup thread's stack */
#define NET_PENDING     (-2)        /* a name's lookup is under way: ask again a moment later */
#define NET_POOL_FIRST  800
#define NET_POOL_LAST   831

typedef struct {
    char host[256];                 /* a DNS name, an IPv4 address, or an IPv6 address (no brackets) */
    int port;
    int typed;                      /* the operator typed it for the package, where the manifest did not name it:
                                     * a name of the operator's may lead into the machine's own network */
} net_dest_t;

typedef struct {
    const char *nft;                /* the nft binary; NULL is /usr/sbin/nft */
} net_env_t;

/* Is table inet ffx loaded, and the image's: the output hook with policy
 * accept, the pool's range jumping to `pool`, the machine refused ahead of
 * the map, a tail that refuses, the `allow` map? 0, or -1 with words. No
 * service starts without it. */
int net_base_ok(const net_env_t *env, char *err, size_t elen);

/* The destinations' names, each asked on a thread of its own and never
 * waited for: 0 when every one is answered and judged, NET_PENDING with
 * the name being looked up while one is inside its own NET_RESOLVE_S, or
 * -1 with words (no answer in that time, a refusal of the resolver's, an
 * address that is no destination). A name is judged by what it answers: a
 * name the manifest gives is refused for an address in a private or local
 * range, on a subnet of one of the machine's addresses, or in an IPv6
 * prefix its routes hold as on-link; one the operator typed may answer
 * there; neither may be the machine, by its own addresses or carried in
 * an IPv6 one (the forms are netrules.c's embedded_v4). Called each time a
 * start is tried, so a later try finds the answer an earlier one asked
 * for. */
int net_lookups(const net_dest_t *dests, int ndests, char *err, size_t elen);

/* The same, waiting for every lookup to end or to pass its own bound: the
 * command line's way, never the supervisor's. */
int net_lookups_wait(const net_dest_t *dests, int ndests, char *err, size_t elen);

/* Give the account its chain: each destination from its stored answer
 * (numeric addresses as they are), every address judged as net_lookups
 * judges it, and with listen_port its answers from that port. Replaces
 * what the account had. With dns set, the resolvers of /etc/resolv.conf
 * are reachable on port 53 (UDP and TCP) so that the package's own lookups
 * of its declared names work. 0, NET_PENDING when a name is still being
 * looked up, or -1 with words. */
int net_allow(const net_env_t *env, uid_t uid, const net_dest_t *dests, int ndests, int listen_port, int dns,
              char *err, size_t elen);

/* The answers table's resolver and clock: getaddrinfo (AF_UNSPEC,
 * SOCK_STREAM) and CLOCK_MONOTONIC, unless a unit test gives its own. NULL
 * puts the default back. */
struct addrinfo;
typedef int (*net_resolver_fn)(const char *host, struct addrinfo **res);
void net_lookup_seams(net_resolver_fn resolve, double (*now)(void));

/* Take the account's chain and map element away. Not having any is not an
 * error. */
int net_revoke(const net_env_t *env, uid_t uid, char *err, size_t elen);

/* Revoke every account that has a chain: the ways out that a daemon that
 * died left open. The number revoked, or -1. */
int net_sweep(const net_env_t *env, char *err, size_t elen);

/* Is the address this machine's, loopback, unspecified, or multicast?
 * `addr` is numeric text. 1, 0, or -1 when it is not an address. */
int net_addr_is_self(const char *addr);

/* Is the IPv6 address (numeric text) inside a prefix that a route table
 * holds as on-link: a route that is up, with no gateway, not refused, not
 * this machine's own (local, anycast, or on lo), not multicast, of 1 to
 * 128 bits? `routes` is a file in the form of the kernel's, NULL for the
 * kernel's own (NET_ROUTES6), which is what a name's answer is judged
 * against. 1, 0, or -1 when it is not an IPv6 address; 1 too for a table
 * that cannot be read, or not to its end, and 0 where there is none (a
 * kernel with no IPv6). */
#define NET_ROUTES6 "/proc/net/ipv6_route"
int net_on_link6(const char *routes, const char *addr);

#endif
