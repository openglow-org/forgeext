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
#define NET_POOL_FIRST  800
#define NET_POOL_LAST   831

typedef struct {
    char host[256];                 /* a DNS name, an IPv4 address, or an IPv6 address (no brackets) */
    int port;
} net_dest_t;

typedef struct {
    const char *nft;                /* the nft binary; NULL is /usr/sbin/nft */
} net_env_t;

/* Is table inet ffx loaded, and the image's: the output hook with policy
 * accept, the pool's range jumping to `pool`, the machine refused ahead of
 * the map, a tail that refuses, the `allow` map? 0, or -1 with words. No
 * service starts without it. */
int net_base_ok(const net_env_t *env, char *err, size_t elen);

/* Give the account its chain: each destination resolved now (numeric
 * addresses as they are), every address judged, and with listen_port its
 * answers from that port. Replaces what the account had. With dns set,
 * the resolvers of /etc/resolv.conf are reachable on port 53 (UDP and TCP)
 * so that the package's own lookups of its declared names work. */
int net_allow(const net_env_t *env, uid_t uid, const net_dest_t *dests, int ndests, int listen_port, int dns,
              char *err, size_t elen);

/* Take the account's chain and map element away. Not having any is not an
 * error. */
int net_revoke(const net_env_t *env, uid_t uid, char *err, size_t elen);

/* Revoke every account that has a chain: the ways out that a daemon that
 * died left open. The number revoked, or -1. */
int net_sweep(const net_env_t *env, char *err, size_t elen);

/* Is the address this machine's, loopback, unspecified, or multicast?
 * `addr` is numeric text. 1, 0, or -1 when it is not an address. */
int net_addr_is_self(const char *addr);

#endif
