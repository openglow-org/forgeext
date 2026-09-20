/*
 * sandbox.h - a package's service started where it can reach only what is its own
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * One process, made from a fork of this daemon, that before it runs a
 * single instruction of the package:
 *
 *   is in the package's cgroup (the parent puts it there; the child waits)
 *   is idle-class in every scheduler: SCHED_IDLE, nice 19, I/O class idle
 *   is first in line for the OOM killer (oom_score_adj 900)
 *   holds no descriptor but stdin (/dev/null) and its log pipe
 *   has the package's account and no group but its own
 *   can gain nothing by exec (no_new_privs)
 *   sees of the file tree only the system's read-only parts, its package
 *     (read and execute), and its data (landlock)
 *   connects and binds only on the TCP ports it declared (landlock, where
 *     the kernel has the network rules), and sends only where the image's
 *     nftables rules allow
 *   cannot make the system calls a package has no business making (seccomp)
 *
 * A step that cannot be taken is a failed start, never a looser sandbox,
 * with one exception that is a property of the kernel and not of the
 * package: landlock parts the running kernel does not have (SANDBOX_NEED_*
 * says which are demanded).
 */
#ifndef FORGEEXT_SANDBOX_H
#define FORGEEXT_SANDBOX_H

#include <stddef.h>
#include <sys/types.h>

#define SANDBOX_MAX_ARGV   24
#define SANDBOX_MAX_PORTS  16
#define SANDBOX_MAX_PATHS  8

#define SANDBOX_NEED_LANDLOCK_FS   1    /* refuse to start without landlock's file rules */
#define SANDBOX_NEED_LANDLOCK_NET  2    /* and without its TCP rules (ABI 4) */

typedef struct {
    const char *id;                         /* for messages */
    uid_t uid;
    gid_t gid;
    const char *pkg_dir;                    /* read and execute */
    const char *data_dir;                   /* read and write; the working directory, HOME, and TMPDIR's parent */
    const char *extra_ro[SANDBOX_MAX_PATHS];    /* further read-only paths (a resolv.conf outside /etc), NULL-ended */
    const char *argv[SANDBOX_MAX_ARGV];     /* NULL-ended; argv[0] is the program's path */
    const char *env[SANDBOX_MAX_ARGV];      /* NULL-ended "KEY=value", beyond the fixed ones */
    int connect_ports[SANDBOX_MAX_PORTS];   /* TCP ports it may connect to; 0-ended */
    int bind_port;                          /* the TCP port it may listen on, or 0 */
    int log_fd;                             /* becomes stdout and stderr */
    int need;                               /* SANDBOX_NEED_* */
    const char *cg_parent, *cg_id;          /* the group it is put in before it goes on; NULL parent = none (tests) */
} sandbox_cfg_t;

/* The landlock ABI the running kernel offers: 0 when it has none. */
int sandbox_landlock_abi(void);

/* Start it. The pid, or -1 with the words: either this process could not
 * fork, or the child reported which step failed before its exec. */
pid_t sandbox_spawn(const sandbox_cfg_t *cfg, char *err, size_t elen);

#endif
