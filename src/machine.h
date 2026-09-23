/*
 * machine.h - the machine's facts, as the supervisor needs them
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Read, never written: the master switch out of the machine's settings
 * file, safe mode from a flag file made at the console, and the rest from
 * forgectrl's read-only routes on loopback, which answer a local peer with
 * no token. What cannot be read is reported as such, and the supervisor
 * takes the careful side of it (an armed window it cannot see is open; a
 * machine it cannot ask is not ready for a new process).
 */
#ifndef FORGEEXT_MACHINE_H
#define FORGEEXT_MACHINE_H

#include <stddef.h>

#define MACHINE_CONF_DEFAULT  "/data/forgefirm/forgefirm.conf"
#define MACHINE_SAFE_DEFAULT  "/run/forgefirm/ext-safe"
#define MACHINE_HOST_DEFAULT  "127.0.0.1"
#define MACHINE_PORT_DEFAULT  80

typedef struct {
    const char *conf;           /* the settings file: ext_enabled=1 turns extensions on */
    const char *safe_file;      /* its presence is safe mode */
    const char *host;           /* forgectrl */
    int port;
} machine_cfg_t;

typedef struct {
    int enabled;                /* the master switch is on and safe mode is not */
    char off_reason[96];
    int armed;                  /* 1, 0, or -1 when it could not be read */
    int mode_cloud;             /* 1 cloud, 0 grbl, -1 when it could not be read */
    int may_start;              /* the controller up, motion verified, no diagnostic, no flash */
    char not_ready[96];         /* why may_start is 0 */
} machine_t;

void machine_cfg_defaults(machine_cfg_t *cfg);

/* The armed window alone, as forgectrl's /cool/status says it: 1 open,
 * 0 closed, -1 when it cannot be read (which the supervisor takes as
 * open). For a turn on which machine_read() asked nothing because
 * extensions are off. */
int machine_armed(const machine_cfg_t *cfg);

/* with_start_facts: also ask what a start needs to know (two more
 * requests); without it may_start is 0. */
void machine_read(const machine_cfg_t *cfg, machine_t *m, int with_start_facts);

/* One GET of forgectrl: the body into out. 0 on a 200, else -1. */
int machine_get(const machine_cfg_t *cfg, const char *path, char *out, size_t olen);

/* A GET whose body is too large for a buffer and too slow for the
 * ordinary timeout: a camera frame. The body is malloc'd into *out and
 * is the caller's to free; *len is its length and ctype the answer's
 * Content-Type. Returns 0 on a 200, or minus the status the machine
 * gave (with its JSON body in *out when it sent one), or -1 when it
 * could not be reached at all. Nothing larger than MACHINE_BLOB_MAX is
 * read. */
#define MACHINE_BLOB_MAX      (8 * 1024 * 1024)
#define MACHINE_BLOB_TIMEOUT_MS 20000

int machine_get_blob(const machine_cfg_t *cfg, const char *path, unsigned char **out, size_t *len,
                     char *ctype, size_t clen);

/* The extension host's own credential, as forgectrl minted it for this
 * run and left in a file only root can read. It holds only what the host
 * may relay, and forgectrl takes it from a loopback peer alone. "" when
 * there is none, which is a machine whose forgectrl has not started or
 * is older than this file. */
#define MACHINE_HOST_TOKEN_FILE "/run/forgefirm/ext-host.token"

void machine_host_token(char *out, size_t olen);

/* A POST the host makes on a package's behalf, with that credential.
 * The answer's JSON into out. 0 on a 200, or minus the status, or -1
 * when the machine could not be reached. */
int machine_post(const machine_cfg_t *cfg, const char *path, char *out, size_t olen);

/* A package's program, sent as the one file part the machine's job route
 * takes, with the fields that go beside it. The program arrives as an
 * open descriptor and not as a path: what was checked has to be what is
 * read, and a path lets the package put something else there in between.
 * The descriptor stays the caller's to close. It is read whole from its
 * start and is refused above MACHINE_JOB_MAX. 0 on a 200, or minus the
 * status, or -1 when the machine could not be reached. */
#define MACHINE_JOB_MAX (2 * 1024 * 1024)

int machine_post_program(const machine_cfg_t *cfg, const char *path, int fd,
                         const char *fields, char *out, size_t olen);

/* `key=value` out of a settings file: 1 when the key is there. */
int machine_conf_value(const char *conf, const char *key, char *out, size_t olen);

#endif
