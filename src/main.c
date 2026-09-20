/*
 * main.c - forgeext, the ForgeFIRM extension host: the command line
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Every command answers with one JSON object on stdout and exits 0 when
 * "ok" is true, 1 when it is not. The options before the command name the
 * world the command works in; their defaults are the machine's.
 */
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps.h"
#include "fflog.h"
#include "install.h"
#include "manifest.h"
#include "pkg.h"
#include "state.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: forgeext [options] <command>\n"
            "  inspect <file.ffx>                 what the archive is and what it asks for; changes nothing\n"
            "  install <file.ffx> [--grant <capability>]... [--consent-community] [--consent-unverified]\n"
            "  list                               what is installed\n"
            "  check [<id>]                       do the installed files still match what was installed\n"
            "  remove <id> [--keep-data]\n"
            "  caps                               the capabilities a manifest may ask for\n"
            "options:\n"
            "  --root <dir>            the extension root (default " EXT_ROOT_DEFAULT ")\n"
            "  --fwup <path>           the fwup binary (default: fwup on PATH)\n"
            "  --official-key <file>   the OpenGlow extension public key\n"
            "  --firmware-key <path>   a key, or a directory of keys, that signs firmware (twice at most)\n"
            "  --budget-mib <n>        what every installed package may hold together (default %lld)\n"
            "  --no-reserve            do not keep free space back for a firmware update\n",
            EXT_BUDGET_DEFAULT >> 20);
    return 2;
}

static int answer(json_t *obj, int ok)
{
    json_object_set_new(obj, "ok", json_boolean(ok));
    char *text = json_dumps(obj, JSON_INDENT(1) | JSON_SORT_KEYS);
    puts(text ? text : "{\"ok\": false}");
    free(text);
    json_decref(obj);
    return ok ? 0 : 1;
}

static int refuse(const char *why)
{
    json_t *obj = json_object();
    json_object_set_new(obj, "error", json_string(why));
    return answer(obj, 0);
}

static json_t *strings(char list[][CAP_MAX_LEN], int n)
{
    json_t *arr = json_array();
    for (int i = 0; i < n; i++)
        json_array_append_new(arr, json_string(list[i]));
    return arr;
}

static json_t *manifest_json(const manifest_t *m)
{
    json_t *j = json_object(), *caps = json_array(), *modes = json_array();
    json_object_set_new(j, "id", json_string(m->id));
    json_object_set_new(j, "name", json_string(m->name));
    json_object_set_new(j, "version", json_string(m->version));
    json_object_set_new(j, "description", json_string(m->description));
    json_object_set_new(j, "author", json_string(m->author));
    json_object_set_new(j, "license", json_string(m->license));
    json_object_set_new(j, "runtime", json_string(manifest_runtime_name(m->runtime)));
    for (int i = 0; i < m->ncaps; i++)
        json_array_append_new(caps, json_string(m->caps[i]));
    json_object_set_new(j, "capabilities", caps);
    if (m->mode_grbl)
        json_array_append_new(modes, json_string("grbl"));
    if (m->mode_cloud)
        json_array_append_new(modes, json_string("cloud"));
    json_object_set_new(j, "modes", modes);
    return j;
}

static json_t *result_json(install_result_t *r)
{
    json_t *j = json_object();
    json_object_set_new(j, "package", manifest_json(&r->manifest));
    json_object_set_new(j, "tier", json_string(pkg_tier_name(r->info.tier)));
    json_object_set_new(j, "key", json_string(r->info.key_id));
    json_object_set_new(j, "files", json_integer(r->tree.files));
    json_object_set_new(j, "bytes", json_integer(r->tree.bytes));
    json_object_set_new(j, "update", json_boolean(r->update));
    json_object_set_new(j, "downgrade", json_boolean(r->downgrade));
    json_object_set_new(j, "from_version", json_string(r->from_version));
    json_object_set_new(j, "needs_grant", strings(r->needs_grant, r->nneeds));
    json_object_set_new(j, "new_capabilities", strings(r->new_caps, r->nnew));
    return j;
}

static int cmd_caps(void)
{
    json_t *obj = json_object(), *arr = json_array();
    for (size_t i = 0; i < caps_count(); i++) {
        const cap_def_t *d = caps_at(i);
        json_t *c = json_object();
        json_object_set_new(c, "name", json_string(d->name));
        json_object_set_new(c, "argument", json_boolean(d->takes_arg));
        json_object_set_new(c, "operator_grant", json_boolean(d->explicit_grant));
        json_object_set_new(c, "offered", json_boolean(d->offered));
        json_object_set_new(c, "grants", json_string(d->grants));
        json_array_append_new(arr, c);
    }
    json_object_set_new(obj, "capabilities", arr);
    json_object_set_new(obj, "api", json_sprintf("%d.%d", EXT_API_MAJOR, EXT_API_MINOR));
    return answer(obj, 1);
}

static int cmd_list(const ext_env_t *env, const char *only, int check)
{
    char err[512];
    state_t *st = calloc(1, sizeof(*st));
    if (!st || state_load(env->root, st, err, sizeof(err)) != 0) {
        free(st);
        return refuse(st ? err : "out of memory");
    }
    json_t *obj = json_object(), *arr = json_array();
    int all_ok = 1, found = 0;
    for (int i = 0; i < st->n; i++) {
        state_pkg_t *p = &st->pkgs[i];
        manifest_t m;
        if (only && strcmp(only, p->id) != 0)
            continue;
        found++;
        json_t *j = json_object();
        json_object_set_new(j, "id", json_string(p->id));
        json_object_set_new(j, "version", json_string(p->version));
        json_object_set_new(j, "previous", json_string(p->previous));
        json_object_set_new(j, "tier", json_string(pkg_tier_name(p->tier)));
        json_object_set_new(j, "key", json_string(p->key_id));
        json_object_set_new(j, "enabled", json_boolean(p->enabled));
        json_object_set_new(j, "quarantined", json_boolean(p->quarantined));
        json_object_set_new(j, "grants", strings(p->grants, p->ngrants));
        if (p->slot >= 0)
            json_object_set_new(j, "account", json_sprintf("ffx%d", p->slot));
        if (ext_manifest_of(env, p->id, &m, err, sizeof(err)) == 0)
            json_object_set_new(j, "package", manifest_json(&m));
        else
            json_object_set_new(j, "manifest_error", json_string(err));
        if (check) {
            int good = ext_check(env, p, err, sizeof(err)) == 0;
            json_object_set_new(j, "intact", json_boolean(good));
            if (!good) {
                json_object_set_new(j, "why", json_string(err));
                all_ok = 0;
            }
        }
        json_array_append_new(arr, j);
    }
    free(st);
    json_object_set_new(obj, "packages", arr);
    if (only && !found) {
        json_decref(obj);
        snprintf(err, sizeof(err), "%.63s is not installed", only);
        return refuse(err);
    }
    return answer(obj, all_ok);
}

int main(int argc, char **argv)
{
    char err[768] = "", keys_dir[512];
    ext_env_t env;
    int i = 1, nfw = 0;

    ext_env_defaults(&env);
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        const char *opt = argv[i];
        if (strcmp(opt, "--no-reserve") == 0) {
            env.reserve_bytes = 0;
            continue;
        }
        if (i + 1 >= argc)
            return usage();
        const char *val = argv[++i];
        if (strcmp(opt, "--root") == 0) {
            env.root = val;
            snprintf(keys_dir, sizeof(keys_dir), "%s/keys", val);
            env.trust.owner_keys_dir = keys_dir;
        } else if (strcmp(opt, "--fwup") == 0) {
            env.trust.fwup = val;
        } else if (strcmp(opt, "--budget-mib") == 0) {
            env.budget_bytes = atoll(val) << 20;
            if (env.budget_bytes <= 0)
                return usage();
        } else if (strcmp(opt, "--official-key") == 0) {
            env.trust.official_key = val;
        } else if (strcmp(opt, "--firmware-key") == 0 && nfw < 2) {
            if (nfw == 0)
                env.trust.firmware_keys[1] = NULL;
            env.trust.firmware_keys[nfw++] = val;
        } else {
            return usage();
        }
    }
    if (i >= argc)
        return usage();
    const char *cmd = argv[i++];
    fflog_init("forgeext");

    if (strcmp(cmd, "caps") == 0)
        return cmd_caps();
    if (strcmp(cmd, "list") == 0)
        return cmd_list(&env, NULL, 0);
    if (strcmp(cmd, "check") == 0)
        return cmd_list(&env, i < argc ? argv[i] : NULL, 1);

    if (strcmp(cmd, "inspect") == 0 && i < argc) {
        install_result_t *res = calloc(1, sizeof(*res));
        if (!res)
            return refuse("out of memory");
        if (ext_inspect(&env, argv[i], res, err, sizeof(err)) != 0) {
            free(res);
            return refuse(err);
        }
        json_t *obj = result_json(res);
        free(res);
        return answer(obj, 1);
    }

    if (strcmp(cmd, "install") == 0 && i < argc) {
        const char *file = argv[i++];
        install_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        for (; i < argc; i++) {
            if (strcmp(argv[i], "--grant") == 0 && i + 1 < argc && opts.ngrants < MANIFEST_MAX_CAPS)
                opts.grants[opts.ngrants++] = argv[++i];
            else if (strcmp(argv[i], "--consent-community") == 0)
                opts.consent_community = 1;
            else if (strcmp(argv[i], "--consent-unverified") == 0)
                opts.consent_unverified = 1;
            else
                return usage();
        }
        install_result_t *res = calloc(1, sizeof(*res));
        if (!res)
            return refuse("out of memory");
        if (ext_install(&env, file, &opts, res, err, sizeof(err)) != 0) {
            fflog(LOG_WARNING, "install of %s refused: %s", file, err);
            free(res);
            return refuse(err);
        }
        fflog(LOG_NOTICE, "installed %s %s (%s%s%s), %d files, %lld bytes", res->manifest.id, res->manifest.version,
              pkg_tier_name(res->info.tier), res->update ? ", over " : "", res->from_version, res->tree.files,
              res->tree.bytes);
        json_t *obj = result_json(res);
        free(res);
        return answer(obj, 1);
    }

    if (strcmp(cmd, "remove") == 0 && i < argc) {
        const char *id = argv[i++];
        int keep = i < argc && strcmp(argv[i], "--keep-data") == 0;
        if (ext_remove(&env, id, keep, err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_NOTICE, "removed %s%s", id, keep ? " (its data kept)" : "");
        json_t *obj = json_object();
        json_object_set_new(obj, "removed", json_string(id));
        return answer(obj, 1);
    }
    return usage();
}
