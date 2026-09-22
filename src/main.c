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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps.h"
#include "fflog.h"
#include "install.h"
#include "manifest.h"
#include "netrules.h"
#include "pkg.h"
#include "run.h"
#include "settings.h"
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
            "  wipe                               every package, its data, and the owner's keys: a change of owner\n"
            "  enable <id> | disable <id>         the operator's switch for one package; enabling lets it out of quarantine\n"
            "  keys | key-add <name> <file.pub> | key-remove <name>\n"
            "                                     the owner's keys: what makes a package community rather than unverified\n"
            "  ui <id>                            the package's interface, as JSON\n"
            "  settings <id> [json]               its settings, and the patch to apply\n"
            "  hold <id> required|advisory        what its hold does when the package cannot speak: stand, or drop\n"
            "  caps                               the capabilities a manifest may ask for\n"
            "  run [--conf <file>] [--safe-file <file>] [--forgectrl <ip>:<port>] [--cg-parent <dir>]\n"
            "      [--run-dir <dir>] [--holds-dir <dir>] [--api-dir <dir>] [--landlock-fs-only] [--ticks <n>]\n"
            "                                     the daemon: run what is installed and enabled, in the sandbox\n"
            "  net-check                          is the image's deny table loaded, and the image's\n"
            "  net-allow <uid> [--listen <port>] [--dns] [<host>:<port>]...\n"
            "                                     give a pool account its way through (what a service start does)\n"
            "  net-revoke <uid>                   and take it away\n"
            "options:\n"
            "  --root <dir>            the extension root (default " EXT_ROOT_DEFAULT ")\n"
            "  --fwup <path>           the fwup binary (default: fwup on PATH)\n"
            "  --official-key <file>   the OpenGlow extension public key\n"
            "  --firmware-key <path>   a key, or a directory of keys, that signs firmware (twice at most)\n"
            "  --nft <path>            the nft binary (default /usr/sbin/nft)\n"
            "  --budget-mib <n>        what every installed package may hold together (default %lld)\n"
            "  --core-version <v>      this firmware's version, for a package's core range\n"
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
    /* Whether the package's "core" range was judged at all. A dev image's
     * version is a build stamp, so there is nothing to compare against;
     * saying so beats leaving an operator to guess. */
    json_object_set_new(j, "core_checked", json_boolean(r->core_checked));
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
        if (state_granted(p, "hold"))
            json_object_set_new(j, "hold", json_string(p->hold_required ? "required" : "advisory"));
        if (p->slot >= 0)
            json_object_set_new(j, "account", json_sprintf("ffx%d", p->slot));
        if (ext_manifest_of(env, p->id, &m, err, sizeof(err)) == 0) {
            json_object_set_new(j, "package", manifest_json(&m));
            /* What the broker would honor for this package: the
             * capabilities that need no grant, and those the operator
             * granted. The manifest's own list is what was *asked for*,
             * which is a different question, and anything deciding what a
             * package may do has to ask this one. It is how op_start()
             * builds the identity behind the API socket, so the panel's
             * bridge and the socket answer alike. */
            json_t *eff = json_array();
            for (int c = 0; c < m.ncaps; c++)
                if (!caps_needs_grant(m.caps[c]) || state_granted(p, m.caps[c]))
                    json_array_append_new(eff, json_string(m.caps[c]));
            json_object_set_new(j, "effective", eff);
        } else {
            json_object_set_new(j, "manifest_error", json_string(err));
        }
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
    net_env_t net = { NULL };
    int i = 1, nfw = 0;

    /* A peer that goes away mid-write, and nft's stdin when it exits on a
     * rule it will not take, both raise SIGPIPE. Every write in this
     * program checks its own result, so the signal is the one thing that
     * must not happen: set once here, for the daemon and the command line
     * alike, rather than by whichever function happened to think of it. */
    signal(SIGPIPE, SIG_IGN);
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
        } else if (strcmp(opt, "--nft") == 0) {
            net.nft = val;
        } else if (strcmp(opt, "--budget-mib") == 0) {
            env.budget_bytes = atoll(val) << 20;
            if (env.budget_bytes <= 0)
                return usage();
        } else if (strcmp(opt, "--core-version") == 0) {
            /* Taken in the form the image writes, "v0.0.6" included, so
             * that what is passed here is what a machine reads. */
            snprintf(env.core_version, sizeof(env.core_version), "%s", manifest_version_text(val));
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

    /* A command whose argument names a package: the id is held to its form
     * here, once, before anything builds a path out of it. forgectrl holds
     * it to the same form before it ever runs this, and a command line is
     * still a command line. */
    static const char *const takes_id[] = { "ui", "settings", "hold", "enable", "disable", "remove", NULL };
    for (int k = 0; takes_id[k]; k++)
        if (strcmp(cmd, takes_id[k]) == 0 && i < argc && !manifest_id_ok(argv[i]))
            return refuse("that is not a package id");

    if (strcmp(cmd, "caps") == 0)
        return cmd_caps();
    if (strcmp(cmd, "list") == 0)
        return cmd_list(&env, NULL, 0);
    if (strcmp(cmd, "check") == 0)
        return cmd_list(&env, i < argc ? argv[i] : NULL, 1);

    if (strcmp(cmd, "run") == 0) {
        static run_cfg_t rc;
        static char host[64];
        run_cfg_defaults(&rc);
        rc.ext = env;
        rc.net = net;
        for (; i < argc; i++) {
            const char *opt = argv[i], *val = i + 1 < argc ? argv[i + 1] : NULL;
            if (strcmp(opt, "--landlock-fs-only") == 0) {
                rc.landlock_fs_only = 1;
                continue;
            }
            if (!val)
                return usage();
            i++;
            if (strcmp(opt, "--conf") == 0) {
                rc.machine.conf = val;
            } else if (strcmp(opt, "--safe-file") == 0) {
                rc.machine.safe_file = val;
            } else if (strcmp(opt, "--cg-parent") == 0) {
                rc.cg_parent = val;
            } else if (strcmp(opt, "--run-dir") == 0) {
                rc.run_dir = val;
            } else if (strcmp(opt, "--holds-dir") == 0) {
                rc.holds_dir = val;
            } else if (strcmp(opt, "--api-dir") == 0) {
                rc.api_dir = val;
            } else if (strcmp(opt, "--ticks") == 0) {
                rc.ticks = atoi(val);
            } else if (strcmp(opt, "--forgectrl") == 0) {
                const char *colon = strrchr(val, ':');
                if (!colon || (size_t)(colon - val) >= sizeof(host))
                    return usage();
                memcpy(host, val, (size_t)(colon - val));
                host[colon - val] = '\0';
                rc.machine.host = host;
                rc.machine.port = atoi(colon + 1);
            } else {
                return usage();
            }
        }
        return run_daemon(&rc);
    }
    if (strcmp(cmd, "net-check") == 0) {
        if (net_base_ok(&net, err, sizeof(err)) != 0)
            return refuse(err);
        return answer(json_object(), 1);
    }
    if ((strcmp(cmd, "net-allow") == 0 || strcmp(cmd, "net-revoke") == 0) && i < argc) {
        int allow = strcmp(cmd, "net-allow") == 0, listen_port = 0, dns = 0, n = 0;
        uid_t uid = (uid_t)atoi(argv[i++]);
        static net_dest_t dests[NET_MAX_DESTS];
        for (; allow && i < argc; i++) {
            if (strcmp(argv[i], "--dns") == 0) {
                dns = 1;
            } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
                listen_port = atoi(argv[++i]);
            } else if (n < NET_MAX_DESTS && caps_outbound_parse(argv[i], dests[n].host, sizeof(dests[n].host), &dests[n].port) == 0) {
                n++;
            } else {
                return refuse("a destination is host:port, the host a lowercase DNS name, an IPv4 address, or an "
                              "IPv6 address in brackets");
            }
        }
        if (net_base_ok(&net, err, sizeof(err)) != 0
            || (allow ? net_allow(&net, uid, dests, n, listen_port, dns, err, sizeof(err))
                      : net_revoke(&net, uid, err, sizeof(err))) != 0)
            return refuse(err);
        return answer(json_object(), 1);
    }

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

    if (strcmp(cmd, "settings") == 0 && i < argc) {
        /* A package's settings as the operator sees them: the values and
         * the schema. Reading needs no grant - they are shown in the
         * panel - and writing is the operator's own act. */
        manifest_t m;
        char why[300];
        const char *id = argv[i];
        if (ext_manifest_of(&env, id, &m, why, sizeof(why)) != 0)
            return answer(json_pack("{s:s}", "error", why), 0);
        if (m.nsettings == 0)
            return answer(json_pack("{s:s}", "error", "this package declares no settings"), 0);
        if (i + 1 < argc) {
            json_error_t je;
            json_t *patch = json_loads(argv[i + 1], JSON_REJECT_DUPLICATES, &je);
            int rc = patch ? settings_write(env.root, id, &m, patch, why, sizeof(why))
                           : (snprintf(why, sizeof(why), "the patch is a JSON object of settings"), -1);
            json_decref(patch);
            if (rc != 0)
                return answer(json_pack("{s:s}", "error", why), 0);
        }
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_string(id));
        json_object_set_new(obj, "settings", settings_read(env.root, id, &m));
        json_object_set_new(obj, "schema", settings_schema_json(&m));
        return answer(obj, 1);
    }
    if (strcmp(cmd, "ui") == 0 && i < argc) {
        /* The page itself, as JSON, so that whatever is in it is a
         * string and never markup this program emitted.
         *
         * A disabled package has no page. Disabling one is the operator's
         * way out of everything it does, and its page is part of that:
         * the page holds no session and reaches the machine only through
         * the panel's bridge, which asks what the package may do - but a
         * door that is shut is shut. */
        char *html = NULL;
        size_t len = 0;
        char why[300];
        static state_t ui_st;
        if (state_load(env.root, &ui_st, err, sizeof(err)) != 0)
            return refuse(err);
        state_pkg_t *up = state_find(&ui_st, argv[i]);
        if (!up)
            return answer(json_pack("{s:s}", "error", "that package is not installed"), 0);
        if (!up->enabled)
            return answer(json_pack("{s:s}", "error", "this package is disabled: its interface is not served"), 0);
        if (ext_ui_html(&env, argv[i], &html, &len, why, sizeof(why)) != 0)
            return answer(json_pack("{s:s}", "error", why), 0);
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_string(argv[i]));
        json_object_set_new(obj, "bytes", json_integer((json_int_t)len));
        json_object_set_new(obj, "html", json_stringn(html, len));
        free(html);
        return answer(obj, 1);
    }
    if (strcmp(cmd, "keys") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "keys", ext_keys_json(&env));
        return answer(obj, 1);
    }
    if (strcmp(cmd, "key-add") == 0 && i + 1 < argc) {
        const char *name = argv[i], *file = argv[i + 1];
        static char text[4096];
        FILE *f = strcmp(file, "-") == 0 ? stdin : fopen(file, "rb");
        if (!f)
            return refuse("cannot read the key file");
        size_t n = fread(text, 1, sizeof(text), f);
        if (f != stdin)
            fclose(f);
        if (ext_key_add(&env, name, text, n, err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_NOTICE, "the owner's key %s was added", name);
        json_t *obj = json_object();
        json_object_set_new(obj, "keys", ext_keys_json(&env));
        return answer(obj, 1);
    }
    if (strcmp(cmd, "key-remove") == 0 && i < argc) {
        if (ext_key_remove(&env, argv[i], err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_NOTICE, "the owner's key %s was removed", argv[i]);
        json_t *obj = json_object();
        json_object_set_new(obj, "keys", ext_keys_json(&env));
        return answer(obj, 1);
    }
    if ((strcmp(cmd, "enable") == 0 || strcmp(cmd, "disable") == 0) && i < argc) {
        const char *id = argv[i];
        int on = strcmp(cmd, "enable") == 0;
        if (ext_set_enabled(&env, id, on, err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_NOTICE, "%s: %s by the operator", id, on ? "enabled" : "disabled");
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_string(id));
        json_object_set_new(obj, "enabled", json_boolean(on));
        return answer(obj, 1);
    }
    if (strcmp(cmd, "hold") == 0 && i + 1 < argc) {
        const char *id = argv[i], *kind = argv[i + 1];
        int required = strcmp(kind, "required") == 0;
        if (!required && strcmp(kind, "advisory") != 0)
            return usage();
        if (ext_set_hold_required(&env, id, required, err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_NOTICE, "%s: its hold is now %s", id, kind);
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_string(id));
        json_object_set_new(obj, "hold", json_string(kind));
        return answer(obj, 1);
    }
    if (strcmp(cmd, "wipe") == 0) {
        /* The ownership reset's, and nobody else's: a package can hold
         * the previous owner's credentials, and a key they added would go
         * on making their packages read as trusted. */
        int npkg = 0, nkey = 0;
        if (ext_wipe(&env, &npkg, &nkey, err, sizeof(err)) != 0)
            return refuse(err);
        fflog(LOG_WARNING, "the extension tree was wiped for a change of owner: %d package%s and %d key%s",
              npkg, npkg == 1 ? "" : "s", nkey, nkey == 1 ? "" : "s");
        json_t *obj = json_object();
        json_object_set_new(obj, "packages", json_integer(npkg));
        json_object_set_new(obj, "keys", json_integer(nkey));
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
