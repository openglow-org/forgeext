/*
 * sandbox_test.c - host test for the sandboxed launcher and the package cgroup
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Needs root and cgroup v2 (exit 77 without): it changes account, makes a
 * cgroup, and applies landlock and seccomp to a real child. The child is a
 * Python probe that tries things and prints what happened; the parent
 * looks at the same process from outside through /proc.
 *
 * From outside: the pool account and no other group, no_new_privs, seccomp
 * in filter mode, SCHED_IDLE, nice 19, I/O class idle, oom_score_adj 900,
 * the package's cgroup, no descriptor but stdio, the limits.
 * From inside: the system's read-only parts and its own package read, its
 * data written, and everything else gone: /proc, /tmp, /home, its package
 * for writing, and a world-readable file beside its package that only
 * landlock can be keeping from it; a netlink socket refused by the filter
 * while a Unix and an IPv4 socket open; and, where the kernel has
 * landlock's TCP rules, a connect to an undeclared port refused while the
 * declared one goes through. On a machine whose image has the deny rules
 * loaded (table inet ffx), the test's account is a pool account, so the
 * declared connect gets past landlock and is then refused by nftables
 * (ECONNREFUSED, the reset), while the undeclared one never leaves
 * landlock (EACCES): each layer is seen doing its own part.
 * The group freezes, thaws, and is destroyed with the process in it; a
 * program that is not there and a group that is not there are failed
 * starts with the step named, and leave no process behind.
 */
#define _GNU_SOURCE
#include "../src/cgroup.h"
#include "../src/sandbox.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

#define TEST_UID 831
#define CG_TEST_PARENT "/sys/fs/cgroup/forgeext-sandbox-test"

static const char PROBE[] =
    "import json, os, socket, sys, time\n"
    "out = {}\n"
    "def attempt(name, fn):\n"
    "    try:\n"
    "        fn()\n"
    "        out[name] = 'ok'\n"
    "    except OSError as e:\n"
    "        out[name] = e.errno\n"
    "pkg, data, secret, port_ok, port_no = sys.argv[1:6]\n"
    "out['uid'] = [os.getuid(), os.geteuid(), os.getgid(), os.getegid(), os.getgroups()]\n"
    "out['cwd'] = os.getcwd()\n"
    "out['env'] = {k: os.environ.get(k) for k in ('HOME', 'TMPDIR', 'FFX_ID', 'FFX_PKG', 'FFX_DATA', 'PATH', 'SECRET_FROM_PARENT')}\n"
    "attempt('read /etc/hostname', lambda: open('/etc/hostname').read())\n"
    "attempt('read own package', lambda: open(pkg + '/probe.py').read())\n"
    "attempt('write own package', lambda: open(pkg + '/new.txt', 'w'))\n"
    "attempt('write own data', lambda: open(data + '/note.txt', 'w').write('x'))\n"
    "attempt('mkdir in own data', lambda: os.mkdir(data + '/sub'))\n"
    "attempt('read the file beside the package', lambda: open(secret).read())\n"
    "attempt('list /proc', lambda: os.listdir('/proc'))\n"
    "attempt('list /tmp', lambda: os.listdir('/tmp'))\n"
    "attempt('list /home', lambda: os.listdir('/home'))\n"
    "attempt('list /sys', lambda: os.listdir('/sys'))\n"
    "attempt('list /', lambda: os.listdir('/'))\n"
    "attempt('write /dev/null', lambda: open('/dev/null', 'w').write('x'))\n"
    "attempt('unix socket', lambda: socket.socket(socket.AF_UNIX))\n"
    "attempt('inet socket', lambda: socket.socket(socket.AF_INET))\n"
    "attempt('netlink socket', lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0))\n"
    "def connect(port):\n"
    "    s = socket.socket(socket.AF_INET)\n"
    "    s.settimeout(3)\n"
    "    s.connect(('127.0.0.1', int(port)))\n"
    "attempt('connect declared', lambda: connect(port_ok))\n"
    "attempt('connect undeclared', lambda: connect(port_no))\n"
    "print(json.dumps(out), flush=True)\n"
    "time.sleep(60)\n";

static char top[64] = "/tmp/forgeext-sandbox.XXXXXX";

static void put_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
}

static int listener(int *port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(a);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0 || getsockname(s, (struct sockaddr *)&a, &len) != 0)
        return -1;
    *port = ntohs(a.sin_port);
    return s;
}

/* A line of /proc/<pid>/status. */
static const char *status_of(pid_t pid, const char *key)
{
    static char line[256];
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    FILE *f = fopen(p, "r");
    line[0] = '\0';
    while (f && fgets(line, sizeof(line), f))
        if (strncmp(line, key, strlen(key)) == 0 && line[strlen(key)] == ':') {
            fclose(f);
            line[strcspn(line, "\n")] = '\0';
            return line + strlen(key) + 1;
        }
    if (f)
        fclose(f);
    return "";
}

static int read_line(int fd, char *out, size_t olen, int seconds)
{
    size_t n = 0;
    time_t end = time(NULL) + seconds;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    while (time(NULL) < end && n + 1 < olen) {
        ssize_t k = read(fd, out + n, 1);
        if (k == 1) {
            if (out[n] == '\n')
                break;
            n++;
        } else {
            struct timespec ts = { 0, 20000000 };
            nanosleep(&ts, NULL);
        }
    }
    out[n] = '\0';
    return (int)n;
}

/* `"name": value` out of the probe's JSON, as text. */
static const char *field(const char *json, const char *name)
{
    static char val[256];
    char key[96];
    snprintf(key, sizeof(key), "\"%s\": ", name);
    const char *p = strstr(json, key);
    val[0] = '\0';
    if (!p)
        return val;
    p += strlen(key);
    size_t n = 0;
    int depth = 0;
    for (; *p && n + 1 < sizeof(val); p++) {
        if (*p == '[' || *p == '{')
            depth++;
        if (*p == ']' || *p == '}') {
            if (depth == 0)
                break;
            depth--;
        }
        if (*p == ',' && depth == 0)
            break;
        val[n++] = *p;
    }
    val[n] = '\0';
    return val;
}

int main(void)
{
    char pkg[128], data[128], tmp[160], secret[128], probe[160], err[256], line[4096], ok_port[16], no_port[16];
    int pfd[2], port_ok = 0, port_no = 0;

    if (geteuid() != 0 || access("/sys/fs/cgroup/cgroup.controllers", R_OK) != 0) {
        printf("skipped: needs root and cgroup v2\n");
        return 77;
    }
    if (!mkdtemp(top))
        return 2;
    chmod(top, 0755);
    snprintf(pkg, sizeof(pkg), "%s/pkg", top);
    snprintf(data, sizeof(data), "%s/data", top);
    snprintf(tmp, sizeof(tmp), "%s/tmp", data);
    snprintf(secret, sizeof(secret), "%s/beside.txt", top);
    snprintf(probe, sizeof(probe), "%s/probe.py", pkg);
    mkdir(pkg, 0755);
    mkdir(data, 0700);
    mkdir(tmp, 0700);
    put_file(probe, PROBE, 0644);
    put_file(secret, "world-readable, and not the package's\n", 0644);
    if (chown(data, TEST_UID, TEST_UID) != 0 || chown(tmp, TEST_UID, TEST_UID) != 0)
        return 2;

    /* A parent group of the test's own, shaped like the image's ffx. */
    mkdir(CG_TEST_PARENT, 0755);
    FILE *f = fopen(CG_TEST_PARENT "/cgroup.subtree_control", "w");
    if (f) {
        fputs("+cpu +memory +pids", f);
        fclose(f);
    }
    CHECK(cg_ready(CG_TEST_PARENT, err, sizeof(err)) == 0, "the test's parent group: %s", err);
    CHECK(cg_ready("/sys/fs/cgroup/no-such-group", err, sizeof(err)) != 0, "a group that is not there is ready");
    cg_limits_t lim = { .cpu_pct = 20, .memory_bytes = 64LL << 20, .pids = 16 };
    CHECK(cg_create(CG_TEST_PARENT, "org.example.probe", &lim, err, sizeof(err)) == 0, "cg_create: %s", err);

    int l_ok = listener(&port_ok), l_no = listener(&port_no);
    CHECK(l_ok >= 0 && l_no >= 0, "the two listeners");
    snprintf(ok_port, sizeof(ok_port), "%d", port_ok);
    snprintf(no_port, sizeof(no_port), "%d", port_no);
    setenv("SECRET_FROM_PARENT", "must not be inherited", 1);

    if (pipe(pfd) != 0)
        return 2;
    int abi = sandbox_landlock_abi();
    printf("landlock ABI here: %d\n", abi);
    sandbox_cfg_t cfg = {
        .id = "org.example.probe", .uid = TEST_UID, .gid = TEST_UID, .pkg_dir = pkg, .data_dir = data,
        .argv = { "/usr/bin/python3", "-B", probe, pkg, data, secret, ok_port, no_port, NULL },
        .env = { "FFX_EXTRA=1", NULL },
        .connect_ports = { port_ok, 0 }, .log_fd = pfd[1],
        .need = SANDBOX_NEED_LANDLOCK_FS, .cg_parent = CG_TEST_PARENT, .cg_id = "org.example.probe",
    };
    pid_t pid = sandbox_spawn(&cfg, err, sizeof(err));
    CHECK(pid > 0, "sandbox_spawn: %s", err);
    if (pid > 0) {
        CHECK(read_line(pfd[0], line, sizeof(line), 20) > 0, "the probe said nothing");
        printf("probe: %.600s\n", line);

        /* From outside. */
        char p[96], text[256];
        CHECK(strstr(status_of(pid, "Uid"), "831\t831\t831\t831"), "Uid:%s", status_of(pid, "Uid"));
        CHECK(strstr(status_of(pid, "Gid"), "831\t831\t831\t831"), "Gid:%s", status_of(pid, "Gid"));
        const char *groups = status_of(pid, "Groups");
        CHECK(groups[strspn(groups, " \t")] == '\0', "supplementary groups:%s", groups);
        CHECK(atoi(status_of(pid, "NoNewPrivs")) == 1, "NoNewPrivs:%s", status_of(pid, "NoNewPrivs"));
        CHECK(atoi(status_of(pid, "Seccomp")) == 2, "Seccomp:%s", status_of(pid, "Seccomp"));
        CHECK(sched_getscheduler(pid) == SCHED_IDLE, "scheduler %d, expected SCHED_IDLE", sched_getscheduler(pid));
        errno = 0;
        CHECK(getpriority(PRIO_PROCESS, (id_t)pid) == 19, "nice %d", getpriority(PRIO_PROCESS, (id_t)pid));
        long io = syscall(SYS_ioprio_get, 1, (int)pid);
        CHECK((io >> 13) == 3, "I/O class %ld, expected 3 (idle)", io >> 13);
        snprintf(p, sizeof(p), "/proc/%d/oom_score_adj", (int)pid);
        f = fopen(p, "r");
        CHECK(f && fgets(text, sizeof(text), f) && atoi(text) == 900, "oom_score_adj %s", text);
        if (f)
            fclose(f);
        snprintf(p, sizeof(p), "/proc/%d/cgroup", (int)pid);
        f = fopen(p, "r");
        CHECK(f && fgets(text, sizeof(text), f) && strstr(text, "forgeext-sandbox-test/org.example.probe"), "cgroup %s", text);
        if (f)
            fclose(f);
        snprintf(p, sizeof(p), "ls /proc/%d/fd | sort -n | tr '\\n' ' '", (int)pid);
        f = popen(p, "r");
        CHECK(f && fgets(text, sizeof(text), f) && strcmp(text, "0 1 2 ") == 0, "descriptors: %s", text);
        if (f)
            pclose(f);
        snprintf(p, sizeof(p), "grep -E 'open files|core file' /proc/%d/limits | awk '{print $(NF-2)}' | tr '\\n' ' '", (int)pid);
        f = popen(p, "r");
        CHECK(f && fgets(text, sizeof(text), f) && strcmp(text, "0 256 ") == 0, "core and open-file limits: %s", text);
        if (f)
            pclose(f);

        /* From inside. */
        CHECK(strcmp(field(line, "uid"), "[831, 831, 831, 831, []") == 0 || strstr(field(line, "uid"), "831, 831, 831, 831"),
              "the probe's ids: %s", field(line, "uid"));
        CHECK(strstr(field(line, "cwd"), data), "cwd %s", field(line, "cwd"));
        CHECK(strstr(line, "\"SECRET_FROM_PARENT\": null"), "the parent's environment leaked");
        CHECK(strstr(line, "\"FFX_ID\": \"org.example.probe\"") && strstr(line, "\"PATH\": \"/usr/bin:/bin\""), "the fixed environment");
        static const char *const allowed[] = { "read /etc/hostname", "read own package", "write own data", "mkdir in own data",
                                               "write /dev/null", "unix socket", "inet socket" };
        int deny_rules = system("nft list table inet ffx >/dev/null 2>&1") == 0;
        printf("the image's deny rules are %s\n", deny_rules ? "loaded: a pool account sends nothing" : "not here");
        if (deny_rules)
            CHECK(atoi(field(line, "connect declared")) == ECONNREFUSED, "connect declared, under the deny rules -> %s, expected "
                  "ECONNREFUSED", field(line, "connect declared"));
        else
            CHECK(strcmp(field(line, "connect declared"), "\"ok\"") == 0, "connect declared -> %s", field(line, "connect declared"));
        for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
            CHECK(strcmp(field(line, allowed[i]), "\"ok\"") == 0, "%s -> %s", allowed[i], field(line, allowed[i]));
        static const char *const denied[] = { "write own package", "read the file beside the package", "list /proc", "list /tmp",
                                              "list /home", "list /sys", "list /" };
        for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
            CHECK(atoi(field(line, denied[i])) == EACCES, "%s -> %s, expected EACCES", denied[i], field(line, denied[i]));
        CHECK(atoi(field(line, "netlink socket")) == EPERM, "netlink socket -> %s, expected EPERM from the filter",
              field(line, "netlink socket"));
        if (abi >= 4)
            CHECK(atoi(field(line, "connect undeclared")) == EACCES, "connect undeclared -> %s", field(line, "connect undeclared"));
        else
            printf("note: landlock ABI %d has no TCP rules; the undeclared connect went %s\n", abi, field(line, "connect undeclared"));

        /* The group. */
        CHECK(cg_populated(CG_TEST_PARENT, "org.example.probe") == 1, "the group is not populated");
        CHECK(cg_create(CG_TEST_PARENT, "org.example.probe", &lim, err, sizeof(err)) != 0, "a populated group was reused");
        CHECK(cg_freeze(CG_TEST_PARENT, "org.example.probe", 1) == 0 && cg_frozen(CG_TEST_PARENT, "org.example.probe") == 1, "freeze");
        CHECK(cg_freeze(CG_TEST_PARENT, "org.example.probe", 0) == 0 && cg_frozen(CG_TEST_PARENT, "org.example.probe") == 0, "thaw");
        CHECK(cg_freeze(CG_TEST_PARENT, "org.example.probe", 1) == 0, "freeze again");
        CHECK(cg_destroy(CG_TEST_PARENT, "org.example.probe") == 0, "destroy a frozen, populated group");
        int status = 0;
        CHECK(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "the probe did not die with its group");
    }

    /* Failed starts name their step and leave nobody behind. */
    CHECK(cg_create(CG_TEST_PARENT, "org.example.bad", &lim, err, sizeof(err)) == 0, "cg_create: %s", err);
    sandbox_cfg_t bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.argv[0] = "/usr/bin/no-such-program";
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "exec"), "a missing program -> %s", err);
    CHECK(cg_populated(CG_TEST_PARENT, "org.example.bad") == 0, "a failed exec left a process in the group");
    bad = cfg;
    bad.cg_id = "org.example.never-made";
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "into its group"), "a group that is not there -> %s", err);
    bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.uid = 0;
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "not root"), "account 0 -> %s", err);
    bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.pkg_dir = "/no/such/package";
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "landlock rules"), "a package that is not there -> %s", err);
    if (abi < 4) {
        bad = cfg;
        bad.cg_id = "org.example.bad";
        bad.need = SANDBOX_NEED_LANDLOCK_FS | SANDBOX_NEED_LANDLOCK_NET;
        CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "no TCP rules"), "TCP rules demanded of ABI %d -> %s", abi, err);
    }
    CHECK(cg_destroy(CG_TEST_PARENT, "org.example.bad") == 0, "destroy the second group");
    CHECK(cg_destroy(CG_TEST_PARENT, "org.example.never-made") == 0, "destroying a group that is not there is not an error");
    rmdir(CG_TEST_PARENT);

    snprintf(line, sizeof(line), "rm -rf %s", top);
    if (system(line) != 0)
        fails++;
    printf("%s: sandbox_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
