/*
 * sandbox_test.c - host test for the sandboxed launcher and the package cgroup
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Needs root and cgroup v2 (exit 77 without): it changes account, makes a
 * cgroup, and applies landlock and seccomp to a real child. The child is a
 * Python probe that tries things and prints what happened; the parent
 * looks at the same process from outside through /proc. The test starts
 * it the way the daemon does: SIGCHLD, SIGTERM and SIGINT blocked, SIGPIPE
 * ignored, and its own nice and realtime limits raised, so that each reset
 * the launcher makes is seen to be the launcher's.
 *
 * From outside: the pool account and no other group, no capability,
 * no_new_privs, seccomp in filter mode, SCHED_IDLE, nice 19, I/O class
 * idle, RLIMIT_NICE and RLIMIT_RTPRIO 0, oom_score_adj 900, a session of
 * its own, the package's cgroup, the limits, and no signal blocked or
 * ignored. The descriptors are seen on a program with none of its own
 * (/bin/sleep): stdio and its call socket at 4, and stdio alone without
 * one.
 * From inside: the system's read-only parts and its own package read, its
 * data written, and everything else gone: /proc, /tmp, /home, its package
 * for writing (the directory is 0777 for the run, so that only landlock
 * refuses it), a world-readable file beside its package that only landlock
 * can be keeping from it, a world-writable one it may not truncate, a
 * script it writes into its data and may not run, and the machine's own
 * files - the settings file and the setup record refused (EACCES), and the
 * pulse device not there at all (ENOENT: its /dev is a tmpfs of four
 * nodes); a file the host lacks is made for the run, root's and readable
 * by every account, and removed after, so that it is the sandbox that
 * keeps it away, while one that is there is left as it is; a netlink
 * socket refused by the filter while a Unix and an IPv4 socket open; the
 * log daemon's socket, /dev/log, made for the run when the host has none,
 * not there, and neither is a socket the test makes in the machine's /dev
 * after the service started; a shared mount the test unmounts leaves the
 * service's namespace too; and the
 * system calls the filter refuses, each answered EPERM (clone3 ENOSYS),
 * where the same call from this unconfined test is answered otherwise; and,
 * where the kernel has landlock's TCP rules, a connect to an undeclared
 * port refused while the declared one goes through, a bind of its declared
 * port taken and of another refused, and with its scoping (ABI 6) a connect
 * to an abstract socket outside it refused. On a machine whose image has
 * the deny rules loaded (table inet ffx), the test's account is a pool
 * account, so the declared connect gets past landlock and is then refused
 * by nftables (ECONNREFUSED, the reset), while the undeclared one never
 * leaves landlock (EACCES): each layer is seen doing its own part. With
 * FFX_MIN_LANDLOCK_ABI set (CI sets 4), a kernel whose landlock is older is
 * a failure, not a note.
 * Its /dev reads zero, urandom and random, and links fd, stdin, stdout and
 * stderr to its own descriptors.
 * The parent group must be an idle one (cpu.idle 1): one that is not is
 * not ready. The group freezes, thaws, and is destroyed with the process in
 * it; a program that is not there and a package directory that is not
 * there are the package's failed start, a group that is not there, a mount
 * namespace the machine cannot make, a landlock rule the kernel will not
 * take (any rule, a port rule alone, and one on the package's own
 * directory), and the package's directory not opening or its data
 * directory not entered for want of descriptors or memory (each refused by
 * a filter of the test's) are the machine's,
 * each with the step named and no process left behind, and with the group
 * missing the program is never even opened. The test's own shared mounts
 * go on every path out.
 */
#define _GNU_SOURCE
#include "../src/cgroup.h"
#include "../src/sandbox.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

#define TEST_UID 831
#define CG_TEST_PARENT "/sys/fs/cgroup/forgeext-sandbox-test"
#define STAND_IN "made by forgeext's sandbox_test for its run\n"

static const char PROBE[] =
    "import ctypes, json, os, socket, subprocess, sys, time\n"
    "out = {}\n"
    "def attempt(name, fn):\n"
    "    try:\n"
    "        fn()\n"
    "        out[name] = 'ok'\n"
    "    except OSError as e:\n"
    "        out[name] = e.errno\n"
    "pkg, data, secret, port_ok, port_no = sys.argv[1:6]\n"
    "cfg = json.load(open(pkg + '/probe.json'))\n"
    "out['uid'] = [os.getuid(), os.geteuid(), os.getgid(), os.getegid(), os.getgroups()]\n"
    "out['cwd'] = os.getcwd()\n"
    "out['env'] = {k: os.environ.get(k) for k in ('HOME', 'TMPDIR', 'FFX_ID', 'FFX_PKG', 'FFX_DATA', 'PATH', 'SECRET_FROM_PARENT')}\n"
    "attempt('read /etc/hostname', lambda: open('/etc/hostname').read())\n"
    "attempt('read own package', lambda: open(pkg + '/probe.py').read())\n"
    "attempt('write own package', lambda: open(pkg + '/new.txt', 'w'))\n"
    "attempt('write own data', lambda: open(data + '/note.txt', 'w').write('x'))\n"
    "attempt('mkdir in own data', lambda: os.mkdir(data + '/sub'))\n"
    "attempt('read the file beside the package', lambda: open(secret).read())\n"
    "attempt('truncate the file beside the package', lambda: os.truncate(cfg['truncate'], 0))\n"
    "def script():\n"
    "    p = data + '/run.sh'\n"
    "    with open(p, 'w') as f:\n"
    "        f.write('#!/bin/sh\\nexit 0\\n')\n"
    "    os.chmod(p, 0o755)\n"
    "    subprocess.run([p], check=True)\n"
    "attempt('run a script of its data', script)\n"
    "attempt('list /proc', lambda: os.listdir('/proc'))\n"
    "attempt('list /tmp', lambda: os.listdir('/tmp'))\n"
    "attempt('list /home', lambda: os.listdir('/home'))\n"
    "attempt('list /sys', lambda: os.listdir('/sys'))\n"
    "attempt('list /', lambda: os.listdir('/'))\n"
    "attempt('write /dev/null', lambda: open('/dev/null', 'w').write('x'))\n"
    "def reads(p):\n"
    "    with open(p, 'rb') as f:\n"
    "        if len(f.read(16)) != 16:\n"
    "            raise OSError(5, 'a short read')\n"
    "for d in ('zero', 'urandom', 'random'):\n"
    "    attempt('read /dev/' + d, lambda d=d: reads('/dev/' + d))\n"
    "def shell(line):\n"
    "    if subprocess.run(['/bin/sh', '-c', line], stderr=subprocess.PIPE).returncode != 0:\n"
    "        raise OSError(5, line)\n"
    "attempt('write /dev/stderr', lambda: shell(': >/dev/stderr'))\n"
    "attempt('read /dev/stdin', lambda: open('/dev/stdin', 'rb').read(1))\n"
    "out['/dev/fd'] = os.readlink('/dev/fd') if os.path.islink('/dev/fd') else None\n"
    "attempt('open the pulse device', lambda: open('/dev/glowforge', 'rb').close())\n"
    "attempt('open the settings file', lambda: open('/data/forgefirm/forgefirm.conf').close())\n"
    "attempt('open the setup record', lambda: open('/data/forgefirm/setup.json').close())\n"
    "attempt('unix socket', lambda: socket.socket(socket.AF_UNIX))\n"
    "attempt('inet socket', lambda: socket.socket(socket.AF_INET))\n"
    "attempt('netlink socket', lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0))\n"
    "def to_log():\n"
    "    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:\n"
    "        s.sendto(b'<11>forgectrl: a line no package may write', '/dev/log')\n"
    "attempt('send to the log daemon', to_log)\n"
    "def abstract():\n"
    "    with socket.socket(socket.AF_UNIX) as s:\n"
    "        s.connect('\\0' + cfg['abstract'])\n"
    "attempt('connect an abstract socket outside', abstract)\n"
    "def connect(port):\n"
    "    s = socket.socket(socket.AF_INET)\n"
    "    s.settimeout(3)\n"
    "    s.connect(('127.0.0.1', int(port)))\n"
    "attempt('connect declared', lambda: connect(port_ok))\n"
    "attempt('connect undeclared', lambda: connect(port_no))\n"
    "def bind(port):\n"
    "    with socket.socket(socket.AF_INET) as s:\n"
    "        s.bind(('127.0.0.1', port))\n"
    "attempt('bind declared', lambda: bind(cfg['bind_ok']))\n"
    "attempt('bind undeclared', lambda: bind(cfg['bind_no']))\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "for name, nr, *args in cfg['calls']:\n"
    "    a = [ctypes.c_char_p(x.encode()) if isinstance(x, str) else ctypes.c_long(x) for x in args]\n"
    "    ctypes.set_errno(0)\n"
    "    r = libc.syscall(ctypes.c_long(nr), *a)\n"
    "    out['call ' + name] = 'ok' if r != -1 else ctypes.get_errno()\n"
    "print(json.dumps(out), flush=True)\n"
    "for _ in range(400):\n"
    "    if os.path.exists(data + '/later'):\n"
    "        break\n"
    "    time.sleep(0.05)\n"
    "def later():\n"
    "    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:\n"
    "        s.sendto(b'<11>forgectrl: a line no package may write', open(data + '/later').read().strip())\n"
    "out = {}\n"
    "attempt('send to a socket made in /dev after the start', later)\n"
    "print(json.dumps(out), flush=True)\n"
    "time.sleep(60)\n";

/* The calls the filter refuses, each with arguments the kernel would
 * answer otherwise: an error of its own (EFAULT, EBADF, EINVAL) or a
 * success the control below undoes. The first three are numbered on
 * x86_64 and 32-bit ARM alike. What the probe should read is EPERM, and
 * ENOSYS for clone3. */
typedef struct {
    const char *name;
    long nr;
    int nargs;
    long args[6];
    const char *text;                       /* the first argument, when it is a string */
    int want;
} call_t;

#define IOPRIO_BE_4 ((2 << 13) | 4)
static const call_t calls[] = {
    { "io_uring_setup", SYS_io_uring_setup, 2, { 1, 0 }, NULL, EPERM },
    { "keyctl", SYS_keyctl, 3, { 0 /* KEYCTL_GET_KEYRING_ID */, -3 /* KEY_SPEC_SESSION_KEYRING */, 0 }, NULL, EPERM },
    { "perf_event_open", SYS_perf_event_open, 5, { 0, 0, -1, -1, 0 }, NULL, EPERM },
    { "shmget", SYS_shmget, 3, { IPC_PRIVATE, 4096, 0600 }, NULL, EPERM },
    { "msgget", SYS_msgget, 2, { IPC_PRIVATE, 0600 }, NULL, EPERM },
    { "semget", SYS_semget, 3, { IPC_PRIVATE, 1, 0600 }, NULL, EPERM },
    { "ioprio_set", SYS_ioprio_set, 3, { 1 /* IOPRIO_WHO_PROCESS */, 0, IOPRIO_BE_4 }, NULL, EPERM },
    { "memfd_create", SYS_memfd_create, 2, { 0, 0 }, "probe", EPERM },
    { "execveat", SYS_execveat, 5, { -1, 0, 0, 0, AT_EMPTY_PATH }, "", EPERM },
    { "clone3", SYS_clone3, 2, { 0, 0 }, NULL, ENOSYS },
    /* Each namespace flag beside CLONE_SIGHAND without CLONE_VM, which the
     * kernel refuses (EINVAL) before it asks for any capability. */
    { "clone NEWNS", SYS_clone, 5, { CLONE_NEWNS | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWCGROUP", SYS_clone, 5, { CLONE_NEWCGROUP | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWUTS", SYS_clone, 5, { CLONE_NEWUTS | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWIPC", SYS_clone, 5, { CLONE_NEWIPC | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWUSER", SYS_clone, 5, { CLONE_NEWUSER | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWPID", SYS_clone, 5, { CLONE_NEWPID | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    { "clone NEWNET", SYS_clone, 5, { CLONE_NEWNET | CLONE_SIGHAND, 0, 0, 0, 0 }, NULL, EPERM },
    /* Kernel AIO, whose requests carry an I/O class of their own. */
    { "io_setup", SYS_io_setup, 2, { 1, 0 }, NULL, EPERM },
    { "io_submit", SYS_io_submit, 3, { 0, 0, 0 }, NULL, EPERM },
};
#define N_CALLS (sizeof(calls) / sizeof(calls[0]))

/* The same call from this unconfined test: its errno, or 0 for a success,
 * whose object is let go again at once. */
static int unconfined(const call_t *c)
{
    long a[6];
    memcpy(a, c->args, sizeof(a));
    if (c->text)
        a[c->nr == SYS_execveat ? 1 : 0] = (long)c->text;
    errno = 0;
    long r = syscall(c->nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (r == -1)
        return errno;
    if (c->nr == SYS_shmget)
        shmctl((int)r, IPC_RMID, NULL);
    else if (c->nr == SYS_msgget)
        msgctl((int)r, IPC_RMID, NULL);
    else if (c->nr == SYS_semget)
        semctl((int)r, 0, IPC_RMID);
    else if (c->nr == SYS_memfd_create)
        close((int)r);
    return 0;
}

static char top[64] = "/tmp/forgeext-sandbox.XXXXXX";

static void put_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
}

/* A stand-in of an earlier run that was killed before it could remove it. */
static int is_stand_in(const char *path)
{
    char buf[sizeof(STAND_IN) + 1] = "";
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strcmp(buf, STAND_IN) == 0;
}

/* The machine's own files a package must never open, with the probe's
 * name for each. One the host lacks is made for the run (its directories
 * too) and removed after; one that is there is left as it is, unless it is
 * a stand-in an earlier run left. */
static const char *const machine_files[][2] = {
    { "/dev/glowforge", "open the pulse device" },
    { "/data/forgefirm/forgefirm.conf", "open the settings file" },
    { "/data/forgefirm/setup.json", "open the setup record" },
};
#define N_MACHINE_FILES (sizeof(machine_files) / sizeof(machine_files[0]))
static int made_file[N_MACHINE_FILES], made_data, made_forgefirm, made_log = -1;

static void make_machine_files(void)
{
    if (access("/data", F_OK) != 0)
        made_data = mkdir("/data", 0755) == 0;
    if (access("/data/forgefirm", F_OK) != 0)
        made_forgefirm = mkdir("/data/forgefirm", 0755) == 0;
    for (size_t i = 0; i < N_MACHINE_FILES; i++)
        if (access(machine_files[i][0], F_OK) != 0) {
            put_file(machine_files[i][0], STAND_IN, 0644);
            made_file[i] = 1;
        } else if (is_stand_in(machine_files[i][0])) {
            made_file[i] = 1;
        }
}

static void remove_machine_files(void)
{
    for (size_t i = 0; i < N_MACHINE_FILES; i++)
        if (made_file[i])
            unlink(machine_files[i][0]);
    if (made_forgefirm)
        rmdir("/data/forgefirm");
    if (made_data)
        rmdir("/data");
}

/* /dev/log, as the log daemon's socket: the host's own when it has one
 * (a link to it counts), or one of the test's for the run. */
static void make_log_socket(void)
{
    struct stat st;
    if (stat("/dev/log", &st) == 0)
        return;
    unlink("/dev/log");                                 /* a link that leads nowhere */
    struct sockaddr_un sa = { .sun_family = AF_UNIX, .sun_path = "/dev/log" };
    made_log = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (made_log < 0 || bind(made_log, (struct sockaddr *)&sa, sizeof(sa)) != 0 || chmod("/dev/log", 0666) != 0)
        printf("note: no /dev/log here, and none could be made: %s\n", strerror(errno));
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
            return line + strlen(key) + 1 + strspn(line + strlen(key) + 1, " \t");
        }
    if (f)
        fclose(f);
    line[0] = '\0';
    return line;
}

/* The soft value of a limit in /proc/<pid>/limits, as text ("" when absent). */
static const char *limit_of(pid_t pid, const char *name)
{
    static char both[72];
    char p[64], line[256], soft[32], hard[32];
    snprintf(p, sizeof(p), "/proc/%d/limits", (int)pid);
    FILE *f = fopen(p, "r");
    both[0] = '\0';
    while (f && fgets(line, sizeof(line), f))
        if (strncmp(line, name, strlen(name)) == 0 && sscanf(line + strlen(name), " %31s %31s", soft, hard) == 2) {
            snprintf(both, sizeof(both), "%s %s", soft, hard);  /* the soft limit, and the hard one it may be raised to */
            break;
        }
    if (f)
        fclose(f);
    return both;
}

/* Does the file hold this text anywhere? */
static int file_has(const char *path, const char *text)
{
    char line[1024];
    int hit = 0;
    FILE *f = fopen(path, "r");
    while (f && !hit && fgets(line, sizeof(line), f))
        hit = strstr(line, text) != NULL;
    if (f)
        fclose(f);
    return hit;
}

/* The session of a process, field 6 of /proc/<pid>/stat. */
static int session_of(pid_t pid)
{
    char p[64], text[512];
    int sid = -1;
    snprintf(p, sizeof(p), "/proc/%d/stat", (int)pid);
    FILE *f = fopen(p, "r");
    if (f && fgets(text, sizeof(text), f)) {
        const char *end = strrchr(text, ')');
        if (end && sscanf(end + 2, "%*c %*d %*d %d", &sid) != 1)
            sid = -1;
    }
    if (f)
        fclose(f);
    return sid;
}

/* The descriptors a process holds, in order, as "0 1 2 ". */
static const char *fds_of(pid_t pid)
{
    static char text[256];
    char p[96];
    snprintf(p, sizeof(p), "ls /proc/%d/fd | sort -n | tr '\\n' ' '", (int)pid);
    FILE *f = popen(p, "r");
    text[0] = '\0';
    if (!f || !fgets(text, sizeof(text), f))
        text[0] = '\0';
    if (f)
        pclose(f);
    return text;
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

static void put_int(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

/* Is a start whose call nr the kernel refuses with the error `with` (a
 * filter of the test's, which the child inherits) the machine's failure?
 * With arg 0 or more, only the calls whose argument of that number is
 * `value` are refused. It runs in a helper of its own, so that the filter
 * stays there. */
static int machine_step_refused(long nr, int arg, uint64_t value, int with, const sandbox_cfg_t *c)
{
    fflush(stdout);                                     /* the helper's output is its own, not a copy of ours */
    pid_t helper = fork();
    if (helper == 0) {
        unsigned at = arg >= 0 ? (unsigned)offsetof(struct seccomp_data, args) + 8U * (unsigned)arg : 0;
        struct sock_filter deny[8];
        unsigned short n = 0;
        deny[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
        deny[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, arg >= 0 ? 5 : 1);
        if (arg >= 0) {                                 /* both halves of the argument, as this machine orders them */
            deny[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, at);
            deny[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)value, 0, 3);
            deny[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, at + 4);
            deny[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(value >> 32), 0, 1);
        }
        deny[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)with);
        deny[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        struct sock_fprog prog = { .len = n, .filter = deny };
        char err[256] = "";
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
            _exit(3);
        pid_t got = sandbox_spawn(c, err, sizeof(err));
        printf("call %ld refused (%s) -> %d: %s\n", nr, strerror(with), (int)got, err);
        fflush(stdout);
        _exit(got == SANDBOX_NOT_READY && strstr(err, "could not be set up") ? 0 : 1);
    }
    int hs = -1;
    return helper > 0 && waitpid(helper, &hs, 0) == helper && WIFEXITED(hs) && WEXITSTATUS(hs) == 0;
}

int main(void)
{
    char pkg[128], data[128], tmp[160], secret[128], trunc[128], probe[160], conf[160], tool[160], err[256], line[4096],
        ok_port[16], no_port[16], text[2048];
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
    snprintf(trunc, sizeof(trunc), "%s/writable.txt", top);
    snprintf(probe, sizeof(probe), "%s/probe.py", pkg);
    snprintf(conf, sizeof(conf), "%s/probe.json", pkg);
    snprintf(tool, sizeof(tool), "%s/true", pkg);
    mkdir(pkg, 0755);
    mkdir(data, 0700);
    mkdir(tmp, 0700);
    put_file(probe, PROBE, 0644);
    put_file(secret, "world-readable, and not the package's\n", 0644);
    put_file(trunc, "world-writable, and not the package's\n", 0666);
    if (chown(data, TEST_UID, TEST_UID) != 0 || chown(tmp, TEST_UID, TEST_UID) != 0)
        return 2;
    snprintf(line, sizeof(line), "cp /bin/true %s", tool);
    if (system(line) != 0)
        return 2;

    /* The daemon's own signal state and limits, which the launcher must not
     * pass on: SIGCHLD, SIGTERM and SIGINT blocked, SIGPIPE ignored, and
     * nice and realtime limits a service could use to leave SCHED_IDLE. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    signal(SIGPIPE, SIG_IGN);
    struct rlimit high = { 20, 20 };
    CHECK(setrlimit(RLIMIT_NICE, &high) == 0 && setrlimit(RLIMIT_RTPRIO, &high) == 0, "raising this test's own limits");

    /* A parent group of the test's own, shaped like the image's ffx: an
     * idle group, and not ready while it is not one. */
    mkdir(CG_TEST_PARENT, 0755);
    put_int(CG_TEST_PARENT "/cgroup.subtree_control", "+cpu +memory +pids");
    put_int(CG_TEST_PARENT "/cpu.idle", "0");
    CHECK(cg_ready(CG_TEST_PARENT, err, sizeof(err)) != 0 && strstr(err, "cpu.idle"),
          "a parent group that is not idle is ready: %s", err);
    put_int(CG_TEST_PARENT "/cpu.idle", "1");
    CHECK(cg_ready(CG_TEST_PARENT, err, sizeof(err)) == 0, "the test's parent group: %s", err);
    CHECK(cg_ready("/sys/fs/cgroup/no-such-group", err, sizeof(err)) != 0, "a group that is not there is ready");
    cg_limits_t lim = { .cpu_pct = 20, .memory_bytes = 64LL << 20, .pids = 16 };
    CHECK(cg_create(CG_TEST_PARENT, "org.example.probe", &lim, err, sizeof(err)) == 0, "cg_create: %s", err);

    int l_ok = listener(&port_ok), l_no = listener(&port_no);
    CHECK(l_ok >= 0 && l_no >= 0, "the two listeners");
    snprintf(ok_port, sizeof(ok_port), "%d", port_ok);
    snprintf(no_port, sizeof(no_port), "%d", port_no);
    int bind_ok = 0, bind_no = 0, b1 = listener(&bind_ok), b2 = listener(&bind_no);
    CHECK(b1 >= 0 && b2 >= 0, "two free ports");
    close(b1);
    close(b2);
    setenv("SECRET_FROM_PARENT", "must not be inherited", 1);

    /* An abstract socket outside the service's landlock domain. */
    char abstract_name[64];
    snprintf(abstract_name, sizeof(abstract_name), "forgeext-sandbox-test-%d", (int)getpid());
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    memcpy(sa.sun_path + 1, abstract_name, strlen(abstract_name));
    int l_abs = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(l_abs >= 0 && bind(l_abs, (struct sockaddr *)&sa, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1
                                                                          + strlen(abstract_name))) == 0
          && listen(l_abs, 4) == 0, "the abstract listener");

    /* What the probe is to try, and the calls with their numbers here. */
    size_t off = (size_t)snprintf(text, sizeof(text), "{\"truncate\": \"%s\", \"bind_ok\": %d, \"bind_no\": %d, "
                                  "\"abstract\": \"%s\", \"calls\": [", trunc, bind_ok, bind_no, abstract_name);
    for (size_t i = 0; i < N_CALLS && off < sizeof(text); i++) {
        off += (size_t)snprintf(text + off, sizeof(text) - off, "%s[\"%s\", %ld", i ? ", " : "", calls[i].name, calls[i].nr);
        for (int k = 0; k < calls[i].nargs && off < sizeof(text); k++) {
            int is_text = calls[i].text && k == (calls[i].nr == SYS_execveat ? 1 : 0);
            if (is_text)
                off += (size_t)snprintf(text + off, sizeof(text) - off, ", \"%s\"", calls[i].text);
            else
                off += (size_t)snprintf(text + off, sizeof(text) - off, ", %ld", calls[i].args[k]);
        }
        off += (size_t)snprintf(text + off, sizeof(text) - off, "]");
    }
    snprintf(text + off, sizeof(text) - off, "]}\n");
    put_file(conf, text, 0644);
    /* The package directory open to every account for the run: only
     * landlock keeps the service from writing into it. */
    chmod(pkg, 0777);

    if (pipe(pfd) != 0)
        return 2;
    int call_pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, call_pair) != 0)
        return 2;
    make_machine_files();
    make_log_socket();
    /* A shared mount of the test's, as the machine's are (forgefirm-sandbox
     * makes its root shared): unmounted later, it must leave the service's
     * namespace too. */
    char outer[160], shared[180];
    snprintf(outer, sizeof(outer), "%s/outer", top);
    snprintf(shared, sizeof(shared), "%s/outer/inner", top);
    mkdir(outer, 0755);
    /* An unmount propagates through the parent mount's peer group: the
     * inner mount sits in a shared outer one, as every mount of the
     * machine's sits in its shared root. */
    CHECK(mount("ffx-test", outer, "tmpfs", 0, "size=8k") == 0 && mount(NULL, outer, NULL, MS_SHARED, NULL) == 0
          && mkdir(shared, 0755) == 0 && mount("ffx-test", shared, "tmpfs", 0, "size=4k") == 0,
          "a shared mount of the test's: %s", strerror(errno));
    int abi = sandbox_landlock_abi();
    printf("landlock ABI here: %d\n", abi);
    const char *need = getenv("FFX_MIN_LANDLOCK_ABI");     /* CI sets it: a weaker kernel there proves less, and fails */
    if (need)
        CHECK(abi >= atoi(need), "landlock ABI %d, below the %s this run asks for: the TCP and scoping cases see nothing",
              abi, need);
    sandbox_cfg_t cfg = {
        .id = "org.example.probe", .uid = TEST_UID, .gid = TEST_UID, .pkg_dir = pkg, .data_dir = data,
        .argv = { "/usr/bin/python3", "-B", probe, pkg, data, secret, ok_port, no_port, NULL },
        .env = { "FFX_EXTRA=1", NULL },
        .connect_ports = { port_ok, 0 }, .bind_port = bind_ok, .log_fd = pfd[1], .call_fd = call_pair[0],
        .need = SANDBOX_NEED_LANDLOCK_FS, .cg_parent = CG_TEST_PARENT, .cg_id = "org.example.probe",
    };
    pid_t pid = sandbox_spawn(&cfg, err, sizeof(err));
    CHECK(pid > 0, "sandbox_spawn: %s", err);
    if (pid > 0) {
        CHECK(read_line(pfd[0], line, sizeof(line), 20) > 0, "the probe said nothing");
        printf("probe: %.900s\n", line);

        /* From outside. */
        char p[96];
        CHECK(strstr(status_of(pid, "Uid"), "831\t831\t831\t831"), "Uid:%s", status_of(pid, "Uid"));
        CHECK(strstr(status_of(pid, "Gid"), "831\t831\t831\t831"), "Gid:%s", status_of(pid, "Gid"));
        const char *groups = status_of(pid, "Groups");
        CHECK(groups[0] == '\0', "supplementary groups: %s", groups);
        CHECK(strcmp(status_of(pid, "CapEff"), "0000000000000000") == 0, "CapEff: %s", status_of(pid, "CapEff"));
        CHECK(strcmp(status_of(pid, "CapPrm"), "0000000000000000") == 0, "CapPrm: %s", status_of(pid, "CapPrm"));
        CHECK(atoi(status_of(pid, "NoNewPrivs")) == 1, "NoNewPrivs: %s", status_of(pid, "NoNewPrivs"));
        CHECK(atoi(status_of(pid, "Seccomp")) == 2, "Seccomp: %s", status_of(pid, "Seccomp"));
        CHECK(strcmp(status_of(pid, "SigBlk"), "0000000000000000") == 0, "SigBlk: %s", status_of(pid, "SigBlk"));
        CHECK(sched_getscheduler(pid) == SCHED_IDLE, "scheduler %d, expected SCHED_IDLE", sched_getscheduler(pid));
        errno = 0;
        CHECK(getpriority(PRIO_PROCESS, (id_t)pid) == 19, "nice %d", getpriority(PRIO_PROCESS, (id_t)pid));
        long io = syscall(SYS_ioprio_get, 1, (int)pid);
        CHECK((io >> 13) == 3, "I/O class %ld, expected 3 (idle)", io >> 13);
        CHECK(session_of(pid) == (int)pid, "session %d, expected its own (%d)", session_of(pid), (int)pid);
        snprintf(p, sizeof(p), "/proc/%d/oom_score_adj", (int)pid);
        FILE *f = fopen(p, "r");
        char small[256] = "";
        CHECK(f && fgets(small, sizeof(small), f) && atoi(small) == 900, "oom_score_adj %s", small);
        if (f)
            fclose(f);
        snprintf(p, sizeof(p), "/proc/%d/cgroup", (int)pid);
        f = fopen(p, "r");
        small[0] = '\0';
        CHECK(f && fgets(small, sizeof(small), f) && strstr(small, "forgeext-sandbox-test/org.example.probe"), "cgroup %s", small);
        if (f)
            fclose(f);
        static const char *const want_limits[][2] = {
            { "Max core file size", "0 0" }, { "Max open files", "256 256" }, { "Max nice priority", "0 0" },
            { "Max realtime priority", "0 0" },
        };
        for (size_t i = 0; i < sizeof(want_limits) / sizeof(want_limits[0]); i++)
            CHECK(strcmp(limit_of(pid, want_limits[i][0]), want_limits[i][1]) == 0, "%s %s, expected %s",
                  want_limits[i][0], limit_of(pid, want_limits[i][0]), want_limits[i][1]);

        /* From inside. */
        CHECK(strcmp(field(line, "uid"), "[831, 831, 831, 831, []]") == 0, "the probe's ids and groups: %s", field(line, "uid"));
        CHECK(strstr(field(line, "cwd"), data), "cwd %s", field(line, "cwd"));
        CHECK(strstr(line, "\"SECRET_FROM_PARENT\": null"), "the parent's environment leaked");
        CHECK(strstr(line, "\"FFX_ID\": \"org.example.probe\"") && strstr(line, "\"PATH\": \"/usr/bin:/bin\""), "the fixed environment");
        static const char *const allowed[] = { "read /etc/hostname", "read own package", "write own data", "mkdir in own data",
                                               "write /dev/null", "read /dev/zero", "read /dev/urandom", "read /dev/random",
                                               "write /dev/stderr", "read /dev/stdin", "unix socket", "inet socket" };
        CHECK(strcmp(field(line, "/dev/fd"), "\"/proc/self/fd\"") == 0, "its /dev/fd -> %s", field(line, "/dev/fd"));
        int deny_rules = system("nft list table inet ffx >/dev/null 2>&1") == 0;
        printf("the image's deny rules are %s\n", deny_rules ? "loaded: a pool account sends nothing" : "not here");
        if (deny_rules)
            CHECK(atoi(field(line, "connect declared")) == ECONNREFUSED, "connect declared, under the deny rules -> %s, expected "
                  "ECONNREFUSED", field(line, "connect declared"));
        else
            CHECK(strcmp(field(line, "connect declared"), "\"ok\"") == 0, "connect declared -> %s", field(line, "connect declared"));
        for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
            CHECK(strcmp(field(line, allowed[i]), "\"ok\"") == 0, "%s -> %s", allowed[i], field(line, allowed[i]));
        static const char *const denied[] = { "write own package", "read the file beside the package", "run a script of its data",
                                              "list /proc", "list /tmp", "list /home", "list /sys", "list /" };
        for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
            CHECK(atoi(field(line, denied[i])) == EACCES, "%s -> %s, expected EACCES", denied[i], field(line, denied[i]));
        if (abi >= 3)
            CHECK(atoi(field(line, "truncate the file beside the package")) == EACCES, "truncate the file beside the package -> %s, "
                  "expected EACCES", field(line, "truncate the file beside the package"));
        for (size_t i = 0; i < N_MACHINE_FILES; i++) {
            /* A device is not even there: the service's /dev holds four
             * nodes. The rest are there and refused by landlock. */
            int want = strncmp(machine_files[i][0], "/dev/", 5) == 0 ? ENOENT : EACCES;
            const char *got = field(line, machine_files[i][1]);
            printf("the machine's file %s (%s for the run), from inside: %s -> %s, expected %s\n",
                   machine_files[i][0], made_file[i] ? "made" : "already there", machine_files[i][1], got, strerror(want));
            CHECK(atoi(got) == want, "%s (%s) -> %s, expected %s", machine_files[i][1], machine_files[i][0], got,
                  strerror(want));
        }
        CHECK(atoi(field(line, "netlink socket")) == EPERM, "netlink socket -> %s, expected EPERM from the filter",
              field(line, "netlink socket"));
        printf("the log daemon's socket (%s for the run), from inside: %s\n", made_log >= 0 ? "made" : "the host's",
               field(line, "send to the log daemon"));
        CHECK(atoi(field(line, "send to the log daemon")) == ENOENT, "send to the log daemon -> %s, expected ENOENT "
              "(its /dev holds no socket)", field(line, "send to the log daemon"));
        struct stat lst;
        /* A socket made in the machine's /dev after the service started
         * (a log daemon started again) never shows in the service's own. */
        char later[96], lpath[200], ltmp[220], line2[512];
        snprintf(later, sizeof(later), "/dev/forgeext-sandbox-test-%d.sock", (int)getpid());
        struct sockaddr_un lsa = { .sun_family = AF_UNIX };
        snprintf(lsa.sun_path, sizeof(lsa.sun_path), "%s", later);
        int ls = socket(AF_UNIX, SOCK_DGRAM, 0);
        CHECK(ls >= 0 && bind(ls, (struct sockaddr *)&lsa, sizeof(lsa)) == 0 && chmod(later, 0666) == 0,
              "a socket made in the machine's /dev after the start: %s", strerror(errno));
        snprintf(lpath, sizeof(lpath), "%s/later", data);
        snprintf(ltmp, sizeof(ltmp), "%s/later.new", data);
        put_file(ltmp, later, 0644);
        rename(ltmp, lpath);
        CHECK(read_line(pfd[0], line2, sizeof(line2), 20) > 0, "the probe said nothing of the socket made later");
        CHECK(atoi(field(line2, "send to a socket made in /dev after the start")) == ENOENT, "send to a socket made in "
              "/dev after the start -> %s, expected ENOENT", field(line2, "send to a socket made in /dev after the start"));
        if (ls >= 0)
            close(ls);
        unlink(later);
        /* The machine's unmount of a shared mount reaches the service's
         * namespace, which holds no stale copy of it. */
        CHECK(umount2(shared, 0) == 0, "the test's shared mount, unmounted: %s", strerror(errno));
        char mi[96];
        snprintf(mi, sizeof(mi), "/proc/%d/mountinfo", (int)pid);
        CHECK(!file_has(mi, shared), "the service's namespace still holds %s after the machine unmounted it", shared);
        CHECK(stat("/dev/log", &lst) == 0 && S_ISSOCK(lst.st_mode), "the machine's own /dev/log is no longer a socket: the "
              "service's mount reached the machine's namespace");
        for (size_t i = 0; i < N_CALLS; i++) {
            char name[64];
            snprintf(name, sizeof(name), "call %s", calls[i].name);
            int outside = unconfined(&calls[i]);
            CHECK(outside != calls[i].want, "%s answers this unconfined test %s too: inside, that proves nothing", calls[i].name,
                  strerror(outside));
            CHECK(atoi(field(line, name)) == calls[i].want, "%s -> %s, expected %s from the filter (unconfined: %s)", name,
                  field(line, name), strerror(calls[i].want), outside ? strerror(outside) : "taken");
        }
        if (abi >= 4) {
            CHECK(atoi(field(line, "connect undeclared")) == EACCES, "connect undeclared -> %s", field(line, "connect undeclared"));
            CHECK(strcmp(field(line, "bind declared"), "\"ok\"") == 0, "bind declared -> %s", field(line, "bind declared"));
            CHECK(atoi(field(line, "bind undeclared")) == EACCES, "bind undeclared -> %s", field(line, "bind undeclared"));
        } else {
            printf("note: landlock ABI %d has no TCP rules; the undeclared connect went %s\n", abi, field(line, "connect undeclared"));
        }
        if (abi >= 6)
            CHECK(atoi(field(line, "connect an abstract socket outside")) == EPERM, "connect an abstract socket outside -> %s, "
                  "expected EPERM from landlock's scoping", field(line, "connect an abstract socket outside"));

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
    /* The test's shared mounts go on every path out, the spawn's failure
     * included: nothing of them is left in the machine's namespace. */
    umount2(shared, MNT_DETACH);
    umount2(outer, MNT_DETACH);

    /* A program that is not Python, whose descriptors are the launcher's
     * alone (an interpreter may open some of its own): stdio and the call
     * socket at 4 with one, stdio alone without, and the signal state of a
     * program started anew. */
    sandbox_cfg_t plain = cfg;
    plain.bind_port = 0;
    memset(plain.argv, 0, sizeof(plain.argv));
    plain.argv[0] = "/bin/sleep";
    plain.argv[1] = "60";
    for (int called = 1; called >= 0; called--) {
        plain.cg_id = called ? "org.example.called" : "org.example.plain";
        plain.call_fd = called ? call_pair[0] : 0;
        CHECK(cg_create(CG_TEST_PARENT, plain.cg_id, &lim, err, sizeof(err)) == 0, "cg_create: %s", err);
        pid = sandbox_spawn(&plain, err, sizeof(err));
        CHECK(pid > 0, "sandbox_spawn of sleep: %s", err);
        if (pid > 0) {
            struct timespec ts = { 0, 300000000 };
            nanosleep(&ts, NULL);                       /* past its exec */
            CHECK(strcmp(fds_of(pid), called ? "0 1 2 4 " : "0 1 2 ") == 0, "descriptors %s a call socket: %s",
                  called ? "with" : "without", fds_of(pid));
            CHECK(strcmp(status_of(pid, "SigBlk"), "0000000000000000") == 0, "SigBlk: %s", status_of(pid, "SigBlk"));
            CHECK(strcmp(status_of(pid, "SigIgn"), "0000000000000000") == 0, "SigIgn: %s", status_of(pid, "SigIgn"));
            CHECK(cg_destroy(CG_TEST_PARENT, plain.cg_id) == 0, "destroy the group %s", plain.cg_id);
            waitpid(pid, NULL, 0);
        }
    }

    /* Failed starts name their step and leave nobody behind. */
    CHECK(cg_create(CG_TEST_PARENT, "org.example.bad", &lim, err, sizeof(err)) == 0, "cg_create: %s", err);
    sandbox_cfg_t bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.argv[0] = "/usr/bin/no-such-program";
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) == -1 && strstr(err, "exec"), "a missing program, the package's own -> %s",
          err);
    CHECK(cg_populated(CG_TEST_PARENT, "org.example.bad") == 0, "a failed exec left a process in the group");
    /* A step of the machine's in the child is the machine's failure: its
     * mount namespace, its mounts refused, and its landlock ruleset, the
     * kernel refusing a rule (as at a memory shortage). */
    bad = plain;
    bad.cg_id = "org.example.bad";
    CHECK(machine_step_refused(__NR_mount, -1, 0, EPERM, &bad), "a mount namespace the machine cannot make was not the "
          "machine's failure");
    CHECK(machine_step_refused(__NR_landlock_add_rule, -1, 0, EPERM, &bad), "a landlock rule the kernel will not take "
          "was not the machine's failure");
    /* So is a port rule alone refused, and a rule the kernel will not take
     * on the package's own directory (one that opens, and is of no file
     * system landlock makes rules for). */
    if (abi >= 4)
        CHECK(machine_step_refused(__NR_landlock_add_rule, 1, 2 /* LANDLOCK_RULE_NET_PORT */, EPERM, &bad),
              "a port rule the kernel will not take was not the machine's failure");
    bad.pkg_dir = "/proc/self/ns/mnt";
    pid_t unruled = sandbox_spawn(&bad, err, sizeof(err));
    CHECK(unruled == SANDBOX_NOT_READY && strstr(err, "landlock rules"), "a rule the kernel will not take on the "
          "package's own directory was not the machine's failure -> %d (%s)", (int)unruled, err);
    /* And the package's own directory failing to open, or its data
     * directory to be entered, for want of something of the machine's. */
    bad = plain;
    bad.cg_id = "org.example.bad";
    CHECK(machine_step_refused(__NR_openat, 1, (uint64_t)(uintptr_t)bad.pkg_dir, ENFILE, &bad), "the package's directory "
          "not opening for want of descriptors was not the machine's failure");
    CHECK(machine_step_refused(__NR_chdir, -1, 0, ENOMEM, &bad), "the data directory not entered for want of memory was "
          "not the machine's failure");
    CHECK(cg_populated(CG_TEST_PARENT, "org.example.bad") == 0, "a failed setup left a process in the group");
    /* A group that is not there: nothing of the package runs, not even its
     * program's first open, which an exec would make. */
    bad = plain;
    bad.cg_id = "org.example.never-made";
    bad.argv[0] = tool;
    bad.argv[1] = NULL;
    int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    CHECK(in >= 0 && inotify_add_watch(in, tool, IN_OPEN) >= 0, "a watch on the program: %s", strerror(errno));
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) == SANDBOX_NOT_READY && strstr(err, "into its group"),
          "a group that is not there is the machine's failure, not the package's -> %s", err);
    char ev[sizeof(struct inotify_event) + 64];
    CHECK(read(in, ev, sizeof(ev)) < 0 && errno == EAGAIN, "a group that is not there: its program was opened");
    close(in);
    bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.uid = 0;
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "not root"), "account 0 -> %s", err);
    bad = cfg;
    bad.cg_id = "org.example.bad";
    bad.pkg_dir = "/no/such/package";
    CHECK(sandbox_spawn(&bad, err, sizeof(err)) == -1 && strstr(err, "landlock rules"), "a package that is not there, the "
          "package's own -> %s", err);
    if (abi < 4) {
        bad = cfg;
        bad.cg_id = "org.example.bad";
        bad.need = SANDBOX_NEED_LANDLOCK_FS | SANDBOX_NEED_LANDLOCK_NET;
        CHECK(sandbox_spawn(&bad, err, sizeof(err)) < 0 && strstr(err, "no TCP rules"), "TCP rules demanded of ABI %d -> %s", abi, err);
    }
    CHECK(cg_destroy(CG_TEST_PARENT, "org.example.bad") == 0, "destroy the second group");
    CHECK(cg_destroy(CG_TEST_PARENT, "org.example.never-made") == 0, "destroying a group that is not there is not an error");
    rmdir(CG_TEST_PARENT);
    remove_machine_files();
    if (made_log >= 0) {
        close(made_log);
        unlink("/dev/log");
    }

    snprintf(line, sizeof(line), "rm -rf %s", top);
    if (system(line) != 0)
        fails++;
    printf("%s: sandbox_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
