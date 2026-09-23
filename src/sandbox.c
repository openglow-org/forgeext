/*
 * sandbox.c - a package's service started where it can reach only what is its own
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroup.h"

/* ---- landlock, by its stable UAPI (the build's kernel headers may be
 *      older than the kernel the image runs) ------------------------------ */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;        /* ABI 4 */
    uint64_t scoped;                    /* ABI 6 */
};
struct ll_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));
struct ll_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};
#define LL_CREATE_RULESET_VERSION 1U
#define LL_RULE_PATH_BENEATH 1
#define LL_RULE_NET_PORT     2

#define LL_FS_EXECUTE     (1ULL << 0)
#define LL_FS_WRITE_FILE  (1ULL << 1)
#define LL_FS_READ_FILE   (1ULL << 2)
#define LL_FS_READ_DIR    (1ULL << 3)
#define LL_FS_REMOVE_DIR  (1ULL << 4)
#define LL_FS_REMOVE_FILE (1ULL << 5)
#define LL_FS_MAKE_CHAR   (1ULL << 6)
#define LL_FS_MAKE_DIR    (1ULL << 7)
#define LL_FS_MAKE_REG    (1ULL << 8)
#define LL_FS_MAKE_SOCK   (1ULL << 9)
#define LL_FS_MAKE_FIFO   (1ULL << 10)
#define LL_FS_MAKE_BLOCK  (1ULL << 11)
#define LL_FS_MAKE_SYM    (1ULL << 12)
#define LL_FS_REFER       (1ULL << 13)  /* ABI 2 */
#define LL_FS_TRUNCATE    (1ULL << 14)  /* ABI 3 */
#define LL_FS_IOCTL_DEV   (1ULL << 15)  /* ABI 5 */
#define LL_NET_BIND_TCP    (1ULL << 0)
#define LL_NET_CONNECT_TCP (1ULL << 1)
#define LL_SCOPE_ABSTRACT_UNIX (1ULL << 0)
#define LL_SCOPE_SIGNAL        (1ULL << 1)

#define LL_READ   (LL_FS_READ_FILE | LL_FS_READ_DIR)
#define LL_RX     (LL_READ | LL_FS_EXECUTE)

int sandbox_landlock_abi(void)
{
    long v = syscall(__NR_landlock_create_ruleset, NULL, 0, LL_CREATE_RULESET_VERSION);
    return v > 0 ? (int)v : 0;
}

/* ---- what the parent prepares, so that the child allocates nothing ------ */

#define ENV_MAX      (SANDBOX_MAX_ARGV + 12)
#define FILTER_MAX   192

typedef struct {
    const sandbox_cfg_t *cfg;
    char env_text[ENV_MAX][320];
    char *envp[ENV_MAX + 1];
    struct sock_filter filter[FILTER_MAX];
    unsigned short nfilter;
    int abi;
    int go_fd, err_fd;
} prepared_t;

/* The system calls a package has no business making. Most need a
 * capability an unprivileged account with no_new_privs cannot have; the
 * filter is there for the day the kernel gets one of those checks wrong. */
static const int denied[] = {
#ifdef __NR_mount
    __NR_mount,
#endif
#ifdef __NR_umount2
    __NR_umount2,
#endif
#ifdef __NR_pivot_root
    __NR_pivot_root,
#endif
#ifdef __NR_chroot
    __NR_chroot,
#endif
#ifdef __NR_reboot
    __NR_reboot,
#endif
#ifdef __NR_kexec_load
    __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
    __NR_kexec_file_load,
#endif
#ifdef __NR_init_module
    __NR_init_module,
#endif
#ifdef __NR_finit_module
    __NR_finit_module,
#endif
#ifdef __NR_delete_module
    __NR_delete_module,
#endif
#ifdef __NR_ptrace
    __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
    __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
    __NR_process_vm_writev,
#endif
#ifdef __NR_bpf
    __NR_bpf,
#endif
#ifdef __NR_perf_event_open
    __NR_perf_event_open,
#endif
#ifdef __NR_add_key
    __NR_add_key,
#endif
#ifdef __NR_request_key
    __NR_request_key,
#endif
#ifdef __NR_keyctl
    __NR_keyctl,
#endif
#ifdef __NR_setns
    __NR_setns,
#endif
#ifdef __NR_unshare
    __NR_unshare,
#endif
#ifdef __NR_swapon
    __NR_swapon,
#endif
#ifdef __NR_swapoff
    __NR_swapoff,
#endif
#ifdef __NR_acct
    __NR_acct,
#endif
#ifdef __NR_settimeofday
    __NR_settimeofday,
#endif
#ifdef __NR_clock_settime
    __NR_clock_settime,
#endif
#ifdef __NR_clock_settime64
    __NR_clock_settime64,
#endif
#ifdef __NR_adjtimex
    __NR_adjtimex,
#endif
#ifdef __NR_clock_adjtime
    __NR_clock_adjtime,
#endif
#ifdef __NR_clock_adjtime64
    __NR_clock_adjtime64,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
    __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
    __NR_io_uring_register,
#endif
#ifdef __NR_open_by_handle_at
    __NR_open_by_handle_at,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
#ifdef __NR_quotactl
    __NR_quotactl,
#endif
#ifdef __NR_syslog
    __NR_syslog,
#endif
#ifdef __NR_vhangup
    __NR_vhangup,
#endif
#ifdef __NR_sethostname
    __NR_sethostname,
#endif
#ifdef __NR_setdomainname
    __NR_setdomainname,
#endif
#ifdef __NR_move_mount
    __NR_move_mount,
#endif
#ifdef __NR_fsopen
    __NR_fsopen,
#endif
#ifdef __NR_fsmount
    __NR_fsmount,
#endif
#ifdef __NR_open_tree
    __NR_open_tree,
#endif
#ifdef __NR_pidfd_getfd
    __NR_pidfd_getfd,
#endif
};

#if defined(__arm__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error "no seccomp architecture for this build"
#endif

#define RET_EPERM (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static int filter_build(struct sock_filter *f, unsigned short *n)
{
    unsigned short k = 0;
#define PUT(code, jt, jf, val) do { if (k >= FILTER_MAX) return -1; f[k++] = (struct sock_filter){ (code), (jt), (jf), (val) }; } while (0)
    PUT(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, arch));
    PUT(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, NATIVE_AUDIT_ARCH);
    PUT(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);           /* another ABI's numbers mean other calls */
    PUT(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    PUT(BPF_JMP | BPF_JGE | BPF_K, 0, 1, 0x40000000U);              /* the x32 numbers */
    PUT(BPF_RET | BPF_K, 0, 0, RET_EPERM);
#endif
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        PUT(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (unsigned)denied[i]);
        PUT(BPF_RET | BPF_K, 0, 0, RET_EPERM);
    }
#ifdef __NR_socket
    /* socket(): the Unix, IPv4, and IPv6 families and no other (netlink,
     * packet, and the rest are not an extension's to open). */
    PUT(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, __NR_socket);
    PUT(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[0]));
    PUT(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 1);                        /* AF_UNIX */
    PUT(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 2);                        /* AF_INET */
    PUT(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 10);                       /* AF_INET6 */
    PUT(BPF_RET | BPF_K, 0, 0, RET_EPERM);
#endif
    PUT(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
#undef PUT
    *n = k;
    return 0;
}

/* ---- the child ------------------------------------------------------------ */

/* Tell the parent which step failed, and go.
 *
 * This runs in a child forked from a daemon that has threads, where only
 * the async-signal-safe calls can be relied on: a lock another thread held
 * at the fork is held forever here. strerror() is not one of them -
 * glibc's may format into a buffer it allocates - so the reentrant form
 * writes into one of ours. */
static void die(int err_fd, const char *step, int saved)
{
    char msg[160], buf[96];
    size_t n = 0;
    for (const char *p = step; *p && n < sizeof(msg) - 40; p++)
        msg[n++] = *p;
    const char *why = saved ? strerror_r(saved, buf, sizeof(buf)) : "";
    if (*why) {
        msg[n++] = ':';
        msg[n++] = ' ';
        for (const char *p = why; *p && n < sizeof(msg) - 1; p++)
            msg[n++] = *p;
    }
    if (write(err_fd, msg, n) < 0) {
        /* nobody to tell */
    }
    _exit(126);
}

static int ll_allow(int ruleset, const char *path, uint64_t access, int required)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return required || errno != ENOENT ? -1 : 0;
    struct ll_path_beneath_attr rule = { .allowed_access = access, .parent_fd = fd };
    struct stat st;
    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))                /* a file takes only the file rights */
        rule.allowed_access &= LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_TRUNCATE | LL_FS_IOCTL_DEV;
    long rc = syscall(__NR_landlock_add_rule, ruleset, LL_RULE_PATH_BENEATH, &rule, 0);
    int saved = errno;
    close(fd);
    errno = saved;
    return rc == 0 ? 0 : -1;
}

/* The ruleset, built while still root (every path opens) and applied after
 * the account change. -1 with errno, or the ruleset's descriptor; -2 when
 * the kernel has no landlock and none is demanded. */
static int ll_build(const prepared_t *p)
{
    const sandbox_cfg_t *c = p->cfg;
    int abi = p->abi;
    if (abi < 1)
        return (c->need & SANDBOX_NEED_LANDLOCK_FS) ? -1 : -2;
    if (abi < 4 && (c->need & SANDBOX_NEED_LANDLOCK_NET)) {
        errno = ENOSYS;
        return -1;
    }
    uint64_t fs = LL_RX | LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE | LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR
                  | LL_FS_MAKE_REG | LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM;
    if (abi >= 2)
        fs |= LL_FS_REFER;
    if (abi >= 3)
        fs |= LL_FS_TRUNCATE;
    if (abi >= 5)
        fs |= LL_FS_IOCTL_DEV;
    struct ll_ruleset_attr attr = { .handled_access_fs = fs };
    size_t size = sizeof(uint64_t);
    if (abi >= 4) {
        attr.handled_access_net = LL_NET_BIND_TCP | LL_NET_CONNECT_TCP;
        size = 2 * sizeof(uint64_t);
    }
    if (abi >= 6) {
        attr.scoped = LL_SCOPE_ABSTRACT_UNIX | LL_SCOPE_SIGNAL;
        size = 3 * sizeof(uint64_t);
    }
    int rs = (int)syscall(__NR_landlock_create_ruleset, &attr, size, 0);
    if (rs < 0)
        return -1;
    static const char *const system_rx[] = { "/usr", "/lib", "/bin", "/sbin", NULL };
    static const char *const system_ro[] = { "/etc", NULL };
    static const char *const devices[] = { "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", NULL };
    uint64_t own = fs & ~(LL_FS_EXECUTE | LL_FS_MAKE_CHAR | LL_FS_MAKE_BLOCK | LL_FS_IOCTL_DEV);
    int ok = 1;
    for (int i = 0; system_rx[i] && ok; i++)
        ok = ll_allow(rs, system_rx[i], LL_RX, 0) == 0;
    for (int i = 0; system_ro[i] && ok; i++)
        ok = ll_allow(rs, system_ro[i], LL_READ, 0) == 0;
    for (int i = 0; devices[i] && ok; i++)
        ok = ll_allow(rs, devices[i], LL_FS_READ_FILE | LL_FS_WRITE_FILE, 0) == 0;
    for (int i = 0; i < SANDBOX_MAX_PATHS && c->extra_ro[i] && ok; i++)
        ok = ll_allow(rs, c->extra_ro[i], LL_READ, 0) == 0;
    ok = ok && ll_allow(rs, c->pkg_dir, LL_RX, 1) == 0 && ll_allow(rs, c->data_dir, own, 1) == 0;
    if (ok && abi >= 4) {
        for (int i = 0; i < SANDBOX_MAX_PORTS && c->connect_ports[i] && ok; i++) {
            struct ll_net_port_attr port = { LL_NET_CONNECT_TCP, (uint64_t)c->connect_ports[i] };
            ok = syscall(__NR_landlock_add_rule, rs, LL_RULE_NET_PORT, &port, 0) == 0;
        }
        if (ok && c->bind_port) {
            struct ll_net_port_attr port = { LL_NET_BIND_TCP, (uint64_t)c->bind_port };
            ok = syscall(__NR_landlock_add_rule, rs, LL_RULE_NET_PORT, &port, 0) == 0;
        }
    }
    if (!ok) {
        int saved = errno;
        close(rs);
        errno = saved;
        return -1;
    }
    return rs;
}

#ifndef IOPRIO_CLASS_IDLE
#define IOPRIO_CLASS_IDLE 3
#endif

static void child(const prepared_t *p)
{
    const sandbox_cfg_t *c = p->cfg;
    int err_fd = p->err_fd;
    char go;

    /* Nothing of the package runs until the parent has put this process
     * into its group; a parent that fails closes the pipe instead. */
    ssize_t got;
    do
        got = read(p->go_fd, &go, 1);
    while (got < 0 && errno == EINTR);
    if (got != 1)
        _exit(125);

    if (setsid() < 0)
        die(err_fd, "setsid", errno);
    int null = open("/dev/null", O_RDONLY);
    if (null < 0 || dup2(null, 0) < 0 || dup2(c->log_fd, 1) < 0 || dup2(c->log_fd, 2) < 0)
        die(err_fd, "stdio", errno);

    int adj = open("/proc/self/oom_score_adj", O_WRONLY);
    if (adj < 0 || write(adj, "900", 3) != 3)
        die(err_fd, "oom_score_adj", errno);
    close(adj);

    struct sched_param sp = { 0 };
    if (sched_setscheduler(0, SCHED_IDLE, &sp) != 0)
        die(err_fd, "SCHED_IDLE", errno);
    if (setpriority(PRIO_PROCESS, 0, 19) != 0)
        die(err_fd, "nice 19", errno);
    if (syscall(SYS_ioprio_set, 1 /* IOPRIO_WHO_PROCESS */, 0, IOPRIO_CLASS_IDLE << 13) != 0)
        die(err_fd, "I/O class idle", errno);

    const struct { int what; rlim_t lim; const char *name; } limits[] = {
        { RLIMIT_CORE, 0, "RLIMIT_CORE" },
        { RLIMIT_NOFILE, 256, "RLIMIT_NOFILE" },
        { RLIMIT_NPROC, 64, "RLIMIT_NPROC" },
        { RLIMIT_AS, (rlim_t)1 << 30, "RLIMIT_AS" },
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        struct rlimit rl = { limits[i].lim, limits[i].lim };
        if (setrlimit(limits[i].what, &rl) != 0)
            die(err_fd, limits[i].name, errno);
    }

    /* Every descriptor but stdio, the word back to the parent, and the
     * listening end of its page's calls at 4. The call socket is moved out
     * of the way first, so that neither move lands on the other. */
    int call = -1;
    if (c->call_fd > 0 && (call = fcntl(c->call_fd, F_DUPFD_CLOEXEC, 10)) < 0)
        die(err_fd, "descriptors", errno);
    if (err_fd != 3) {
        if (dup2(err_fd, 3) < 0)
            die(err_fd, "descriptors", errno);
        err_fd = 3;
    }
    if (call >= 0 && dup2(call, 4) < 0)             /* dup2 leaves 4 open across the exec */
        die(err_fd, "descriptors", errno);
    if (fcntl(err_fd, F_SETFD, FD_CLOEXEC) != 0 || syscall(SYS_close_range, call >= 0 ? 5U : 4U, ~0U, 0U) != 0)
        die(err_fd, "descriptors", errno);

    int ruleset = ll_build(p);
    if (ruleset == -1)
        die(err_fd, "landlock rules", errno);

    if (chdir(c->data_dir) != 0)
        die(err_fd, "the data directory", errno);
    if (setgroups(0, NULL) != 0 || setresgid(c->gid, c->gid, c->gid) != 0 || setresuid(c->uid, c->uid, c->uid) != 0)
        die(err_fd, "the account", errno);
    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    if (getresuid(&ru, &eu, &su) != 0 || getresgid(&rg, &eg, &sg) != 0 || ru != c->uid || eu != c->uid || su != c->uid
        || rg != c->gid || eg != c->gid || sg != c->gid || (c->uid != 0 && setuid(0) == 0))
        die(err_fd, "the account did not take", 0);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die(err_fd, "no_new_privs", errno);
    if (ruleset >= 0) {
        if (syscall(__NR_landlock_restrict_self, ruleset, 0) != 0)
            die(err_fd, "landlock", errno);
        close(ruleset);
    }
    struct sock_fprog prog = { .len = p->nfilter, .filter = (struct sock_filter *)p->filter };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
        die(err_fd, "seccomp", errno);

    execve(c->argv[0], (char *const *)c->argv, p->envp);
    die(err_fd, "exec", errno);
}

/* ---- the parent ------------------------------------------------------------- */

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

static int env_add(prepared_t *p, int *n, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int env_add(prepared_t *p, int *n, const char *fmt, ...)
{
    if (*n >= ENV_MAX)
        return -1;
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(p->env_text[*n], sizeof(p->env_text[0]), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(p->env_text[0]))
        return -1;
    p->envp[*n] = p->env_text[*n];
    (*n)++;
    p->envp[*n] = NULL;
    return 0;
}

pid_t sandbox_spawn(const sandbox_cfg_t *cfg, char *err, size_t elen)
{
    static prepared_t prep;                     /* one start at a time: the supervisor's thread */
    prepared_t *p = &prep;
    int go[2] = { -1, -1 }, ep[2] = { -1, -1 }, n = 0;

    if (!cfg->argv[0] || !cfg->pkg_dir || !cfg->data_dir || cfg->uid == 0 || cfg->gid == 0)
        return fail(err, elen, "a service needs a program, its two directories, and an account that is not root");
    memset(p, 0, sizeof(*p));
    p->cfg = cfg;
    p->abi = sandbox_landlock_abi();
    if (p->abi < 1 && (cfg->need & SANDBOX_NEED_LANDLOCK_FS))
        return fail(err, elen, "this kernel has no landlock");
    if (p->abi < 4 && (cfg->need & SANDBOX_NEED_LANDLOCK_NET))
        return fail(err, elen, "this kernel's landlock (ABI %d) has no TCP rules", p->abi);
    if (filter_build(p->filter, &p->nfilter) != 0)
        return fail(err, elen, "the seccomp filter does not fit");
    if (env_add(p, &n, "PATH=/usr/bin:/bin") || env_add(p, &n, "LANG=C") || env_add(p, &n, "HOME=%s", cfg->data_dir)
        || env_add(p, &n, "TMPDIR=%s/tmp", cfg->data_dir) || env_add(p, &n, "FFX_ID=%s", cfg->id ? cfg->id : "")
        || env_add(p, &n, "FFX_PKG=%s", cfg->pkg_dir) || env_add(p, &n, "FFX_DATA=%s", cfg->data_dir)
        || env_add(p, &n, "PYTHONDONTWRITEBYTECODE=1") || env_add(p, &n, "PYTHONUNBUFFERED=1"))
        return fail(err, elen, "the service's environment does not fit");
    for (int i = 0; i < SANDBOX_MAX_ARGV && cfg->env[i]; i++)
        if (env_add(p, &n, "%s", cfg->env[i]) != 0)
            return fail(err, elen, "the service's environment does not fit");

    if (pipe2(go, O_CLOEXEC) != 0 || pipe2(ep, O_CLOEXEC) != 0) {
        int saved = errno;
        if (go[0] >= 0) {
            close(go[0]);
            close(go[1]);
        }
        return fail(err, elen, "cannot make a pipe: %s", strerror(saved));
    }
    p->go_fd = go[0];
    p->err_fd = ep[1];
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(go[0]);
        close(go[1]);
        close(ep[0]);
        close(ep[1]);
        return fail(err, elen, "cannot fork: %s", strerror(saved));
    }
    if (pid == 0) {
        close(go[1]);
        close(ep[0]);
        child(p);
        _exit(127);
    }
    close(go[0]);
    close(ep[1]);

    /* Into its group first; only then is it told to go on. */
    int in_group = !cfg->cg_parent || cg_add(cfg->cg_parent, cfg->cg_id, pid) == 0;
    int saved = errno;
    if (in_group && write(go[1], "g", 1) != 1)
        in_group = 0;
    close(go[1]);

    char word[200];
    ssize_t got = 0, k;
    while ((k = read(ep[0], word + got, sizeof(word) - 1 - (size_t)got)) > 0)
        got += k;
    close(ep[0]);
    word[got > 0 ? got : 0] = '\0';
    if (!in_group || got > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (!in_group)
            return fail(err, elen, "cannot put the service into its group: %s", strerror(saved));
        return fail(err, elen, "the service did not start: %s", word);
    }
    return pid;
}
