/*
 * pkg.c - an extension archive (.ffx): who signed it, what is in it, and
 *         its payload unpacked where nothing in it can reach outside
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include "pkg.h"

#include <archive.h>
#include <archive_entry.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FWUP_TIMEOUT_S   120
#define ENTRY_SIG        "meta.conf.ed25519"
#define ENTRY_META       "meta.conf"
#define ENTRY_PAYLOAD    "data/payload.tar.gz"
#define RESOURCE_NAME    "payload.tar.gz"

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

const char *pkg_tier_name(pkg_tier_t t)
{
    return t == TIER_OFFICIAL ? "official" : t == TIER_COMMUNITY ? "community" : "unverified";
}

static void hex(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ---- fwup, asked without a shell --------------------------------------- */

/* Runs fwup with argv (argv[0] is replaced by the binary), collects its
 * stdout, and returns its exit status, or -1 when it could not be run or
 * outlived FWUP_TIMEOUT_S. */
static int fwup_run(const char *fwup, const char *const argv_in[], char *out, size_t olen)
{
    const char *argv[12];
    int n = 0, pfd[2];
    argv[n++] = fwup ? fwup : "fwup";
    for (int i = 1; argv_in[i] && n < 11; i++)
        argv[n++] = argv_in[i];
    argv[n] = NULL;
    if (out && olen)
        out[0] = '\0';
    if (pipe2(pfd, O_CLOEXEC) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0);
        dup2(pfd[1], 1);
        dup2(null, 2);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t got = 0;
    time_t end = time(NULL) + FWUP_TIMEOUT_S;
    int timed_out = 0;
    for (;;) {
        struct pollfd p = { .fd = pfd[0], .events = POLLIN };
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
        ssize_t k = read(pfd[0], buf, sizeof(buf));
        if (k <= 0)
            break;
        if (out && got + 1 < olen) {
            size_t take = (size_t)k < olen - 1 - got ? (size_t)k : olen - 1 - got;
            memcpy(out + got, buf, take);
            got += take;
            out[got] = '\0';
        }
    }
    close(pfd[0]);
    if (timed_out)
        kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    if (timed_out || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

/* The value of `key=` in fwup -m output or in a meta.conf: quotes, when
 * there, removed. 0 when found. */
static int conf_value(const char *text, const char *key, char *out, size_t olen)
{
    size_t klen = strlen(key);
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, key, klen) != 0 || line[klen] != '=')
            continue;
        const char *v = line + klen + 1;
        size_t n = strcspn(v, "\r\n");
        if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
            v++;
            n -= 2;
        }
        if (n >= olen)
            return -1;
        memcpy(out, v, n);
        out[n] = '\0';
        return 0;
    }
    return -1;
}

/* ---- keys --------------------------------------------------------------- */

static int key_read(const char *path, unsigned char pk[crypto_sign_PUBLICKEYBYTES])
{
    char text[160];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    if (n == crypto_sign_PUBLICKEYBYTES) {          /* the factory keyring: 32 raw bytes */
        memcpy(pk, text, crypto_sign_PUBLICKEYBYTES);
        return 0;
    }
    text[n] = '\0';
    while (n > 0 && isspace((unsigned char)text[n - 1]))
        text[--n] = '\0';
    size_t len = 0;
    unsigned char bin[64];
    if (sodium_base642bin(bin, sizeof(bin), text, (size_t)n, NULL, &len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || len != crypto_sign_PUBLICKEYBYTES)
        return -1;
    memcpy(pk, bin, crypto_sign_PUBLICKEYBYTES);
    return 0;
}

int pkg_key_id(const char *key_file, char out[65])
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], h[32];
    out[0] = '\0';
    if (sodium_init() < 0 || key_read(key_file, pk) != 0)
        return -1;
    crypto_generichash(h, sizeof(h), pk, sizeof(pk), NULL, 0);
    hex(h, sizeof(h), out);
    return 0;
}

static int signed_by(const char *key_file, const unsigned char *sig, const unsigned char *meta, size_t mlen)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    if (key_read(key_file, pk) != 0)
        return 0;
    return crypto_sign_verify_detached(sig, meta, mlen, pk) == 0;
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* The *.pub files of a directory, sorted, as full paths. */
static int keys_in(const char *dir, char paths[][256], int max)
{
    int n = 0;
    DIR *d = dir ? opendir(dir) : NULL;
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        size_t len = strlen(e->d_name);
        if (e->d_name[0] == '.' || len < 5 || strcmp(e->d_name + len - 4, ".pub") != 0)
            continue;
        if (snprintf(paths[n], 256, "%s/%s", dir, e->d_name) < 256)
            n++;
    }
    closedir(d);
    qsort(paths, (size_t)n, 256, name_cmp);
    return n;
}

/* Is the path a key, or a directory holding one, that made this signature? */
static int firmware_signed(const char *path, const unsigned char *sig, const unsigned char *meta, size_t mlen)
{
    struct stat st;
    if (!path || stat(path, &st) != 0)
        return 0;
    if (!S_ISDIR(st.st_mode))
        return signed_by(path, sig, meta, mlen);
    DIR *d = opendir(path);
    if (!d)
        return 0;
    int hit = 0;
    struct dirent *e;
    while (!hit && (e = readdir(d)) != NULL) {
        char p[512];
        if (e->d_name[0] == '.' || snprintf(p, sizeof(p), "%s/%s", path, e->d_name) >= (int)sizeof(p))
            continue;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode))
            hit = signed_by(p, sig, meta, mlen);
    }
    closedir(d);
    return hit;
}

/* ---- the signed metadata ------------------------------------------------ */

typedef struct {
    char product[64];
    char version[33];
    char b2[65];
    long long length;
} meta_t;

/* An extension's meta.conf holds meta-* lines and one file-resource block
 * for payload.tar.gz, and nothing else: no task, no partition table, no
 * requirement, no include. Every line is accounted for or the archive is
 * refused, so there is nothing here for a second parser to read another
 * way. */
static int meta_parse(const char *text, meta_t *m, char *err, size_t elen)
{
    int in_block = 0, blocks = 0;
    memset(m, 0, sizeof(*m));
    m->length = -1;
    for (const char *line = text; *line;) {
        size_t n = strcspn(line, "\n");
        char buf[512];
        if (n >= sizeof(buf))
            return fail(err, elen, "the archive's metadata has a line longer than %zu bytes", sizeof(buf) - 1);
        memcpy(buf, line, n);
        buf[n] = '\0';
        line += n + (line[n] == '\n');
        char *s = buf;
        while (isspace((unsigned char)*s))
            s++;
        size_t len = strlen(s);
        while (len && isspace((unsigned char)s[len - 1]))
            s[--len] = '\0';
        if (!len)
            continue;
        if (strncmp(s, "task", 4) == 0 && (isspace((unsigned char)s[4]) || s[4] == '"' || s[4] == '{' || !s[4]))
            return fail(err, elen, "the archive lists a task: an extension archive writes nothing to a disk");
        if (in_block) {
            if (strcmp(s, "}") == 0) {
                in_block = 0;
            } else if (strncmp(s, "length=", 7) == 0) {
                char *end;
                if (!isdigit((unsigned char)s[7]))
                    return fail(err, elen, "the payload's length is not a plain number (%.40s)", s);
                m->length = strtoll(s + 7, &end, 10);
                if (*end)
                    return fail(err, elen, "the payload's length is not a plain number (%.40s)", s);
            } else if (strncmp(s, "blake2b-256=", 12) == 0) {
                const char *h = s + 12;
                size_t hl = strlen(h);
                if (hl >= 2 && h[0] == '"' && h[hl - 1] == '"') {
                    h++;
                    hl -= 2;
                }
                if (hl != 64 || strspn(h, "0123456789abcdef") < 64)
                    return fail(err, elen, "the payload's blake2b-256 is not 64 hex digits");
                memcpy(m->b2, h, 64);
                m->b2[64] = '\0';
            } else {
                return fail(err, elen, "the archive's resource block holds a line an extension's does not: %.60s", s);
            }
            continue;
        }
        if (strncmp(s, "meta-", 5) == 0 && strchr(s, '='))
            continue;
        if (strcmp(s, "file-resource \"" RESOURCE_NAME "\" {") == 0 || strcmp(s, "file-resource " RESOURCE_NAME " {") == 0) {
            if (blocks++)
                return fail(err, elen, "the archive names its payload twice");
            in_block = 1;
            continue;
        }
        return fail(err, elen, "the archive's metadata holds a line an extension's does not: %.60s", s);
    }
    if (in_block || blocks != 1)
        return fail(err, elen, "the archive does not hold exactly one resource, " RESOURCE_NAME);
    if (m->length < 0 || !m->b2[0])
        return fail(err, elen, "the archive's metadata does not give the payload's length and blake2b-256");
    if (conf_value(text, "meta-product", m->product, sizeof(m->product)) != 0)
        return fail(err, elen, "the archive names no product");
    if (conf_value(text, "meta-version", m->version, sizeof(m->version)) != 0)
        return fail(err, elen, "the archive names no version");
    return 0;
}

/* ---- the archive ---------------------------------------------------------- */

/* All of an entry's data into buf (at most max bytes; more is a refusal). */
static long long entry_to_buf(struct archive *a, unsigned char *buf, size_t max)
{
    size_t got = 0;
    for (;;) {
        la_ssize_t k = archive_read_data(a, buf + got, max - got + 1 > 65536 ? 65536 : max - got + 1);
        if (k < 0)
            return -1;
        if (k == 0)
            return (long long)got;
        got += (size_t)k;
        if (got > max)
            return -2;
    }
}

int pkg_open(const pkg_trust_t *trust, const char *file, const char *out_payload,
             pkg_info_t *info, char *err, size_t elen)
{
    unsigned char sig[crypto_sign_BYTES + 1], *meta = NULL, h[32];
    char text[4096], value[128], owner[PKG_MAX_KEYS][256];
    int have_sig = 0, have_meta = 0, have_payload = 0, out_fd = -1, rc = -1;
    long long payload_len = 0, mlen = 0;
    crypto_generichash_state hs;
    struct archive *a = NULL;
    struct stat st;
    meta_t m;

    memset(info, 0, sizeof(*info));
    memset(&m, 0, sizeof(m));
    memset(sig, 0, sizeof(sig));
    memset(h, 0, sizeof(h));
    if (sodium_init() < 0)
        return fail(err, elen, "the crypto library did not start");
    if (lstat(file, &st) != 0 || !S_ISREG(st.st_mode))
        return fail(err, elen, "the archive is not a file");
    if (st.st_size > PKG_MAX_ARCHIVE)
        return fail(err, elen, "the archive is larger than %lld MiB", PKG_MAX_ARCHIVE >> 20);
    meta = malloc(PKG_MAX_META + 2);
    if (!meta)
        return fail(err, elen, "out of memory");

    /* 1. Read it the way fwup does: streaming, the local headers, in order. */
    a = archive_read_new();
    archive_read_support_format_zip_streamable(a);
    if (archive_read_open_filename(a, file, 65536) != ARCHIVE_OK) {
        fail(err, elen, "not an extension archive (%s)", archive_error_string(a));
        goto out;
    }
    struct archive_entry *e;
    int r;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(e);
        if (!name) {
            fail(err, elen, "the archive holds an entry with no name");
            goto out;
        }
        if (strcmp(name, ENTRY_SIG) == 0 && !have_sig && !have_meta && !have_payload) {
            long long n = entry_to_buf(a, sig, crypto_sign_BYTES);
            if (n != crypto_sign_BYTES) {
                fail(err, elen, "the archive's signature is not %d bytes", (int)crypto_sign_BYTES);
                goto out;
            }
            have_sig = 1;
        } else if (strcmp(name, ENTRY_META) == 0 && !have_meta && !have_payload) {
            mlen = entry_to_buf(a, meta, PKG_MAX_META);
            if (mlen <= 0) {
                fail(err, elen, "the archive's metadata is empty, unreadable, or larger than %d bytes", PKG_MAX_META);
                goto out;
            }
            meta[mlen] = '\0';
            if (strlen((const char *)meta) != (size_t)mlen) {
                fail(err, elen, "the archive's metadata holds a NUL");
                goto out;
            }
            if (meta_parse((const char *)meta, &m, err, elen) != 0)
                goto out;
            have_meta = 1;
        } else if (strcmp(name, ENTRY_PAYLOAD) == 0 && have_meta && !have_payload) {
            if (out_payload) {
                out_fd = open(out_payload, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
                if (out_fd < 0) {
                    fail(err, elen, "cannot write the payload: %s", strerror(errno));
                    goto out;
                }
            }
            crypto_generichash_init(&hs, NULL, 0, sizeof(h));
            unsigned char buf[65536];
            la_ssize_t k;
            while ((k = archive_read_data(a, buf, sizeof(buf))) > 0) {
                payload_len += k;
                if (payload_len > PKG_MAX_ARCHIVE) {
                    fail(err, elen, "the payload is larger than %lld MiB", PKG_MAX_ARCHIVE >> 20);
                    goto out;
                }
                crypto_generichash_update(&hs, buf, (size_t)k);
                if (out_fd >= 0 && write(out_fd, buf, (size_t)k) != k) {
                    fail(err, elen, "cannot write the payload: %s", strerror(errno));
                    goto out;
                }
            }
            if (k < 0) {
                fail(err, elen, "the payload does not read: %s", archive_error_string(a));
                goto out;
            }
            crypto_generichash_final(&hs, h, sizeof(h));
            have_payload = 1;
        } else {
            fail(err, elen, "an extension archive holds its metadata and one resource, in that order; "
                            "this one holds \"%.80s\"", name);
            goto out;
        }
    }
    if (r != ARCHIVE_EOF) {
        fail(err, elen, "not an extension archive (%s)", archive_error_string(a));
        goto out;
    }
    if (!have_meta || !have_payload) {
        fail(err, elen, "not an extension archive: it has no %s", have_meta ? "payload" : "metadata");
        goto out;
    }

    /* 2. The product gate. */
    if (strcmp(m.product, PKG_PRODUCT) != 0) {
        fail(err, elen, "the archive's product is \"%.40s\", not \"" PKG_PRODUCT "\"", m.product);
        goto out;
    }

    /* 3. The payload is the one the metadata names. */
    hex(h, sizeof(h), value);
    if (payload_len != m.length || strcmp(value, m.b2) != 0) {
        fail(err, elen, "the payload is not the one the archive's metadata names (length or blake2b-256)");
        goto out;
    }

    /* 4. Who signed the metadata. */
    info->tier = TIER_UNVERIFIED;
    if (have_sig) {
        const char *by = NULL;
        if (trust->official_key && signed_by(trust->official_key, sig, meta, (size_t)mlen)) {
            info->tier = TIER_OFFICIAL;
            by = trust->official_key;
        } else {
            int n = keys_in(trust->owner_keys_dir, owner, PKG_MAX_KEYS);
            for (int i = 0; i < n && !by; i++)
                if (signed_by(owner[i], sig, meta, (size_t)mlen)) {
                    info->tier = TIER_COMMUNITY;
                    by = owner[i];
                }
        }
        if (by) {
            snprintf(info->key_file, sizeof(info->key_file), "%.255s", by);
            pkg_key_id(by, info->key_id);
        } else {
            for (int i = 0; i < 4 && trust->firmware_keys[i]; i++)
                if (firmware_signed(trust->firmware_keys[i], sig, meta, (size_t)mlen)) {
                    fail(err, elen, "the archive is signed with a firmware key: no extension is");
                    goto out;
                }
        }
    }

    /* 5. fwup's own reading must agree: the product, the version, no task,
     *    and its verification of the hashes (and of the signature, when
     *    this reader found the key). */
    const char *argv_m[] = { "", "-m", "-i", file, NULL };
    if (fwup_run(trust->fwup, argv_m, text, sizeof(text)) != 0) {
        fail(err, elen, "fwup does not read the archive's metadata");
        goto out;
    }
    if (conf_value(text, "meta-product", value, sizeof(value)) != 0 || strcmp(value, PKG_PRODUCT) != 0
        || conf_value(text, "meta-version", value, sizeof(value)) != 0 || strcmp(value, m.version) != 0) {
        fail(err, elen, "fwup reads another product or version out of the archive than this verifier does");
        goto out;
    }
    const char *argv_l[] = { "", "-l", "-i", file, NULL };
    if (fwup_run(trust->fwup, argv_l, text, sizeof(text)) != 0 || text[strspn(text, " \t\r\n")] != '\0') {
        fail(err, elen, "the archive lists a task: an extension archive writes nothing to a disk");
        goto out;
    }
    const char *argv_v[] = { "", "-V", "-i", file, info->key_file[0] ? "-p" : NULL, info->key_file, NULL };
    if (fwup_run(trust->fwup, argv_v, NULL, 0) != 0) {
        fail(err, elen, "fwup does not verify the archive");
        goto out;
    }

    snprintf(info->version, sizeof(info->version), "%s", m.version);
    snprintf(info->payload_b2, sizeof(info->payload_b2), "%s", m.b2);
    info->payload_len = m.length;
    rc = 0;
out:
    if (a)
        archive_read_free(a);
    if (out_fd >= 0) {
        if (rc == 0 && fsync(out_fd) != 0)
            rc = fail(err, elen, "cannot write the payload: %s", strerror(errno));
        close(out_fd);
        if (rc != 0)
            unlink(out_payload);
    }
    free(meta);
    return rc;
}

/* ---- the payload ---------------------------------------------------------- */

typedef struct {
    char path[PKG_MAX_PATH + 1];
    char b2[65];
    unsigned mode;
    long long size;
} listed_t;

static int listed_cmp(const void *a, const void *b)
{
    return strcmp(((const listed_t *)a)->path, ((const listed_t *)b)->path);
}

/* A payload path made safe, or refused: relative, no "." or ".." or empty
 * segment, printable ASCII, no backslash, within the depth and length
 * limits. "./" in front is what tar writes and is dropped; "" comes back
 * for the payload's own root. */
static int clean_path(const char *in, char *out, size_t olen)
{
    while (in[0] == '.' && in[1] == '/')
        in += 2;
    if (strcmp(in, ".") == 0)
        in++;
    size_t len = strlen(in);
    while (len && in[len - 1] == '/')
        len--;
    if (len >= olen || len > PKG_MAX_PATH)
        return -1;
    if (len == 0) {
        out[0] = '\0';
        return 0;
    }
    if (in[0] == '/')
        return -1;
    int depth = 1;
    size_t seg = 0;
    for (size_t i = 0; i <= len; i++) {
        unsigned char c = i < len ? (unsigned char)in[i] : '/';
        if (c == '/') {
            if (seg == 0 || (seg == 1 && in[i - 1] == '.') || (seg == 2 && in[i - 1] == '.' && in[i - 2] == '.'))
                return -1;
            seg = 0;
            if (i < len && ++depth > PKG_MAX_DEPTH)
                return -1;
        } else if (c < ' ' || c > '~' || c == '\\') {
            return -1;
        } else {
            seg++;
        }
    }
    memcpy(out, in, len);
    out[len] = '\0';
    return 0;
}

/* mkdir -p of path's directories under dirfd; with whole != 0 the last
 * segment is a directory too. Nothing here follows a symbolic link: the
 * tree is this process's own and holds none. */
static int make_dirs(int dirfd, const char *path, int whole)
{
    char p[PKG_MAX_PATH + 1];
    snprintf(p, sizeof(p), "%s", path);
    size_t len = strlen(p);
    for (size_t i = 1; i <= len; i++) {
        if (p[i] != '/' && !(p[i] == '\0' && whole))
            continue;
        char keep = p[i];
        p[i] = '\0';
        struct stat st;
        if ((mkdirat(dirfd, p, 0755) != 0 && errno != EEXIST)
            || fstatat(dirfd, p, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode))
            return -1;
        p[i] = keep;
    }
    return 0;
}

int pkg_unpack(const char *payload, const char *dest, const char *list_path,
               pkg_tree_t *tree, char *err, size_t elen)
{
    listed_t *list = NULL;
    int nlist = 0, rc = -1, dirfd = -1;
    pkg_tree_t t = { 0, 0, 0 };
    struct archive *a = NULL;

    if (sodium_init() < 0)
        return fail(err, elen, "the crypto library did not start");
    dirfd = open(dest, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        return fail(err, elen, "cannot open the unpack directory: %s", strerror(errno));
    list = calloc(PKG_MAX_FILES, sizeof(*list));
    if (!list) {
        fail(err, elen, "out of memory");
        goto out;
    }
    a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    if (archive_read_open_filename(a, payload, 65536) != ARCHIVE_OK) {
        fail(err, elen, "the payload is not a gzip-compressed tar (%s)", archive_error_string(a));
        goto out;
    }
    struct archive_entry *e;
    int r;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        char path[PKG_MAX_PATH + 1];
        const char *raw = archive_entry_pathname(e);
        if (!raw || clean_path(raw, path, sizeof(path)) != 0) {
            fail(err, elen, "the payload holds a path that does not stay inside the package, or is longer than "
                            "%d characters or deeper than %d directories: \"%.80s\"", PKG_MAX_PATH, PKG_MAX_DEPTH,
                 raw ? raw : "");
            goto out;
        }
        if (archive_entry_hardlink(e) || archive_entry_symlink(e)) {
            fail(err, elen, "the payload holds a link (\"%.80s\"): a package is files and directories", path);
            goto out;
        }
        mode_t type = archive_entry_filetype(e);
        if (type == AE_IFDIR) {
            if (path[0] && make_dirs(dirfd, path, 1) != 0) {
                fail(err, elen, "cannot make directory \"%.80s\"", path);
                goto out;
            }
            if (path[0])
                t.dirs++;
            continue;
        }
        if (type != AE_IFREG || !path[0]) {
            fail(err, elen, "the payload holds something that is neither a file nor a directory: \"%.80s\"", path);
            goto out;
        }
        if (nlist >= PKG_MAX_FILES) {
            fail(err, elen, "the payload holds more than %d files", PKG_MAX_FILES);
            goto out;
        }
        if (make_dirs(dirfd, path, 0) != 0) {
            fail(err, elen, "cannot make the directories of \"%.80s\"", path);
            goto out;
        }
        unsigned mode = (archive_entry_perm(e) & 0111) ? 0755 : 0644;
        int fd = openat(dirfd, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
        if (fd < 0) {
            fail(err, elen, errno == EEXIST ? "the payload lists \"%.80s\" twice" : "cannot write \"%.80s\"", path);
            goto out;
        }
        crypto_generichash_state hs;
        crypto_generichash_init(&hs, NULL, 0, 32);
        unsigned char buf[65536], h[32];
        long long size = 0;
        la_ssize_t k;
        while ((k = archive_read_data(a, buf, sizeof(buf))) > 0) {
            size += k;
            t.bytes += k;
            if (size > PKG_MAX_FILE || t.bytes > PKG_MAX_UNPACKED || write(fd, buf, (size_t)k) != k)
                break;
            crypto_generichash_update(&hs, buf, (size_t)k);
        }
        int bad = k != 0 || fchmod(fd, mode) != 0 || fsync(fd) != 0;
        close(fd);
        if (bad) {
            if (size > PKG_MAX_FILE || t.bytes > PKG_MAX_UNPACKED)
                fail(err, elen, "the payload unpacks to more than %lld MiB, or one file to more than %lld MiB",
                     PKG_MAX_UNPACKED >> 20, PKG_MAX_FILE >> 20);
            else
                fail(err, elen, "cannot write \"%.80s\"", path);
            goto out;
        }
        crypto_generichash_final(&hs, h, sizeof(h));
        listed_t *l = &list[nlist++];
        snprintf(l->path, sizeof(l->path), "%s", path);
        hex(h, sizeof(h), l->b2);
        l->mode = mode;
        l->size = size;
        t.files++;
    }
    if (r != ARCHIVE_EOF) {
        fail(err, elen, "the payload does not read: %s", archive_error_string(a));
        goto out;
    }
    qsort(list, (size_t)nlist, sizeof(*list), listed_cmp);
    FILE *f = fopen(list_path, "wxe");
    if (!f) {
        fail(err, elen, "cannot write the file list: %s", strerror(errno));
        goto out;
    }
    for (int i = 0; i < nlist; i++)
        fprintf(f, "%s %04o %lld %s\n", list[i].b2, list[i].mode, list[i].size, list[i].path);
    int wrote = fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0 || !wrote) {
        fail(err, elen, "cannot write the file list: %s", strerror(errno));
        unlink(list_path);
        goto out;
    }
    if (tree)
        *tree = t;
    rc = 0;
out:
    if (a)
        archive_read_free(a);
    free(list);
    close(dirfd);
    return rc;
}

/* ---- the tree, checked again ---------------------------------------------- */

static int hash_file_at(int dirfd, const char *path, char out[65], long long *size, unsigned *mode)
{
    int fd = openat(dirfd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    crypto_generichash_state hs;
    crypto_generichash_init(&hs, NULL, 0, 32);
    unsigned char buf[65536], h[32];
    ssize_t k;
    long long n = 0;
    while ((k = read(fd, buf, sizeof(buf))) > 0) {
        crypto_generichash_update(&hs, buf, (size_t)k);
        n += k;
    }
    close(fd);
    if (k < 0)
        return -1;
    crypto_generichash_final(&hs, h, sizeof(h));
    hex(h, sizeof(h), out);
    *size = n;
    *mode = st.st_mode & 07777;
    return 0;
}

/* Counts the regular files under dirfd/rel; anything that is neither a
 * file nor a directory is -1. */
static int count_files(int dirfd, const char *rel, int depth)
{
    int fd = openat(dirfd, rel[0] ? rel : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || depth > PKG_MAX_DEPTH + 1) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return -1;
    }
    int n = 0;
    struct dirent *e;
    while (n >= 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            n = -1;
        } else if (S_ISREG(st.st_mode)) {
            n++;
        } else if (S_ISDIR(st.st_mode)) {
            int sub = count_files(fd, e->d_name, depth + 1);
            n = sub < 0 ? -1 : n + sub;
        } else {
            n = -1;
        }
    }
    closedir(d);
    return n;
}

int pkg_tree_check(const char *dir, const char *list_path, char *err, size_t elen)
{
    if (sodium_init() < 0)
        return fail(err, elen, "the crypto library did not start");
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        return fail(err, elen, "the package's files are missing");
    FILE *f = fopen(list_path, "re");
    if (!f) {
        close(dirfd);
        return fail(err, elen, "the package's file list is missing");
    }
    char line[PKG_MAX_PATH + 128];
    int listed = 0, rc = 0;
    while (rc == 0 && fgets(line, sizeof(line), f)) {
        char b2[65], got[65];
        unsigned mode, gmode;
        long long size, gsize;
        int off = 0;
        if (sscanf(line, "%64s %o %lld %n", b2, &mode, &size, &off) != 3 || off == 0) {
            rc = fail(err, elen, "the package's file list does not read");
            break;
        }
        char *path = line + off;
        path[strcspn(path, "\n")] = '\0';
        char clean[PKG_MAX_PATH + 1];
        if (clean_path(path, clean, sizeof(clean)) != 0 || strcmp(clean, path) != 0 || !path[0]) {
            rc = fail(err, elen, "the package's file list does not read");
            break;
        }
        if (hash_file_at(dirfd, path, got, &gsize, &gmode) != 0)
            rc = fail(err, elen, "a file of the package is missing: %.80s", path);
        else if (strcmp(got, b2) != 0 || gsize != size)
            rc = fail(err, elen, "a file of the package changed since it was installed: %.80s", path);
        else if (gmode != mode)
            rc = fail(err, elen, "the mode of a file of the package changed since it was installed: %.80s", path);
        listed++;
    }
    fclose(f);
    if (rc == 0) {
        int found = count_files(dirfd, "", 0);
        if (found != listed)
            rc = fail(err, elen, "the package holds something that was not installed with it");
    }
    close(dirfd);
    return rc;
}

/* ---- removal ------------------------------------------------------------------ */

static int rm_at(int dirfd, const char *name, int depth)
{
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(dirfd, name, 0);
    if (depth > 64)
        return -1;
    int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return -1;
    }
    int rc = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (rm_at(fd, e->d_name, depth + 1) != 0)
            rc = -1;
    }
    closedir(d);
    if (unlinkat(dirfd, name, AT_REMOVEDIR) != 0)
        rc = -1;
    return rc;
}

int pkg_rmtree(const char *dir)
{
    return rm_at(AT_FDCWD, dir, 0);
}
