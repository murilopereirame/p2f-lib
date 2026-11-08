/*
 * The resumable download of a file or a folder.
 *
 *   - Each file goes to the same local path every time.
 *   - A stopped copy keeps its bytes. The next try asks the webseed for
 *     the ciphertext from that offset (HTTP Range) and appends the rest.
 *     CTR is seekable, so the resume is byte-exact.
 *   - A finished file is checked against the server's plaintext SHA-256.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cJSON.h"
#include "p2f_internal.h"

#include "mbedtls/sha256.h"

#define BLOCK_LEN 16
#define IO_BUF (256 * 1024)

typedef struct {
    char *remote;    /* path on the server */
    char *relative;  /* path under the local target; "" for a single file */
    int64_t size;
} remote_file;

typedef struct {
    remote_file *items;
    size_t len, cap;
} file_list;

/* ---- Small helpers ---------------------------------------------------- */

static char *join(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    char *s;
    if (la == 0)
        return strdup(b);
    if (lb == 0)
        return strdup(a);
    s = malloc(la + lb + 2);
    if (!s)
        return NULL;
    memcpy(s, a, la);
    s[la] = '/';
    memcpy(s + la + 1, b, lb + 1);
    return s;
}

static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int mkdir_p(const char *path)
{
    char tmp[1024];
    size_t i, n = strlen(path);
    if (n == 0 || n >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, n + 1);
    for (i = 1; i <= n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
                return -1;
            tmp[i] = saved;
        }
    }
    return 0;
}

static int mkdir_parent(const char *file)
{
    char tmp[1024];
    char *slash;
    if (strlen(file) >= sizeof(tmp))
        return -1;
    strcpy(tmp, file);
    slash = strrchr(tmp, '/');
    if (!slash || slash == tmp)
        return 0;
    *slash = '\0';
    return mkdir_p(tmp);
}

static int64_t local_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (int64_t)st.st_size : 0;
}

static int list_push(file_list *l, const char *remote, const char *relative,
                     int64_t size)
{
    if (l->len == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        remote_file *n = realloc(l->items, cap * sizeof(*n));
        if (!n)
            return P2F_ERR_NOMEM;
        l->items = n;
        l->cap = cap;
    }
    l->items[l->len].remote = strdup(remote);
    l->items[l->len].relative = strdup(relative);
    l->items[l->len].size = size;
    if (!l->items[l->len].remote || !l->items[l->len].relative)
        return P2F_ERR_NOMEM;
    l->len++;
    return P2F_OK;
}

static void list_free(file_list *l)
{
    size_t i;
    for (i = 0; i < l->len; i++) {
        free(l->items[i].remote);
        free(l->items[i].relative);
    }
    free(l->items);
}

static void to_hex(const unsigned char *in, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int file_sha256(const char *path, char hex[65])
{
    unsigned char digest[32];
    mbedtls_sha256_context sha;
    unsigned char *buf;
    FILE *f;
    size_t n;

    f = fopen(path, "rb");
    if (!f)
        return P2F_ERR_IO;
    buf = malloc(IO_BUF);
    if (!buf) {
        fclose(f);
        return P2F_ERR_NOMEM;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    while ((n = fread(buf, 1, IO_BUF, f)) > 0)
        mbedtls_sha256_update(&sha, buf, n);
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    free(buf);
    if (ferror(f)) {
        fclose(f);
        return P2F_ERR_IO;
    }
    fclose(f);
    to_hex(digest, 32, hex);
    return P2F_OK;
}

/* ---- Remote enumeration ----------------------------------------------- */

static int collect(p2f_client *c, const char *remote_dir, const char *base,
                   file_list *out, int depth)
{
    p2f_entry *e = NULL;
    size_t n = 0, i;
    int rc;

    if (depth > 64)
        return p2f_fail(c, P2F_ERR_PROTO, "folder tree too deep");
    rc = p2f_list(c, remote_dir, &e, &n);
    if (rc != P2F_OK)
        return rc;
    for (i = 0; i < n && rc == P2F_OK; i++) {
        char *remote = join(remote_dir, e[i].name);
        char *relative = join(base, e[i].name);
        if (!remote || !relative)
            rc = P2F_ERR_NOMEM;
        else if (e[i].is_dir)
            rc = collect(c, remote, relative, out, depth + 1);
        else
            rc = list_push(out, remote, relative, e[i].size < 0 ? 0 : e[i].size);
        free(remote);
        free(relative);
    }
    p2f_entries_free(e, n);
    return rc;
}

/*
 * A folder -> every file under it. A file -> one entry. The server answers
 * /api/list on a file with 400 (or 404), which is how the two differ.
 */
static int enumerate(p2f_client *c, const char *remote, file_list *out,
                     int *is_dir)
{
    p2f_entry *e = NULL;
    size_t n = 0, i;
    char parent[1024];
    const char *name;
    int rc;

    rc = collect(c, remote, "", out, 0);
    if (rc == P2F_OK) {
        *is_dir = 1;
        return P2F_OK;
    }
    if (rc != P2F_ERR_HTTP || (c->last_status != 400 && c->last_status != 404))
        return rc;

    /* A single file. Its size comes from the parent listing. */
    *is_dir = 0;
    name = base_name(remote);
    if ((size_t)(name - remote) >= sizeof(parent))
        return P2F_ERR_ARG;
    memcpy(parent, remote, (size_t)(name - remote));
    parent[name - remote] = '\0';
    if (parent[0] && parent[strlen(parent) - 1] == '/')
        parent[strlen(parent) - 1] = '\0';

    rc = p2f_list(c, parent, &e, &n);
    if (rc != P2F_OK)
        return rc;
    rc = p2f_fail(c, P2F_ERR_NOTFOUND, "remote path not found: %s", remote);
    for (i = 0; i < n; i++) {
        if (!e[i].is_dir && strcmp(e[i].name, name) == 0) {
            rc = list_push(out, remote, "", e[i].size < 0 ? 0 : e[i].size);
            break;
        }
    }
    p2f_entries_free(e, n);
    return rc;
}

/* ---- Per-file metadata ------------------------------------------------ */

typedef struct {
    const p2f_download_opts *opts;
    p2f_progress prog;
} run_state;

static int report(run_state *s)
{
    if (s->opts->on_progress)
        return s->opts->on_progress(&s->prog, s->opts->user);
    return 0;
}

typedef struct {
    int64_t length;
    char wrapped[256];
    char sha256[65];
} file_meta;

/*
 * The server answers /api/torrent only when it has read and hashed the
 * whole file. The first time, a large file takes minutes. The request asks
 * with async=1: a new server then answers 202 ("preparing") at once, with
 * its progress, and we ask again. An old server keeps the request open; the
 * long timeout covers that, and a timeout is retried (the server keeps
 * hashing and caches the result).
 */
#define META_REQUEST_TIMEOUT_MS 120000

/* Wait ms, in small steps, so that a stop request is seen. */
static int wait_or_stop(run_state *s, int ms)
{
    while (ms > 0) {
        int step = ms > 200 ? 200 : ms;
        p2f_platform_sleep_ms(step);
        ms -= step;
        if (report(s))
            return 1;
    }
    return 0;
}

static int parse_meta(p2f_client *c, const char *remote, const char *body,
                      file_meta *m)
{
    const cJSON *len, *wrap, *sha;
    cJSON *j = cJSON_Parse(body);

    len = cJSON_GetObjectItemCaseSensitive(j, "length");
    wrap = cJSON_GetObjectItemCaseSensitive(j, "encKeyWrapped");
    sha = cJSON_GetObjectItemCaseSensitive(j, "plainSha256");
    if (!cJSON_IsNumber(len) || !cJSON_IsString(wrap) ||
        strlen(wrap->valuestring) >= sizeof(m->wrapped)) {
        cJSON_Delete(j);
        return p2f_fail(c, P2F_ERR_PROTO, "bad torrent metadata for %s", remote);
    }
    m->length = (int64_t)len->valuedouble;
    strcpy(m->wrapped, wrap->valuestring);
    m->sha256[0] = '\0';
    if (cJSON_IsString(sha) && strlen(sha->valuestring) == 64)
        strcpy(m->sha256, sha->valuestring);
    cJSON_Delete(j);
    return P2F_OK;
}

static int fetch_meta(p2f_client *c, const char *remote, const char *ck,
                      file_meta *m, run_state *s)
{
    char *p_enc, *ck_enc, *pq, *body = NULL;
    int rc, status, retry_after, fails = 0;
    int timeout = c->timeout_ms > META_REQUEST_TIMEOUT_MS
                      ? c->timeout_ms : META_REQUEST_TIMEOUT_MS;
    uint64_t t0 = p2f_platform_now_ms();
    int limit = s->opts->prepare_timeout_ms;

    p_enc = p2f_urlencode(remote);
    ck_enc = p2f_urlencode(ck);
    pq = (p_enc && ck_enc) ? malloc(strlen(p_enc) + strlen(ck_enc) + 48) : NULL;
    if (!pq) {
        free(p_enc);
        free(ck_enc);
        return P2F_ERR_NOMEM;
    }
    sprintf(pq, "/api/torrent?path=%s&ck=%s&async=1", p_enc, ck_enc);
    free(p_enc);
    free(ck_enc);

    for (;;) {
        cJSON *j;
        const cJSON *err, *done, *total;
        int from_p2f, delay;

        c->last_status = 0;
        rc = p2f_get_raw(c, pq, timeout, &status, &body, &retry_after);
        if (rc != P2F_OK && rc != P2F_ERR_NET)
            break;
        if (rc == P2F_OK && status >= 200 && status <= 299 && status != 202) {
            rc = parse_meta(c, remote, body, m);
            break;
        }

        /* Not ready, or a failure. Is it worth another try? */
        j = (rc == P2F_OK) ? cJSON_Parse(body) : NULL;
        err = cJSON_GetObjectItemCaseSensitive(j, "error");
        from_p2f = cJSON_IsString(err) ||
                   cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(j, "preparing"));
        if (status == 202) {
            fails = 0;
            done = cJSON_GetObjectItemCaseSensitive(j, "bytesDone");
            total = cJSON_GetObjectItemCaseSensitive(j, "bytesTotal");
            s->prog.preparing = 1;
            s->prog.prepare_done = cJSON_IsNumber(done) ? (uint64_t)done->valuedouble : 0;
            s->prog.prepare_total = cJSON_IsNumber(total) ? (uint64_t)total->valuedouble : 0;
            delay = p2f_retry_delay_ms(202, 1, 1, retry_after);
        } else {
            fails++;
            delay = p2f_retry_delay_ms(rc == P2F_OK ? status : 0, from_p2f,
                                       fails, retry_after);
            if (delay < 0) {
                c->last_status = status;
                if (status == 404)
                    rc = p2f_fail(c, P2F_ERR_NOTFOUND, "HTTP 404: %s",
                                  cJSON_IsString(err) ? err->valuestring
                                                      : "not found");
                else if (cJSON_IsString(err))
                    rc = p2f_fail(c, P2F_ERR_HTTP, "HTTP %d: %s", status,
                                  err->valuestring);
                else
                    rc = p2f_fail(c, P2F_ERR_HTTP, "HTTP %d", status);
                cJSON_Delete(j);
                break;
            }
            s->prog.preparing = 1;
        }
        cJSON_Delete(j);
        free(body);
        body = NULL;

        if (limit > 0 && p2f_platform_now_ms() - t0 + (uint64_t)delay > (uint64_t)limit) {
            rc = p2f_fail(c, P2F_ERR_NET,
                          "the server is still preparing %s (gave up after %d s)",
                          remote, limit / 1000);
            break;
        }
        if (report(s) || wait_or_stop(s, delay)) {
            rc = P2F_ERR_ABORT;
            break;
        }
    }
    free(body);
    free(pq);
    s->prog.preparing = 0;
    s->prog.prepare_done = s->prog.prepare_total = 0;
    return rc;
}

/* ---- One file --------------------------------------------------------- */

static int download_file(p2f_client *c, const remote_file *file,
                         const char *local, p2f_keypair *kp,
                         const char *server_pub, uint64_t base, run_state *s)
{
    uint8_t key[32], iv[16];
    file_meta meta;
    p2f_resume_plan plan;
    int64_t existing, start, block_start, drop, written = 0;
    int append, hashing = 0, rc, idle;
    p2f_http h;
    p2f_ctr ctr;
    mbedtls_sha256_context sha;
    unsigned char *buf = NULL;
    FILE *f = NULL;

    s->prog.current = file->remote;
    existing = local_size(local);

    rc = fetch_meta(c, file->remote, kp->pub_b64, &meta, s);
    if (rc != P2F_OK)
        return rc;
    if (p2f_unwrap_transfer_key(kp, server_pub, meta.wrapped, key, iv) != P2F_OK)
        return p2f_fail(c, P2F_ERR_CRYPTO, "key unwrap failed for %s",
                        file->remote);

    /* Resume plan. */
    plan = p2f_plan_resume(existing, meta.length);
    if (plan.skip) {
        struct stat st;
        /* An empty remote file: make sure the local file exists. */
        if (meta.length == 0 && stat(local, &st) != 0) {
            FILE *e = fopen(local, "wb");
            if (!e)
                return p2f_fail(c, P2F_ERR_IO, "cannot create %s", local);
            fclose(e);
        }
        s->prog.bytes_done = base + (uint64_t)meta.length;
        s->prog.files_done++;
        return report(s) ? P2F_ERR_ABORT : P2F_OK;
    }
    if (!plan.append && existing > 0)
        remove(local);  /* the local file is bad; start again */
    start = plan.start;
    append = plan.append;
    block_start = start - (start % BLOCK_LEN);
    drop = start - block_start;

    s->prog.bytes_done = base + (uint64_t)start;
    if (report(s))
        return P2F_ERR_ABORT;

    idle = s->opts->idle_timeout_ms > 0 ? s->opts->idle_timeout_ms : 60000;
    {
        char *enc = p2f_urlencode(file->remote);
        char *pq = enc ? malloc(strlen(enc) + 24) : NULL;
        if (!pq) {
            free(enc);
            return P2F_ERR_NOMEM;
        }
        sprintf(pq, "/api/raw?path=%s", enc);
        free(enc);
        c->last_status = 0;
        rc = p2f_http_get(c, pq, block_start, idle, &h);
        free(pq);
        if (rc != P2F_OK)
            return rc;
    }
    if (h.status < 200 || h.status > 299) {
        c->last_status = h.status;
        p2f_http_close(&h);
        return p2f_fail(c, P2F_ERR_HTTP, "webseed returned HTTP %d", h.status);
    }
    /* A range was asked for but the whole file came: start from zero. */
    if (block_start > 0 && h.status != 206) {
        block_start = 0;
        drop = 0;
        start = 0;
        append = 0;
    }

    if (p2f_ctr_init(&ctr, key, iv, (uint64_t)block_start / BLOCK_LEN) != P2F_OK) {
        p2f_http_close(&h);
        return p2f_fail(c, P2F_ERR_CRYPTO, "AES init failed");
    }
    memset(key, 0, sizeof(key));

    buf = malloc(IO_BUF);
    f = fopen(local, append ? "ab" : "wb");
    if (!buf || !f) {
        rc = buf ? p2f_fail(c, P2F_ERR_IO, "cannot open %s (errno %d)", local, errno)
                 : P2F_ERR_NOMEM;
        goto done;
    }

    /* Hash as it streams when the copy starts at zero; else re-read later. */
    hashing = (start == 0);
    if (hashing) {
        mbedtls_sha256_init(&sha);
        mbedtls_sha256_starts(&sha, 0);
    }

    rc = P2F_OK;
    for (;;) {
        ssize_t n = p2f_http_read(&h, buf, IO_BUF);
        unsigned char *out = buf;
        if (n == 0)
            break;
        if (n < 0) {
            rc = p2f_fail(c, P2F_ERR_NET, "connection lost or stalled");
            break;
        }
        p2f_ctr_update(&ctr, buf, (size_t)n);
        if (drop > 0) {
            int64_t d = drop < n ? drop : n;
            out += d;
            n -= (ssize_t)d;
            drop -= d;
        }
        if (n == 0)
            continue;
        if (fwrite(out, 1, (size_t)n, f) != (size_t)n) {
            rc = p2f_fail(c, P2F_ERR_IO, "write failed (disk full?)");
            break;
        }
        if (hashing)
            mbedtls_sha256_update(&sha, out, (size_t)n);
        written += n;
        s->prog.bytes_done = base + (uint64_t)(start + written);
        if (report(s)) {
            rc = P2F_ERR_ABORT;
            break;
        }
    }

done:
    p2f_http_close(&h);
    p2f_ctr_free(&ctr);
    free(buf);
    if (f && fclose(f) != 0 && rc == P2F_OK)
        rc = p2f_fail(c, P2F_ERR_IO, "close failed for %s", local);
    if (rc != P2F_OK) {
        if (hashing)
            mbedtls_sha256_free(&sha);
        if (rc == P2F_ERR_NET)
            rc = P2F_ERR_SHORT;  /* the bytes so far are kept for a resume */
        return rc;
    }

    /* A short read means the link dropped. The next try resumes. */
    if (local_size(local) != meta.length) {
        if (hashing)
            mbedtls_sha256_free(&sha);
        return p2f_fail(c, P2F_ERR_SHORT, "'%s' is short: %lld of %lld bytes",
                        file->remote, (long long)local_size(local),
                        (long long)meta.length);
    }

    if (s->opts->verify && meta.sha256[0]) {
        char got[65];
        if (hashing) {
            unsigned char digest[32];
            mbedtls_sha256_finish(&sha, digest);
            mbedtls_sha256_free(&sha);
            to_hex(digest, 32, got);
        } else {
            rc = file_sha256(local, got);
            if (rc != P2F_OK)
                return p2f_fail(c, rc, "cannot read %s to verify", local);
        }
        if (strcmp(got, meta.sha256) != 0) {
            remove(local);
            return p2f_fail(c, P2F_ERR_CHECKSUM,
                            "'%s' failed the checksum; it was removed",
                            file->remote);
        }
    } else if (hashing) {
        mbedtls_sha256_free(&sha);
    }

    s->prog.bytes_done = base + (uint64_t)meta.length;
    s->prog.files_done++;
    return report(s) ? P2F_ERR_ABORT : P2F_OK;
}

/* ---- Public entry point ----------------------------------------------- */

static int fetch_server_key(p2f_client *c, char *out, size_t max)
{
    char *body = NULL;
    const cJSON *k;
    cJSON *j;
    int rc = p2f_get_json(c, "/api/info", &body);
    if (rc != P2F_OK)
        return rc;
    j = cJSON_Parse(body);
    free(body);
    k = cJSON_GetObjectItemCaseSensitive(j, "ecdhPublicKey");
    if (!cJSON_IsString(k) || strlen(k->valuestring) >= max) {
        cJSON_Delete(j);
        return p2f_fail(c, P2F_ERR_PROTO, "server info has no ECDH key");
    }
    strcpy(out, k->valuestring);
    cJSON_Delete(j);
    return P2F_OK;
}

int p2f_download_path(p2f_client *c, const char *remote, const char *local_dir,
                      const p2f_download_opts *opts, char *out_local,
                      size_t out_local_len)
{
    static const p2f_download_opts defaults = { NULL, NULL, 1, 60000, 0 };
    char server_pub[256];
    char remote_clean[1024];
    file_list files = { 0 };
    p2f_keypair kp;
    run_state s;
    char *target = NULL;
    uint64_t base = 0;
    size_t i, n;
    int rc, is_dir = 0;

    if (!c || !remote || !local_dir)
        return P2F_ERR_ARG;
    if (!opts)
        opts = &defaults;

    /* Drop leading and trailing slashes from the remote path. */
    while (*remote == '/')
        remote++;
    n = strlen(remote);
    while (n > 0 && remote[n - 1] == '/')
        n--;
    if (n == 0 || n >= sizeof(remote_clean))
        return p2f_fail(c, P2F_ERR_ARG, "bad remote path");
    memcpy(remote_clean, remote, n);
    remote_clean[n] = '\0';

    rc = fetch_server_key(c, server_pub, sizeof(server_pub));
    if (rc != P2F_OK)
        return rc;
    if (p2f_keypair_generate(&kp) != P2F_OK)
        return p2f_fail(c, P2F_ERR_CRYPTO, "key generation failed");

    rc = enumerate(c, remote_clean, &files, &is_dir);
    if (rc != P2F_OK)
        goto out;

    memset(&s, 0, sizeof(s));
    s.opts = opts;
    s.prog.files_total = (int)files.len;
    for (i = 0; i < files.len; i++)
        s.prog.bytes_total += (uint64_t)files.items[i].size;
    if (report(&s)) {
        rc = P2F_ERR_ABORT;
        goto out;
    }

    target = join(local_dir, base_name(remote_clean));
    if (!target) {
        rc = P2F_ERR_NOMEM;
        goto out;
    }
    if (out_local && out_local_len > 0)
        snprintf(out_local, out_local_len, "%s", target);
    if (mkdir_p(is_dir ? target : local_dir) != 0) {
        rc = p2f_fail(c, P2F_ERR_IO, "cannot create %s (errno %d)",
                      is_dir ? target : local_dir, errno);
        goto out;
    }

    for (i = 0; i < files.len; i++) {
        const remote_file *f = &files.items[i];
        char *local = f->relative[0] ? join(target, f->relative) : strdup(target);
        if (!local) {
            rc = P2F_ERR_NOMEM;
            break;
        }
        if (mkdir_parent(local) != 0) {
            rc = p2f_fail(c, P2F_ERR_IO, "cannot create folder for %s", local);
            free(local);
            break;
        }
        rc = download_file(c, f, local, &kp, server_pub, base, &s);
        free(local);
        if (rc != P2F_OK)
            break;
        base += (uint64_t)f->size;
    }

out:
    if (rc == P2F_ERR_ABORT)
        p2f_fail(c, rc, "stopped");
    free(target);
    list_free(&files);
    p2f_keypair_free(&kp);
    return rc;
}
