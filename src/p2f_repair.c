/*
 * Download repair: the pure parts, with no I/O. The C download
 * (p2f_download.c) and the JavaScript package (through the WebAssembly
 * build) both use them.
 *
 * The torrent of a file lists the SHA-1 of each piece of the ciphertext.
 * The local file is the plaintext, but AES-CTR is seekable and keeps the
 * length, so any piece of the local file can be encrypted again on its own
 * and checked against its hash. That says exactly which pieces are wrong;
 * only those are fetched again (an HTTP range each).
 */
#include <string.h>

#include "p2f_crypto.h"

#include "mbedtls/sha1.h"

/* ---- A minimal bencode reader ----------------------------------------- */

typedef struct {
    const uint8_t *p, *end;
} bcur;

static int b_int(bcur *b, int64_t *out)
{
    int neg = 0, digits = 0;
    int64_t v = 0;
    if (b->p >= b->end || *b->p != 'i')
        return -1;
    b->p++;
    if (b->p < b->end && *b->p == '-') {
        neg = 1;
        b->p++;
    }
    while (b->p < b->end && *b->p >= '0' && *b->p <= '9') {
        if (v > (INT64_MAX - 9) / 10)
            return -1;
        v = v * 10 + (*b->p - '0');
        b->p++;
        digits++;
    }
    if (!digits || b->p >= b->end || *b->p != 'e')
        return -1;
    b->p++;
    *out = neg ? -v : v;
    return 0;
}

static int b_str(bcur *b, const uint8_t **s, size_t *len)
{
    size_t n = 0;
    int digits = 0;
    while (b->p < b->end && *b->p >= '0' && *b->p <= '9') {
        if (n > ((size_t)-1) / 10 - 9)
            return -1;
        n = n * 10 + (size_t)(*b->p - '0');
        b->p++;
        digits++;
    }
    if (!digits || b->p >= b->end || *b->p != ':')
        return -1;
    b->p++;
    if ((size_t)(b->end - b->p) < n)
        return -1;
    *s = b->p;
    *len = n;
    b->p += n;
    return 0;
}

/* Skip any one value. */
static int b_skip(bcur *b, int depth)
{
    const uint8_t *s;
    size_t n;
    int64_t v;
    if (depth > 32 || b->p >= b->end)
        return -1;
    switch (*b->p) {
    case 'i':
        return b_int(b, &v);
    case 'l':
    case 'd':
        b->p++;
        while (b->p < b->end && *b->p != 'e')
            if (b_skip(b, depth + 1) != 0)
                return -1;
        if (b->p >= b->end)
            return -1;
        b->p++;
        return 0;
    default:
        return b_str(b, &s, &n);
    }
}

static int key_is(const uint8_t *k, size_t n, const char *want)
{
    return n == strlen(want) && memcmp(k, want, n) == 0;
}

int p2f_torrent_parse(const uint8_t *buf, size_t len, p2f_torrent_layout *out)
{
    bcur b = { buf, buf + len };
    int found_info = 0;

    memset(out, 0, sizeof(*out));
    if (!buf || len == 0 || *b.p != 'd')
        return P2F_ERR_PROTO;
    b.p++;
    while (b.p < b.end && *b.p != 'e') {
        const uint8_t *k;
        size_t kn;
        if (b_str(&b, &k, &kn) != 0)
            return P2F_ERR_PROTO;
        if (!key_is(k, kn, "info")) {
            if (b_skip(&b, 0) != 0)
                return P2F_ERR_PROTO;
            continue;
        }
        /* The info dictionary. */
        if (b.p >= b.end || *b.p != 'd')
            return P2F_ERR_PROTO;
        b.p++;
        out->length = -1;
        while (b.p < b.end && *b.p != 'e') {
            if (b_str(&b, &k, &kn) != 0)
                return P2F_ERR_PROTO;
            if (key_is(k, kn, "piece length")) {
                if (b_int(&b, &out->piece_length) != 0)
                    return P2F_ERR_PROTO;
            } else if (key_is(k, kn, "length")) {
                if (b_int(&b, &out->length) != 0)
                    return P2F_ERR_PROTO;
            } else if (key_is(k, kn, "pieces")) {
                size_t pn;
                if (b_str(&b, &out->pieces, &pn) != 0 || pn % 20 != 0)
                    return P2F_ERR_PROTO;
                out->piece_count = pn / 20;
            } else if (key_is(k, kn, "files")) {
                return P2F_ERR_PROTO; /* multi-file torrents: not served */
            } else if (b_skip(&b, 0) != 0) {
                return P2F_ERR_PROTO;
            }
        }
        if (b.p >= b.end)
            return P2F_ERR_PROTO;
        b.p++;
        found_info = 1;
    }
    if (!found_info || out->piece_length <= 0 || out->length < 0 ||
        !out->pieces ||
        out->piece_count != (size_t)((out->length + out->piece_length - 1) /
                                     out->piece_length))
        return P2F_ERR_PROTO;
    return P2F_OK;
}

void p2f_torrent_piece(const p2f_torrent_layout *t, size_t index,
                       int64_t *start, size_t *size)
{
    int64_t s = (int64_t)index * t->piece_length;
    int64_t n = t->length - s;
    if (n > t->piece_length)
        n = t->piece_length;
    if (n < 0)
        n = 0;
    *start = s;
    *size = (size_t)n;
}

int p2f_ctr_xor_at(const uint8_t key[32], const uint8_t iv[16],
                   uint64_t offset, uint8_t *buf, size_t len)
{
    p2f_ctr ctr;
    uint8_t skip[16] = { 0 };
    size_t drop = (size_t)(offset % 16);
    int rc = p2f_ctr_init(&ctr, key, iv, offset / 16);
    if (rc != P2F_OK)
        return rc;
    if (drop)
        rc = p2f_ctr_update(&ctr, skip, drop);
    if (rc == P2F_OK)
        rc = p2f_ctr_update(&ctr, buf, len);
    p2f_ctr_free(&ctr);
    return rc;
}

int p2f_piece_matches(const p2f_torrent_layout *t, size_t index,
                      const uint8_t *cipher, size_t len)
{
    uint8_t digest[20];
    int64_t start;
    size_t size;
    if (index >= t->piece_count)
        return 0;
    p2f_torrent_piece(t, index, &start, &size);
    if (len != size)
        return 0;
    if (mbedtls_sha1(cipher, len, digest) != 0)
        return 0;
    return memcmp(digest, t->pieces + index * 20, 20) == 0;
}
