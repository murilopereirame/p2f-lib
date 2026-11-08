/*
 * The WebAssembly exports used by the JavaScript package (js/src/core.ts).
 * Pointers are offsets into the module memory; the JavaScript side copies
 * data in and out. Sizes up to 2^53 travel as doubles (JavaScript numbers).
 */
#include <stdlib.h>
#include <string.h>

#include "p2f_crypto.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#define EXPORT(name) __attribute__((export_name(#name)))

EXPORT(p2f_alloc) void *wasm_alloc(size_t n)
{
    return malloc(n ? n : 1);
}

EXPORT(p2f_free) void wasm_free(void *p)
{
    free(p);
}

EXPORT(p2f_version) const char *wasm_version(void)
{
    return p2f_version();
}

/* ---- Policy ----------------------------------------------------------- */

EXPORT(p2f_retry_delay_ms) int wasm_retry_delay_ms(int status, int from_p2f,
                                                   int attempt, int retry_after_ms)
{
    return p2f_retry_delay_ms(status, from_p2f, attempt, retry_after_ms);
}

/* out[0] = skip, out[1] = start, out[2] = append */
EXPORT(p2f_plan_resume) void wasm_plan_resume(double existing, double size,
                                              double *out)
{
    p2f_resume_plan p = p2f_plan_resume((int64_t)existing, (int64_t)size);
    out[0] = p.skip;
    out[1] = (double)p.start;
    out[2] = p.append;
}

/* ---- Key exchange ----------------------------------------------------- */

EXPORT(p2f_keypair_new) p2f_keypair *wasm_keypair_new(void)
{
    p2f_keypair *kp = malloc(sizeof(*kp));
    if (!kp)
        return NULL;
    if (p2f_keypair_generate(kp) != P2F_OK) {
        free(kp);
        return NULL;
    }
    return kp;
}

/* The public key, Base64, NUL-terminated (the "ck" request value). */
EXPORT(p2f_keypair_public) const char *wasm_keypair_public(p2f_keypair *kp)
{
    return kp->pub_b64;
}

EXPORT(p2f_keypair_free) void wasm_keypair_free(p2f_keypair *kp)
{
    if (!kp)
        return;
    p2f_keypair_free(kp);
    mbedtls_platform_zeroize(kp, sizeof(*kp));
    free(kp);
}

/* out: key(32) || iv(16). Return 0 or P2F_ERR_CRYPTO. */
EXPORT(p2f_unwrap) int wasm_unwrap(p2f_keypair *kp, const char *server_pub_b64,
                                   const char *wrapped_b64, uint8_t *out)
{
    return p2f_unwrap_transfer_key(kp, server_pub_b64, wrapped_b64, out,
                                   out + 32);
}

/* ---- AES-256-CTR ------------------------------------------------------ */

EXPORT(p2f_ctr_new) p2f_ctr *wasm_ctr_new(const uint8_t *key, const uint8_t *iv,
                                          uint64_t block_index)
{
    p2f_ctr *ctr = malloc(sizeof(*ctr));
    if (!ctr)
        return NULL;
    if (p2f_ctr_init(ctr, key, iv, block_index) != P2F_OK) {
        free(ctr);
        return NULL;
    }
    return ctr;
}

/* XOR the keystream into buf, in place. */
EXPORT(p2f_ctr_update) int wasm_ctr_update(p2f_ctr *ctr, uint8_t *buf, size_t len)
{
    return p2f_ctr_update(ctr, buf, len);
}

EXPORT(p2f_ctr_free) void wasm_ctr_free(p2f_ctr *ctr)
{
    if (!ctr)
        return;
    p2f_ctr_free(ctr);
    free(ctr);
}

/* ---- SHA-256 ---------------------------------------------------------- */

EXPORT(p2f_sha256_new) mbedtls_sha256_context *wasm_sha256_new(void)
{
    mbedtls_sha256_context *h = malloc(sizeof(*h));
    if (!h)
        return NULL;
    mbedtls_sha256_init(h);
    mbedtls_sha256_starts(h, 0);
    return h;
}

EXPORT(p2f_sha256_update) void wasm_sha256_update(mbedtls_sha256_context *h,
                                                  const uint8_t *buf, size_t len)
{
    mbedtls_sha256_update(h, buf, len);
}

/* Write the 32-byte digest and free the context. */
EXPORT(p2f_sha256_final) void wasm_sha256_final(mbedtls_sha256_context *h,
                                                uint8_t *out)
{
    mbedtls_sha256_finish(h, out);
    mbedtls_sha256_free(h);
    free(h);
}

/* ---- Repair ----------------------------------------------------------- */

typedef struct {
    p2f_torrent_layout t;
    uint8_t *buf;  /* the .torrent; t.pieces points into it */
} wasm_torrent;

/* Parse a .torrent (copied). NULL if it is not a usable single-file one. */
EXPORT(p2f_torrent_new) wasm_torrent *wasm_torrent_new(const uint8_t *buf, size_t len)
{
    wasm_torrent *w = malloc(sizeof(*w));
    if (!w)
        return NULL;
    w->buf = malloc(len ? len : 1);
    if (!w->buf) {
        free(w);
        return NULL;
    }
    memcpy(w->buf, buf, len);
    if (p2f_torrent_parse(w->buf, len, &w->t) != P2F_OK) {
        free(w->buf);
        free(w);
        return NULL;
    }
    return w;
}

/* out[0] = piece length, out[1] = length, out[2] = piece count */
EXPORT(p2f_torrent_info) void wasm_torrent_info(const wasm_torrent *w, double *out)
{
    out[0] = (double)w->t.piece_length;
    out[1] = (double)w->t.length;
    out[2] = (double)w->t.piece_count;
}

EXPORT(p2f_torrent_free) void wasm_torrent_free(wasm_torrent *w)
{
    if (!w)
        return;
    free(w->buf);
    free(w);
}

/* 1 if this ciphertext is piece index, else 0. */
EXPORT(p2f_piece_matches) int wasm_piece_matches(const wasm_torrent *w, double index,
                                                 const uint8_t *cipher, size_t len)
{
    return p2f_piece_matches(&w->t, (size_t)index, cipher, len);
}

/* AES-256-CTR, in place, for bytes that sit at offset of the file. */
EXPORT(p2f_ctr_xor_at) int wasm_ctr_xor_at(const uint8_t *key, const uint8_t *iv,
                                           double offset, uint8_t *buf, size_t len)
{
    return p2f_ctr_xor_at(key, iv, (uint64_t)offset, buf, len);
}
