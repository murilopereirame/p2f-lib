/*
 * The client-side crypto of the peer-to-file protocol (p2f_crypto.c).
 * No network code: the WebAssembly build uses this header too.
 */
#ifndef P2F_CRYPTO_H
#define P2F_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "p2f.h"

#include "mbedtls/aes.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

/* Fill buf with secure random bytes (an app/platform hook, see
 * include/p2f_platform.h; declared here so the wasm build needs no
 * network headers). */
int p2f_platform_random(void *buf, size_t len);

/* ---- Crypto (p2f_crypto.c) -------------------------------------------- */

typedef struct {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    char pub_b64[128];  /* raw uncompressed point, Base64: the "ck" value */
} p2f_keypair;

int p2f_keypair_generate(p2f_keypair *kp);
void p2f_keypair_free(p2f_keypair *kp);

int p2f_unwrap_transfer_key(p2f_keypair *kp, const char *server_pub_b64,
                            const char *wrapped_b64,
                            uint8_t key[32], uint8_t iv[16]);

/* The CTR counter block_index blocks after iv (128-bit big-endian add). */
void p2f_ctr_counter(const uint8_t iv[16], uint64_t block_index,
                     uint8_t out[16]);

typedef struct {
    mbedtls_aes_context aes;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    size_t nc_off;
} p2f_ctr;

int p2f_ctr_init(p2f_ctr *ctr, const uint8_t key[32], const uint8_t iv[16],
                 uint64_t block_index);
/* Decrypt in place. */
int p2f_ctr_update(p2f_ctr *ctr, uint8_t *buf, size_t len);
void p2f_ctr_free(p2f_ctr *ctr);

/* ---- Repair (p2f_repair.c) -------------------------------------------- */

/* The piece layout of a single-file torrent. pieces points into the
 * buffer given to p2f_torrent_parse (20-byte SHA-1 of each piece of the
 * ciphertext), so that buffer must outlive the layout. */
typedef struct {
    int64_t piece_length;
    int64_t length;
    size_t piece_count;
    const uint8_t *pieces;
} p2f_torrent_layout;

/* Read the layout out of a .torrent file. P2F_ERR_PROTO if it is not a
 * single-file torrent whose piece count fits its length. */
int p2f_torrent_parse(const uint8_t *buf, size_t len, p2f_torrent_layout *out);

/* The byte offset and size of one piece. */
void p2f_torrent_piece(const p2f_torrent_layout *t, size_t index,
                       int64_t *start, size_t *size);

/* AES-256-CTR over buf, which sits at byte offset of the file (any offset,
 * not only a block boundary). Encrypt and decrypt are the same. In place. */
int p2f_ctr_xor_at(const uint8_t key[32], const uint8_t iv[16],
                   uint64_t offset, uint8_t *buf, size_t len);

/* 1 if this ciphertext is piece index (right size and SHA-1), else 0. */
int p2f_piece_matches(const p2f_torrent_layout *t, size_t index,
                      const uint8_t *cipher, size_t len);

#endif
