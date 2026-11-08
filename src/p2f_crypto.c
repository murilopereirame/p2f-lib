/*
 * The client-side crypto of the peer-to-file protocol, on mbedTLS.
 * Byte-identical to p2f-lib src/crypto.ts:
 *   ECDH P-256 -> HKDF-SHA256 (empty salt, info "p2f-key-wrap") -> 32 bytes
 *   AES-256-GCM unwrap: blob = nonce(12) || ciphertext || tag(16)
 *   plaintext = key(32) || iv(16)
 *   AES-256-CTR with a full 128-bit big-endian counter
 */
#include <string.h>

#include "p2f_crypto.h"

#include "mbedtls/base64.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#define HKDF_INFO "p2f-key-wrap"
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return p2f_platform_random(out, len) == 0 ? 0 : -1;
}

int p2f_keypair_generate(p2f_keypair *kp)
{
    unsigned char pub[65];
    size_t pub_len = 0, b64_len = 0;
    int rc;

    mbedtls_ecp_group_init(&kp->grp);
    mbedtls_mpi_init(&kp->d);
    mbedtls_ecp_point_init(&kp->Q);
    kp->pub_b64[0] = '\0';

    rc = mbedtls_ecp_group_load(&kp->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0)
        rc = mbedtls_ecdh_gen_public(&kp->grp, &kp->d, &kp->Q, rng, NULL);
    if (rc == 0)
        rc = mbedtls_ecp_point_write_binary(&kp->grp, &kp->Q,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &pub_len, pub, sizeof(pub));
    if (rc == 0)
        rc = mbedtls_base64_encode((unsigned char *)kp->pub_b64,
                                   sizeof(kp->pub_b64), &b64_len,
                                   pub, pub_len);
    if (rc != 0) {
        p2f_keypair_free(kp);
        return P2F_ERR_CRYPTO;
    }
    return P2F_OK;
}

void p2f_keypair_free(p2f_keypair *kp)
{
    mbedtls_ecp_group_free(&kp->grp);
    mbedtls_mpi_free(&kp->d);
    mbedtls_ecp_point_free(&kp->Q);
}

/* ECDH(client, server) -> HKDF-SHA256 -> the 32-byte wrap key. */
static int derive_wrap_key(p2f_keypair *kp, const char *server_pub_b64,
                           uint8_t wrap_key[32])
{
    unsigned char server_pub[133];
    unsigned char shared[32];
    size_t server_pub_len = 0;
    mbedtls_ecp_point peer;
    mbedtls_mpi z;
    int rc;

    if (mbedtls_base64_decode(server_pub, sizeof(server_pub), &server_pub_len,
                              (const unsigned char *)server_pub_b64,
                              strlen(server_pub_b64)) != 0)
        return P2F_ERR_CRYPTO;

    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&z);

    rc = mbedtls_ecp_point_read_binary(&kp->grp, &peer, server_pub,
                                       server_pub_len);
    if (rc == 0)
        rc = mbedtls_ecp_check_pubkey(&kp->grp, &peer);
    if (rc == 0)
        rc = mbedtls_ecdh_compute_shared(&kp->grp, &z, &peer, &kp->d, rng,
                                         NULL);
    /* Node's computeSecret returns the x coordinate, 32 bytes big-endian. */
    if (rc == 0)
        rc = mbedtls_mpi_write_binary(&z, shared, sizeof(shared));
    if (rc == 0)
        rc = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                          NULL, 0, shared, sizeof(shared),
                          (const unsigned char *)HKDF_INFO,
                          strlen(HKDF_INFO), wrap_key, 32);

    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&z);
    return rc == 0 ? P2F_OK : P2F_ERR_CRYPTO;
}

int p2f_unwrap_transfer_key(p2f_keypair *kp, const char *server_pub_b64,
                            const char *wrapped_b64,
                            uint8_t key[32], uint8_t iv[16])
{
    uint8_t wrap_key[32];
    unsigned char blob[256];
    unsigned char material[256];
    size_t blob_len = 0, ct_len;
    mbedtls_gcm_context gcm;
    int rc;

    if (mbedtls_base64_decode(blob, sizeof(blob), &blob_len,
                              (const unsigned char *)wrapped_b64,
                              strlen(wrapped_b64)) != 0)
        return P2F_ERR_CRYPTO;
    if (blob_len < GCM_NONCE_LEN + GCM_TAG_LEN)
        return P2F_ERR_CRYPTO;
    ct_len = blob_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (ct_len < 48)
        return P2F_ERR_CRYPTO;

    rc = derive_wrap_key(kp, server_pub_b64, wrap_key);
    if (rc != P2F_OK)
        return rc;

    mbedtls_gcm_init(&gcm);
    rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, wrap_key, 256);
    if (rc == 0)
        rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len,
                                      blob, GCM_NONCE_LEN,   /* nonce */
                                      NULL, 0,               /* no AAD */
                                      blob + blob_len - GCM_TAG_LEN,
                                      GCM_TAG_LEN,
                                      blob + GCM_NONCE_LEN, material);
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(wrap_key, sizeof(wrap_key));
    if (rc != 0)
        return P2F_ERR_CRYPTO;

    memcpy(key, material, 32);
    memcpy(iv, material + 32, 16);
    mbedtls_platform_zeroize(material, sizeof(material));
    return P2F_OK;
}

void p2f_ctr_counter(const uint8_t iv[16], uint64_t block_index,
                     uint8_t out[16])
{
    unsigned carry = 0;
    int i;

    memcpy(out, iv, 16);
    for (i = 15; i >= 0; i--) {
        unsigned sum = (unsigned)out[i] + (unsigned)(block_index & 0xff) + carry;
        out[i] = (uint8_t)sum;
        carry = sum >> 8;
        block_index >>= 8;
        if (block_index == 0 && carry == 0)
            break;
    }
}

int p2f_ctr_init(p2f_ctr *ctr, const uint8_t key[32], const uint8_t iv[16],
                 uint64_t block_index)
{
    mbedtls_aes_init(&ctr->aes);
    if (mbedtls_aes_setkey_enc(&ctr->aes, key, 256) != 0) {
        mbedtls_aes_free(&ctr->aes);
        return P2F_ERR_CRYPTO;
    }
    p2f_ctr_counter(iv, block_index, ctr->nonce_counter);
    memset(ctr->stream_block, 0, sizeof(ctr->stream_block));
    ctr->nc_off = 0;
    return P2F_OK;
}

int p2f_ctr_update(p2f_ctr *ctr, uint8_t *buf, size_t len)
{
    return mbedtls_aes_crypt_ctr(&ctr->aes, len, &ctr->nc_off,
                                 ctr->nonce_counter, ctr->stream_block,
                                 buf, buf) == 0 ? P2F_OK : P2F_ERR_CRYPTO;
}

void p2f_ctr_free(p2f_ctr *ctr)
{
    mbedtls_aes_free(&ctr->aes);
    mbedtls_platform_zeroize(ctr, sizeof(*ctr));
}
