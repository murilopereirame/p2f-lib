/* mbedTLS for the WebAssembly build: only the crypto of the protocol.
 * P-256 ECDH, HKDF-SHA256, AES-256-GCM, AES-256-CTR, SHA-256, Base64, and
 * SHA-1 for the torrent piece hashes (repair). */
#ifndef P2F_MBEDTLS_CONFIG_WASM_H
#define P2F_MBEDTLS_CONFIG_WASM_H

#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C      /* torrent piece hashes (repair) */
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_BASE64_C

#endif
