/*
 * Minimal mbedTLS configuration for p2f.
 *
 * Protocol crypto: ECDH P-256, HKDF-SHA256, AES-256-GCM (key unwrap),
 *                  AES-256-CTR (file decrypt), SHA-256 (verify), Base64.
 * Transport:       a TLS 1.2 client (ECDHE with RSA or ECDSA certificates,
 *                  AES-GCM or ChaCha20-Poly1305) with certificate checks.
 */
#ifndef P2F_MBEDTLS_CONFIG_H
#define P2F_MBEDTLS_CONFIG_H

/* x86-64 assembly and AES-NI. The PS4 Jaguar CPU has AES-NI. */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_AESNI_C

/* Time: needed to check certificate validity dates. */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* ---- Symmetric ---------------------------------------------------------- */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* ---- Hashes ------------------------------------------------------------- */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C      /* only for old certificate chains */
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_HKDF_C

/* ---- Public key --------------------------------------------------------- */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* ---- Encodings and certificates ---------------------------------------- */
#define MBEDTLS_BASE64_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_FS_IO       /* load a custom CA file */

/* ---- Random (seeded from the platform layer, no entropy module) ------- */
#define MBEDTLS_CTR_DRBG_C

/* ---- TLS client --------------------------------------------------------- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

#endif
