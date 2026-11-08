/* The TLS client configuration of a p2f client (HTTPS). */
#include <stdio.h>
#include <string.h>

#include "p2f_internal.h"

extern const char p2f_ca_bundle[];
extern const size_t p2f_ca_bundle_len;

static int drbg_entropy(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return p2f_platform_random(out, len) == 0 ? 0 : -1;
}

void p2f_tls_init(p2f_client *c)
{
    mbedtls_ssl_config_init(&c->ssl_conf);
    mbedtls_x509_crt_init(&c->ca);
    mbedtls_ctr_drbg_init(&c->drbg);
    mbedtls_ssl_session_init(&c->session);
    c->tls_ready = 0;
    c->have_session = 0;
}

void p2f_tls_free(p2f_client *c)
{
    mbedtls_ssl_session_free(&c->session);
    mbedtls_ssl_config_free(&c->ssl_conf);
    mbedtls_x509_crt_free(&c->ca);
    mbedtls_ctr_drbg_free(&c->drbg);
    c->tls_ready = 0;
    c->have_session = 0;
}

int p2f_tls_setup(p2f_client *c)
{
    static const char pers[] = "p2f-tls";
    int rc;

    if (c->tls_ready)
        return P2F_OK;

    rc = mbedtls_ctr_drbg_seed(&c->drbg, drbg_entropy, NULL,
                               (const unsigned char *)pers, sizeof(pers) - 1);
    if (rc != 0)
        return p2f_fail(c, P2F_ERR_TLS, "TLS: random seed failed (-0x%04x)", -rc);

    if (c->ca_file) {
        rc = mbedtls_x509_crt_parse_file(&c->ca, c->ca_file);
        if (rc < 0)
            return p2f_fail(c, P2F_ERR_TLS, "TLS: cannot read CA file %s (-0x%04x)",
                            c->ca_file, -rc);
    } else {
        /* rc > 0 is the number of certificates that did not parse (for
         * example, unsupported algorithms). The rest are still usable. */
        rc = mbedtls_x509_crt_parse(&c->ca, (const unsigned char *)p2f_ca_bundle,
                                    p2f_ca_bundle_len);
        if (rc < 0)
            return p2f_fail(c, P2F_ERR_TLS, "TLS: built-in CA bundle failed (-0x%04x)",
                            -rc);
    }
    if (c->ca.raw.len == 0)
        return p2f_fail(c, P2F_ERR_TLS, "TLS: no CA certificates loaded");

    rc = mbedtls_ssl_config_defaults(&c->ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0)
        return p2f_fail(c, P2F_ERR_TLS, "TLS: config failed (-0x%04x)", -rc);

    mbedtls_ssl_conf_authmode(&c->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c->ssl_conf, &c->ca, NULL);
    mbedtls_ssl_conf_rng(&c->ssl_conf, mbedtls_ctr_drbg_random, &c->drbg);

    c->tls_ready = 1;
    return P2F_OK;
}
