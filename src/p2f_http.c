/*
 * A small HTTP/1.1 GET client over BSD sockets. One request per
 * connection ("Connection: close"). Supports Content-Length, chunked
 * transfer encoding and read-until-close bodies.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "p2f_internal.h"

#include "mbedtls/net_sockets.h"  /* only for the MBEDTLS_ERR_NET_* codes */

#define USER_AGENT "p2f-c/0.2"

int p2f_fail(p2f_client *c, int code, const char *fmt, ...)
{
    va_list ap;
    if (c) {
        va_start(ap, fmt);
        vsnprintf(c->err, sizeof(c->err), fmt, ap);
        va_end(ap);
    }
    return code;
}

char *p2f_urlencode(const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = strlen(s);
    char *out = malloc(n * 3 + 1), *p = out;
    if (!out)
        return NULL;
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (isalnum(ch) || strchr("-_.!~*'()", ch)) {
            *p++ = (char)ch;
        } else {
            *p++ = '%';
            *p++ = hex[ch >> 4];
            *p++ = hex[ch & 15];
        }
    }
    *p = '\0';
    return out;
}

static void set_timeout(int fd, int ms)
{
    struct timeval tv;
    if (ms <= 0)
        return;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* A write to a socket the server closed raises SIGPIPE, which ends the app
 * on Android and iOS. Linux (and Android) take a per-call flag; Apple
 * systems a socket option (set in connect below). */
#if defined(__linux__)
#define P2F_SEND_FLAGS MSG_NOSIGNAL
#else
#define P2F_SEND_FLAGS 0
#endif

/* ---- Socket I/O for mbedTLS (blocking socket with timeouts) ----------- */

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n;
    do {
        n = send(fd, buf, len, P2F_SEND_FLAGS);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        return (errno == EPIPE || errno == ECONNRESET)
                   ? MBEDTLS_ERR_NET_CONN_RESET : MBEDTLS_ERR_NET_SEND_FAILED;
    return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n;
    do {
        n = recv(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        return errno == ECONNRESET ? MBEDTLS_ERR_NET_CONN_RESET
                                   : MBEDTLS_ERR_NET_RECV_FAILED;
    return (int)n;  /* 0 = the peer closed the TCP connection */
}

static int send_all(p2f_http *h, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n;
        if (h->ssl) {
            int r = mbedtls_ssl_write(h->ssl, (const unsigned char *)buf, len);
            if (r == MBEDTLS_ERR_SSL_WANT_WRITE || r == MBEDTLS_ERR_SSL_WANT_READ)
                continue;
            n = r;
        } else {
            n = send(h->fd, buf, len, P2F_SEND_FLAGS);
            if (n < 0 && errno == EINTR)
                continue;
        }
        if (n <= 0)
            return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Read from the connection. Return bytes, 0 at EOF, <0 on error. */
static ssize_t conn_recv(p2f_http *h, void *buf, size_t len)
{
    ssize_t n;
    if (h->ssl) {
        int r;
        do {
            r = mbedtls_ssl_read(h->ssl, buf, len);
        } while (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_SSL_CONN_EOF)
            return 0;  /* a short body is caught by the length checks */
        return r;
    }
    do {
        n = recv(h->fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);
    return n;
}

/* TLS handshake on the connected socket h->fd. */
static int tls_connect(p2f_client *c, p2f_http *h)
{
    int rc = p2f_tls_setup(c);
    if (rc != P2F_OK)
        return rc;

    h->ssl = malloc(sizeof(*h->ssl));
    if (!h->ssl)
        return P2F_ERR_NOMEM;
    mbedtls_ssl_init(h->ssl);
    rc = mbedtls_ssl_setup(h->ssl, &c->ssl_conf);
    if (rc == 0)
        rc = mbedtls_ssl_set_hostname(h->ssl, c->host);  /* SNI + name check */
    if (rc != 0)
        return p2f_fail(c, P2F_ERR_TLS, "TLS: setup failed (-0x%04x)", -rc);
    mbedtls_ssl_set_bio(h->ssl, &h->fd, bio_send, bio_recv, NULL);
    if (c->have_session)
        mbedtls_ssl_set_session(h->ssl, &c->session);  /* resume: faster */

    do {
        rc = mbedtls_ssl_handshake(h->ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (rc != 0) {
        uint32_t flags = mbedtls_ssl_get_verify_result(h->ssl);
        if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags != 0 &&
            flags != (uint32_t)-1) {
            char info[256];
            char *p;
            mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
            for (p = info; *p; p++)  /* one line */
                if (*p == '\n')
                    *p = (p[1] ? ';' : '\0');
            return p2f_fail(c, P2F_ERR_TLS,
                            "TLS: certificate of %s not trusted:%s%s", c->host,
                            info,
                            (flags & (MBEDTLS_X509_BADCERT_EXPIRED |
                                      MBEDTLS_X509_BADCERT_FUTURE))
                                ? " (check the console date and time)" : "");
        }
        /* A dropped connection during the handshake: retry later. */
        if (rc == MBEDTLS_ERR_NET_RECV_FAILED || rc == MBEDTLS_ERR_NET_SEND_FAILED ||
            rc == MBEDTLS_ERR_NET_CONN_RESET || rc == MBEDTLS_ERR_SSL_CONN_EOF)
            return p2f_fail(c, P2F_ERR_NET, "TLS: connection lost in handshake");
        c->have_session = 0;
        return p2f_fail(c, P2F_ERR_TLS, "TLS: handshake with %s failed (-0x%04x)",
                        c->host, -rc);
    }

    /* Keep the session for the next connection. */
    mbedtls_ssl_session_free(&c->session);
    mbedtls_ssl_session_init(&c->session);
    c->have_session = mbedtls_ssl_get_session(h->ssl, &c->session) == 0;
    return P2F_OK;
}

/* Fill the buffer from the socket. Return bytes read, 0 at EOF, <0 error. */
static ssize_t fill(p2f_http *h)
{
    ssize_t n;
    if (h->pos > 0 && h->pos < h->len) {
        memmove(h->buf, h->buf + h->pos, h->len - h->pos);
        h->len -= h->pos;
        h->pos = 0;
    } else if (h->pos >= h->len) {
        h->pos = h->len = 0;
    }
    if (h->len >= sizeof(h->buf))
        return -1;
    n = conn_recv(h, h->buf + h->len, sizeof(h->buf) - h->len);
    if (n > 0)
        h->len += (size_t)n;
    return n;
}

/* Read one CRLF-terminated line from the buffer. */
static int read_line(p2f_http *h, char *line, size_t max)
{
    for (;;) {
        char *start = h->buf + h->pos;
        char *nl = memchr(start, '\n', h->len - h->pos);
        if (nl) {
            size_t n = (size_t)(nl - start);
            if (n > 0 && start[n - 1] == '\r')
                n--;
            if (n >= max)
                return -1;
            memcpy(line, start, n);
            line[n] = '\0';
            h->pos += (size_t)(nl - start) + 1;
            return 0;
        }
        if (fill(h) <= 0)
            return -1;
    }
}

int p2f_http_get(p2f_client *c, const char *path_query, int64_t range_start,
                 int timeout_ms, p2f_http *h)
{
    struct sockaddr_in addr;
    char req[4096], line[2048];
    int one = 1, n;

    memset(h, 0, sizeof(*h));
    h->fd = -1;
    h->content_length = -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(c->port);
    {
        char why[256];
        if (p2f_resolve(c->host, &addr.sin_addr, why, sizeof(why)) != 0)
            return p2f_fail(c, P2F_ERR_NET, "cannot resolve host '%s'%s%s%s",
                            c->host, why[0] ? " (" : "", why, why[0] ? ")" : "");
    }

    h->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (h->fd < 0)
        return p2f_fail(c, P2F_ERR_NET, "socket failed (errno %d)", errno);
    set_timeout(h->fd, timeout_ms);
    setsockopt(h->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#if defined(__APPLE__) && defined(SO_NOSIGPIPE)
    setsockopt(h->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    if (connect(h->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int e = errno;
        p2f_http_close(h);
        return p2f_fail(c, P2F_ERR_NET, "cannot connect to %s:%u (errno %d)",
                        c->host, c->port, e);
    }
    if (c->tls) {
        int rc = tls_connect(c, h);
        if (rc != P2F_OK) {
            p2f_http_close(h);
            return rc;
        }
    }

    n = snprintf(req, sizeof(req),
                 "GET %s%s HTTP/1.1\r\n"
                 "Host: %s:%u\r\n"
                 "Authorization: Bearer %s\r\n"
                 "User-Agent: " USER_AGENT "\r\n"
                 "Accept-Encoding: identity\r\n"
                 "Connection: close\r\n",
                 c->base_path, path_query, c->host, c->port, c->token);
    if (n > 0 && range_start > 0 && (size_t)n < sizeof(req))
        n += snprintf(req + n, sizeof(req) - (size_t)n,
                      "Range: bytes=%lld-\r\n", (long long)range_start);
    if (n > 0 && (size_t)n < sizeof(req))
        n += snprintf(req + n, sizeof(req) - (size_t)n, "\r\n");
    if (n <= 0 || (size_t)n >= sizeof(req)) {
        p2f_http_close(h);
        return p2f_fail(c, P2F_ERR_ARG, "request too long");
    }
    if (send_all(h, req, (size_t)n) != 0) {
        p2f_http_close(h);
        return p2f_fail(c, P2F_ERR_NET, "send failed (errno %d)", errno);
    }

    /* Status line. */
    if (read_line(h, line, sizeof(line)) != 0 ||
        sscanf(line, "HTTP/%*d.%*d %d", &h->status) != 1) {
        p2f_http_close(h);
        return p2f_fail(c, P2F_ERR_NET, "no valid HTTP response");
    }

    /* Headers. */
    for (;;) {
        char *colon, *val;
        if (read_line(h, line, sizeof(line)) != 0) {
            p2f_http_close(h);
            return p2f_fail(c, P2F_ERR_NET, "truncated HTTP headers");
        }
        if (line[0] == '\0')
            break;
        colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';
        val = colon + 1;
        while (*val == ' ' || *val == '\t')
            val++;
        if (strcasecmp(line, "Content-Length") == 0)
            h->content_length = strtoll(val, NULL, 10);
        else if (strcasecmp(line, "Transfer-Encoding") == 0 &&
                 strstr(val, "chunked"))
            h->chunked = 1;
        else if (strcasecmp(line, "Retry-After") == 0) {
            /* Only the delay-seconds form; an HTTP date is ignored. */
            long sec = strtol(val, NULL, 10);
            if (sec > 0 && sec < 3600)
                h->retry_after_ms = (int)sec * 1000;
        }
    }

    if (h->chunked)
        h->left = 0;  /* read the first chunk size on demand */
    else if (h->content_length >= 0)
        h->left = h->content_length;
    else
        h->left = -1; /* until close */
    if (h->status == 204 || h->status == 304 || h->content_length == 0)
        h->eof = 1;
    return P2F_OK;
}

ssize_t p2f_http_read(p2f_http *h, void *out, size_t n)
{
    size_t avail, take;

    if (h->eof || n == 0)
        return 0;

    if (h->chunked && h->left == 0) {
        char line[128];
        /* After a chunk's data comes a CRLF; skip it (not for the first). */
        if (read_line(h, line, sizeof(line)) != 0)
            return -1;
        if (line[0] == '\0' && read_line(h, line, sizeof(line)) != 0)
            return -1;
        h->left = strtoll(line, NULL, 16);
        if (h->left < 0)
            return -1;
        if (h->left == 0) {
            /* Trailers until an empty line. */
            do {
                if (read_line(h, line, sizeof(line)) != 0)
                    break;
            } while (line[0] != '\0');
            h->eof = 1;
            return 0;
        }
    }

    if (h->pos >= h->len) {
        ssize_t r = fill(h);
        if (r < 0)
            return -1;
        if (r == 0) {
            /* EOF: fine only for a read-until-close body. */
            if (!h->chunked && h->left < 0) {
                h->eof = 1;
                return 0;
            }
            return -1;
        }
    }

    avail = h->len - h->pos;
    take = n < avail ? n : avail;
    if (h->left >= 0 && (int64_t)take > h->left)
        take = (size_t)h->left;
    memcpy(out, h->buf + h->pos, take);
    h->pos += take;
    if (h->left >= 0) {
        h->left -= (int64_t)take;
        if (!h->chunked && h->left == 0)
            h->eof = 1;
    }
    return (ssize_t)take;
}

int p2f_http_read_all(p2f_http *h, char **out, size_t *len, size_t max)
{
    size_t cap = 4096, used = 0;
    char *buf = malloc(cap + 1);
    if (!buf)
        return P2F_ERR_NOMEM;
    for (;;) {
        ssize_t r;
        if (used == cap) {
            char *nb;
            if (cap >= max) {
                free(buf);
                return P2F_ERR_PROTO;
            }
            cap *= 2;
            nb = realloc(buf, cap + 1);
            if (!nb) {
                free(buf);
                return P2F_ERR_NOMEM;
            }
            buf = nb;
        }
        r = p2f_http_read(h, buf + used, cap - used);
        if (r < 0) {
            free(buf);
            return P2F_ERR_NET;
        }
        if (r == 0)
            break;
        used += (size_t)r;
    }
    buf[used] = '\0';
    *out = buf;
    if (len)
        *len = used;
    return P2F_OK;
}

void p2f_http_close(p2f_http *h)
{
    if (h->ssl) {
        mbedtls_ssl_free(h->ssl);
        free(h->ssl);
        h->ssl = NULL;
    }
    if (h->fd >= 0)
        close(h->fd);
    h->fd = -1;
}
