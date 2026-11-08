/*
 * A minimal DNS client: one A-record query over UDP (RFC 1035).
 * Used as a fallback on platforms where the system resolver fails.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "p2f_internal.h"

#define DNS_PORT 53
#define TYPE_A 1
#define CLASS_IN 1

/* Write host as DNS labels. Return the length, or -1 for a bad name. */
static int encode_name(const char *host, uint8_t *out, size_t max)
{
    size_t pos = 0;
    const char *p = host;
    if (!*host || strlen(host) > 253)
        return -1;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63 || pos + len + 2 > max)
            return -1;
        out[pos++] = (uint8_t)len;
        memcpy(out + pos, p, len);
        pos += len;
        p += len;
        if (*p == '.')
            p++;
    }
    out[pos++] = 0;
    return (int)pos;
}

/* Skip a (maybe compressed) name. Return the new offset, or -1. */
static int skip_name(const uint8_t *m, int len, int off)
{
    int hops = 0;
    while (off < len) {
        uint8_t b = m[off];
        if (b == 0)
            return off + 1;
        if ((b & 0xC0) == 0xC0)  /* pointer: the name ends here */
            return off + 2 <= len ? off + 2 : -1;
        if (b & 0xC0)
            return -1;
        off += 1 + b;
        if (++hops > 128)
            return -1;
    }
    return -1;
}

int p2f_dns_query_a(const char *server, uint16_t port, const char *host,
                    int timeout_ms, struct in_addr *out,
                    char *err, size_t errlen)
{
    struct sockaddr_in sa;
    struct timeval tv;
    uint8_t q[512], r[1500];
    uint16_t id;
    int fd, qlen, nlen, attempt;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port ? port : DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
        snprintf(err, errlen, "bad DNS server '%s'", server);
        return -1;
    }

    /* Header: id, RD flag, one question. */
    if (p2f_platform_random(&id, sizeof(id)) != 0)
        id = 0x5032;
    memset(q, 0, 12);
    q[0] = (uint8_t)(id >> 8);
    q[1] = (uint8_t)id;
    q[2] = 0x01;  /* RD */
    q[5] = 1;     /* QDCOUNT */
    nlen = encode_name(host, q + 12, sizeof(q) - 16);
    if (nlen < 0) {
        snprintf(err, errlen, "bad host name");
        return -1;
    }
    qlen = 12 + nlen;
    q[qlen++] = 0; q[qlen++] = TYPE_A;
    q[qlen++] = 0; q[qlen++] = CLASS_IN;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket failed (errno %d)", errno);
        return -1;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    snprintf(err, errlen, "no answer from %s", server);
    for (attempt = 0; attempt < 2; attempt++) {
        if (sendto(fd, q, (size_t)qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) != qlen) {
            snprintf(err, errlen, "send to %s failed (errno %d)", server, errno);
            break;
        }
        for (;;) {
            int i, off, n, ancount, rcode;
            ssize_t got = recvfrom(fd, r, sizeof(r), 0, NULL, NULL);
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                snprintf(err, errlen, "no answer from %s", server);
                break;  /* timeout: try again */
            }
            n = (int)got;
            if (n < 12 || r[0] != q[0] || r[1] != q[1] || !(r[2] & 0x80))
                continue;  /* not our reply */
            rcode = r[3] & 0x0F;
            if (rcode == 3) {
                snprintf(err, errlen, "%s: name does not exist (NXDOMAIN)", server);
                close(fd);
                return -1;
            }
            if (rcode != 0) {
                snprintf(err, errlen, "%s: DNS error code %d", server, rcode);
                close(fd);
                return -1;
            }
            ancount = (r[6] << 8) | r[7];
            off = 12;
            for (i = (r[4] << 8) | r[5]; i > 0 && off >= 0; i--) {  /* questions */
                off = skip_name(r, n, off);
                if (off >= 0)
                    off += 4;
            }
            for (i = 0; i < ancount && off >= 0 && off < n; i++) {  /* answers */
                int type, klass, rdlen;
                off = skip_name(r, n, off);
                if (off < 0 || off + 10 > n)
                    break;
                type = (r[off] << 8) | r[off + 1];
                klass = (r[off + 2] << 8) | r[off + 3];
                rdlen = (r[off + 8] << 8) | r[off + 9];
                off += 10;
                if (off + rdlen > n)
                    break;
                /* CNAME records come first; the A record follows. */
                if (type == TYPE_A && klass == CLASS_IN && rdlen == 4) {
                    memcpy(&out->s_addr, r + off, 4);
                    close(fd);
                    return 0;
                }
                off += rdlen;
            }
            snprintf(err, errlen, "%s: no IPv4 address for this name", server);
            close(fd);
            return -1;
        }
    }
    close(fd);
    return -1;
}

/* ---- Shared resolve step ------------------------------------------------
 * IPv4 literal -> cache -> DNS server set with p2f_set_dns_server()
 * -> the platform resolver (which may have its own fallbacks).
 */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define CACHE_SECONDS 300

static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;
static char dns_server[64];
static uint16_t dns_port;
static char cache_host[256];
static struct in_addr cache_addr;
static time_t cache_time;

int p2f_set_dns_server(const char *server)
{
    char ip[64];
    const char *colon;
    long port = 53;
    struct in_addr tmp;

    if (!server || !*server) {
        pthread_mutex_lock(&dns_lock);
        dns_server[0] = '\0';
        pthread_mutex_unlock(&dns_lock);
        return P2F_OK;
    }
    colon = strchr(server, ':');
    if (colon) {
        port = strtol(colon + 1, NULL, 10);
        if (port <= 0 || port > 65535 || (size_t)(colon - server) >= sizeof(ip))
            return P2F_ERR_ARG;
        memcpy(ip, server, (size_t)(colon - server));
        ip[colon - server] = '\0';
    } else {
        if (strlen(server) >= sizeof(ip))
            return P2F_ERR_ARG;
        strcpy(ip, server);
    }
    if (inet_pton(AF_INET, ip, &tmp) != 1)
        return P2F_ERR_ARG;
    pthread_mutex_lock(&dns_lock);
    strcpy(dns_server, ip);
    dns_port = (uint16_t)port;
    cache_host[0] = '\0';
    pthread_mutex_unlock(&dns_lock);
    return P2F_OK;
}

int p2f_resolve(const char *host, struct in_addr *out, char *err, size_t errlen)
{
    char server[64];
    uint16_t port;
    time_t now = time(NULL);

    err[0] = '\0';
    if (inet_pton(AF_INET, host, out) == 1)
        return 0;

    pthread_mutex_lock(&dns_lock);
    if (cache_host[0] && strcmp(cache_host, host) == 0 &&
        now - cache_time < CACHE_SECONDS) {
        *out = cache_addr;
        pthread_mutex_unlock(&dns_lock);
        return 0;
    }
    strcpy(server, dns_server);
    port = dns_port;
    pthread_mutex_unlock(&dns_lock);

    if (server[0]) {
        if (p2f_dns_query_a(server, port, host, 3000, out, err, errlen) != 0)
            return -1;  /* an explicit DNS server: do not fall back */
    } else if (p2f_platform_resolve(host, out, err, errlen) != 0) {
        return -1;
    }

    pthread_mutex_lock(&dns_lock);
    if (strlen(host) < sizeof(cache_host)) {
        strcpy(cache_host, host);
        cache_addr = *out;
        cache_time = now;
    }
    pthread_mutex_unlock(&dns_lock);
    return 0;
}
