/*
 * The platform hooks of p2f-lib. The library calls these and does not
 * define them for any console or device: each app (or src/platform/posix.c
 * for desktop builds) provides them. The PS4 ones live in the P2PS repo.
 */
#ifndef P2F_PLATFORM_H
#define P2F_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Provided by the app ---------------------------------------------- */

/* Fill buf with secure random bytes. Return 0 on success. */
int p2f_platform_random(void *buf, size_t len);

/* Resolve a host name to an IPv4 address with the system resolver.
 * Return 0 on success; on failure write the reason to err (may be empty).
 * (IP literals, the DNS override and the cache are handled before this.) */
int p2f_platform_resolve(const char *host, struct in_addr *out,
                         char *err, size_t errlen);

/* Sleep. */
void p2f_platform_sleep_ms(int ms);

/* A monotonic clock in ms (any start point). */
uint64_t p2f_platform_now_ms(void);

/* ---- Provided by the library, for platform code ------------------------ */

/* One DNS A-record query over UDP to server:port. Return 0 on success.
 * Useful as a fallback when the system resolver is unreliable. */
int p2f_dns_query_a(const char *server, uint16_t port, const char *host,
                    int timeout_ms, struct in_addr *out,
                    char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif
