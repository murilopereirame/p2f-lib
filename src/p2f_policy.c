/*
 * Shared policy: pure functions with no I/O. The C download and the
 * JavaScript package (through the WebAssembly build) both call these, so
 * a fix here reaches every client.
 */
#include "p2f.h"

#ifndef P2F_VERSION
#define P2F_VERSION "0.0.0-dev"
#endif

const char *p2f_version(void)
{
    return P2F_VERSION;
}

p2f_resume_plan p2f_plan_resume(int64_t existing, int64_t size)
{
    p2f_resume_plan p;
    if (existing == size) {
        p.skip = 1;
        p.start = size;
        p.append = 0;
    } else if (existing > size || existing < 0) {
        /* The local file is bad. Write it again from the start. */
        p.skip = 0;
        p.start = 0;
        p.append = 0;
    } else {
        p.skip = 0;
        p.start = existing;
        p.append = existing > 0;
    }
    return p;
}

#define BACKOFF_BASE_MS 2000
#define BACKOFF_MAX_MS 30000
#define POLL_MS 2000
#define POLL_MIN_MS 500
#define POLL_MAX_MS 10000
#define RETRY_AFTER_MAX_MS 60000
/* A 404 that is not from the server: retry this many times, then stop. */
#define FOREIGN_404_TRIES 5

static int backoff(int attempt, int retry_after_ms)
{
    int ms = BACKOFF_BASE_MS, i;
    for (i = 1; i < attempt && ms < BACKOFF_MAX_MS; i++)
        ms *= 2;
    if (ms > BACKOFF_MAX_MS)
        ms = BACKOFF_MAX_MS;
    if (retry_after_ms > ms)
        ms = retry_after_ms > RETRY_AFTER_MAX_MS ? RETRY_AFTER_MAX_MS
                                                 : retry_after_ms;
    return ms;
}

int p2f_retry_delay_ms(int status, int from_p2f, int attempt,
                       int retry_after_ms)
{
    if (attempt < 1)
        attempt = 1;
    switch (status) {
    case 202: /* still preparing: poll at a steady pace */
        if (retry_after_ms <= 0)
            return POLL_MS;
        if (retry_after_ms < POLL_MIN_MS)
            return POLL_MIN_MS;
        return retry_after_ms > POLL_MAX_MS ? POLL_MAX_MS : retry_after_ms;
    case 0:   /* network error or timeout */
    case 408: case 425: case 429:
    case 500: case 502: case 503: case 504:
    case 520: case 521: case 522: case 523: case 524:
        return backoff(attempt, retry_after_ms);
    case 404:
        if (!from_p2f && attempt <= FOREIGN_404_TRIES)
            return backoff(attempt, retry_after_ms);
        return -1;
    default:
        return -1;
    }
}
