/* Platform layer for the WebAssembly build: random bytes from the host
 * (WASI random_get; the JavaScript loader maps it to
 * crypto.getRandomValues). No network, no clock. */
#include <unistd.h>

#include "p2f_crypto.h"

int p2f_platform_random(void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        size_t n = len > 256 ? 256 : len;  /* getentropy limit */
        if (getentropy(p, n) != 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}
