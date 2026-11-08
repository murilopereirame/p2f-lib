/*
 * Platform layer for the PS4 (OpenOrbis toolchain).
 *   random:  FreeBSD sysctl kern.arandom (the PS4 kernel is FreeBSD 9)
 *   resolve: 1. the system resolver (libSceNet: init, pool, resolver)
 *            2. fallback: a direct DNS query to the DNS servers in the
 *               PS4 network settings (libSceNetCtl)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "p2f_internal.h"

/* libkernel exports sysctl; the SDK has no sys/sysctl.h. */
int sysctl(const int *name, unsigned int namelen, void *oldp, size_t *oldlenp,
           const void *newp, size_t newlen);
#define CTL_KERN 1
#define KERN_ARND 37

/* libSceNet. The SDK header declares some of these as void(void), so declare
 * them here with their real signatures (do not include orbis/Net.h). */
int sceNetInit(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int memid);
int sceNetResolverCreate(const char *name, int memid, int flags);
int sceNetResolverStartNtoa(int rid, const char *hostname,
                            struct in_addr *addr, int timeout_us, int retry,
                            int flags);
int sceNetResolverGetError(int rid, int *result);
int sceNetResolverDestroy(int rid);

/* libSceNetCtl: the DNS servers from the network settings. */
#define NETCTL_INFO_PRIMARY_DNS 17
#define NETCTL_INFO_SECONDARY_DNS 18
typedef union {
    char primary_dns[16];
    char secondary_dns[16];
    char pad[512]; /* the real union is about 260 bytes */
} netctl_info;
int sceNetCtlInit(void);
int sceNetCtlGetInfo(int code, netctl_info *info);

#define POOL_SIZE (16 * 1024)

int p2f_platform_random(void *buf, size_t len)
{
    int mib[2] = { CTL_KERN, KERN_ARND };
    uint8_t *p = buf;
    while (len > 0) {
        /* kern.arandom returns at most 256 bytes per call. */
        size_t want = len > 256 ? 256 : len;
        size_t got = want;
        if (sysctl(mib, 2, p, &got, NULL, 0) != 0 || got == 0)
            return -1;
        p += got;
        len -= got;
    }
    return 0;
}

/* The system resolver. Return 0 or a negative SCE error code. */
static int sce_resolve(const char *host, struct in_addr *out)
{
    static int net_ready;
    int memid, rid, rc;

    if (!net_ready) {
        sceNetInit();  /* "already initialized" (EBUSY) is fine */
        net_ready = 1;
    }
    memid = sceNetPoolCreate("p2f_dns", POOL_SIZE, 0);
    if (memid < 0)
        return memid;
    rid = sceNetResolverCreate("p2f_resolver", memid, 0);
    if (rid < 0) {
        sceNetPoolDestroy(memid);
        return rid;
    }
    rc = sceNetResolverStartNtoa(rid, host, out, 5 * 1000 * 1000, 2, 0);
    if (rc < 0) {
        int detail = 0;
        if (sceNetResolverGetError(rid, &detail) == 0 && detail != 0)
            rc = detail < 0 ? detail : -detail;
    } else if (out->s_addr == 0) {
        rc = -1;
    }
    sceNetResolverDestroy(rid);
    sceNetPoolDestroy(memid);
    return rc < 0 ? rc : 0;
}

/* A DNS server from the network settings, or "" if none. */
static void netctl_dns(int code, char *out, size_t max)
{
    static int ctl_ready;
    netctl_info info;
    struct in_addr tmp;

    out[0] = '\0';
    if (!ctl_ready) {
        sceNetCtlInit();
        ctl_ready = 1;
    }
    memset(&info, 0, sizeof(info));
    if (sceNetCtlGetInfo(code, &info) < 0)
        return;
    info.pad[15] = '\0';
    if (inet_pton(AF_INET, info.primary_dns, &tmp) == 1 && tmp.s_addr != 0)
        snprintf(out, max, "%s", info.primary_dns);
}

int p2f_platform_resolve(const char *host, struct in_addr *out,
                         char *err, size_t errlen)
{
    char dns1[16], dns2[16], e1[160] = "", e2[160] = "";
    int rc;

    rc = sce_resolve(host, out);
    if (rc == 0)
        return 0;

    /* Fallback: ask the PS4's DNS servers directly. */
    netctl_dns(NETCTL_INFO_PRIMARY_DNS, dns1, sizeof(dns1));
    netctl_dns(NETCTL_INFO_SECONDARY_DNS, dns2, sizeof(dns2));
    if (dns1[0] && p2f_dns_query_a(dns1, 53, host, 3000, out, e1, sizeof(e1)) == 0)
        return 0;
    if (dns2[0] && strcmp(dns1, dns2) != 0 &&
        p2f_dns_query_a(dns2, 53, host, 3000, out, e2, sizeof(e2)) == 0)
        return 0;

    snprintf(err, errlen, "system resolver 0x%08x; %s%s%s",
             (unsigned)rc,
             dns1[0] ? e1 : "no DNS server in network settings",
             e2[0] ? "; " : "", e2);
    return -1;
}

/* libkernel */
int sceKernelUsleep(unsigned int microseconds);
uint64_t sceKernelGetProcessTime(void);  /* microseconds since start */

void p2f_platform_sleep_ms(int ms)
{
    if (ms > 0)
        sceKernelUsleep((unsigned int)ms * 1000u);
}

uint64_t p2f_platform_now_ms(void)
{
    return sceKernelGetProcessTime() / 1000u;
}
