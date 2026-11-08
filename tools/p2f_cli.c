/*
 * Command-line client and test tool for p2f-lib.
 *   p2f-cli <base_url> <token> <remote_path> <local_dir> [--abort-at N]
 *           [--abort-preparing] [--prepare-timeout ms] [--ls] [--ca file.pem]
 *           [--dns ip[:port]] [--no-repair]
 * With a repair, it prints "repaired N pieces" (the tests read this).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p2f.h"

static long long abort_at = -1;
static int abort_preparing;
static int saw_preparing;
static unsigned repaired, verified;

static int on_progress(const p2f_progress *p, void *user)
{
    (void)user;
    if (p->preparing) {
        if (!saw_preparing)
            fprintf(stderr, "preparing on the server...\n");
        saw_preparing = 1;
        fprintf(stderr, "\rpreparing %llu/%llu   ",
                (unsigned long long)p->prepare_done,
                (unsigned long long)p->prepare_total);
        return abort_preparing;
    }
    if (p->repair_phase == P2F_REPAIR_VERIFYING) {
        verified = p->repair_done;
        fprintf(stderr, "\rchecking pieces %u/%u   ", p->repair_done, p->repair_total);
        return 0;
    }
    if (p->repair_phase == P2F_REPAIR_FETCHING) {
        repaired = p->repair_done;
        fprintf(stderr, "\rrepairing %u/%u pieces   ", p->repair_done, p->repair_total);
        return 0;
    }
    fprintf(stderr, "\r%6.2f%%  %llu/%llu  file %d/%d   ",
            p->bytes_total ? 100.0 * (double)p->bytes_done / (double)p->bytes_total : 0.0,
            (unsigned long long)p->bytes_done,
            (unsigned long long)p->bytes_total, p->files_done, p->files_total);
    return abort_at >= 0 && (long long)p->bytes_done >= abort_at;
}

int main(int argc, char **argv)
{
    p2f_client *c;
    p2f_download_opts o = { on_progress, NULL, 1, 5000, 0, 0 };
    char local[1024];
    const char *ca = NULL;
    int rc, i, ls = 0;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <base_url> <token> <remote> <local_dir>"
                        " [--abort-at N] [--abort-preparing] [--prepare-timeout ms]"
                        " [--ls] [--ca file.pem] [--dns ip[:port]]"
                        " [--no-repair]\n", argv[0]);
        return 2;
    }
    for (i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--abort-at") == 0 && i + 1 < argc)
            abort_at = atoll(argv[++i]);
        else if (strcmp(argv[i], "--abort-preparing") == 0)
            abort_preparing = 1;
        else if (strcmp(argv[i], "--prepare-timeout") == 0 && i + 1 < argc)
            o.prepare_timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ls") == 0)
            ls = 1;
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
            ca = argv[++i];
        else if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc)
            p2f_set_dns_server(argv[++i]);
        else if (strcmp(argv[i], "--no-repair") == 0)
            o.no_repair = 1;
    }
    if (p2f_client_new(&c, argv[1], argv[2], 5000) != P2F_OK) {
        fprintf(stderr, "bad base url\n");
        return 2;
    }
    if (ca)
        p2f_client_set_ca_file(c, ca);
    if (ls) {
        p2f_entry *e;
        size_t n, k;
        rc = p2f_list(c, argv[3], &e, &n);
        if (rc == P2F_OK) {
            for (k = 0; k < n; k++)
                printf("%s\t%lld\t%s\n", e[k].is_dir ? "dir " : "file",
                       (long long)e[k].size, e[k].name);
            p2f_entries_free(e, n);
        }
    } else {
        rc = p2f_download_path(c, argv[3], argv[4], &o, local, sizeof(local));
        fprintf(stderr, "\n");
        if (verified)
            printf("checked %u pieces\n", verified);
        if (repaired)
            printf("repaired %u pieces\n", repaired);
        if (rc == P2F_OK)
            printf("saved to %s\n", local);
    }
    if (rc != P2F_OK)
        printf("error %d: %s\n", rc, p2f_last_error(c));
    p2f_client_free(c);
    return rc == P2F_OK ? 0 : 1;
}
