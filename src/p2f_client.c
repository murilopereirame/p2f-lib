/* The p2f client object, URL parsing, JSON requests and folder listing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "p2f_internal.h"

#define MAX_JSON (8u * 1024u * 1024u)

int p2f_is_retryable(int err)
{
    return err == P2F_ERR_NET || err == P2F_ERR_SHORT ||
           err == P2F_ERR_CHECKSUM;
}

const char *p2f_last_error(const p2f_client *c)
{
    return c ? c->err : "no client";
}

int p2f_last_status(const p2f_client *c)
{
    return c ? c->last_status : 0;
}

int p2f_client_new(p2f_client **out, const char *base_url, const char *token,
                   int timeout_ms)
{
    p2f_client *c;
    const char *p, *host_end, *path;
    size_t host_len;
    int tls;

    *out = NULL;
    if (!base_url || !token)
        return P2F_ERR_ARG;
    while (*base_url == ' ' || *base_url == '\t')
        base_url++;
    if (strncmp(base_url, "http://", 7) == 0) {
        tls = 0;
        p = base_url + 7;
    } else if (strncmp(base_url, "https://", 8) == 0) {
        tls = 1;
        p = base_url + 8;
    } else {
        return P2F_ERR_ARG;
    }

    c = calloc(1, sizeof(*c));
    if (!c)
        return P2F_ERR_NOMEM;
    p2f_tls_init(c);
    c->tls = tls;
    c->port = tls ? 443 : 80;
    c->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;
    c->token = strdup(token);
    if (!c->token) {
        p2f_client_free(c);
        return P2F_ERR_NOMEM;
    }

    path = strchr(p, '/');
    host_end = path ? path : p + strlen(p);
    {
        const char *colon = memchr(p, ':', (size_t)(host_end - p));
        if (colon) {
            long port = strtol(colon + 1, NULL, 10);
            if (port <= 0 || port > 65535)
                goto bad;
            c->port = (uint16_t)port;
            host_len = (size_t)(colon - p);
        } else {
            host_len = (size_t)(host_end - p);
        }
    }
    if (host_len == 0 || host_len >= sizeof(c->host))
        goto bad;
    memcpy(c->host, p, host_len);
    c->host[host_len] = '\0';

    if (path) {
        size_t n = strlen(path);
        while (n > 0 && path[n - 1] == '/')
            n--;
        while (n > 0 && (path[n - 1] == ' ' || path[n - 1] == '\n' ||
                         path[n - 1] == '\r'))
            n--;
        if (n >= sizeof(c->base_path))
            goto bad;
        memcpy(c->base_path, path, n);
        c->base_path[n] = '\0';
    }
    *out = c;
    return P2F_OK;

bad:
    p2f_client_free(c);
    return P2F_ERR_ARG;
}

void p2f_client_free(p2f_client *c)
{
    if (!c)
        return;
    if (c->token) {
        memset(c->token, 0, strlen(c->token));
        free(c->token);
    }
    p2f_tls_free(c);
    free(c->ca_file);
    free(c);
}

int p2f_client_set_ca_file(p2f_client *c, const char *pem_path)
{
    char *dup;
    if (!c || !pem_path || !pem_path[0])
        return P2F_ERR_ARG;
    dup = strdup(pem_path);
    if (!dup)
        return P2F_ERR_NOMEM;
    free(c->ca_file);
    c->ca_file = dup;
    /* Load the new CA on the next request. */
    p2f_tls_free(c);
    p2f_tls_init(c);
    return P2F_OK;
}

int p2f_get_json(p2f_client *c, const char *path_query, char **body)
{
    p2f_http h;
    int rc;

    *body = NULL;
    c->last_status = 0;
    rc = p2f_http_get(c, path_query, 0, c->timeout_ms, &h);
    if (rc != P2F_OK)
        return rc;
    rc = p2f_http_read_all(&h, body, NULL, MAX_JSON);
    p2f_http_close(&h);
    if (rc != P2F_OK)
        return p2f_fail(c, rc, "reading %s failed", path_query);

    if (h.status < 200 || h.status > 299) {
        cJSON *j = cJSON_Parse(*body);
        const cJSON *e = cJSON_GetObjectItemCaseSensitive(j, "error");
        c->last_status = h.status;
        if (cJSON_IsString(e))
            p2f_fail(c, P2F_ERR_HTTP, "HTTP %d: %s", h.status, e->valuestring);
        else
            p2f_fail(c, P2F_ERR_HTTP, "HTTP %d", h.status);
        cJSON_Delete(j);
        free(*body);
        *body = NULL;
        return P2F_ERR_HTTP;
    }
    return P2F_OK;
}

int p2f_get_raw(p2f_client *c, const char *path_query, int timeout_ms,
                int *status, char **body, int *retry_after_ms)
{
    p2f_http h;
    int rc;

    *body = NULL;
    *status = 0;
    *retry_after_ms = 0;
    rc = p2f_http_get(c, path_query, 0, timeout_ms, &h);
    if (rc != P2F_OK)
        return rc;
    rc = p2f_http_read_all(&h, body, NULL, MAX_JSON);
    p2f_http_close(&h);
    if (rc != P2F_OK)
        return p2f_fail(c, rc, "reading %s failed", path_query);
    *status = h.status;
    *retry_after_ms = h.retry_after_ms;
    return P2F_OK;
}

int p2f_list(p2f_client *c, const char *path, p2f_entry **entries,
             size_t *count)
{
    char *enc, *body = NULL, *pq;
    cJSON *j, *arr, *it;
    p2f_entry *list;
    size_t n = 0, i = 0;
    int rc;

    *entries = NULL;
    *count = 0;
    enc = p2f_urlencode(path ? path : "");
    if (!enc)
        return P2F_ERR_NOMEM;
    pq = malloc(strlen(enc) + 32);
    if (!pq) {
        free(enc);
        return P2F_ERR_NOMEM;
    }
    sprintf(pq, "/api/list?path=%s", enc);
    free(enc);
    rc = p2f_get_json(c, pq, &body);
    free(pq);
    if (rc != P2F_OK)
        return rc;

    j = cJSON_Parse(body);
    free(body);
    arr = cJSON_GetObjectItemCaseSensitive(j, "entries");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(j);
        return p2f_fail(c, P2F_ERR_PROTO, "listing has no entries");
    }
    n = (size_t)cJSON_GetArraySize(arr);
    list = calloc(n ? n : 1, sizeof(*list));
    if (!list) {
        cJSON_Delete(j);
        return P2F_ERR_NOMEM;
    }
    cJSON_ArrayForEach(it, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(it, "name");
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(it, "type");
        const cJSON *size = cJSON_GetObjectItemCaseSensitive(it, "size");
        if (!cJSON_IsString(name) || !cJSON_IsString(type))
            continue;
        list[i].name = strdup(name->valuestring);
        if (!list[i].name) {
            p2f_entries_free(list, i);
            cJSON_Delete(j);
            return P2F_ERR_NOMEM;
        }
        list[i].is_dir = strcmp(type->valuestring, "dir") == 0;
        list[i].size = (cJSON_IsNumber(size) && !list[i].is_dir)
                           ? (int64_t)size->valuedouble : -1;
        i++;
    }
    cJSON_Delete(j);
    *entries = list;
    *count = i;
    return P2F_OK;
}

void p2f_entries_free(p2f_entry *entries, size_t count)
{
    size_t i;
    if (!entries)
        return;
    for (i = 0; i < count; i++)
        free(entries[i].name);
    free(entries);
}
