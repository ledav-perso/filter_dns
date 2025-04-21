#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <msgpack.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "uthash.h"

// Structure de cache
struct dns_cache_entry {
    char ip[64];
    char hostname[NI_MAXHOST];
    time_t time_added;
    UT_hash_handle hh;
};

// Contexte global du plugin
struct dnslookup_ctx {
    struct dns_cache_entry *cache;
    int cache_ttl;
};

// Ajouter une entrée au cache
static void dns_cache_store(struct dnslookup_ctx *ctx, const char *ip, const char *hostname, time_t now) {
    struct dns_cache_entry *entry;

    HASH_FIND_STR(ctx->cache, ip, entry);
    if (!entry) {
        entry = flb_malloc(sizeof(struct dns_cache_entry));
        if (!entry) return;

        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->ip[sizeof(entry->ip) - 1] = '\0';
        HASH_ADD_STR(ctx->cache, ip, entry);
    }

    strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
    entry->hostname[sizeof(entry->hostname) - 1] = '\0';
    entry->time_added = now;
}

// Chercher dans le cache avec TTL
static const char *dns_cache_lookup(struct dnslookup_ctx *ctx, const char *ip, time_t now, int ttl) {
    struct dns_cache_entry *entry;

    HASH_FIND_STR(ctx->cache, ip, entry);
    if (entry) {
        if ((now - entry->time_added) > ttl) {
            HASH_DEL(ctx->cache, entry);
            flb_free(entry);
            return NULL;
        }
        return entry->hostname;
    }
    return NULL;
}

// Nettoyer le cache
static void dns_cache_destroy(struct dnslookup_ctx *ctx) {
    struct dns_cache_entry *entry, *tmp;
    HASH_ITER(hh, ctx->cache, entry, tmp) {
        HASH_DEL(ctx->cache, entry);
        flb_free(entry);
    }
}

// Fonction principale de filtrage
static int cb_dnslookup_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_bytes,
                               struct flb_filter_instance *f_ins,
                               struct flb_input_instance *i_ins,
                               void *context,
                               struct flb_config *config)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;

    struct dnslookup_ctx *ctx = context;
    time_t now = time(NULL);

    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        msgpack_object root = result.data;

        if (root.type != MSGPACK_OBJECT_ARRAY || root.via.array.size != 2) {
            continue;
        }

        msgpack_object map = root.via.array.ptr[1];
        if (map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        msgpack_pack_array(&pck, 2);
        msgpack_pack_object(&pck, root.via.array.ptr[0]);

        msgpack_pack_map(&pck, map.via.map.size + 1);

        char ip[64] = {0};
        int found_ip = 0;
        for (int i = 0; i < map.via.map.size; i++) {
            msgpack_object_kv *kv = &map.via.map.ptr[i];

            msgpack_pack_object(&pck, kv->key);
            msgpack_pack_object(&pck, kv->val);

            if (kv->key.type == MSGPACK_OBJECT_STR &&
                strncmp(kv->key.via.str.ptr, "SRC", kv->key.via.str.size) == 0)
            {
                snprintf(ip, sizeof(ip), "%.*s",
                         kv->val.via.str.size, kv->val.via.str.ptr);
                found_ip = 1;
            }
        }

        msgpack_pack_str(&pck, 8);
        msgpack_pack_str_body(&pck, "HOSTNAME", 8);

        if (found_ip) {
            const char *cached = dns_cache_lookup(ctx, ip, now, ctx->cache_ttl);
            if (cached) {
                msgpack_pack_str(&pck, strlen(cached));
                msgpack_pack_str_body(&pck, cached, strlen(cached));
            } else {
                struct sockaddr_in sa;
                char hostname[NI_MAXHOST] = "unknown";

                if (inet_pton(AF_INET, ip, &sa.sin_addr) == 1) {
                    sa.sin_family = AF_INET;
                    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                                    hostname, sizeof(hostname),
                                    NULL, 0, 0) == 0)
                    {
                        dns_cache_store(ctx, ip, hostname, now);
                        msgpack_pack_str(&pck, strlen(hostname));
                        msgpack_pack_str_body(&pck, hostname, strlen(hostname));
                    } else {
                        msgpack_pack_str(&pck, 7);
                        msgpack_pack_str_body(&pck, "unknown", 7);
                    }
                } else {
                    msgpack_pack_str(&pck, 7);
                    msgpack_pack_str_body(&pck, "invalid", 7);
                }
            }
        } else {
            msgpack_pack_str(&pck, 7);
            msgpack_pack_str_body(&pck, "unknown", 7);
        }
    }

    msgpack_unpacked_destroy(&result);
    *out_buf = sbuf.data;
    *out_bytes = sbuf.size;

    return FLB_FILTER_MODIFIED;
}

// Initialisation
static int cb_dnslookup_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    struct dnslookup_ctx *ctx = flb_malloc(sizeof(struct dnslookup_ctx));
    if (!ctx) {
        return -1;
    }

    ctx->cache = NULL;

    const char *ttl_str = flb_filter_get_property("cache_ttl", f_ins);
    ctx->cache_ttl = ttl_str ? atoi(ttl_str) : 300;

    flb_info("[dnslookup] Plugin initialisé avec TTL = %d sec", ctx->cache_ttl);
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

// Libération
static int cb_dnslookup_exit(void *context, struct flb_config *config)
{
    struct dnslookup_ctx *ctx = context;
    if (ctx) {
        dns_cache_destroy(ctx);
        flb_free(ctx);
        flb_info("[dnslookup] Cache nettoyé et plugin terminé.");
    }
    return 0;
}

// Déclaration du plugin
struct flb_filter_plugin filter_dnslookup_plugin = {
    .name         = "dnslookup",
    .description  = "Ajoute le champ HOSTNAME depuis IP SRC avec cache DNS TTL",
    .cb_init      = cb_dnslookup_init,
    .cb_filter    = cb_dnslookup_filter,
    .cb_exit      = cb_dnslookup_exit,
    .flags        = 0
};