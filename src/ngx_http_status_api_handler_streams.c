//
// Created by o.kononenko on 21.04.2025.
//
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_status_api_handler_streams.h"

#ifdef NGX_STREAM_STS_STATUS
#include "ngx_http_stream_server_traffic_status_module.h"
#include "ngx_http_stream_server_traffic_status_shm.h"
#include "ngx_http_stream_server_traffic_status_display.h"

static ngx_int_t ngx_http_status_api_display_handler(ngx_http_request_t *r);
static ngx_int_t http_status_api_display_handler_default(ngx_http_request_t *r);
u_char *http_status_api_display_set(ngx_http_request_t *r,u_char *buf);
u_char *http_status_api_display_set_upstream_group(ngx_http_request_t *r,u_char *buf);
u_char *http_status_api_display_set_upstream_alone(ngx_http_request_t *r,u_char *buf, ngx_rbtree_node_t *node);
u_char *http_status_api_display_set_upstream_node(ngx_http_request_t *r,u_char *buf, ngx_stream_upstream_server_t *us,ngx_http_stream_server_traffic_status_node_t *stsn);
#endif



ngx_int_t ngx_http_status_api_handler_streams_handler(ngx_http_request_t *r) {
#ifdef NGX_STREAM_STS_STATUS
    return ngx_http_status_api_display_handler(r);
#else
    return NGX_HTTP_NOT_FOUND;
#endif
}




static ngx_int_t
ngx_http_status_api_display_handler(ngx_http_request_t *r)
{
    ngx_int_t                                     rc;
    ngx_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_stream_server_traffic_status_module);

    if (!ctx->enable) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_stream_server_traffic_status_shm_init(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_handler::shm_init() failed");
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    /* default processing handler */
    rc = http_status_api_display_handler_default(r);

    return rc;
}



static ngx_int_t
http_status_api_display_handler_default(ngx_http_request_t *r)
{
    ngx_str_t                                          type;
    ngx_int_t                                          size, rc;
    ngx_buf_t                                         *b;
    ngx_chain_t                                       *out;
    ngx_slab_pool_t                                   *shpool;
    ngx_http_stream_server_traffic_status_ctx_t       *ctx;
    ngx_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_stream_server_traffic_status_module);

    stscf = ngx_http_get_module_loc_conf(r, ngx_http_stream_server_traffic_status_module);

    if (stscf == NULL) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (!ctx->enable) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&type, "application/json");
    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;

    size = ngx_http_stream_server_traffic_status_display_get_size(r);
    if (size == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::display_get_size() failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][http_status_api_display_handler_default] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    shpool = (ngx_slab_pool_t *) stscf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    b->last = http_status_api_display_set(r, b->last);
    ngx_shmtx_unlock(&shpool->mutex);

    if (b->last == b->pos) {
          b->last = ngx_sprintf(b->last, "{}");
    }


    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0; /* if subrequest 0 else 1 */
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}



u_char *
http_status_api_display_set(ngx_http_request_t *r,
    u_char *buf)
{
    u_char                                            *o, *s;

    ngx_http_stream_server_traffic_status_loc_conf_t  *stscf;

    stscf = ngx_http_get_module_loc_conf(r, ngx_http_stream_server_traffic_status_module);

    /* init stats */
    ngx_memzero(&stscf->stats, sizeof(stscf->stats));
    ngx_http_stream_server_traffic_status_node_time_queue_init(&stscf->stats.stat_session_times);

    /* upstreamZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_UPSTREAM_S);

    s = buf;

    buf = http_status_api_display_set_upstream_group(r, buf);

    if (s == buf) {
        buf = o;
        buf--;

    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_E);
    }

    return buf;
}


u_char *http_status_api_display_set_upstream_group(ngx_http_request_t *r,u_char *buf)
{
    size_t                                         len;
    u_char                                        *p, *o, *s;
    uint32_t                                       hash;
    unsigned                                       type, zone;
    ngx_int_t                                      rc;
    ngx_str_t                                      key, dst;
    ngx_uint_t                                     i, j, k;
    ngx_rbtree_node_t                             *node;
    ngx_stream_upstream_server_t                  *us, usn;
#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_stream_upstream_rr_peer_t                 *peer;
    ngx_stream_upstream_rr_peers_t                *peers;
#endif
    ngx_stream_upstream_srv_conf_t                *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t               *umcf;
    ngx_http_stream_server_traffic_status_ctx_t   *ctx;
    ngx_http_stream_server_traffic_status_node_t  *stsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_stream_server_traffic_status_module);
    umcf = ctx->upstream;
    uscfp = umcf->upstreams.elts;

    len = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        len = ngx_max(uscf->host.len, len);
    }

    dst.len = len + sizeof("@[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535") - 1;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return buf;
    }

    p = dst.data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

            type = NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG;

            o = buf;

            buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            zone = 0;

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            zone = 1;

            peers = uscf->peer.data;

            ngx_stream_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer ; peer = peer->next) {
                p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = ngx_cpymem(p, peer->name.data, peer->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;

                rc = ngx_http_stream_server_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                if (rc != NGX_OK) {
                    ngx_stream_upstream_rr_peers_unlock(peers);
                    return buf;
                }

                hash = ngx_crc32_short(key.data, key.len);
                node = ngx_http_stream_server_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                usn.weight = peer->weight;
                usn.max_fails = peer->max_fails;
                usn.fail_timeout = peer->fail_timeout;
                usn.backup = 0;
                usn.down = peer->down;


                usn.name = peer->name;


                if (node != NULL) {
                    stsn = (ngx_http_stream_server_traffic_status_node_t *) &node->color;
                    buf = http_status_api_display_set_upstream_node(r, buf, &usn, stsn);
                } else {
                    buf = http_status_api_display_set_upstream_node(r, buf, &usn, NULL);
                }

                p = dst.data;
            }

            ngx_stream_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                usn = us[j];

                if (zone && usn.backup != 1) {
                    continue;
                }

                /* for all A records */
                for (k = 0; k < usn.naddrs; k++) {
                    p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                    *p++ = NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = ngx_cpymem(p, usn.addrs[k].name.data, usn.addrs[k].name.len);

                    dst.len = uscf->host.len + sizeof("@") - 1 + usn.addrs[k].name.len;

                    rc = ngx_http_stream_server_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                    if (rc != NGX_OK) {
                        return buf;
                    }

                    hash = ngx_crc32_short(key.data, key.len);
                    node = ngx_http_stream_server_traffic_status_node_lookup(ctx->rbtree, &key, hash);


                    usn.name = usn.addrs[k].name;


                    if (node != NULL) {
                        stsn = (ngx_http_stream_server_traffic_status_node_t *) &node->color;
                        buf = http_status_api_display_set_upstream_node(r, buf, &usn, stsn);
                    } else {
                        buf = http_status_api_display_set_upstream_node(r, buf, &usn, NULL);
                    }

                    p = dst.data;
                }
            }

            if (s == buf) {
                buf = o;

            } else {
                buf--;
                buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_E);
                buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_NEXT);
            }
        }
    }

    /* alones */
    o = buf;

    ngx_str_set(&key, "::nogroups");

    buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_S, &key);

    s = buf;

    buf = http_status_api_display_set_upstream_alone(r, buf, ctx->rbtree->root);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_E);
        buf = ngx_sprintf(buf, NGX_HTTP_STATUS_API_JSON_FMT_NEXT);
    }

    return buf;
}



u_char *
http_status_api_display_set_upstream_alone(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    unsigned                                       type;
    ngx_str_t                                      key;
    ngx_stream_upstream_server_t                   us;
    ngx_http_stream_server_traffic_status_ctx_t   *ctx;
    ngx_http_stream_server_traffic_status_node_t  *stsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_stream_server_traffic_status_module);

    type = NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA;

    if (node != ctx->rbtree->sentinel) {
        stsn = (ngx_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == type) {
            key.len = stsn->len;
            key.data = stsn->data;

            (void) ngx_http_stream_server_traffic_status_node_position_key(&key, 1);

            us.name = key;
            us.weight = 0;
            us.max_fails = 0;
            us.fail_timeout = 0;
            us.down = 0;
            us.backup = 0;

            buf = http_status_api_display_set_upstream_node(r, buf, &us, stsn);
        }

        buf = http_status_api_display_set_upstream_alone(r, buf, node->left);
        buf = http_status_api_display_set_upstream_alone(r, buf, node->right);
    }

    return buf;
}



u_char *
http_status_api_display_set_upstream_node(ngx_http_request_t *r,
                                          u_char *buf,
                                          ngx_stream_upstream_server_t *us,
                                          ngx_http_stream_server_traffic_status_node_t *stsn)
{
    ngx_int_t                                          rc;
    ngx_str_t                                          key;
    ngx_http_stream_server_traffic_status_loc_conf_t  *stscf;

    stscf = ngx_http_get_module_loc_conf(r, ngx_http_stream_server_traffic_status_module);

    rc = ngx_http_stream_server_traffic_status_escape_json_pool(r->pool, &key, &us->name);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_upstream_node::escape_json_pool() failed");
    }

    if (stsn != NULL) {
        buf = ngx_sprintf(buf, NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, stsn->stat_connect_counter,
                stsn->stat_in_bytes, stsn->stat_out_bytes,
                stsn->stat_1xx_counter, stsn->stat_2xx_counter,
                stsn->stat_3xx_counter, stsn->stat_4xx_counter,
                stsn->stat_5xx_counter,
                stsn->stat_session_time_counter,
                ngx_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_session_times, stscf->average_method,
                    stscf->average_period),
                stsn->stat_upstream.session_time_counter,
                ngx_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.session_times, stscf->average_method,
                    stscf->average_period),
                stsn->stat_upstream.connect_time_counter,
                ngx_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.connect_times, stscf->average_method,
                    stscf->average_period),
                stsn->stat_upstream.first_byte_time_counter,
                ngx_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.first_byte_times, stscf->average_method,
                    stscf->average_period),
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_http_stream_server_traffic_status_boolean_to_string(us->backup),
                ngx_http_stream_server_traffic_status_boolean_to_string(us->down));

    } else {
        buf = ngx_sprintf(buf, NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_http_stream_server_traffic_status_boolean_to_string(us->backup),
                ngx_http_stream_server_traffic_status_boolean_to_string(us->down));
    }

    return buf;
}
