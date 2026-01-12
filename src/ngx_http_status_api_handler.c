//
// Created by o.kononenko on 13.02.2025.
//
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include "ngx_http_status_api_module.h"
#include "ngx_http_status_api_handler.h"

static ngx_int_t ngx_http_status_api_handler_root(ngx_http_request_t *r,ngx_str_t *path);
static ngx_int_t ngx_http_status_api_handler_ssl(ngx_http_request_t *r);
static ngx_int_t ngx_http_status_api_handler_nginx(ngx_http_request_t *r);

#ifdef NGX_STAT_STUB
    static ngx_int_t ngx_http_status_api_handler_connections(ngx_http_request_t *r);
    static ngx_int_t ngx_http_status_api_handler_requests(ngx_http_request_t *r);
#endif

#ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
    #include "ngx_http_dynamic_healthcheck.h"
    #include "ngx_http_status_api_handler_upstreams.h"
    #include "ngx_http_status_api_handler_streams.h"
#endif

static ngx_int_t ngx_http_status_api_handler_server_zones(ngx_http_request_t *r);

//+ Handle headers and simple checks
ngx_int_t ngx_http_status_api_handler(ngx_http_request_t *r) {
    ngx_str_t                   type;
    ngx_http_core_loc_conf_t    *loc_conf;
    ngx_str_t                   path;

    if (!(r->method & NGX_HTTP_GET)) {
        http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler] Not GET request to API");
        return NGX_HTTP_NOT_ALLOWED;
    }

    loc_conf = *r->loc_conf;
    if (loc_conf == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler] loc_conf is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->uri.len < loc_conf->name.len) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler] very strange request_uri smaller than location name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.data = r->uri.data+loc_conf->name.len;
    path.len = r->uri.len-loc_conf->name.len;

    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler] request path: '%V'", &path);

    ngx_str_set(&type, "application/json");

    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;
    r->headers_out.content_type_lowcase = NULL;

    return ngx_http_status_api_handler_root(r, &path);
 }

//+ Base URLs handler
static ngx_int_t ngx_http_status_api_handler_root(ngx_http_request_t *r,ngx_str_t *path) {
    ngx_buf_t       *b;
    ngx_chain_t     *out;
    ngx_int_t       rc;
    ngx_uint_t      size;
    //discard body
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    //Handele /
    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] GET [%V]", path);

    //Dirty hack for /
    if ( path->len ==0 ) {
        return NGX_HTTP_NOT_FOUND;
    }
    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }
    // handle /api
    if ((ngx_strncmp(path->data, "/",path->len) == 0) || (ngx_strncmp(path->data, "",path->len) == 0)) {
        size = sizeof(NGX_HTTP_STATUS_API_VERSIONS_JSON)+1;
        b = ngx_create_temp_buf(r->pool, size);

        if (b == NULL) {
            http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] Can't allocate temp buffer [b] pointer is null");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last, NGX_HTTP_STATUS_API_VERSIONS_JSON);

        out.buf = b;
        out.next = NULL;
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = b->last - b->pos;

        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        return ngx_http_output_filter(r, out);
    }

    if ((ngx_strncmp(path->data, "/v1",path->len) == 0) || (ngx_strncmp(path->data, "/v1/",path->len) == 0)) {
        size = sizeof(NGX_HTTP_STATUS_API_DIVISION_JSON)+1;
        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] Can't allocate temp buffer [b] pointer is null");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last,NGX_HTTP_STATUS_API_DIVISION_JSON);

        out.buf = b;
        out.next = NULL;
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = b->last - b->pos;

        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        return ngx_http_output_filter(r, out);
    }

    if ((ngx_strncmp(path->data, "/v1/http",path->len) == 0) || (ngx_strncmp(path->data, "/v1/http/",path->len) == 0)) {
        size = sizeof("["
                    #ifdef NGX_STAT_STUB
                    "\"requests\","
                    #endif
                    #ifdef NGX_HTTP_VTS_STATUS
                    "\"upstreams\","
                    #endif
                    #ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
                    "\"heathchecks\","
                    #endif
                    "\"server_zones\""
                    "]")+1;
        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] Can't allocate temp buffer [b] pointer is null");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last, "["
                    #ifdef NGX_STAT_STUB
                    "\"requests\","
                    #endif
                    #ifdef NGX_HTTP_VTS_STATUS
                    "\"upstreams\","
                    #endif
                    #ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
                    "\"healthchecks\","
                    #endif
                    "\"server_zones\""
                    "]");

        out.buf = b;
        out.next = NULL;
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = b->last - b->pos;

        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        return ngx_http_output_filter(r, out);
    }


    if ((ngx_strncmp(path->data, "/v1/stream",path->len) == 0) || (ngx_strncmp(path->data, "/v1/stream/",path->len) == 0)) {
        size = sizeof("["
                    #ifdef NGX_STREAM_STS_STATUS
                    "\"upstreams\","
                    #endif
                    #ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
                    "\"heathchecks\""
                    #endif
                    "]")+1;
        b = ngx_create_temp_buf(r->pool, size);

        if (b == NULL) {
            http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_root] Can't allocate temp buffer [b] pointer is null");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last, "["
                    #ifdef NGX_STREAM_STS_STATUS
                    "\"upstreams\","
                    #endif
                    #ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
                    "\"healthchecks\""
                    #endif
                    "]");

        out.buf = b;
        out.next = NULL;
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = b->last - b->pos;

        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        return ngx_http_output_filter(r, out);
    }


    if (ngx_strncmp(path->data, "/v1/ssl",path->len) == 0) {
        return ngx_http_status_api_handler_ssl(r);
    }

    if (ngx_strncmp(path->data, "/v1/nginx",path->len) == 0) {
        return ngx_http_status_api_handler_nginx(r);
    }

    #ifdef NGX_STAT_STUB
    if (ngx_strncmp(path->data, "/v1/connections",path->len) == 0) {
        return ngx_http_status_api_handler_connections(r);
    }
    if (ngx_strncmp(path->data, "/v1/http/requests",path->len) == 0) {
      return ngx_http_status_api_handler_requests(r);
    }
    #endif
    if (ngx_strncmp(path->data, "/v1/http/server_zones",path->len) == 0) {
      return ngx_http_status_api_handler_server_zones(r);
    }

    if (ngx_strncmp(path->data, "/v1/stream/upstreams",path->len) == 0) {
        return ngx_http_status_api_handler_streams_handler(r);
    }

    if (ngx_strncmp(path->data, "/v1/http/upstreams",path->len) == 0) {
        return ngx_http_status_api_handler_upstreams_handler(r);
    }

    #ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
    if (ngx_strncmp(path->data, "/v1/http/healthchecks",path->len) == 0) {
        return ngx_http_dynamic_healthcheck_upstream_status_handler(r);
    }
    if (ngx_strncmp(path->data, "/v1/stream/healthchecks",path->len) == 0) {
        return ngx_http_dynamic_healthcheck_stream_status_handler(r);
    }
    #endif
    return NGX_HTTP_NOT_FOUND;
}

//+ Handle nginx statistic
static ngx_int_t ngx_http_status_api_handler_nginx(ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         *out;
    ngx_int_t                           rc;
    int                                 reload_timestamp = -1;
    int                                 start_timestamp = -1;


    ngx_http_core_srv_conf_t            **servers_conf_list;
    ngx_uint_t                          servers_num = 0;
    ngx_uint_t                          i;
    ngx_http_status_api_srv_conf_t      *server_conf;
    ngx_http_core_main_conf_t 			*core_main_conf;
    ngx_http_status_api_shm_ctx         *ctx;

    struct timeval   tv;

    //Get data to response
    ngx_gettimeofday(&tv);

    //Get servers status_zone stat
    // get core main conf
    core_main_conf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    if (core_main_conf == NULL) {
        http_status_api_log_error(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx] Get main conf error, pointer is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // get all servers in current worker
    servers_conf_list = core_main_conf->servers.elts;
    servers_num = core_main_conf->servers.nelts;

    for (i = 0; i < servers_num ; i++) {
       	server_conf = servers_conf_list[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        if (server_conf && server_conf->shm_zone && server_conf->shm_zone->data) {
            ctx = server_conf->shm_zone->data;

            dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx][default] Try lock shm mutex");
            ngx_shmtx_lock(&ctx->shpool->mutex);
            dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx][default] Try lock shm mutex success");

            reload_timestamp = ctx->counters->load_config_timestamp;
            start_timestamp = ctx->counters->nginx_load_timestamp;

            dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx][default] Try unlock shm mutex");
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx][default] Try unlock shm mutex success");
            break;
        }
    }

    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_nginx] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }

    // Response generate
    b = ngx_create_temp_buf(r->pool, NGX_HTTP_STATUS_API_NGINX_INFO_JSON_BUFFER_SIZE);
    if (b == NULL) {
        http_status_api_log_error(r->connection->log,"[http-status-api][ngx_http_status_api_handler_nginx] Get buffer error, pointer is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last,NGX_HTTP_STATUS_API_NGINX_INFO_JSON,
        NGINX_VERSION,
        NGX_BUILD,
        &ngx_cycle->hostname,
        tv.tv_sec,
        start_timestamp,
        reload_timestamp);


    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}

#ifdef NGX_STAT_STUB
//+ Handle nginx connections statistic
static ngx_int_t ngx_http_status_api_handler_connections (ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         *out;
    ngx_int_t                           rc;
    ngx_atomic_int_t                    conn_accepted,conn_dropped,conn_handled,conn_active,conn_idle,conn_reading,conn_writing;


    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_connections] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_STATUS_API_CONNECTION_JSON_BUFFER_SIZE);
    if (b == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_connections] Can't allocate temp buffer [b] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    conn_accepted = *ngx_stat_accepted;
    conn_handled = *ngx_stat_handled;
    conn_dropped = conn_accepted - conn_handled;
    conn_active = *ngx_stat_active;
    conn_reading = *ngx_stat_reading;
    conn_writing = *ngx_stat_writing;
    conn_idle = conn_active - (conn_reading +  conn_writing);

    b->last = ngx_sprintf(b->last,NGX_HTTP_STATUS_API_CONNECTION_JSON,
        conn_accepted,
        conn_dropped,
        conn_active,
        conn_idle);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}

//+ Handle nginx requests statistic
static ngx_int_t ngx_http_status_api_handler_requests (ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         *out;
    ngx_int_t                           rc;
    ngx_atomic_int_t                    requests,conn_reading,conn_writing;

    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_int_t ngx_http_status_api_handler_requests] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }


    b = ngx_create_temp_buf(r->pool, NGX_HTTP_STATUS_API_REQUESTS_JSON_BUFFER_SIZE);
    if (b == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_int_t ngx_http_status_api_handler_requests] Can't allocate temp buffer [b] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    conn_reading = *ngx_stat_reading;
    conn_writing = *ngx_stat_writing;
	requests = *ngx_stat_requests;

    b->last = ngx_sprintf(b->last,NGX_HTTP_STATUS_API_REQUESTS_JSON,
        requests,
        conn_reading+conn_writing);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}
#endif

//+ Handle SSL statistic
static ngx_int_t ngx_http_status_api_handler_ssl(ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         *out;
    ngx_int_t                           rc;

    ngx_uint_t                          handshakes = 0;
    ngx_uint_t            				session_reuses = 0;
    ngx_uint_t 							handshake_timeout = 0;
    ngx_uint_t						    handshakes_failed = 0;

    ngx_http_core_srv_conf_t            **servers_conf_list;
    ngx_uint_t                          servers_num = 0;
    ngx_uint_t                          i;
    ngx_http_status_api_srv_conf_t      *server_conf;
    ngx_http_core_main_conf_t 			*core_main_conf;
    ngx_http_status_api_shm_ctx         *ctx;

    //Get servers status_zone stat
    // get core main conf
    core_main_conf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    if (core_main_conf == NULL) {
        http_status_api_log_error(r->connection->log,"[http-status-api][ngx_http_status_api_handler_ssl] Get default SHM error, pointer is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // get all servers in current worker
    servers_conf_list = core_main_conf->servers.elts;
    servers_num = core_main_conf->servers.nelts;

    for (i = 0; i < servers_num ; i++) {
       	server_conf = servers_conf_list[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];

        if (server_conf && server_conf->shm_zone && server_conf->shm_zone->data) {
            ctx = server_conf->shm_zone->data;

            dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl][%i] Try lock mutex for SHM.",i);
            ngx_shmtx_lock(&ctx->shpool->mutex);//Mutex
            dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl][%i] Mutex lock success.",i);


            handshakes += ctx->counters->ssl_accept;
            handshakes_failed += ctx->counters->ssl_accept - ctx->counters->ssl_accept_good;
            session_reuses +=  ctx->counters->ssl_hits;
            handshake_timeout += ctx->counters->ssl_timeouts;

            dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl][%i] Try unlock mutex for SHM.",i);
            ngx_shmtx_unlock(&ctx->shpool->mutex);//Mutex
            dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl][%i] Mutex unlock success.",i);
        }
    }


    // Generate response
    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl]] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_STATUS_API_SSL_JSON_BUFFER_SIZE);
    if (b == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_ssl]] Can't allocate temp buffer [b] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, NGX_HTTP_STATUS_API_SSL_JSON,
            handshakes,
            session_reuses,
            handshakes_failed,
            handshake_timeout);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}

//+ Handle server_zones statistic
static ngx_int_t ngx_http_status_api_handler_server_zones(ngx_http_request_t *r) {
    ngx_http_core_srv_conf_t            **servers_conf_list;
    ngx_uint_t                          servers_num = 0;
    ngx_uint_t                          i,zone_counter;
    ngx_http_status_api_srv_conf_t      *server_conf;
    ngx_http_core_main_conf_t 			*core_main_conf;
    ngx_http_status_api_shm_ctx         *ctx;

    ngx_buf_t                           *b;
    ngx_chain_t                         *out;
    ngx_int_t                           rc;

    // get core main conf
    core_main_conf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    // get all servers in current worker
    servers_conf_list = core_main_conf->servers.elts;
    servers_num = core_main_conf->servers.nelts;

    //Generate response
    out = ngx_alloc_chain_link(r->pool)
    if (out == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_server_zones] Can't allocate chain link [out] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR
    }

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_STATUS_API_SERVER_ZONE_JSON_BUFFER_SIZE*(servers_num+1));
    if (b == NULL) {
        http_status_api_log_error(r->connection->log, "[http-status-api][ngx_http_status_api_handler_server_zones] Can't allocate temporary buffer [b] pointer is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, "{");



    zone_counter = 0;
    for (i = 0; i < servers_num; i++) {
        // this module config
        server_conf = servers_conf_list[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        if (server_conf == NULL) { continue; }
        if (server_conf->shm_zone == NULL) { continue; }

        ctx = server_conf->shm_zone->data;

        if (ctx == NULL) { continue; }

        if (zone_counter > 0) {
            b->last = ngx_sprintf(b->last, ",");
        }

        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Try lock mutex for SHM.",i);
        ngx_shmtx_lock(&ctx->shpool->mutex);//Mutex
        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Mutex lock success.",i);

        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%s] Stat from zones get success",server_conf->shm_zone->shm.name.data);

        b->last = ngx_sprintf(b->last, NGX_HTTP_STATUS_API_SERVER_ZONE_JSON,
            server_conf->shm_zone->shm.name.data+SHM_ZONE_PREFIX_LEN,
            ctx->counters->ssl_accept,
            ctx->counters->ssl_hits,
            ctx->counters->ssl_accept - ctx->counters->ssl_accept_good,
            ctx->counters->ssl_timeouts,
            ctx->counters->resp_total,
            ctx->counters->resp_1xx,
            ctx->counters->resp_2xx,
            ctx->counters->resp_3xx,
            ctx->counters->resp_4xx,
            ctx->counters->resp_5xx,
            ctx->counters->in_bytes,
            ctx->counters->out_bytes);

        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Try unlock mutex for SHM.",i);
        ngx_shmtx_unlock(&ctx->shpool->mutex);//Mutex
        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Mutex unlock success.",i);
        zone_counter ++;
    }
    b->last = ngx_sprintf(b->last, "}");
    // response finalized
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}







