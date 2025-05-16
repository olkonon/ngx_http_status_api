//
// Created by o.kononenko on 13.02.2025.
//
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include "ngx_http_status_api_module.h"
#include "ngx_http_status_api_handler_upstreams.h"
#include "ngx_http_status_api_handler_streams.h"

static ngx_int_t ngx_http_status_api_api_handler_root(ngx_http_request_t *r,ngx_str_t *path);
static ngx_int_t ngx_http_status_api_api_handler_ssl(ngx_http_request_t *r);
static ngx_int_t ngx_http_status_api_api_handler_nginx(ngx_http_request_t *r);

#ifdef NGX_STAT_STUB
static ngx_int_t ngx_http_status_api_api_handler_connections(ngx_http_request_t *r);
static ngx_int_t ngx_http_status_api_api_handler_requests(ngx_http_request_t *r);
#endif

#ifdef NGX_HTTP_DYNAMIC_HEALTHCHEK
#include "ngx_http_dynamic_healthcheck.h"
//ngx_int_t ngx_http_dynamic_healthcheck_upstream_status(ngx_http_request_t *r);
#endif


static ngx_int_t ngx_http_status_api_api_handler_server_zones(ngx_http_request_t *r);

/* Reply on location marked with api_status */
ngx_int_t ngx_http_status_api_api_handler(ngx_http_request_t *r) {
    ngx_str_t          type;

    ngx_http_core_loc_conf_t *loc_conf;
    ngx_str_t path;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    loc_conf = *r->loc_conf;
    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[http-status-api] loc_conf is null");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (r->uri.len < loc_conf->name.len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[http-status-api] very strange request_uri smaller than location name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.data = r->uri.data+loc_conf->name.len;
    path.len = r->uri.len-loc_conf->name.len;

    ngx_log_error(NGX_LOG_INFO,r->connection->log,0, "[http-status-api] request path: '%V'", &path);

    ngx_str_set(&type, "application/json");

    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;
    r->headers_out.content_type_lowcase = NULL;

    return ngx_http_status_api_api_handler_root(r, &path);


 }

static ngx_int_t ngx_http_status_api_api_handler_root(ngx_http_request_t *r,ngx_str_t *path) {
    ngx_buf_t       *b;
    ngx_chain_t     out;
    ngx_int_t       rc;
    ngx_uint_t      size;
    //discard body
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    //Handele /
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "[http-status-api] path [%V] [%ui]", path,path->len);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "[http-status-api] path [%ui]", ngx_strncmp(path->data, "api",path->len));

    //Dirty hack for /
    if ( path->len ==0 ) {
        return NGX_HTTP_NOT_FOUND;
    }
    // handle /api
    if ((ngx_strncmp(path->data, "/",path->len) == 0) || (ngx_strncmp(path->data, "",path->len) == 0)) {
        size = sizeof("[\"v1\"]")+1;
        b = ngx_create_temp_buf(r->pool, size);

        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last, "[\"v1\"]");

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
        return ngx_http_output_filter(r, &out);
    }

    if ((ngx_strncmp(path->data, "/v1",path->len) == 0) || (ngx_strncmp(path->data, "/v1/",path->len) == 0)) {
        size = sizeof("["
                    "\"ssl\","
                    #ifdef NGX_STAT_STUB
                    "\"connections\","
                    #endif
                    "\"nginx\","
                    "\"http\","
                    "\"stream\""
                    "]")+1;
        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_sprintf(b->last, "["
                    "\"ssl\","
                    #ifdef NGX_STAT_STUB
                    "\"connections\","
                    #endif
                    "\"nginx\","
                    "\"http\","
                    "\"stream\""
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
        return ngx_http_output_filter(r, &out);
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
        return ngx_http_output_filter(r, &out);
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
        return ngx_http_output_filter(r, &out);
    }


    if (ngx_strncmp(path->data, "/v1/ssl",path->len) == 0) {
        return ngx_http_status_api_api_handler_ssl(r);
    }

    if (ngx_strncmp(path->data, "/v1/nginx",path->len) == 0) {
        return ngx_http_status_api_api_handler_nginx(r);
    }

    #ifdef NGX_STAT_STUB
    if (ngx_strncmp(path->data, "/v1/connections",path->len) == 0) {
        return ngx_http_status_api_api_handler_connections(r);
    }
    if (ngx_strncmp(path->data, "/v1/http/requests",path->len) == 0) {
      return ngx_http_status_api_api_handler_requests(r);
    }
    #endif
    if (ngx_strncmp(path->data, "/v1/http/server_zones",path->len) == 0) {
      return ngx_http_status_api_api_handler_server_zones(r);
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




//handle nginx statistic
static ngx_int_t ngx_http_status_api_api_handler_nginx(ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         out;
    ngx_int_t                           rc;

    struct timeval   tv;

    b = ngx_create_temp_buf(r->pool, 65535);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


    ngx_gettimeofday(&tv);

    out.buf = b;
    out.next = NULL;
    b->last = ngx_sprintf(b->last,"{\"version\": \"%s\",",NGINX_VERSION);
    b->last = ngx_sprintf(b->last,"\"build\": \"%s\",",NGX_BUILD);
    b->last = ngx_sprintf(b->last,"\"hostname\": \"%V\",",&ngx_cycle->hostname);
    b->last = ngx_sprintf(b->last,"\"timestmap\": %ui,",tv.tv_sec);
    b->last = ngx_sprintf(b->last,"\"load_timestamp\": %ui}",*get_config_load_time());

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


//handle server_zones statistic
static ngx_int_t ngx_http_status_api_api_handler_server_zones(ngx_http_request_t *r) {
    ngx_uint_t                          i,num;
    ngx_http_status_api_counters_t      *counters;
    ngx_buf_t                           *b;
    ngx_chain_t                         out;
    ngx_int_t                           rc;
    ngx_uint_t                          handshakes,session_reuses,handshake_timeout,handshakes_failed;
    ngx_uint_t resp_total,resp_1xx,resp_2xx,resp_3xx,resp_4xx,resp_5xx,in_bytes,out_bytes;
    ngx_slab_pool_t                     *shpool;
    ngx_http_core_srv_conf_t            **cscfp;
    ngx_http_status_api_srv_conf_t      *sslscf;


    b = ngx_create_temp_buf(r->pool, 655350);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, "{");

    // get core main conf
    ngx_http_core_main_conf_t *cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    // get all servers in current worker
    cscfp = cmcf->servers.elts;
    num = cmcf->servers.nelts;

    for (i = 0; i < num; i++) {
        // this module config
        sslscf = cscfp[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        if (sslscf->shm_zone != NULL  && sslscf->shm_zone->shm.addr != NULL) {
            shpool = (ngx_slab_pool_t *) sslscf->shm_zone->shm.addr;
            if (shpool == NULL) {
                dbg_http_status_api_log_error(r->connection->log,"[http-status-api][api_handler_server_zones][%i] Var is NULL shpool.",i);
                continue;
            }
            counters = sslscf->shm_zone->data;
            if (counters!=NULL) {
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Try lock mutex for shpool.",i);
                ngx_shmtx_lock(&shpool->mutex);//Mutex
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Mutex lock SUCCESS.",i);

                handshakes = counters->ssl_accept;
                handshakes_failed = counters->ssl_accept - counters->ssl_accept_good;
                session_reuses =  counters->ssl_hits;
                handshake_timeout = counters->ssl_timeouts;

                resp_total = counters->resp_total;
                resp_1xx = counters->resp_1xx;
                resp_2xx = counters->resp_2xx;
                resp_3xx = counters->resp_3xx;
                resp_4xx = counters->resp_4xx;
                resp_5xx = counters->resp_5xx;
                in_bytes = counters->in_bytes;
                out_bytes = counters->out_bytes;




                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%s] Stat from zones get success",sslscf->shm_zone->shm.name.data);
                b->last = ngx_sprintf(b->last, "\"%s\":{",sslscf->shm_zone->shm.name.data);

                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Try unlock mutex for shpool.",i);
                ngx_shmtx_unlock(&shpool->mutex);//Mutex
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][api_handler_server_zones][%i] Mutex unlock SUCCESS.",i);

                b->last = ngx_sprintf(b->last, "\"ssl\":{\"handshakes\":%ui,\"session_reuses\":%ui,\"handshakes_failed\":%ui,\"handshake_timeout\":%ui},",
                  handshakes,session_reuses,handshakes_failed,handshake_timeout);
                b->last = ngx_sprintf(b->last,
                                    "\"responses\":{"
                                        "\"total\": %ui,"
                                        "\"1xx\": %ui,"
                                        "\"2xx\": %ui,"
                                        "\"3xx\": %ui,"
                                          "\"4xx\": %ui,"
                                          "\"5xx\": %ui"
                                    "},",
                                          resp_total,
                                          resp_1xx,
                                          resp_2xx,
                                          resp_3xx,
                                          resp_4xx,
                                          resp_5xx);
                b->last = ngx_sprintf(b->last,
                                    "\"received\": %ui,"
                                    "\"sent\": %ui", in_bytes, out_bytes);
                } else {
                    dbg_http_status_api_log_error(r->connection->log,"[http-status-api][api_handler_server_zones] zone %i counters is NULL found",i);
                }

                if (i == num-1) {
                    b->last = ngx_sprintf(b->last, "}");
                } else {
                    b->last = ngx_sprintf(b->last, "},");
                }
        }

    }

    b->last = ngx_sprintf(b->last, "}");


    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


//handle SSL statistic
static ngx_int_t ngx_http_status_api_api_handler_ssl(ngx_http_request_t *r) {
    ngx_uint_t                          i,num;
    ngx_http_status_api_counters_t      *counters;
    ngx_buf_t                           *b;
    ngx_chain_t                         out;
    ngx_int_t                           rc;
    ngx_uint_t                          handshakes = 0;
    ngx_uint_t            				session_reuses = 0;
    ngx_uint_t 							handshake_timeout = 0;
    ngx_uint_t						    handshakes_failed = 0;
    ngx_slab_pool_t                     *shpool;
    ngx_http_core_main_conf_t 			*cmcf;
    ngx_http_core_srv_conf_t            **cscfp;
    ngx_http_status_api_srv_conf_t      *sslscf;
    ngx_http_status_api_srv_conf_t      *hsamcf;

    //Get default zone stat
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_status_api_module);
    hsamcf = (ngx_http_status_api_srv_conf_t *) cmcf;
    if (hsamcf!= NULL && hsamcf->shm_zone != NULL && hsamcf->shm_zone->shm.addr != NULL) {
      		dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Get stat from default status_zone");
            shpool = (ngx_slab_pool_t *) hsamcf->shm_zone->shm.addr;
            if (shpool != NULL)  {
            	dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Try lock mutex for shpool.");
            	ngx_shmtx_lock(&shpool->mutex);//Mutex
            	dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Mutex lock SUCCESS.");

            	counters = hsamcf->shm_zone->data;
                if (counters!=NULL) {

                	handshakes += counters->ssl_accept;
                	handshakes_failed += counters->ssl_accept - counters->ssl_accept_good;
                	session_reuses +=  counters->ssl_hits;
                	handshake_timeout += counters->ssl_timeouts;

         		} else {
              		dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][default] counters is NULL");
            	}
                dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Try unlock mutex for shpool.");
            	ngx_shmtx_unlock(&shpool->mutex);//Mutex
            	dbg_http_status_api_log_info(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Mutex unlock SUCCESS.");

            } else {
      			dbg_http_status_api_log_error(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][default] Var is NULL shpool.");
            }
    }

    //Get servers status_zone stat
    // get core main conf
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    // get all servers in current worker
    cscfp = cmcf->servers.elts;
    num = cmcf->servers.nelts;

;


    for (i = 0; i < num ; i++) {
       	sslscf = cscfp[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        if (sslscf->shm_zone != NULL  && sslscf->shm_zone->shm.addr != NULL) {
            shpool = (ngx_slab_pool_t *) sslscf->shm_zone->shm.addr;
            if (shpool == NULL) {
                dbg_http_status_api_log_error(r->connection->log,"[http-status-api][ngx_http_status_api_api_handler_ssl][%i] Var is NULL shpool.",i);
                continue;
            }
            counters = sslscf->shm_zone->data;
            if (counters!=NULL) {
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][%i] Try lock mutex for shpool.",i);
                ngx_shmtx_lock(&shpool->mutex);//Mutex
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][%i] Mutex lock SUCCESS.",i);


                handshakes += counters->ssl_accept;
                handshakes_failed += counters->ssl_accept - counters->ssl_accept_good;
                session_reuses +=  counters->ssl_hits;
                handshake_timeout += counters->ssl_timeouts;

                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][%i] Try unlock mutex for shpool.",i);
                ngx_shmtx_unlock(&shpool->mutex);//Mutex
                dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][%i] Mutex unllock SUCCESS.",i);


            } else {
              	dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_api_handler_ssl][%i] counters is NULL found",i);
            }
        }
    }



    b = ngx_create_temp_buf(r->pool, 65535);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, "{\"handshakes\":%ui,\"session_reuses\":%ui,\"handshakes_failed\":%ui,\"handshake_timeout\":%ui}",
            handshakes,session_reuses,handshakes_failed,handshake_timeout);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


#ifdef NGX_STAT_STUB
//handle nginx connections statistic
static ngx_int_t ngx_http_status_api_api_handler_connections (ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         out;
    ngx_int_t                           rc;
    ngx_atomic_int_t                    conn_accepted,conn_dropped,conn_handled,conn_active,conn_idle,conn_reading,conn_writing;

    b = ngx_create_temp_buf(r->pool, 65535);
    if (b == NULL) {
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




    b->last = ngx_sprintf(b->last,"{\"accepted\": %ui,", conn_accepted);
    b->last = ngx_sprintf(b->last,"\"dropped\": %ui,", conn_dropped);
    b->last = ngx_sprintf(b->last,"\"active\": %ui,",conn_active);
    b->last = ngx_sprintf(b->last,"\"idle\": %ui}",conn_idle);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

//handle nginx requests statistic
static ngx_int_t ngx_http_status_api_api_handler_requests (ngx_http_request_t *r) {
    ngx_buf_t                           *b;
    ngx_chain_t                         out;
    ngx_int_t                           rc;
    ngx_atomic_int_t                    requests,conn_reading,conn_writing;

    b = ngx_create_temp_buf(r->pool, 65535);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    conn_reading = *ngx_stat_reading;
    conn_writing = *ngx_stat_writing;
	requests = *ngx_stat_requests;


    b->last = ngx_sprintf(b->last,"{"
			"\"total\": %uA,"
			"\"current\": %uA"
                                  "}",requests,conn_reading+conn_writing);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}
#endif





