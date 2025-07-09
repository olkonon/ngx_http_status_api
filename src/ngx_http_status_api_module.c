/* @source ngx_http_status_api_module
* Nginx statistics module.
* @author: Kononenko Oleg (o.kononenko@qiwi.com)
*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_status_api_module.h"
#include "ngx_http_status_api_handler.h"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_int_t ngx_http_status_api_server_zone_counter(ngx_http_request_t *r);
static void *ngx_http_status_api_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_status_api_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_status_api_module_init_worker(ngx_cycle_t *cycle);
static char *ngx_http_status_api(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_status_api_zone(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
//+ Timer event for periodic stat polling
static ngx_event_t ngx_http_status_api_timer;

static ngx_command_t  ngx_http_status_api_module_commands[] = {

    { ngx_string("status_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_status_api,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_status_api_loc_conf_t, shm_zone),
      NULL },

    { ngx_string("status_zone"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_status_api_zone,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_status_api_srv_conf_t, shm_zone),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_status_api_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,    							   /* init main configuration */


    ngx_http_status_api_create_srv_conf,   /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_status_api_create_loc_conf,   /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_status_api_module = {
    NGX_MODULE_V1,
    &ngx_http_status_api_module_ctx,         /* module context */
    ngx_http_status_api_module_commands,     /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    ngx_http_status_api_module_init_worker,  /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

//+ Callback for init SHM zone for status_zone
static ngx_int_t
ngx_http_status_api_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
    struct timeval                  tv;
    ngx_http_status_api_shm_ctx     *old_ctx=data;
    ngx_http_status_api_shm_ctx     *ctx=shm_zone->data;

    if (old_ctx) {
        ctx->counters = old_ctx->counters;
        ctx->shpool = old_ctx->shpool;
        ctx->name = old_ctx->name;
        //ssl ctx counters reset when reload
        ctx->prev_counters = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_status_api_counters_t));
        if (ctx->prev_counters == NULL) {
            return NGX_ERROR;
        }
        ngx_gettimeofday(&tv);
        ctx->nginx_load_timestamp = old_ctx->nginx_load_timestamp;
        ctx->load_config_timestamp = tv.tv_sec;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ctx->counters = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_status_api_counters_t));
    if (ctx->counters == NULL) {
        return NGX_ERROR;
    }
    ctx->prev_counters = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_status_api_counters_t));
    if (ctx->prev_counters == NULL) {
        return NGX_ERROR;
    }

    ngx_gettimeofday(&tv);
    ctx->nginx_load_timestamp = tv.tv_sec;
    ctx->load_config_timestamp = tv.tv_sec;

  //  ctx->shpool->log_nomem = 0;
    return NGX_OK;
}

//+ Get or create SHM zone with name
static ngx_shm_zone_t* get_or_create_shm_zone(ngx_conf_t *cf, ngx_str_t *name) {
    ngx_shm_zone_t                 *shm_zone;
    ngx_str_t               *shm_name_prefix;
    ngx_str_t                      *shm_name;
    ngx_http_status_api_shm_ctx         *ctx;


	http_status_api_conf_log_info(cf, "[http-status-api][get_or_create_shm_zone][%V] Start init zone.", name);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_status_api_shm_ctx));
    if (ctx == NULL) {
        dbg_http_status_api_conf_log_error(cf,"[http-status-api][get_or_create_shm_zone][%V] Error creating ngx_http_status_api_shm_ctx", name);
        return NULL;
    }

    ctx->name = ngx_palloc(cf->pool,sizeof(ngx_str_t));
    ctx->name->len = name->len;
    ctx->name->data = ngx_palloc(cf->pool,sizeof(u_char)*name->len);
    ngx_snprintf( ctx->name->data,  ctx->name->len, "%V", name);

    dbg_http_status_api_conf_log_info(cf, "[http-status-api][get_or_create_shm_zone][%V] ngx_http_status_api_shm_ctx create success.", name);


    //Init prefix for shm status_zone
    shm_name_prefix = ngx_palloc(cf->pool,sizeof(ngx_str_t));
    ngx_str_set(shm_name_prefix,"http-status-api-");

    //Init real name of shm
    shm_name = ngx_pcalloc(cf->pool,sizeof(ngx_str_t));
    if (shm_name == NULL) {
        dbg_http_status_api_conf_log_error(cf,"[http-status-api][get_or_create_shm_zone][%V] Can't allocate mem for zone creating.", name);
        return NULL;
    }

    shm_name->len = shm_name_prefix->len + name->len + 1;
    shm_name->data = ngx_pcalloc(cf->pool,sizeof(u_char)*shm_name->len);
    ngx_snprintf(shm_name->data, shm_name->len, "%V%V", shm_name_prefix, name);
    ngx_pfree(cf->pool,shm_name_prefix);

    //Create SHM
	shm_zone = ngx_shared_memory_add(cf, shm_name, SHM_SIZE,&ngx_http_status_api_module);
    if (shm_zone == NULL) {
    	http_status_api_conf_log_error(cf,"[http-status-api][get_or_create_shm_zone][%V] Error creating shm-zone", name);
        return NULL;
    }
    if (shm_zone->data) {
        dbg_http_status_api_conf_log_info(cf,"[http-status-api][get_or_create_shm_zone][%V] Reusing zone.", name);
        return shm_zone;
    }

    shm_zone->init = ngx_http_status_api_init_zone;
    shm_zone->data = ctx;

    return shm_zone;
}

//+ Location configuration, status_api directive
static char *
ngx_http_status_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t        *loc_conf;
    // attach handler to generate reply on this location
    loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    loc_conf->handler = ngx_http_status_api_handler;
    return NGX_CONF_OK;
}

/*+ Poll SSL stat timer callback
This will be called by timer to append openssl stat values of current worker
process to counters in shm */
static void ngx_http_status_api_poll_stat(ngx_event_t *ev) {
    // add only delta (current - previous) to counter in shm
    // remember last (current) value for feature calls
    #define ngx_http_status_api_add_ssl_counter_delta(counter, openssl_func) \
        counter_val = openssl_func(ssl_conf->ssl.ctx); \
        ctx->counters->counter += counter_val - ctx->prev_counters->counter; \
        ctx->prev_counters->counter = counter_val;


    ngx_cycle_t                     *cycle = ev->data;
    ngx_http_core_main_conf_t       *core_main_conf;
    ngx_uint_t				        num_servers,i,counter_val;
    ngx_http_core_srv_conf_t        **servers_conf_list;
    ngx_http_ssl_srv_conf_t         *ssl_conf;
    ngx_http_status_api_srv_conf_t  *server_conf;
    ngx_http_status_api_shm_ctx     *ctx;

    core_main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    servers_conf_list = core_main_conf->servers.elts; // get all servers conf in current worker
    num_servers = core_main_conf->servers.nelts;  // get all servers count in current worker
    //Get conigs

    dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat] Start stat timer.");
 	dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat] Get %ui servers from configs",num_servers);



    for (i = 0; i < num_servers; i++) {
        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Process server",i);
		//ssl module config
        ssl_conf = servers_conf_list[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        // this module config
        server_conf = servers_conf_list[i]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        //if ssl not enabled for server
        if ( ssl_conf->ssl.ctx == NULL) {
          dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Server hasn't ssl context http server only",i);
          continue;
        }

        if (server_conf->shm_zone == NULL) {
            dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Server hasn't status_zone directive",i);
            continue;
        }

	    //SSL only server
        // if status_zone defined & enabled
        ctx = server_conf->shm_zone->data;
        if (!ctx) {
             dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] ctx is NULL ", i);
             continue;
        }

        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Try lock mutex for SHM", i);
        ngx_shmtx_lock(&ctx->shpool->mutex);//Mutex
        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Mutex lock success.", i);

        ngx_http_status_api_add_ssl_counter_delta(ssl_accept, SSL_CTX_sess_accept);
        ngx_http_status_api_add_ssl_counter_delta(ssl_accept_good, SSL_CTX_sess_accept_good);
        ngx_http_status_api_add_ssl_counter_delta(ssl_hits, SSL_CTX_sess_hits);
        ngx_http_status_api_add_ssl_counter_delta(ssl_timeouts, SSL_CTX_sess_timeouts);

        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Try unlock mutex for SHM", i);
        ngx_shmtx_unlock(&ctx->shpool->mutex);//Mutex
        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Mutex unlock success.", i);
    }

    ngx_add_timer(ev, STAT_POLL_INTERVAL);
}

// Server configuration, status_zone directive
static char *
ngx_http_status_api_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_status_api_srv_conf_t  *srv_cf = conf;
    ngx_str_t                       *value = cf->args->elts;
    ngx_str_t 						*zone_name = &value[1];

    dbg_http_status_api_conf_log_info(cf,"[http-status-api][ngx_http_status_api_zone][%V] Init status zone from configuration.",zone_name);


	dbg_http_status_api_conf_log_info(cf,"[http-status-api][ngx_http_status_api_zone][%V] Create new srv_cf->shm_zone",zone_name);
    srv_cf->shm_zone = get_or_create_shm_zone(cf, zone_name);
    if (srv_cf->shm_zone==NULL) {
        dbg_http_status_api_conf_log_info(cf,"[http-status-api][ngx_http_status_api_zone][%V] Create srv_cf->shm_zone error",zone_name);
        return NGX_CONF_ERROR;
    }

    dbg_http_status_api_conf_log_info(cf, "[http-status-api][ngx_http_status_api_zone][%V] Create srv_cf->shm_zone success",zone_name);
    return NGX_CONF_OK;
}

//Create module server configs
static void *ngx_http_status_api_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_status_api_srv_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_srv_conf_t));

    return conf;
}

//Create module locations config
static void *ngx_http_status_api_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_status_api_loc_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_loc_conf_t));

    return conf;
}

//+ When a worker has started: run periodic task to poll openssl stats
static ngx_int_t ngx_http_status_api_module_init_worker(ngx_cycle_t *cycle) {
    //Add poll ssl stat timer
    ngx_http_status_api_timer.handler = ngx_http_status_api_poll_stat;
    ngx_http_status_api_timer.log = cycle->log;
    ngx_http_status_api_timer.data = cycle; // attach ngx_cycle_t struct to access to statistic shm
    ngx_http_status_api_timer.cancelable = 1;// allows workers shutting down gracefully
	ngx_add_timer(&ngx_http_status_api_timer, STAT_POLL_INTERVAL);

    //Add top filter for aggregate response statistic
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_status_api_server_zone_counter;
    return NGX_OK;
}

//Counting request size for stat
ngx_int_t get_in_request_body_size(ngx_http_request_t *r) {
    ngx_int_t size = 0;
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    dbg_http_status_api_log_info(r->connection->log,"[http-status-api][get_in_request_body_size] Get Request %V, size: %i",&r->request_line,r->request_line.len);
    size += r->request_line.len+2;//+ "\r\n"

    dbg_http_status_api_log_info(r->connection->log,"[http-status-api][get_in_request_body_size] Header count %i",part->nelts);
    for (ngx_uint_t i = 0;i < part->nelts ; i++) {
        dbg_http_status_api_log_info(r->connection->log,
                                     "[http-status-api][get_in_request_body_size][%i] Header %V : %V len %i",i,
                                     &header[i].key, &header[i].value, header[i].key.len+2+header[i].value.len);
        size += header[i].key.len + 2 + header[i].value.len + 2; // +2 for ": " and +2 for "\r\n"
    }

    // Add "\r\n", body divider
    size += 2;

     dbg_http_status_api_log_info(r->connection->log,"[http-status-api][get_in_request_body_size] Header summary size=%i",size);


    if (r->headers_in.content_length_n != -1) {
        size += r->headers_in.content_length_n;
    }

    dbg_http_status_api_log_info(r->connection->log,"[http-status-api][get_in_request_body_size] Summary out size %i",size);
    return size;
}

//Counting response size for stat
ngx_int_t get_out_request_body_size(ngx_http_request_t *r) {
    ngx_int_t size = 0;

    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *header = part->elts;

    for (ngx_uint_t i = 0; i < part->nelts; i++) {
        dbg_http_status_api_log_info(r->connection->log,
                                     "[http-status-api][get_out_request_body_size][%i] Header %V : %V len %i",i,
                                     &header[i].key, &header[i].value, header[i].key.len+2+header[i].value.len);
        size += header[i].key.len + 2 + header[i].value.len + 2; // +2 for ": " and +2 for "\r\n"
    }

    // Add "\r\n", body divider
    size += 2;

    if (r->headers_out.content_length_n != -1) {
        size += r->headers_out.content_length_n;
    }

    dbg_http_status_api_log_info(r->connection->log,"[http-status-api][get_out_request_body_size] Summary out size %i",size);
    return size;
}

//+ Callback to write response stat to SHM
static ngx_int_t ngx_http_status_api_server_zone_counter(ngx_http_request_t *r) {
    #define ngx_http_status_api_add_response_counter_delta(counter,delta)   \
        ctx->counters->counter += delta;                                    \

    ngx_http_status_api_shm_ctx     *ctx;
    ngx_http_status_api_srv_conf_t  *server_conf;
    ngx_uint_t                      in_bytes,out_bytes;
    ngx_int_t                       status;

    server_conf = ngx_http_get_module_srv_conf(r, ngx_http_status_api_module);

    in_bytes = get_in_request_body_size(r);
    out_bytes = get_out_request_body_size(r);
    status = r->headers_out.status;

    if (server_conf->shm_zone == NULL) {
        dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_server_zone_counter] No status_zone ignore request");
        return ngx_http_next_header_filter(r);
    }

    ctx = server_conf->shm_zone->data;

    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_server_zone_counter] Try lock mutex for SHM.");
    ngx_shmtx_lock(&ctx->shpool->mutex);//Mutex
    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_server_zone_counter] Mutex lock success.");

    if ( status >= 0 &&   status <200) {
        ngx_http_status_api_add_response_counter_delta(resp_1xx,1);
    } else if (status >= 200 && status < 300) {
        ngx_http_status_api_add_response_counter_delta(resp_2xx,1);
    } else if (status >= 300 && status < 400) {
        ngx_http_status_api_add_response_counter_delta(resp_3xx,1);
    } else if (status >= 400 && status < 500) {
        ngx_http_status_api_add_response_counter_delta(resp_4xx,1);
    } else if (status >= 500 && status < 600) {
        ngx_http_status_api_add_response_counter_delta(resp_5xx,1);
    }

    ngx_http_status_api_add_response_counter_delta(resp_total,1);
    ngx_http_status_api_add_response_counter_delta(in_bytes, in_bytes);
    ngx_http_status_api_add_response_counter_delta(out_bytes, out_bytes);

    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_server_zone_counter] Try unlock mutex for SHM.");
    ngx_shmtx_unlock(&ctx->shpool->mutex);//Mutex
    dbg_http_status_api_log_info(r->connection->log, "[http-status-api][ngx_http_status_api_server_zone_counter] Mutex unlock success.");

    return ngx_http_next_header_filter(r);
}
