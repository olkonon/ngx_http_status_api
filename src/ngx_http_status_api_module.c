/* @source ngx_http_status_api_module
* Nginx statistics module.
* @author: Kononenko Oleg (o.kononenko@qiwi.com)
*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_status_api_module.h"
#include "ngx_http_status_api_api_handler.h"

static ngx_array_t *http_status_api_ctx = NULL;
ngx_array_t *get_http_status_api_ctx() {
  return http_status_api_ctx;
}

static int *load_config_sec = NULL;

int *get_config_load_time() {
  return load_config_sec;
}


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_int_t ngx_http_status_api_server_zone_counter(ngx_http_request_t *r);
static void *ngx_http_status_api_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_status_api_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_status_api_module_init_worker(ngx_cycle_t *cycle);
static char *ngx_http_status_api(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_status_api_zone(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);


/* Timer event for periodic stat polling */
static ngx_event_t ngx_http_status_api_timer;
// milliseconds

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

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

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

static ngx_int_t
ngx_http_status_api_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    shm_zone->data = ngx_slab_calloc(shpool,
            sizeof(ngx_http_status_api_counters_t));

    if (shm_zone->data == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_status_api_add_shm_to_ctx(ngx_conf_t *cf,ngx_shm_zone_t *shm_zone,ngx_str_t *name) {
    ngx_http_status_api_ctx_record_t *record,*records;
    ngx_uint_t i;

    if (http_status_api_ctx == NULL) {
        http_status_api_ctx = ngx_array_create(cf->pool, 1, sizeof(ngx_http_status_api_ctx_record_t));
        if (http_status_api_ctx == NULL) {
            ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,"http_status_api_ctx create error, zone %V",name);
            return NGX_ERROR;
        } else {
            records = http_status_api_ctx->elts;
            records[0].name.len = name->len;
            records[0].name.data = name->data;
            records[0].shm_zone = shm_zone;
            return NGX_OK;
        }
    } else {
      //Remove duplicate zones
      records = http_status_api_ctx->elts;
      for(i=0;i<http_status_api_ctx->nelts;i++) {
        if (ngx_strcmp(&records[i].name, name) == 0) {
            if (records[i].shm_zone == shm_zone) {
                return NGX_OK;
            }
        }
      }
    }

    record = ngx_array_push(http_status_api_ctx);
    ngx_memzero(record, sizeof(ngx_http_status_api_ctx_record_t));

    if (record == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"[http-status-api] create record error, zone %V",name);
        return NGX_ERROR;
    }

    record->name.len = name->len;
    record->name.data = name->data;
    record->shm_zone = shm_zone;


    return NGX_OK;
}


static ngx_shm_zone_t* get_or_create_shm_zone(ngx_conf_t *cf, ngx_str_t *name) {
    ngx_str_t *shm_name_prefix;
    ngx_str_t *shm_name;
    ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
           "[status-api][get_or_create_shm_zone] Init zone  \"%V\"", name);
    //Init prefix for shm status_zone
    shm_name_prefix = ngx_palloc(cf->pool,sizeof(ngx_str_t));
    ngx_str_set(shm_name_prefix,"http-status-api-");

    //Init real name of shm
    shm_name = ngx_pcalloc(cf->pool,sizeof(ngx_str_t));
    if (shm_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,"[status-api][get_or_create_shm_zone] can't alocate mem for zone creating\"%s\"", name->data);
        return NULL;
    }

    shm_name->len = shm_name_prefix->len + name->len + 1;
    shm_name->data = ngx_pcalloc(cf->pool,sizeof(u_char)*shm_name->len);
    ngx_snprintf(shm_name->data, shm_name->len, "%V%V", shm_name_prefix, name);
    ngx_pfree(cf->pool,shm_name_prefix);

    //Create SHM
    ngx_shm_zone_t* zone = ngx_shared_memory_add(cf, shm_name, SHM_SIZE,
                                                 &ngx_http_status_api_module);
    if (zone == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
                "[status-api][get_or_create_shm_zone] error accessing shm-zone \"%s\"", name->data);
        return NULL;
    }
    zone->init = ngx_http_status_api_init_zone;


    if (ngx_http_status_api_add_shm_to_ctx(cf, zone, name)!= NGX_OK) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
        "[status-api][get_or_create_shm_zone] can't create context for shm-zone \"%s\"", name->data);
        return NULL;
    };

    return zone;
}



/* Location configuration, status_api directive */
static char *
ngx_http_status_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t        *clcf;
    // attach handler to generate reply on this location
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_api_api_handler;
    return NGX_CONF_OK;
}


// add only delta (current - previous) to counter in shm
// remember last (current) value for feature calls
#define ngx_http_status_api_add_ssl_counter_delta(counter, openssl_func) \
    tmp = openssl_func(sscf->ssl.ctx); \
    counters->counter += tmp - sslscf->prev_counters->counter; \
    sslscf->prev_counters->counter = tmp;

#define ngx_http_status_api_add_response_counter_delta(counter, delta) \
    counters->counter += delta; \


/* This will be called by timer to append openssl stat values of current worker
 * process to counters in shm */
static void ngx_http_status_api_poll_stat(ngx_event_t *ev) {
    ngx_uint_t                       s, tmp;
    ngx_http_core_main_conf_t       *cmcf = ev->data;
    ngx_http_ssl_srv_conf_t         *sscf;
    ngx_http_core_srv_conf_t       **cscfp;
    ngx_http_status_api_srv_conf_t  *sslscf;
    ngx_http_status_api_counters_t  *counters;
    ngx_slab_pool_t                           *shpool;

    // get all servers in current worker
    cscfp = cmcf->servers.elts;

    // for server_index in servers
    for (s = 0; s < cmcf->servers.nelts; s++) {
        //ssl module config
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        // this module config
        sslscf = cscfp[s]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        // if ssl_status_zone is defined && ssl is enabled
        if (sslscf->shm_zone != NULL && sscf->ssl.ctx != NULL) {
            shpool = (ngx_slab_pool_t *) sslscf->shm_zone->shm.addr;
            ngx_shmtx_lock(&shpool->mutex);//Mutex
            counters = sslscf->shm_zone->data;

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept, SSL_CTX_sess_accept);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept_good, SSL_CTX_sess_accept_good);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_hits, SSL_CTX_sess_hits);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_timeouts, SSL_CTX_sess_timeouts);
            ngx_shmtx_unlock(&shpool->mutex);//Mutex
        }
    }

    ngx_add_timer(ev, STAT_POLL_INTERVAL);
}


/* Server configuration, ssl_status_zone directive */
static char *
ngx_http_status_api_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_status_api_srv_conf_t  *sslscf = conf;
    ngx_str_t                       *value = cf->args->elts;

    sslscf->shm_zone = get_or_create_shm_zone(cf, &value[1]);
    if (sslscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static void *ngx_http_status_api_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_status_api_srv_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_srv_conf_t));
    conf->prev_counters = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_status_api_counters_t));
    ngx_str_t default_zone_name = ngx_string(SHM_DEFAULT_NAME);
    conf->shm_zone = get_or_create_shm_zone(cf, &default_zone_name);
    if (conf->shm_zone == NULL)
        return NULL;
    return conf;
}


static void *ngx_http_status_api_create_loc_conf(ngx_conf_t *cf) {
    struct timeval   tv;
    load_config_sec = ngx_pcalloc(cf->pool, sizeof(int));
    ngx_gettimeofday(&tv);
    *load_config_sec = tv.tv_sec;

    ngx_http_status_api_loc_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_loc_conf_t));


    return conf;
}


/* When a worker has started: run periodic task to poll openssl stats */
static ngx_int_t ngx_http_status_api_module_init_worker(ngx_cycle_t *cycle) {
    ngx_http_core_main_conf_t  *cmcf = ngx_http_cycle_get_module_main_conf(
            cycle, ngx_http_core_module);


    ngx_http_status_api_timer.handler = ngx_http_status_api_poll_stat;
    ngx_http_status_api_timer.log = cycle->log;
    // attach ngx_http_core_main_conf_t struct to access all configured servers
    ngx_http_status_api_timer.data = cmcf;
    // allows workers shutting down gracefully
    ngx_http_status_api_timer.cancelable = 1;
    ngx_add_timer(&ngx_http_status_api_timer, STAT_POLL_INTERVAL);

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_status_api_server_zone_counter;
    return NGX_OK;
}


ngx_int_t get_in_request_body_size(ngx_http_request_t *r) {
    ngx_int_t size = 0;

    if (r->headers_in.content_length_n != -1) {
        size = r->headers_in.content_length_n;
    }

    return size;
}


ngx_int_t get_out_request_body_size(ngx_http_request_t *r) {
    ngx_int_t size = 0;

    if (r->headers_out.content_length_n != -1) {
        size = r->headers_out.content_length_n;
    }

    return size;
}

static ngx_int_t ngx_http_status_api_server_zone_counter(ngx_http_request_t *r) {
  ngx_http_status_api_srv_conf_t  *srv_cf;
  ngx_uint_t in_bytes,out_bytes;
  ngx_http_status_api_counters_t  *counters;
  ngx_slab_pool_t                           *shpool;
  ngx_int_t status;

  srv_cf = ngx_http_get_module_srv_conf(r, ngx_http_status_api_module);
  in_bytes = get_in_request_body_size(r);
  out_bytes = get_out_request_body_size(r);
  status = r->headers_out.status;


  if ( (srv_cf !=NULL ) && (srv_cf->shm_zone != NULL) ) {
      shpool = (ngx_slab_pool_t *) srv_cf->shm_zone->shm.addr;
      ngx_shmtx_lock(&shpool->mutex); //Mutex

      counters = srv_cf->shm_zone->data;

      if ( status >= 0 &&   status <200) {
             ngx_http_status_api_add_response_counter_delta(
                    resp_1xx, 1);
      } else if (status >= 200 && status < 300) {
                     ngx_http_status_api_add_response_counter_delta(
                    resp_2xx, 1);
      } else if (status >= 300 && status < 400) {
                          ngx_http_status_api_add_response_counter_delta(
                    resp_3xx, 1);
      } else if (status >= 400 && status < 500) {
                          ngx_http_status_api_add_response_counter_delta(
                    resp_4xx, 1);
      } else if (status >= 500 && status < 600) {
                          ngx_http_status_api_add_response_counter_delta(
                    resp_5xx, 1);
      }

      ngx_http_status_api_add_response_counter_delta(
                    resp_total, 1);

       ngx_http_status_api_add_response_counter_delta(
                   in_bytes,in_bytes);

        ngx_http_status_api_add_response_counter_delta(
                    out_bytes, out_bytes);
       ngx_shmtx_unlock(&shpool->mutex);//Mutext
  }


  return ngx_http_next_header_filter(r);
}