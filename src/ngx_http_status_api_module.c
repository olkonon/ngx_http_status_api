/* @source ngx_http_status_api_module
* Nginx statistics module.
* @author: Kononenko Oleg (o.kononenko@qiwi.com)
*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_status_api_module.h"
#include "ngx_http_status_api_api_handler.h"

static int *load_config_sec = NULL;

int *get_config_load_time() {
  return load_config_sec;
}


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_int_t ngx_http_status_api_server_zone_counter(ngx_http_request_t *r);
static void *ngx_http_status_api_create_main_conf(ngx_conf_t *cf);
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

    ngx_http_status_api_create_main_conf,  /* create main configuration */
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


static ngx_shm_zone_t* get_or_create_shm_zone(ngx_conf_t *cf, ngx_str_t *name) {
	#ifdef NGX_DEBUG
    	ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "[http-status-api][get_or_create_shm_zone][%V] Start init zone.", name);
    #endif
    //Create SHM
	ngx_shm_zone_t* zone = ngx_shared_memory_add(cf, name, SHM_SIZE,&ngx_http_status_api_module);
    if (zone == NULL) {
    	ngx_conf_log_error(NGX_LOG_ERR, cf, 0,"[http-status-api][get_or_create_shm_zone][%V] Error accessing shm-zone", name);
        return NULL;
    }
	zone->noreuse = 1;
    zone->init = ngx_http_status_api_init_zone;

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
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_core_main_conf_t  *cmcflocal;
    ngx_http_ssl_srv_conf_t         *sscf;
    ngx_http_core_srv_conf_t       **cscfp;
    ngx_http_status_api_srv_conf_t  *sslscf;
    ngx_http_status_api_srv_conf_t  *hsamcf;
    ngx_http_status_api_counters_t  *counters;
    ngx_slab_pool_t                           *shpool;
	ngx_cycle_t *cycle = ev->data;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    cmcflocal = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_status_api_module);

    #ifdef NGX_DEBUG
      ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "[http-status-api][ngx_http_status_api_poll_stat] Start stat timer.");
      ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "[http-status-api][ngx_http_status_api_poll_stat] Nginx state flags ngx_exiting=%i ngx_quit=%i"
                  ,ngx_exiting,ngx_quit);
    #endif
    if (ngx_exiting) {
      #ifdef NGX_DEBUG
      	ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Detect ngx_exiting timer handle stoped.");
      #endif
      return;
    }
    if (ngx_quit) {
      #ifdef NGX_DEBUG
      	ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Detect ngx_quit timer handle stoped.");
      #endif
      return;
    }

    // get all servers in current worker
    cscfp = cmcf->servers.elts;
    //ngx_http_conf_get_module_main_conf(cf, ngx_http_my_module);
	hsamcf = (ngx_http_status_api_srv_conf_t *) cmcflocal;

    // for server_index in servers
    #ifdef NGX_DEBUG
    	ngx_log_error(NGX_LOG_ERR, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Start servers iterate");
    #endif
    for (s = 0; s < cmcf->servers.nelts; s++) {
        dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Process server",s);

		//ssl module config
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        // this module config
        sslscf = cscfp[s]->ctx->srv_conf[ngx_http_status_api_module.ctx_index];
        // if ssl_status_zone is defined && ssl is enabled
        if (sslscf->shm_zone != NULL && sscf->ssl.ctx != NULL && sslscf->shm_zone->shm.addr != NULL) {
      		dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Write stat to server specific status_zone",s);

            shpool = (ngx_slab_pool_t *) sslscf->shm_zone->shm.addr;
            if (shpool == NULL) {
      			dbg_http_status_api_log_error(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Var is NULL shpool.",s);
                continue;
            }
            #ifdef NGX_DEBUG
      			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Try lock mutex for shpool.");
      		#endif
            ngx_shmtx_lock(&shpool->mutex);//Mutex
            #ifdef NGX_DEBUG
      			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Mutex lock SUCCESS.");
      		#endif
            counters = sslscf->shm_zone->data;

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept, SSL_CTX_sess_accept);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept_good, SSL_CTX_sess_accept_good);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_hits, SSL_CTX_sess_hits);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_timeouts, SSL_CTX_sess_timeouts);
            #ifdef NGX_DEBUG
      			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Try unlock mutex for shpool");
      		#endif
            ngx_shmtx_unlock(&shpool->mutex);//Mutex
            #ifdef NGX_DEBUG
      			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "[http-status-api][ngx_http_status_api_poll_stat] Mutex unlock SUCCESS.");
      		#endif
        } else if (hsamcf->shm_zone != NULL && sscf->ssl.ctx != NULL && hsamcf->shm_zone->shm.addr != NULL) {
      		dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Write stat to default status_zone",s);

            shpool = (ngx_slab_pool_t *) hsamcf->shm_zone->shm.addr;
            if (shpool == NULL) {
      			dbg_http_status_api_log_error(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Var is NULL shpool.",s);
                continue;
            }

            dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Try lock mutex for shpool.",s);
            ngx_shmtx_lock(&shpool->mutex);//Mutex
            dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Mutex lock SUCCESS.",s);

            counters = hsamcf->shm_zone->data;

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept, SSL_CTX_sess_accept);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_accept_good, SSL_CTX_sess_accept_good);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_hits, SSL_CTX_sess_hits);

            ngx_http_status_api_add_ssl_counter_delta(
                    ssl_timeouts, SSL_CTX_sess_timeouts);

            dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Try unlock mutex for shpool",s);
            ngx_shmtx_unlock(&shpool->mutex);//Mutex
            dbg_http_status_api_log_info(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Mutex unlock SUCCESS.",s);
        } else {
            dbg_http_status_api_log_error(ev->log,"[http-status-api][ngx_http_status_api_poll_stat][%i] Strange variant, some bugs may be:-)",s);
        }
    }

    ngx_add_timer(ev, STAT_POLL_INTERVAL);
}


/* Server configuration, ssl_status_zone directive */
static char *
ngx_http_status_api_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_status_api_srv_conf_t  *sslscf = conf;
    ngx_str_t                       *value = cf->args->elts;
    ngx_str_t 						*zone_name;

   zone_name = &value[1];

   #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Init status zone from configuration.",zone_name);
   #endif

    if (sslscf->shm_zone == NULL) {
	  #ifdef NGX_DEBUG
   			ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] sslscf->shm_zone is NULL create new",zone_name);
   	  #endif
      sslscf->shm_zone = get_or_create_shm_zone(cf, zone_name );

    } else {
      #ifdef NGX_DEBUG
   			ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] sslscf->shm_zone is not NULL check zone addresses",zone_name);
   	  #endif

      ngx_shm_zone_t *shm_zone = get_or_create_shm_zone(cf, zone_name );
      if (shm_zone == sslscf->shm_zone) {
        #ifdef NGX_DEBUG
   			ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Address is match success",zone_name);
            ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Init status zone from configuration SUCCESS",zone_name);
   	    #endif
        return NGX_CONF_OK;
      } else {
   		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Address NOT match EPIC FAIL!",zone_name);
		return NGX_CONF_ERROR;
      }
    }



    if (sslscf->shm_zone == NULL) {
      	ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Creation zone error  sslscf->shm_zone is NULL EPIC FAIL!",zone_name);
        return NGX_CONF_ERROR;
    }
    #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_zone][%V] Init status zone from configuration SUCCESS",zone_name);
    #endif
    return NGX_CONF_OK;
}

static void *ngx_http_status_api_create_main_conf(ngx_conf_t *cf) {
   ngx_http_status_api_srv_conf_t *conf;

    ngx_str_t default_zone_name = ngx_string(SHM_DEFAULT_NAME);

    #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[ngx_http_status_api_create_main_conf][%V] Init status zone from configuration",&default_zone_name );
    #endif
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_srv_conf_t));
    #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_create_main_conf][%V] new conf allocation success",&default_zone_name );
    #endif
    conf->prev_counters = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_status_api_counters_t));
    #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_create_main_conf][%V] conf->prev_counters allocation success",&default_zone_name );
    #endif
    ngx_shm_zone_t *shm_zone = get_or_create_shm_zone(cf, &default_zone_name);
	if (conf->shm_zone == NULL) {
          #ifdef NGX_DEBUG
   			ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_create_main_conf][%V] conf->shm_zone is NULL reinit",&default_zone_name );
    	  #endif
          conf->shm_zone = shm_zone;

	} else {
        #ifdef NGX_DEBUG
   			ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_create_main_conf][%V] conf->shm_zone is not NULL!",&default_zone_name );
    	#endif
	}

    if (conf->shm_zone == NULL)
        return NULL;

    #ifdef NGX_DEBUG
   		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "[http-status-api][ngx_http_status_api_create_main_conf][%V] Init status zone from configuration SUCCESS!",&default_zone_name );
    #endif
    return conf;
}

static void *ngx_http_status_api_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_status_api_srv_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_status_api_srv_conf_t));
    conf->prev_counters = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_status_api_counters_t));
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
    //Add poll stat timer
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