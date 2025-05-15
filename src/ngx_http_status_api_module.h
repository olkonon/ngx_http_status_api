//
// Created by o.kononenko on 13.02.2025.
//

#ifndef NGX_HTTP_STATUS_API_MODULE_H
#define NGX_HTTP_STATUS_API_MODULE_H
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define SHM_SIZE 65536
#define SHM_DEFAULT_NAME "default"
#define STAT_POLL_INTERVAL 1000

#ifdef NGX_DEBUG
    #define dbg_http_status_api_conf_log_info(cf,...)                 ngx_conf_log_error (NGX_LOG_INFO, cf, 0, __VA_ARGS__)
    #define dbg_http_status_api_log_info(log,...)                     ngx_log_error (NGX_LOG_INFO, log, 0, __VA_ARGS__)

    #define dbg_http_status_api_conf_log_error(cf,...)                ngx_conf_log_error (NGX_LOG_ERR, cf, 0, __VA_ARGS__)
    #define dbg_http_status_api_log_error(log,...)                    ngx_log_error (NGX_LOG_ERR, log, 0, __VA_ARGS__)
#else
    #define dbg_http_status_api_conf_log_info(cf,...)
    #define dbg_http_status_api_log_info(log,...)

    #define dbg_http_status_api_conf_log_error(cf,...)
    #define dbg_http_status_api_log_error(log,...)
#endif

ngx_array_t *get_http_status_api_ctx();
int *get_config_load_time();

typedef struct {
    ngx_uint_t ssl_accept;
    ngx_uint_t ssl_accept_good;
    ngx_uint_t ssl_hits;
    ngx_uint_t ssl_timeouts;
    ngx_uint_t resp_total;
    ngx_uint_t resp_1xx;
    ngx_uint_t resp_2xx;
    ngx_uint_t resp_3xx;
    ngx_uint_t resp_4xx;
    ngx_uint_t resp_5xx;
    ngx_uint_t in_bytes;
    ngx_uint_t out_bytes;
} ngx_http_status_api_counters_t;

typedef struct {
    ngx_str_t name;
    ngx_shm_zone_t *shm_zone;
} ngx_http_status_api_ctx_record_t;


typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_status_api_loc_conf_t;


typedef struct {
    ngx_shm_zone_t *shm_zone;
    ngx_http_status_api_counters_t *prev_counters;
} ngx_http_status_api_srv_conf_t;

//export module for linking
extern ngx_module_t ngx_http_status_api_module;

#endif //NGX_HTTP_STATUS_API_MODULE_H
