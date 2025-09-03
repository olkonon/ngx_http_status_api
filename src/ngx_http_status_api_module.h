//
// Created by o.kononenko on 13.02.2025.
//

#ifndef NGX_HTTP_STATUS_API_MODULE_H
#define NGX_HTTP_STATUS_API_MODULE_H
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define SHM_ZONE_PREFIX "http-status-api-"
//#define SHM_ZONE_PREFIX_LEN 16 // len in bytes of string SHM_ZONE_PREFIX
#define SHM_ZONE_PREFIX_LEN sizeof(SHM_ZONE_PREFIX)-1
#define SHM_SIZE 2*ngx_pagesize
#define STAT_POLL_INTERVAL 1000


//logging primitives
#define http_status_api_log_error(log,...)                        ngx_log_error (NGX_LOG_ERR, log, 0, __VA_ARGS__)
#define http_status_api_conf_log_error(cf,...)                    ngx_conf_log_error (NGX_LOG_ERR, cf, 0, __VA_ARGS__)

#define http_status_api_log_info(log,...)                        ngx_log_error (NGX_LOG_INFO, log, 0, __VA_ARGS__)
#define http_status_api_conf_log_info(cf,...)                    ngx_conf_log_error (NGX_LOG_INFO, cf, 0, __VA_ARGS__)

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

int *get_config_load_time();

typedef struct {
    ngx_uint_t  ssl_accept;
    ngx_uint_t  ssl_accept_good;
    ngx_uint_t  ssl_hits;
    ngx_uint_t  ssl_timeouts;
    ngx_uint_t  prev_ssl_accept;
    ngx_uint_t  prev_ssl_accept_good;
    ngx_uint_t  prev_ssl_hits;
    ngx_uint_t  prev_ssl_timeouts;
    ngx_uint_t  resp_total;
    ngx_uint_t  resp_1xx;
    ngx_uint_t  resp_2xx;
    ngx_uint_t  resp_3xx;
    ngx_uint_t  resp_4xx;
    ngx_uint_t  resp_5xx;
    ngx_uint_t  in_bytes;
    ngx_uint_t  out_bytes;
    int         load_config_timestamp;
    int         nginx_load_timestamp;

} ngx_http_status_api_counters_t;

typedef struct {
    ngx_slab_pool_t *shpool;
    ngx_http_status_api_counters_t *counters;
} ngx_http_status_api_shm_ctx;

typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_status_api_loc_conf_t;


typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_status_api_srv_conf_t;


//export module for linking
extern ngx_module_t ngx_http_status_api_module;

#endif //NGX_HTTP_STATUS_API_MODULE_H
