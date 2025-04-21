//
// Created by o.kononenko on 21.04.2025.
//
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_status_api_handler_streams.h"

#ifdef NGX_STREAM_STS_STATUS
#include "ngx_http_stream_server_traffic_status_display.h"
#endif

ngx_int_t ngx_http_status_api_handler_streams_handler(ngx_http_request_t *r) {
#ifdef NGX_STREAM_STS_STATUS
    return ngx_http_stream_server_traffic_status_display_handler_default(r);
#else
    return NGX_HTTP_NOT_FOUND;
#endif
}