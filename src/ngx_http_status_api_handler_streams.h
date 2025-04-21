//
// Created by o.kononenko on 21.04.2025.
//

#ifndef NGX_HTTP_STATUS_API_HANDLER_STREAMS_H
#define NGX_HTTP_STATUS_API_HANDLER_STREAMS_H
#define NGX_HTTP_STATUS_API_JSON_FMT_UPSTREAM_S  "{"
#define NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_S     "\"%V\":["
#define NGX_HTTP_STATUS_API_JSON_FMT_ARRAY_E     "]"
#define NGX_HTTP_STATUS_API_JSON_FMT_NEXT        ","
#define NGX_HTTP_STATUS_API_JSON_FMT_E           "}"
#define NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT        ","

#define NGX_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM                \
    "{\"server\":\"%V\","                                                      \
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"sessionMsecCounter\":%uA,"                                              \
    "\"sessionMsec\":%M,"                                                      \
    "\"uSessionMsecCounter\":%uA,"                                             \
    "\"uSessionMsec\":%M,"                                                     \
    "\"uConnectMsecCounter\":%uA,"                                             \
    "\"uConnectMsec\":%M,"                                                     \
    "\"uFirstByteMsecCounter\":%uA,"                                           \
    "\"uFirstByteMsec\":%M,"                                                   \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s"                                                             \
    "},"


ngx_int_t ngx_http_status_api_handler_streams_handler(ngx_http_request_t *r);
#endif //NGX_HTTP_STATUS_API_HANDLER_STREAMS_H
