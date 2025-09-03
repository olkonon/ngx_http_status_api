//
// Created by o.kononenko on 13.02.2025.
//

#ifndef NGX_HTTP_STATUS_API_API_HANDLER_H
#define NGX_HTTP_STATUS_API_API_HANDLER_H

ngx_int_t ngx_http_status_api_handler(ngx_http_request_t *r);

#define NGX_HTTP_STATUS_API_VERSIONS_JSON "[\"v1\"]"

#ifdef NGX_STAT_STUB
    #define NGX_HTTP_STATUS_API_DIVISION_JSON   \
        "["                                     \
            "\"ssl\","                          \
            "\"connections\","                  \
            "\"nginx\","                        \
            "\"http\","                         \
            "\"stream\""                        \
        "]"
#else
     #define NGX_HTTP_STATUS_API_DIVISION_JSON   \
         "["                                     \
             "\"ssl\","                          \
             "\"nginx\","                        \
             "\"http\","                         \
             "\"stream\""                        \
         "]"
#endif

#define NGX_HTTP_STATUS_API_NGINX_INFO_JSON_BUFFER_SIZE 1024
#define NGX_HTTP_STATUS_API_NGINX_INFO_JSON \
    "{\"version\": \"%s\","                 \
        "\"build\": \"%s\","                \
        "\"hostname\": \"%V\","             \
        "\"timestmap\": %ui,"               \
        "\"start_timestamp\": %ui,"         \
        "\"reload_timestamp\": %ui"        \
    "}"

#ifdef NGX_STAT_STUB
    #define NGX_HTTP_STATUS_API_CONNECTION_JSON_BUFFER_SIZE 512
    #define NGX_HTTP_STATUS_API_CONNECTION_JSON     \
        "{"                                         \
            "\"accepted\": %ui,"                    \
            "\"dropped\": %ui,"                     \
            "\"active\": %ui,"                      \
            "\"idle\": %ui"                         \
        "}"
    #define NGX_HTTP_STATUS_API_REQUESTS_JSON_BUFFER_SIZE 256
    #define NGX_HTTP_STATUS_API_REQUESTS_JSON   \
        "{"                                     \
            "\"total\": %uA,"                   \
    		"\"current\": %uA"                  \
        "}"
#endif

#define NGX_HTTP_STATUS_API_SSL_JSON_BUFFER_SIZE 512
#define NGX_HTTP_STATUS_API_SSL_JSON    \
    "{"                                 \
        "\"handshakes\":%ui,"           \
        "\"session_reuses\":%ui,"       \
        "\"handshakes_failed\":%ui,"    \
        "\"handshake_timeout\":%ui"     \
    "}"
#define NGX_HTTP_STATUS_API_SERVER_ZONE_JSON_BUFFER_SIZE 1024
#define NGX_HTTP_STATUS_API_SERVER_ZONE_JSON    \
    "\"%s\":{"                                  \
        "\"ssl\":{"                             \
            "\"handshakes\":%ui,"                 \
            "\"session_reuses\":%ui,"           \
            "\"handshakes_failed\":%ui,"        \
            "\"handshake_timeout\":%ui"         \
        "},"                                    \
        "\"responses\":{"                       \
            "\"total\": %ui,"                   \
            "\"1xx\": %ui,"                     \
            "\"2xx\": %ui,"                     \
            "\"3xx\": %ui,"                     \
            "\"4xx\": %ui,"                     \
            "\"5xx\": %ui"                      \
        "},"                                    \
        "\"received\": %ui,"                    \
        "\"sent\": %ui"                         \
    "}"


#endif //NGX_HTTP_STATUS_API_API_HANDLER_H
