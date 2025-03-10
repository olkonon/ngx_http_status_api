//
// Created by o.kononenko on 19.02.2025.
//

#ifndef NGX_HTTP_STATUS_API_HANDLER_UPSTREAMS_H
#define NGX_HTTP_STATUS_API_HANDLER_UPSTREAMS_H
ngx_int_t ngx_http_status_api_handler_upstreams_handler(ngx_http_request_t *r);

#define NGX_HTTP_STATUS_API_JSON_FMT_UPSTREAM "{\"server\":\"%V\","            \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"responseMsecCounter\":%uA,"                                             \
    "\"responseMsec\":%M,"                                                     \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s"                                                             \
    "},"

#endif //NGX_HTTP_STATUS_API_HANDLER_UPSTREAMS_H