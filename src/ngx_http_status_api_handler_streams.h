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
    "\"sessionMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"sessionBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uSessionMsecCounter\":%uA,"                                             \
    "\"uSessionMsec\":%M,"                                                     \
    "\"uSessionMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uSessionBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uConnectMsecCounter\":%uA,"                                             \
    "\"uConnectMsec\":%M,"                                                     \
    "\"uConnectMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uConnectBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uFirstByteMsecCounter\":%uA,"                                           \
    "\"uFirstByteMsec\":%M,"                                                   \
    "\"uFirstByteMsecs\":{"                                                    \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uFirstByteBuckets\":{"                                                  \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s,"                                                             \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"sessionMsecCounter\":%uA,"                                              \
    "\"uSessionMsecCounter\":%uA,"                                             \
    "\"uConnectMsecCounter\":%uA,"                                             \
    "\"uFirstByteMsecCounter\":%uA"                                            \
    "}"                                                                        \
    "},"


ngx_int_t ngx_http_status_api_handler_streams_handler(ngx_http_request_t *r);
#endif //NGX_HTTP_STATUS_API_HANDLER_STREAMS_H
