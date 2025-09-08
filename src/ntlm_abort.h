#ifndef _NTLM_ABORT_H_INCLUDED_
#define _NTLM_ABORT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_http_request_t  *r;
    ngx_connection_t    *upstream_conn; /* may be NULL until upstream connected */
    ngx_log_t           *log;
} ngx_http_ntlm_abort_ctx_t;

ngx_int_t ngx_http_ntlm_abort_register(ngx_http_request_t *r, ngx_connection_t *uconn);
ngx_int_t ngx_http_ntlm_abort_update(ngx_http_request_t *r, ngx_connection_t *uconn);

#endif /* _NTLM_ABORT_H_INCLUDED_ */