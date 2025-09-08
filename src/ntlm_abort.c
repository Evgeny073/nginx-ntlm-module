#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ntlm_abort.h"

static void ngx_http_ntlm_abort_handler(void *data);

static ngx_http_ntlm_abort_ctx_t *
ngx_http_ntlm_abort_get_or_create_ctx(ngx_http_request_t *r)
{
    ngx_http_cleanup_t *cln;

    for (cln = r->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_ntlm_abort_handler && cln->data) {
            return (ngx_http_ntlm_abort_ctx_t *) cln->data;
        }
    }

    cln = ngx_http_cleanup_add(r, sizeof(ngx_http_ntlm_abort_ctx_t));
    if (cln == NULL) {
        return NULL;
    }

    ngx_http_ntlm_abort_ctx_t *ctx = (ngx_http_ntlm_abort_ctx_t *) cln->data;
    ngx_memzero(ctx, sizeof(*ctx));
    ctx->r   = r;
    ctx->log = r->connection ? r->connection->log : ngx_cycle->log;

    cln->handler = ngx_http_ntlm_abort_handler;
    return ctx;
}

static void
ngx_http_ntlm_abort_close(ngx_http_ntlm_abort_ctx_t *ctx, const char *why)
{
    if (!ctx) return;

    ngx_connection_t *c = ctx->upstream_conn;
    if (c == NULL) return;

    /* В nginx/Angie нет поля `closed`; используем fd==-1 или флаг close */
    if (c->fd == (ngx_socket_t) -1 || c->close) {
        ctx->upstream_conn = NULL;
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "ntlm-abort: closing upstream %p (%s)",
                   c, why ? why : "cleanup");

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            /* Если хотели бы асинхронно — потребовался бы handler; здесь закрываем синхронно */
        }
    }
#endif

    if (c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }

    ngx_close_connection(c);
    ctx->upstream_conn = NULL;
}

static void
ngx_http_ntlm_abort_handler(void *data)
{
    ngx_http_ntlm_abort_ctx_t *ctx = (ngx_http_ntlm_abort_ctx_t *) data;
    ngx_http_ntlm_abort_close(ctx, "request cleanup");
}

ngx_int_t
ngx_http_ntlm_abort_register(ngx_http_request_t *r, ngx_connection_t *uconn)
{
    ngx_http_ntlm_abort_ctx_t *ctx = ngx_http_ntlm_abort_get_or_create_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->upstream_conn = uconn;
    return NGX_OK;
}

ngx_int_t
ngx_http_ntlm_abort_update(ngx_http_request_t *r, ngx_connection_t *uconn)
{
    ngx_http_ntlm_abort_ctx_t *ctx = ngx_http_ntlm_abort_get_or_create_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->upstream_conn = uconn;
    return NGX_OK;
}