/* Copyright (C) Contrast Security, Inc. */

#ifndef _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_
#define _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_auto_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if !(NGX_HAVE_VARIADIC_MACROS)
#   error("platform is missing variadic macro support")
#endif

/* debugging code enabled using --with-debug on nginx ./configure */
#if (NGX_DEBUG)
/* easy debug printing used for development and debugging. */
#   define dd(fmt, ...) \
    fprintf(stderr, "[contrast] %s:%d (%s): " fmt "\n", \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#   define dd(...)
#endif

#define contrast_log(lvl, log, err, fmt, ...) \
    ngx_log_error(NGX_LOG_ ## lvl, log, err, \
            "[contrast]: " fmt, ## __VA_ARGS__)

#define contrast_dbg_log(log, err, fmt, ...) \
    ngx_log_error(NGX_LOG_DEBUG_HTTP, log, err, \
            "[contrast]: " fmt, ## __VA_ARGS__)

typedef struct { 
    char uuid[32 + 1];
} ngx_contrast_uuid_t;
/*
 * structure for context
 */
typedef struct {
    /* 
     * separate pool for buffered outgoing data. Having a separate pool makes
     * using the ngx buf/chain functions easier as they won't get confused
     * with the buf chain in the request object pool.
     */
    ngx_contrast_uuid_t uuid;
    ngx_int_t complete;
    ngx_pool_t *out_pool;
    ngx_chain_t *output_chain;
    size_t content_len;
    ngx_chain_t *prev_cl;

    unsigned waiting_more_body:1;
    unsigned body_requested:1;
} ngx_http_contrast_ctx_t;

/*
 * structure for configuration
 */
typedef struct {
    ngx_flag_t enable;
    ngx_flag_t debug;
    ngx_str_t socket_path;
    ngx_str_t app_name;
} ngx_http_contrast_connector_conf_t;

/*
 * extern reference to module definition
 */
extern ngx_module_t ngx_http_contrast_connector_module;

/*
 * utility method to get unix millis
 */
int64_t unix_millis();

/*
 * utility method to create C strings from ngx strings
 */
char *ngx_str_to_char(const ngx_str_t *a, ngx_pool_t *p);

/*
 * parse connection and params for non-request body request
 */
ngx_int_t ngx_http_contrast_connector_preaccess_handler(
        ngx_http_request_t * r);


#endif
