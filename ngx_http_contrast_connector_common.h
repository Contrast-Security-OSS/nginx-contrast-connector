/* Copyright (C) Contrast Security, Inc. */

#ifndef _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_
#define _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define LOG_PREFIX  "[contrast]: "

#define dd(...) fprintf(stderr, "contrast *** %s: ", __func__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, " at %s line %d\n", __FILE__, __LINE__)

/*
 * structure for context
 */
typedef struct {
  unsigned done:1;
} ngx_http_contrast_connector_ctx_t;

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
 * update request body filter chain
 */
ngx_int_t ngx_http_catch_body_init(ngx_conf_t *cf);

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
