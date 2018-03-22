#ifndef _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_
#define _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 
 * simple debugger
 */
#if (NGX_HAVE_VARIADIC_MACROS)
#	define dd(...) fprintf(stderr, "contrast *** %s: ", __func__); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, " at %s line %d\n", __FILE__, __LINE__)
#else
#include <stdarg.h>
#include <stdio.h>
static void dd(const char *fmt, ...) { /* NOOP */ }
#endif

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
} ngx_http_contrast_connector_conf_t;

/*
 * extern reference to module definition
 */
extern ngx_module_t ngx_http_contrast_connector_module;



#endif
