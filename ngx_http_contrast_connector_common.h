#ifndef _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_
#define _NGX_HTTP_CONTRAST_CONNECTOR_COMMON_H_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

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
