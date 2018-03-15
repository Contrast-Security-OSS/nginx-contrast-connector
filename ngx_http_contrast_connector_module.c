/* Core stuff */
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

/* NGINX stuff */
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Protobuf stuff */
#include <protobuf-c/protobuf-c.h>
#include "dtm.pb-c.h"
#include "settings.pb-c.h"

/* Connector stuff */


static void * ngx_http_contrast_connector_create_loc_config(ngx_conf_t * cf);

/*
 * From: https://github.com/SpiderLabs/ModSecurity-nginx
 *
 * return: NULL on empty string, -1 on failed allocation
 */
ngx_inline char * ngx_str_to_char(ngx_str_t a, ngx_pool_t * p)
{
    char * str = NULL;
    if (a.len==0) {
        /* string is empty; return NULL */
        return NULL;
    }

    str = ngx_pnalloc(p, a.len+1);
    if (str==NULL) {
        /* string could not be allocated; return -1 */
        return (char *) -1;
    }

    /* return 0 terminated string */
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';
    return str;
}

/*
 * structure for configuration
 */
typedef struct {
  ngx_flag_t enable;
  ngx_flag_t debug;
  ngx_str_t socket_path;
} ngx_http_contrast_connector_conf_t;

/*
 * available commands for module
 */
static ngx_command_t ngx_http_contrast_connector_commands[] = {
        {
                ngx_string("contrast"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_contrast_connector_conf_t, enable),
                NULL
        },
        {
                ngx_string("contrast_debug"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_contrast_connector_conf_t, debug),
                NULL
        },
        {
                ngx_string("contrast_unix_socket"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_contrast_connector_conf_t, socket_path),
                NULL
        },
        ngx_null_command
};

/*
 * create location configuration
 */
static void * ngx_http_contrast_connector_create_loc_config(ngx_conf_t * cf)
{
    ngx_http_contrast_connector_conf_t * conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_contrast_connector_conf_t));

    if (conf==NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;


    return conf;
}

/*
 * merge location configurations
 */
static char * ngx_http_contrast_connector_merge_loc_config(ngx_conf_t * cf, void * parent, void * child)
{
    ngx_http_contrast_connector_conf_t * prev = parent;
    ngx_http_contrast_connector_conf_t * conf = child;

    ngx_conf_merge_off_value(conf->enable, prev->enable, NGX_CONF_UNSET);
    ngx_conf_merge_off_value(conf->debug, prev->debug, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->socket_path, prev->socket_path, "/tmp/contrast-security.sock");

    fprintf(stderr, "current socket_path = %s\n", conf->socket_path.data);
    return NGX_CONF_OK;
}

/*
 * module context structure
 */
static ngx_http_module_t ngx_http_contrast_connector_module_ctx = {

        /* pre configuration */
        NULL,

        /* post configuration */
        NULL,

        /* create main configuration */
        NULL,

        /* init main configuration */
        NULL,

        /* create server configuration */
        NULL,

        /* merge server configuration */
        NULL,

        /* create location configuration */
        ngx_http_contrast_connector_create_loc_config,

        /* merge location configuration */
        ngx_http_contrast_connector_merge_loc_config
};

/*
 * module definition structur
 */
ngx_module_t ngx_http_contrast_connector_module = {
        NGX_MODULE_V1,

        /* address of module context */
        &ngx_http_contrast_connector_module_ctx,

        /* module directives */
        ngx_http_contrast_connector_commands,

        /* module type */
        NGX_HTTP_MODULE,

        /* init master */
        NULL,

        /* init module */
        NULL,

        /* init process */
        NULL,

        /* init thread */
        NULL,

        /* exit thread */
        NULL,

        /* exit process */
        NULL,

        /* exit master */
        NULL,
        NGX_MODULE_V1_PADDING
};

