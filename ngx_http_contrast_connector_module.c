/* Copyright (C) Contrast Security, Inc.
 *
 * The module will insert an http handler into the PRE-ACCESS phase of the
 * http module. The handler will send request/response data to the Contrast
 * rules engine for determination on if the request/response should proceed.
 */

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

#include <protobuf-c/protobuf-c.h>
#include "dtm.pb-c.h"
#include "settings.pb-c.h"

#include "ngx_http_contrast_connector_common.h"

static void *ngx_http_contrast_connector_create_loc_config(ngx_conf_t *cf);
static char *ngx_http_contrast_connector_merge_loc_config(ngx_conf_t *cf,
    void * parent, void * child);
static ngx_int_t ngx_http_contrast_connector_module_init(ngx_conf_t *cf);


/*
 * get the current epoch time in millis
 */
ngx_inline int64_t
unix_millis() 
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/*
 * Convert an nginx str to a null terminated str.
 *
 * Uses pool *p for allocation.
 */
ngx_inline char *
ngx_str_to_char(const ngx_str_t *a, ngx_pool_t *p)
{
    char *str = NULL;
    if (a->len == 0) {
        goto fail;
    }

    str = ngx_pnalloc(p, a->len + 1);
    if (str == NULL) {
        goto fail;
    }

    ngx_memcpy(str, a->data, a->len);
    str[a->len] = '\0';

fail:
    return str;
}

/*
 * available commands for module
 */
static ngx_command_t ngx_http_contrast_connector_commands[] = {
    {
        ngx_string("contrast"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF
            | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_contrast_connector_conf_t, enable),
        NULL
    },
    {
        ngx_string("contrast_debug"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF
            | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_contrast_connector_conf_t, debug),
        NULL
    },
    {
        ngx_string("contrast_unix_socket"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF
            | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_contrast_connector_conf_t, socket_path),
        NULL
    },
    {
        ngx_string("contrast_app_name"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF
            | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_contrast_connector_conf_t, app_name),
        NULL
    },
    ngx_null_command
};


/*
 * module context structure
 */
static ngx_http_module_t ngx_http_contrast_connector_module_ctx = {
    /* pre configuration */
    NULL,
    /* post configuration */
    ngx_http_contrast_connector_module_init,
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
 * module definition structure
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
    /* required */
    NGX_MODULE_V1_PADDING
};

/*
 * default socket to communicate with contrast service
 */
static const char DEFAULT_SOCKET[] = "/tmp/contrast-security.sock";

/*
 * default name for applications in contrast service
 * XXX: Should this be required? can it be determined from the HOST field?
 */
static const char DEFAULT_NAME[] = "unknown";


static void *
ngx_http_contrast_connector_create_loc_config(ngx_conf_t *cf)
{
    ngx_http_contrast_connector_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_contrast_connector_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_contrast_connector_merge_loc_config(ngx_conf_t *cf, 
    void *parent, void *child)
{
    ngx_http_contrast_connector_conf_t *prev = parent;
    ngx_http_contrast_connector_conf_t *conf = child;

    /* default to disable Contrast protection */
    ngx_conf_merge_off_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_off_value(conf->debug, prev->debug, 0);
    ngx_conf_merge_str_value(conf->socket_path, prev->socket_path,
        DEFAULT_SOCKET);
    
    contrast_log(INFO, cf->log, 0, 
        "APP NAME = %s %s", conf->app_name.data, prev->app_name.data); 
    ngx_conf_merge_str_value(conf->app_name, prev->app_name, DEFAULT_NAME);

    if (conf->debug) {
        contrast_log(INFO, cf->log, 0,
            "contrast rule-engine socket_path: %s", conf->socket_path.data);
    }
    return NGX_CONF_OK;
}


/*
 * init module and place in the http phase chain
 */
static ngx_int_t
ngx_http_contrast_connector_module_init(ngx_conf_t * cf)
{
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(
        cf, ngx_http_core_module);
    if (main_conf == NULL) {
        contrast_log(ERR, cf->log, 0, "Main conf was NULL");
        return NGX_ERROR;
    }

    /* attach url handler after the pre-access phase. */
    ngx_http_handler_pt *h_preaccess = ngx_array_push(
        &main_conf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h_preaccess == NULL) {
        contrast_log(ERR, cf->log, 0, "Preaccess handler was NULL");
        return NGX_ERROR;
    }
    *h_preaccess = ngx_http_contrast_connector_preaccess_handler;

    contrast_log(INFO, cf->log, 0,
	    "Completed initialization of contrast connector module");
    return NGX_OK;
}


