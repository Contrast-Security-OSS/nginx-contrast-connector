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

static void * ngx_http_contrast_connector_create_main_config(ngx_conf_t *cf);

/*
 * From: https://github.com/SpiderLabs/ModSecurity-nginx
 *
 * return: NULL on empty string, -1 on failed allocation
 */
ngx_inline char * ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
	char * str = NULL;
	if (a.len == 0) {
		/* string is empty; return NULL */
		return NULL;
	}

	str = ngx_pnalloc(p, a.len + 1);
	if (str == NULL) {
		/* string could not be allocated; return -1 */
		return (char *)-1;
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
static ngx_command_t ngx_contrast_connector_commands[] = 
{
	{
		ngx_string("contrast"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_contrast_connector_conf_t, enable),
		NULL
	},
	{
		ngx_string("contrast_debug"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_contrast_connector_conf_t, debug),
		NULL
	},
	{
		ngx_string("contrast_unix_socket"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
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
static void * ngx_http_contrast_connector_create_loc_config(ngx_conf_t *cf)
{
	ngx_http_contrast_connector_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_contrast_connector_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->enable = NGX_CONF_UNSET;
	conf->debug = NGX_CONF_UNSET;
	ngx_conf_merge_str_value(conf->socket_path, conf->socket_path, "/tmp/default.sock");

	fprintf(stderr, "current socket_path = %s\n", conf->socket_path);
	return conf;
}

