/* Core stuff */
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>

/* NGINX stuff */
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Protobuf stuff */
#include <protobuf-c/protobuf-c.h>
#include "dtm.pb-c.h"
#include "settings.pb-c.h"

/* Unix Socket stuff */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Connector stuff */
#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"


/* TODO: not using filters anymore...
static ngx_int_t ngx_http_contrast_connector_module_header_filter(ngx_http_request_t * r);
static ngx_int_t ngx_http_contrast_connector_module_body_filter(ngx_http_request_t * r, ngx_chain_t * chain);
*/

/*
 * allocate and initialize location configuration
 */
static void * ngx_http_contrast_connector_create_loc_config(ngx_conf_t * cf);

/*
 * merge location configurations
 */
static char * ngx_http_contrast_connector_merge_loc_config(ngx_conf_t * cf, 
		void * parent, 
		void * child);

static ngx_int_t ngx_http_contrast_connector_module_init(ngx_conf_t * cf);
static char * ngx_http_contrast_connector(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_contrast_connector_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_contrast_connector_handler(ngx_http_request_t *r);

/*
static u_char * read_request_body(ngx_http_request_t * r, ngx_chain_t * chain);
static u_char * append_request_body(u_char * dest, size_t dest_len, u_char * src, size_t src_len, ngx_log_t * log);
*/

/*
 * static reference to next body filter callback
 */
static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;

/*
 * get the current epoch time in millis
 */
ngx_inline int64_t unix_millis() 
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/*
 * From: https://github.com/SpiderLabs/ModSecurity-nginx
 *
 * return: NULL on empty string, -1 on failed allocation
 */
ngx_inline char * ngx_str_to_char(ngx_str_t a, ngx_pool_t * p)
{
    char * str = NULL;
    if (a.len == 0) {
        /* string is empty; return NULL */
        return NULL;
    }

    str = ngx_pnalloc(p, a.len + 1);
    if (str == NULL) {
        /* string could not be allocated; return -1 */
        return (char *) -1;
    }

    /* return 0 terminated string */
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';
    return str;
}

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
 * create location configuration
 */
static void * ngx_http_contrast_connector_create_loc_config(ngx_conf_t * cf)
{
    ngx_http_contrast_connector_conf_t * conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_contrast_connector_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;
    return conf;
}

/*
 * merge location configurations
 */
static char * ngx_http_contrast_connector_merge_loc_config(ngx_conf_t * cf, 
		void * parent, 
		void * child)
{
    ngx_http_contrast_connector_conf_t * prev = parent;
    ngx_http_contrast_connector_conf_t * conf = child;

    ngx_conf_merge_off_value(conf->enable, prev->enable, NGX_CONF_UNSET);
    ngx_conf_merge_off_value(conf->debug, prev->debug, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->socket_path, prev->socket_path, DEFAULT_SOCKET);

    if (conf->debug > 0) {
		dd("config enabled socket_path=%s", conf->socket_path.data);
    }
    return NGX_CONF_OK;
}

/*
 * init module and place in the filter chain
 */
static ngx_int_t ngx_http_contrast_connector_module_init(ngx_conf_t * cf)
{

	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_contrast_connector_conf_t *cccf;

	cccf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_contrast_connector_module);
	if (!cccf->enable) {
		dd("contrast connector not enabled");
		return NGX_OK;
	}

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
	if (h == NULL) {
		dd("could not push handler into phase");
		return NGX_ERROR;
	}

	dd("assigned contrast connector handler (success)");
	*h = ngx_http_contrast_connector_handler;
    return NGX_OK;
}

static void ngx_http_contrast_connector_post_handler(ngx_http_request_t *r) 
{
	ngx_http_contrast_connector_ctx_t *ctx;

	dd("finalize read request body");
	ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);

	if (ctx == NULL) {
		dd("ctx was NULL");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

#if defined(nginx_version) && nginx_verion >= 8011
	r->main->count--;
#endif

	if (!ctx->done) {
		ctx->done = 1;
		ngx_http_core_run_phases(r);
	}
}

static ngx_int_t ngx_http_contrast_connector_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_contrast_connector_conf_t *cccf;
	ngx_http_contrast_connector_ctx_t *ctx;

	dd("contrast connector handler, uri=%s c=%d", r->uri.data, r->main->count);

	cccf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
	if (!cccf->enable) {
		dd("module not enabled");
		return NGX_DECLINED;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);
	if (ctx == NULL) {
		ctx = ngx_palloc(r->connection->pool, sizeof(ngx_http_contrast_connector_ctx_t));
		if (ctx == NULL) {
			dd("[ERROR] could not allocate ctx");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ctx->done = 0;
		ngx_http_set_ctx(r, ctx, ngx_http_contrast_connector_module);
	}

	if (!ctx->done) {
		r->request_body_in_single_buf = 1;
		r->request_body_in_persistent_file = 1;
		r->request_body_in_clean_file = 1;

		rc = ngx_http_read_client_request_body(r, ngx_http_contrast_connector_post_handler);
		if (rc == NGX_ERROR) {
			dd("[ERROR] rc returned error");
			return NGX_ERROR;
		}

		if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
			dd("[ERROR] rc returned special response");
			return rc;
		}

		dd("handler done");
		return NGX_DONE;
	}

	dd("handler declined");
	return NGX_DECLINED;
}


