#include "dtm.pb-c.h"
#include "settings.pb-c.h"
#include "ngx_http_contrast_connector_common.h"

 /*
  * static reference to next request body filter callback
  */
static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;

/*
 * examine http request and forward to speedracer
 */
static ngx_int_t ngx_http_catch_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char *p;
    ngx_chain_t *cl;
    ngx_http_contrast_connector_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
    if (!conf->enable) {
        return ngx_http_next_request_body_filter(r, in);
    }

	dd("catch request body filter");
    for (cl = in; cl; cl = cl->next) {

        p = cl->buf->pos;

        for (p = cl->buf->pos; p < cl->buf->last; p++) {

			dd("catch body char=%c", *p);
            if (*p == 'X') {
				dd("catch body: found");

                /*
                 * As we return NGX_HTTP_FORBIDDEN, the r->keepalive flag
                 * won't be reset by ngx_http_special_response_handler().
                 * Make sure to reset it to prevent processing of unread
                 * parts of the request body.
                 */

                r->keepalive = 0;
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    return ngx_http_next_request_body_filter(r, in);
}

/*
 * update request body filter chain
 */
ngx_int_t ngx_http_catch_body_init(ngx_conf_t *cf)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_catch_body_filter;

    return NGX_OK;
}
