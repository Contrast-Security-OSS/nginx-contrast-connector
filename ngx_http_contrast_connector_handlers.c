/* NGINX stuff */
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Protobuf stuff */
#include "dtm.pb-c.h"
#include "settings.pb-c.h"

/* Connector stuff */
#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"


#define APP_LANG  "Ruby" /* XXX: temp placeholder for TS */
#define CLIENT_ID  "NGINX"

typedef struct address_s {
    char *address;
    int32_t port;
    int32_t version;
} address_t;


static ngx_http_contrast_ctx_t * ngx_http_contrast_create_ctx(
        ngx_http_request_t *r);
static ngx_http_output_body_filter_pt ngx_http_next_output_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_int_t ngx_http_contrast_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_contrast_output_body_filter(
        ngx_http_request_t *r,  ngx_chain_t *in);
static void ngx_http_contrast_pool_cleanup(void *data);
static void build_http_headers_in_dtm(
        ngx_pool_t *pool, ngx_list_t *hdrs,
        Contrast__Api__Dtm__SimplePair ***hdr_array, size_t *hdrcnt,
        ngx_log_t *log);

/*
 * populate addr with information about a IPv4 address.
 * address is dynamically allocated and must be freed. 
 */
static ngx_int_t
read_address(
        struct sockaddr *sockaddr, address_t *addr, ngx_http_request_t *r)
{
    if (sockaddr && sockaddr->sa_family == AF_INET) {
        struct sockaddr_in * sin = (struct sockaddr_in *)sockaddr;
        if (sin != NULL) {
            addr->address = ngx_pcalloc(r->pool, INET_ADDRSTRLEN);
            if (addr->address != NULL) {           
                inet_ntop(AF_INET, &(sin->sin_addr), addr->address, INET_ADDRSTRLEN);
                addr->port = sin->sin_port;
                addr->version = 4;
                return NGX_OK;
            }
        }
    }

    return NGX_ERROR;
}


void chain_to_buffer(ngx_chain_t *in, void *out, off_t max_sz)
{
    off_t total_sz = 0;
    void *pos = out;
    for (ngx_chain_t *cl = in; cl; cl = cl->next)
    {
        ngx_buf_t *buf = cl->buf;
        off_t size = ngx_buf_size(buf);
        total_sz += size;
        
        if (total_sz > max_sz)
        {
            dd("something wrong in copying chain");
            return;
        }

        if (buf->in_file) {
            ngx_read_file(buf->file, pos, size, buf->file_pos);
        }
        else if (ngx_buf_in_memory(buf)) {
            ngx_memcpy(pos, buf->start, size);
        }

        pos += size;
    }
    return;
}


/*
 * populate addr with information about a IPv6 address.
 * address is dynamically allocated and must be freed. 
 */
static ngx_int_t
read_ipv6_address(ngx_connection_t *connection, address_t *addr) {
    return NGX_ERROR;
}

static Contrast__Api__Dtm__RawResponse *
create_response_dtm(ngx_pool_t *pool, ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;
    contrast_dbg_log(log, 0, "building RawResponse dtm");
    ngx_http_contrast_ctx_t *ctx = ngx_http_get_module_ctx(
            r, ngx_http_contrast_connector_module);

    if (ctx == NULL) {
        contrast_log(ERR, log, 0, "ctx doesn't exists on response");
        return NULL;
    }

    Contrast__Api__Dtm__RawResponse *dtm = ngx_pcalloc(
        pool, sizeof(Contrast__Api__Dtm__RawResponse));
    
    if (dtm == NULL) {
        contrast_log(ERR, log, 0, "failed to alloc response dtm");
        return dtm;
    }

    contrast__api__dtm__raw_response__init(dtm);

    dtm->timestamp_ms = unix_millis();
    dtm->uuid = ngx_pnalloc(pool, sizeof(ngx_contrast_uuid_t));
    ngx_memcpy(dtm->uuid, ctx->uuid.uuid, sizeof(ngx_contrast_uuid_t));

    dd("dtm response uuid '%s'", ctx->uuid.uuid);

    dtm->response_code = r->headers_out.status;
    dd("access code is %d", r->headers_out.status);
    /* XXX: need to check on these copies. NGINX documentation made a comment
     * that ngx_str_t may not always be null terminated.  The pcalloc is 
     * side-stepping the problem, but it may not be necessary if we handle
     * the case explicitly
     */

    dtm->n_response_headers = 0;
    build_http_headers_in_dtm(
            pool, &(r->headers_out.headers),
            &(dtm->response_headers), &dtm->n_response_headers, log);
    
    if (ctx->output_chain == NULL || ctx->content_len == 0)
    {
        goto exit;
    }

    dtm->response_body = ngx_pnalloc(pool, ctx->content_len);
    chain_to_buffer(ctx->output_chain, dtm->response_body, ctx->content_len);

exit:

    return dtm;
}


static Contrast__Api__Dtm__RawRequest *
create_request_dtm(ngx_pool_t *pool, ngx_http_request_t *r) 
{
    ngx_log_t *log = r->connection->log;
    ngx_http_contrast_ctx_t *ctx = ngx_http_get_module_ctx(
            r, ngx_http_contrast_connector_module);

    Contrast__Api__Dtm__RawRequest *dtm = ngx_pcalloc(
        pool, sizeof(Contrast__Api__Dtm__RawRequest));
    
    if (dtm == NULL) {
        contrast_log(ERR, log, 0, "failed to alloc dtm");
        return dtm;
    }

    contrast__api__dtm__raw_request__init(dtm);

    dtm->timestamp_ms = unix_millis();
    dtm->uuid = ngx_pnalloc(pool, sizeof(ngx_contrast_uuid_t));
    ngx_memcpy(dtm->uuid, ctx->uuid.uuid, sizeof(ngx_contrast_uuid_t));
    dd("dtm request uuid '%s'", ctx->uuid.uuid);

    /* XXX: need to check on these copies. NGINX documentation made a comment
     * that ngx_str_t may not always be null terminated.  The pcalloc is 
     * side-stepping the problem, but it may not be necessary if we handle
     * the case explicitly
     */
    dtm->request_line = ngx_pcalloc(pool, r->request_line.len + 1);
    if (dtm->request_line != NULL) {
        strncpy(dtm->request_line, (char*)r->request_line.data,
                r->request_line.len);
        contrast_dbg_log(log, 0, "request_line: %s", dtm->request_line);
    }

    dtm->normalized_uri = ngx_pcalloc(pool, r->uri.len + 1);
    if (dtm->normalized_uri != NULL) {
        strncpy(dtm->normalized_uri, (char*)r->uri.data, r->uri.len);
        contrast_dbg_log(log, 0, "normalized_uri: %s", dtm->normalized_uri);
    }

    struct address_s client_address;
    if (read_address(r->connection->sockaddr, &client_address, r) == NGX_OK) {
        if (client_address.address != NULL) {
            dtm->client_ip = client_address.address;
            dtm->client_ip_version = client_address.version;
            dtm->client_port = client_address.port;
            contrast_dbg_log(log, 0, "-> ip=%s (ipv%d) port=%d",
                dtm->client_ip, dtm->client_ip_version, dtm->client_port); 
        }
    }

    struct address_s server_address;
    if (read_address(r->connection->listening->sockaddr, &server_address, r) == NGX_OK) {
        if (server_address.address != NULL) {
            dtm->server_ip = server_address.address;
            dtm->server_ip_version = server_address.version;
            dtm->server_port = server_address.port;
            contrast_dbg_log(log, 0, "<- ip=%s (ipv%d) port=%d",
                dtm->server_ip, dtm->server_ip_version, dtm->server_port); 
        }
    }

    dtm->request_body = NULL;

    dtm->n_request_headers = 0;

    build_http_headers_in_dtm(
            pool, &(r->headers_in.headers),
            &(dtm->request_headers), &dtm->n_request_headers, log);
    return dtm;
}


static void
build_http_headers_in_dtm(
        ngx_pool_t *pool,
        ngx_list_t *hdrs,
        Contrast__Api__Dtm__SimplePair ***hdr_array,
        size_t *hdrcnt,
        ngx_log_t *log)
{
    ngx_list_t list = *hdrs;
    *hdrcnt = 0;
    if (list.nalloc <= 0) {
        return;
    }

    ngx_list_part_t * curr = &list.part;
    ngx_table_elt_t * entry_ptr = (ngx_table_elt_t *)curr->elts;
    ngx_table_elt_t * entry = NULL;

    for(size_t count = 0; ; count++) {
        if (count >= curr->nelts) {
            if (curr->next == NULL) {
                break;
            }

            curr = curr->next;
            entry_ptr = (ngx_table_elt_t *)curr->elts;
            count = 0;
        }

        entry = (&entry_ptr[count]);
    
        Contrast__Api__Dtm__SimplePair *pair = ngx_pcalloc(
                pool, sizeof(Contrast__Api__Dtm__SimplePair));
        contrast__api__dtm__simple_pair__init(pair);

        pair->key = ngx_pcalloc(pool, entry->key.len + 1);
        if (pair->key == NULL) {
            ngx_pfree(pool, pair);
            continue;
        }
        strncpy(pair->key, (char*)entry->key.data, entry->key.len);

        pair->value = ngx_pcalloc(pool, entry->value.len + 1);
        if (pair->value == NULL) {
            ngx_pfree(pool, pair->key);
            ngx_pfree(pool, pair);
            continue;
        }
        strncpy(pair->value, (char*)entry->value.data, entry->value.len);

        *hdr_array = realloc(
                *hdr_array, 
                sizeof(Contrast__Api__Dtm__SimplePair *) * (*hdrcnt + 1));
        if (*hdr_array == NULL) {
            contrast_log(ERR, log, 0,
                    "error: alloc or realloc failed for headers");
            ngx_pfree(pool, pair->key);
            ngx_pfree(pool, pair->value);
            ngx_pfree(pool, pair);
            *hdrcnt = 0;
            break;
        }
        contrast_dbg_log(log, 0, "[header] %s=%s", pair->key, pair->value);
        (*hdr_array)[*hdrcnt] = pair;
        (*hdrcnt)++;
    }

    dd("leaving with: hdr_array %p", hdr_array);
    return;
}


static void
free_response_dtm(ngx_pool_t *pool, Contrast__Api__Dtm__RawResponse *dtm) 
{
    if (dtm->uuid != NULL) {
        ngx_pfree(pool, dtm->uuid);
    }

    if (dtm->response_headers != NULL) {
        for (size_t i = 0; i < dtm->n_response_headers; ++i) {
            ngx_pfree(pool, dtm->response_headers[i]);
        }
        /* realloc was used for this memory */
        ngx_free(dtm->response_headers);
    }

    if (dtm->response_body != NULL) {
        ngx_pfree(pool, dtm->response_body);
    }

    ngx_pfree(pool, dtm); 
}


static void
free_request_dtm(ngx_pool_t *pool, Contrast__Api__Dtm__RawRequest *dtm) 
{
    if (dtm->uuid != NULL) {
        ngx_pfree(pool, dtm->uuid);
    }

    if (dtm->request_line != NULL) {
        ngx_pfree(pool, dtm->request_line);
    }

    if (dtm->normalized_uri != NULL) {
        ngx_pfree(pool, dtm->normalized_uri);
    }

    if (dtm->client_ip != NULL) {
        ngx_pfree(pool, dtm->client_ip);
    }

    if (dtm->server_ip != NULL) {
        ngx_pfree(pool, dtm->server_ip);
    }

    if (dtm->request_headers != NULL) {
        for (size_t i = 0; i < dtm->n_request_headers; ++i) {
            ngx_pfree(pool, dtm->request_headers[i]);
        }
        /* realloc was used for this memory */
        ngx_free(dtm->request_headers);
    }

    if (dtm->request_body != NULL) {
        ngx_pfree(pool, dtm->request_body);
    }

    ngx_pfree(pool, dtm); 
}

static ngx_int_t 
send_response_dtm_to_socket(
        Contrast__Api__Dtm__RawResponse *dtm, 
        ngx_str_t socket_path,
        ngx_str_t app_name,
        ngx_log_t *log,
        ngx_pool_t *pool)
{
    static int32_t message_count = 0;
    ngx_int_t deny = 0;
    ngx_str_t *response = NULL;

    char *app_name_str = ngx_str_to_char(&app_name, pool);
    if (app_name_str == NULL) {
        contrast_log(ERR, log, 0,
            "failed to convert app_name to char string");
        return deny;
    }

    Contrast__Api__Dtm__Message msg = CONTRAST__API__DTM__MESSAGE__INIT;
    msg.client_id = CLIENT_ID;
    msg.pid = (int32_t)ngx_processes[ngx_process_slot].pid;
    msg.client_number = (int32_t)1;
    msg.client_total = (int32_t)1;
    msg.message_count = ++message_count;
    msg.app_name = app_name_str;
    msg.app_language = APP_LANG;
    msg.timestamp_ms = unix_millis();
    msg.event_case = CONTRAST__API__DTM__MESSAGE__EVENT_RESPONSE;
    msg.response = dtm;
    
    contrast_dbg_log(log, 0, "built parent message structure: %s (%s)",
        msg.app_name, msg.app_language);

    size_t len = contrast__api__dtm__message__get_packed_size(&msg);
    contrast_dbg_log(log, 0, "estimated size of packed message: %ld", len);

    void * buf = ngx_palloc(pool, len);
    if (buf == NULL) {
        contrast_log(ERR, log, 0,
                "error: could not allocate buffer size for protobuf message");
        goto fail;
    }

    size_t packed_size = contrast__api__dtm__message__pack(&msg, buf);
    contrast_dbg_log(log, 0, "actual packed message size: %ld", packed_size);
    response = write_to_service(socket_path, buf, len, log);
    ngx_pfree(pool, buf);
    
    if (response == NULL) {
        contrast_log(ERR, log, 0, "error writing dtm to analysis engine");
        goto fail;
    }

    Contrast__Api__Settings__AgentSettings *settings = NULL;
    settings = contrast__api__settings__agent_settings__unpack(
        NULL, response->len, response->data);
    ngx_free(response->data);
    ngx_free(response);

    if (settings == NULL) {
        contrast_log(ERR, log, 0,
                "failed to deserialize analysis engine response");
        goto fail;
    }

    if (settings->protect_state == NULL) {
        contrast_log(ERR, log, 0, "error reading response protect_state");
        goto fail;
    }

    contrast_dbg_log(log, 0, "security exception value: %d", 
        settings->protect_state->security_exception);
    
    if (settings->protect_state->security_exception) {
        contrast_log(WARN, log, 0, "security exception: %s uuid=%s", 
            settings->protect_state->security_message,
            settings->protect_state->uuid);
        deny = 1;
    }

fail:
    if (settings) {
        ngx_free(settings);
    }

    ngx_pfree(pool, app_name_str);
    return deny;
}


static ngx_int_t 
send_dtm_to_socket(
        Contrast__Api__Dtm__RawRequest *dtm, 
        ngx_str_t socket_path,
        ngx_str_t app_name,
        ngx_log_t *log,
        ngx_pool_t *pool)
{
    static int32_t message_count = 0;
    ngx_int_t deny = 0;
    ngx_str_t *response = NULL;

    char *app_name_str = ngx_str_to_char(&app_name, pool);
    if (app_name_str == NULL) {
        contrast_log(ERR, log, 0,
            "failed to convert app_name to char string");
        return deny;
    }

    Contrast__Api__Dtm__Message msg = CONTRAST__API__DTM__MESSAGE__INIT;
    msg.client_id = CLIENT_ID;
    msg.pid = (int32_t)ngx_processes[ngx_process_slot].pid;
    msg.client_number = (int32_t)1;
    msg.client_total = (int32_t)1;
    msg.message_count = ++message_count;
    msg.app_name = app_name_str;
    msg.app_language = APP_LANG;
    msg.timestamp_ms = unix_millis();
    msg.event_case = CONTRAST__API__DTM__MESSAGE__EVENT_REQUEST;
    msg.request = dtm;
    
    contrast_dbg_log(log, 0, "built parent message structure: %s (%s)",
        msg.app_name, msg.app_language);

    size_t len = contrast__api__dtm__message__get_packed_size(&msg);
    contrast_dbg_log(log, 0, "estimated size of packed message: %ld", len);

    void * buf = ngx_palloc(pool, len);
    if (buf == NULL) {
        contrast_log(ERR, log, 0,
                "error: could not allocate buffer size for protobuf message");
        goto fail;
    }

    size_t packed_size = contrast__api__dtm__message__pack(&msg, buf);
    contrast_dbg_log(log, 0, "actual packed message size: %ld", packed_size);
    response = write_to_service(socket_path, buf, len, log);
    ngx_pfree(pool, buf);
    
    if (response == NULL) {
        contrast_log(ERR, log, 0, "error writing dtm to analysis engine");
        goto fail;
    }

    Contrast__Api__Settings__AgentSettings *settings = NULL;
    settings = contrast__api__settings__agent_settings__unpack(
        NULL, response->len, response->data);
    ngx_free(response->data);
    ngx_free(response);

    if (settings == NULL) {
        contrast_log(ERR, log, 0,
                "failed to deserialize analysis engine response");
        goto fail;
    }

    if (settings->protect_state == NULL) {
        contrast_log(ERR, log, 0, "error reading response protect_state");
        goto fail;
    }

    contrast_dbg_log(log, 0, "security exception value: %d", 
        settings->protect_state->security_exception);
    
    if (settings->protect_state->security_exception) {
        contrast_log(WARN, log, 0, "security exception: %s uuid=%s", 
            settings->protect_state->security_message,
            settings->protect_state->uuid);
        deny = 1;
    }

fail:
    if (settings) {
        ngx_free(settings);
    }

    ngx_pfree(pool, app_name_str);
    return deny;
}


/* 
 * by using this body_handler, we have taken control of the nginx processing
 * flow and its now up to us to to keep it going. Thats the reason why there
 * is no return value in this callback. So we either need to finish the request
 * processing by calling ngx_http_finalize_request() or some other mechanism.
 * That 'other' mechanism is by manually advancing the phase state and
 * re-entering the request state machine processing.
 *
 * If this is a request that we should allow, then we will re-enter the state
 * machine processing. Otherwise, we finalize the request and provide an error
 * or forbidden http response directly.
 */
void
ngx_http_contrast_connector_body_handler(ngx_http_request_t *r)
{
    off_t         len;
    ngx_http_contrast_connector_conf_t *conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);
    
    if (r->request_body == NULL) {
        /* XXX: under what circumstatnces could this ever happen? */ 
        contrast_log(ERR, r->connection->log, 0,
                "request body was null!! why!?");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    len = 0;

    for (ngx_chain_t *in = r->request_body->bufs; in; in = in->next) {
        len += ngx_buf_size(in->buf);
    }
    
    Contrast__Api__Dtm__RawRequest * dtm = create_request_dtm(r->pool, r);
    if (dtm == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /*
     * request_body memory owned by dtm and will be freed in free_dtm. In the
     * future, I'd like for build_dtm_from_request to handle this or have the
     * analysis engine take the body in chunks.
     */
    dtm->request_body = ngx_pcalloc(r->pool, len + 1);
    if (dtm->request_body == NULL) {
        contrast_log(ERR, r->connection->log, 0,"failed to alloc req body");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_buf_t *rb_buf = r->request_body->bufs->buf;
    
    /* 
     * XXX: probably should loop this as if it was a chain. I'm not clear on nginx
     * promises with how it organizes the buffers in this case. I've only ever
     * seen one buf in use.
     */
    if (rb_buf->in_file) {
        ngx_read_file(rb_buf->file, dtm->request_body, len, rb_buf->file_pos);
    }
    else if (ngx_buf_in_memory(rb_buf)) {
        ngx_memcpy(dtm->request_body, rb_buf->start, len);
    }

    contrast_dbg_log(r->connection->log, 0,
            "request_body: '%s'", dtm->request_body);

    ngx_int_t deny = send_dtm_to_socket(dtm, 
        conf->socket_path, 
        conf->app_name, 
        r->connection->log,
        r->pool);

    free_request_dtm(r->pool, dtm);

    contrast_dbg_log(r->connection->log, 0,
            "analysis result (body filter): %s", deny ? "blocked" : "allowed");
    if (deny) {
        contrast_log(WARN, r->connection->log, 0,
                "Blocked Request (body filter)");
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        /*
         * I would have expected the above finalize_request() to reset the
         * nginx state machine to handle another request however it leaves the
         * read_event_handler in a blocking state. The finalize_request()
         * function will call itself again later with the NGX_OK rc value, but
         * this is not enough to reset the state machine.
         *
         * The finalize_request() below passes the NGX_DONE code which will
         * close out associated connections and reset the state machine to
         * acception more http requests.
         */
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    /*
     * This handler isn't able to return any values to instruct the nginx core
     * what to do next so instead we must manually advance the nginx http phase
     * and re-enter the phase execution logic.
     */
    r->phase_handler++;
    ngx_http_core_run_phases(r);
    ngx_http_finalize_request(r, NGX_DONE);
    return;
}


ngx_int_t
ngx_http_contrast_connector_preaccess_handler(ngx_http_request_t *r)
{
    contrast_dbg_log(r->connection->log, 0, "in preaccess handler");
    ngx_http_contrast_connector_conf_t * conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);
    ngx_int_t rc;
    ngx_http_contrast_ctx_t *ctx = NULL;

    if (!conf->enable) {
        contrast_dbg_log(r->connection->log, 0,
                "skipping processing because not enabled");
        return NGX_DECLINED;
    }

    if (r != r->main) {
        contrast_dbg_log(r->connection->log, 0,
                "skipping processing because not a main request");
        return NGX_DECLINED;
    }

    ctx = ngx_http_contrast_create_ctx(r);

    if (ctx == NULL) {
        contrast_log(ERR, r->connection->log, 0, "ctx alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_contrast_connector_module);
 
    if (r->method == NGX_HTTP_POST) {
        contrast_dbg_log(r->connection->log, 0,
                "handling HTTP POST for request %p", r);
        rc = ngx_http_read_client_request_body(
            r, ngx_http_contrast_connector_body_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            contrast_log(ERR, r->connection->log, 0,"got bad rc: %d", rc);
            return rc;
        }
        /*
         * we return NGX_DONE here to tell the nginx that we have fully handled
         * the request and that it should not bother calling
         * ngx_http_finalize_request() to move to the next phase of request
         * processing.
         *
         * We do this because our body handler registered above will take care
         * of generating the FORBIDDEN response if needed or moving the request
         * to the next nginx phase and kicking the phase processor again.
         *
         * In short, by registering the body_handler above and returning DONE
         * here, we have effectively paused nginx processing on this request 
         * until the full body has been recieved. This is not the best for
         * performance, but will deliver correct processing with the current
         * design.
         */
        return NGX_DONE;
    }

    /* this is done for GETs and everything else */
    Contrast__Api__Dtm__RawRequest *dtm = create_request_dtm(r->pool, r);
    if (dtm == NULL) {
        contrast_log(ERR, r->connection->log, 0, "failed dtm allocation");
        return NGX_DECLINED;
    }

    ngx_int_t deny = send_dtm_to_socket(
        dtm, conf->socket_path, 
        conf->app_name, 
        r->connection->log, 
        r->pool);

    free_request_dtm(r->pool, dtm);

    contrast_dbg_log(r->connection->log, 0,
        "analysis result: %s", deny ? "blocked" : "allowed");
    if (deny) {
        contrast_log(WARN, r->connection->log, 0, "Blocked Request");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}

    
static ngx_http_contrast_ctx_t *
ngx_http_contrast_create_ctx(ngx_http_request_t *r)
{
    ngx_http_contrast_ctx_t *ctx = NULL;
    ngx_pool_cleanup_t *cln;
    dd("creating new contrast ctx");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_contrast_ctx_t));
    if (ctx == NULL) {
        contrast_log(ERR, r->connection->log, 0, "ctx mem allocation failed");
        return ctx;
    }

    /* this may be ngx version dependent... at least 0.11. */
    ngx_sprintf(ctx->uuid.uuid, "%08xD%08xD%08xD%08xD",
            (uint32_t) ngx_random(), (uint32_t) ngx_random(),
            (uint32_t) ngx_random(), (uint32_t) ngx_random());

    dd("created uuid '%s'", ctx->uuid.uuid);

    ctx->out_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE * 2, r->connection->log);
    if (ctx->out_pool == NULL) {
        contrast_log(ERR, r->connection->log, 0, "ctx mem allocation failed");
        return NULL; /* XXX: leaks ctx */
    }
    
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_contrast_ctx_t));
    cln->handler = ngx_http_contrast_pool_cleanup;
    cln->data = ctx;
    dd("created a new ctx pool");

    return ctx;
}

static void
ngx_http_contrast_pool_cleanup(void *data)
{
    dd("cleaning ctx pool");
    ngx_http_contrast_ctx_t *ctx = data;
    ngx_destroy_pool(ctx->out_pool);
    dd("done cleaning ctx pool");
    return;
}


/**************************************************
 * Output Body processing
 **************************************************/

ngx_int_t
ngx_http_contrast_output_filters_init(ngx_conf_t *cf)
{
    ngx_http_next_output_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_contrast_output_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_contrast_header_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_contrast_header_filter(ngx_http_request_t *r)
{
    contrast_log(ERR, r->connection->log, 0, "in header filter");
    /* 
     * XXX: possible code needed...
     * if the output body filter changes the response body (because of error or
     * blocking it), then this header filter will need to set content_length_n
     * to -1.
     */
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_contrast_output_body_filter(ngx_http_request_t *r,  ngx_chain_t *in)
{
    ngx_int_t last_buf = 0;
    ngx_http_contrast_ctx_t *ctx = NULL;
    ngx_http_contrast_connector_conf_t *cf = NULL;
    ngx_log_t *log = r->connection->log;

    contrast_log(ERR, r->connection->log, 0, "output body filter entered");
    cf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);
    
    /*
     * XXX: These checks could be compressed to one line, but I want to see
     * them separately for now
     */
    if (r != r->main) {
        contrast_dbg_log(log, 0, "bodyfilter, !r->main");
        return ngx_http_next_output_body_filter(r, in);
    } else if (!cf->enable) {
        contrast_dbg_log(log, 0, "bodyfilter, disabled");
        return ngx_http_next_output_body_filter(r, in);
    } else if (ctx == NULL) {
        contrast_dbg_log(log, 0, "bodyfilter, ctx is NULL");
        return ngx_http_next_output_body_filter(r, in);
    }

    for (ngx_chain_t *cl = in; cl != NULL; cl = cl->next) {
        ngx_chain_t *new_cl = NULL;
        ngx_buf_t *buf = cl->buf;
        off_t size = ngx_buf_size(buf);
        ctx->content_len += size;
        contrast_dbg_log(r->connection->log, 0, "buf sz: %d", size);
        new_cl = ngx_pcalloc(ctx->out_pool, sizeof(ngx_chain_t));
        if (new_cl == NULL) {
            contrast_log(ERR, log, 0, "new_cl alloc failed");
            return ngx_http_next_output_body_filter(r, in);
        }
        if (ctx->output_chain == NULL) {
            ctx->output_chain = new_cl;
            dd("setting up first link in chain %p", new_cl);
        }
        new_cl->next = NULL;
        if (size) {
            new_cl->buf = ngx_create_temp_buf(ctx->out_pool, size);
            /* XXX: check alloc status */
            ngx_memcpy(new_cl->buf->pos, cl->buf->pos, size);
            new_cl->buf->last = new_cl->buf->end;
        } else {
            new_cl->buf = ngx_calloc_buf(ctx->out_pool);
            dd("new empty buf: %p", new_cl->buf);
            dd("last_buf?? %d", new_cl->buf->last_buf);
        }
        if (ctx->prev_cl != NULL) {
            dd("assigning prev_cl next: p: %p, cl: %p", ctx->prev_cl, new_cl);
            ctx->prev_cl->next = new_cl;
        }
        dd("assigning prev_cl to %p", new_cl);
        ctx->prev_cl = new_cl;

        if (buf->last_buf)
        {
            contrast_dbg_log(r->connection->log, 0, "got last buf!!!");
            last_buf = 1;
            new_cl->buf->last_buf = 1;
        }
        /* 
         * After buffering the outgoing data in the request context, we need to
         * make the buffer we are given appear as if the data has been
         * processed and handled. Otherwise, the nginx framework will get
         * confused that we are asking for more data via NGX_AGAIN when we
         * haven't handled the full buffer it already gave us.
         */
        dd("consuming in buf");
        buf->pos = buf->last;
    }

    dd("checking last buf");
    if (last_buf)
    {
        dd("FULL BUF gotten, now DTM it for analysis");
        Contrast__Api__Dtm__RawResponse *http_resp_dtm = create_response_dtm(
                r->pool, r);
        dd("pretend to send http-resp dtm");
        ngx_int_t deny = send_response_dtm_to_socket(
            http_resp_dtm, cf->socket_path, 
            cf->app_name, 
            r->connection->log, 
            r->pool);

        free_response_dtm(r->pool, http_resp_dtm);

        contrast_dbg_log(r->connection->log, 0, "calling next body filter");
        return ngx_http_next_output_body_filter(r, ctx->output_chain);
    } else {
        contrast_dbg_log(r->connection->log, 0, "body filter returning NGX_AGAIN");
        return NGX_AGAIN;
    }
}



