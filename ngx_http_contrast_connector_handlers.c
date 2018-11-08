/* NGINX stuff */
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <netinet/in.h>

/* Protobuf stuff */
#include "connect.pb-c.h"

/* Connector stuff */
#include "module_version.h"
#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"

/* Language key to report to Teamsever */
#define APP_LANG  "Proxy" 

/*
 * Client ID for contrast-service. This is used as part of larger communication
 * protocol with features that don't apply to this webserver agent.
 * ClientID+PID is used by TS/contrast-service to record which agents have
 * received their settings from TS. This does not apply to webserver connectory
 * modules thus a non-uniquely identifying client id is ok.
 */
#define CLIENT_ID  "NGINX"

/* XXX: eh, any better options?  name should reflect its global. Will this be
 * accessed/modified concurrently in the same memory space? If so, we have an
 * issue.
 */
static int32_t message_count = 0;

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
        Contrast__Api__Connect__Pair ***hdr_array, size_t *hdrcnt,
        ngx_log_t *log);
static void read_chain_buf(void *dst, ngx_buf_t *buf, off_t max_sz);

/*
 * populate addr with information about a IPv4/IPv6 address.
 * address is dynamically allocated and must be freed. 
 */
static ngx_int_t
read_address(ngx_connection_t *conn, address_t *addr)
{
    /* nginx env should *always* have a valid sockaddr */
    struct sockaddr *sockaddr = conn->sockaddr;

    if (sockaddr->sa_family == AF_INET) {
        struct sockaddr_in * sin = (struct sockaddr_in *)sockaddr;
        addr->address = ngx_pcalloc(conn->pool, INET_ADDRSTRLEN);
        if (addr->address != NULL) {           
            inet_ntop(AF_INET, &(sin->sin_addr), addr->address, INET_ADDRSTRLEN);
            addr->port = sin->sin_port;
            addr->version = 4;
            return NGX_OK;
        }
    } else if (sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 * sin = (struct sockaddr_in6 *)sockaddr;
        addr->address = ngx_pcalloc(conn->pool, INET6_ADDRSTRLEN);
        if (addr->address != NULL) { 
            inet_ntop(AF_INET6, &(sin->sin6_addr), addr->address, INET6_ADDRSTRLEN);
            addr->port = sin->sin6_port;
            addr->version = 6;
            return NGX_OK;
        }
    } else {
        contrast_log(ERR, conn->log, 0,
            "unknown sockaddr family used [0x%x], can't obtain ip information",
            sockaddr->sa_family);
    }

    return NGX_ERROR;
}

static void
read_chain_buf(void *dst, ngx_buf_t *buf, off_t max_sz)
{
    off_t size = ngx_buf_size(buf);
    
    if (size > max_sz)
    {
        dd("something wrong in buf copy");
        return;
    }

    if (buf->in_file) {
        ngx_read_file(buf->file, dst, size, buf->file_pos);
    }
    else if (ngx_buf_in_memory(buf)) {
        /* 
         * XXX: when running as a dynamic module, the 'start' field is nil!
         * This doesn't seem to jive with the nginx dev guide. Anyways, be 
         * sure to always use the 'pos' field when dealing with memory bufs.
         */
        dd("reading buf from memory (%p, %p, %llu)",
            dst, buf->pos, (unsigned long long)size);
        ngx_memcpy(dst, buf->pos, size);
    }

    return;
}

void chain_to_buffer(ngx_chain_t *in, void *out, off_t max_sz)
{
    off_t total_sz = 0;
    u_char *pos = out;
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

        read_chain_buf(pos, buf, size);
        pos += size;

        if (buf->last_buf) {
            dd("I just hit the last buffer in a chain!");
        }
    }
    return;
}


static Contrast__Api__Connect__Request *
create_http_response_dtm(ngx_pool_t *pool, ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;
    contrast_dbg_log(log, 0, "building RawResponse dtm");
    ngx_http_contrast_connector_conf_t *conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);
    ngx_http_contrast_ctx_t *ctx = ngx_http_get_module_ctx(
            r, ngx_http_contrast_connector_module);

    if (ctx == NULL) {
        contrast_log(ERR, log, 0, "ctx doesn't exists on response");
        return NULL;
    }

    Contrast__Api__Connect__Request *dtm = ngx_pcalloc(
        pool, sizeof(Contrast__Api__Connect__Request));
    
    if (dtm == NULL) {
        contrast_log(ERR, log, 0, "failed to alloc response dtm");
        return dtm;
    }

    contrast__api__connect__request__init(dtm);
    /* XXX: phase4 command, should have #def */
    dtm->command = 4;
    dtm->app_language = APP_LANG;
    dtm->message_count = ++message_count;
    dtm->client_id = CLIENT_ID;

    /* XXX: the next two should be migrated to the PING command */
    dtm->connector_type = NGINX_VER;
    dtm->connector_version = CONTRAST_MODULE_VERSION;
    dtm->pid = (int32_t)ngx_processes[ngx_process_slot].pid;

    dtm->timestamp_ms = unix_millis();
    dtm->uuid = ngx_pnalloc(pool, sizeof(ngx_contrast_uuid_t));
    ngx_memcpy(dtm->uuid, ctx->uuid.uuid, sizeof(ngx_contrast_uuid_t));

    dd("dtm response uuid '%s'", ctx->uuid.uuid);
    dtm->app_name = ngx_str_to_char(&conf->app_name, pool);

    dtm->response_code = r->headers_out.status;
    dd("access code is %lu", r->headers_out.status);
    /* XXX: need to check on these copies. NGINX documentation made a comment
     * that ngx_str_t may not always be null terminated.  The pcalloc is 
     * side-stepping the problem, but it may not be necessary if we handle
     * the case explicitly
     */

    dd("response hdr content-type: %s", r->headers_out.content_type.data);
    dtm->n_response_headers = 0;
    build_http_headers_in_dtm(
            pool, &(r->headers_out.headers),
            &(dtm->response_headers), &dtm->n_response_headers, log);
    

    Contrast__Api__Connect__Pair *pair = ngx_pcalloc(
            pool, sizeof(Contrast__Api__Connect__Pair));
    contrast__api__connect__pair__init(pair);

    ngx_str_t content_type_str = ngx_string("Content-Type");
    dd("str.data: '%s', str.len: %lu", content_type_str.data, content_type_str.len);
    pair->key = ngx_str_to_char(&content_type_str, pool);
    pair->value = ngx_str_to_char(&r->headers_out.content_type, pool);

    dd("ct key: %s", pair->key);
    dd("ct val: %s", pair->value);

    dtm->response_headers = realloc(dtm->response_headers,
        sizeof(Contrast__Api__Connect__Pair *) * (dtm->n_response_headers + 1));
    dtm->response_headers[dtm->n_response_headers] = pair;
    dtm->n_response_headers++;

    /*
     * ctx->content_len will be zero if there is no content or if
     * contrast_enable_response_body is off as this function will be called in
     * the LOG phase which is before any body filter logic that fills the
     * ctx->content_len. I imagine refactoring this logic in the future, it's
     * hard to follow.
     */
    if (ctx->output_chain == NULL || ctx->content_len == 0)
    {
        goto exit;
    }

    dtm->response_body.data = ngx_pnalloc(pool, ctx->content_len);
    chain_to_buffer(ctx->output_chain, dtm->response_body.data, ctx->content_len);
    dtm->response_body.len = ctx->content_len;

exit:

    return dtm;
}


static Contrast__Api__Connect__Request *
create_http_request_dtm(ngx_pool_t *pool, ngx_http_request_t *r) 
{
    Contrast__Api__Connect__Request *dtm = NULL;
    ngx_http_contrast_connector_conf_t *conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);
    ngx_log_t *log = r->connection->log;
    ngx_http_contrast_ctx_t *ctx = ngx_http_get_module_ctx(
            r, ngx_http_contrast_connector_module);

    dtm = ngx_pcalloc(pool, sizeof(Contrast__Api__Connect__Request));
    if (dtm == NULL) {
        contrast_log(ERR, log, 0, "failed to alloc dtm");
        return dtm;
    }

    contrast__api__connect__request__init(dtm);
    dtm->client_id = CLIENT_ID;
    dtm->pid = (int32_t)ngx_processes[ngx_process_slot].pid;

    /* XXX: phase 2 command.  This should have a #def for the value */
    dtm->command = 2;
    dtm->message_count = ++message_count;
    dtm->app_language = APP_LANG;
    dtm->client_id = CLIENT_ID;
    /* XXX: the next two will migrate to the PING command msg */
    dtm->connector_type = NGINX_VER;
    dtm->connector_version = CONTRAST_MODULE_VERSION;
    dtm->pid = (int32_t)ngx_processes[ngx_process_slot].pid;
    dtm->timestamp_ms = unix_millis();
    dtm->uuid = ngx_pnalloc(pool, sizeof(ngx_contrast_uuid_t));
    ngx_memcpy(dtm->uuid, ctx->uuid.uuid, sizeof(ngx_contrast_uuid_t));
    dd("dtm request uuid '%s'", ctx->uuid.uuid);

    /* perhaps this app_name should be global as its unlikely to change */
    dtm->app_name = ngx_str_to_char(&conf->app_name, pool);
    
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
    if (read_address(r->connection, &client_address) == NGX_OK) {
        if (client_address.address != NULL) {
            dtm->client_ip = client_address.address;
            dtm->client_ip_version = client_address.version;
            dtm->client_port = client_address.port;
            contrast_dbg_log(log, 0, "-> ip=%s (ipv%d) port=%d",
                dtm->client_ip, dtm->client_ip_version, dtm->client_port); 
        }
    }

    struct address_s server_address;
    if (read_address(r->connection, &server_address) == NGX_OK) {
        if (server_address.address != NULL) {
            dtm->server_ip = server_address.address;
            dtm->server_ip_version = server_address.version;
            dtm->server_port = server_address.port;
            contrast_dbg_log(log, 0, "<- ip=%s (ipv%d) port=%d",
                dtm->server_ip, dtm->server_ip_version, dtm->server_port); 
        }
    }

    dtm->request_body.data = NULL;
    dtm->request_body.len = 0;

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
        Contrast__Api__Connect__Pair ***hdr_array,
        size_t *hdrcnt,
        ngx_log_t *log)
{
    ngx_list_t list = *hdrs;
    *hdrcnt = 0;
    dd("list nalloc: %lu", list.nalloc);
    if (list.nalloc <= 0) {
        return;
    }

    ngx_list_part_t * curr = &list.part;
    ngx_table_elt_t * entry_ptr = (ngx_table_elt_t *)curr->elts;
    ngx_table_elt_t * entry = NULL;

    dd("list part nelts: %lu", curr->nelts);

    for(size_t count = 0; ; count++) {
        if (count >= curr->nelts) {
            if (curr->next == NULL) {
                dd("hdr loop done");
                break;
            }

            curr = curr->next;
            entry_ptr = (ngx_table_elt_t *)curr->elts;
            count = 0;
        }

        entry = (&entry_ptr[count]);
    
        Contrast__Api__Connect__Pair *pair = ngx_pcalloc(
                pool, sizeof(Contrast__Api__Connect__Pair));
        contrast__api__connect__pair__init(pair);

        pair->key = ngx_str_to_char(&entry->key, pool);
        if (pair->key == NULL) {
            contrast_log(ERR, log, 0, "error: alloc failed for key");
            ngx_pfree(pool, pair);
            continue;
        }
        
        pair->value = ngx_str_to_char(&entry->value, pool);
        if (pair->value == NULL) {
            contrast_log(ERR, log, 0, "error: alloc failed for val");
            ngx_pfree(pool, pair->key);
            ngx_pfree(pool, pair);
            continue;
        }
        *hdr_array = realloc(
                *hdr_array, 
                sizeof(Contrast__Api__Connect__Pair *) * (*hdrcnt + 1));
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
free_http_response_dtm(ngx_pool_t *pool, Contrast__Api__Connect__Request *dtm) 
{
    dd("free response dtm");
    if (dtm->uuid != NULL) {
        ngx_pfree(pool, dtm->uuid);
    }

    if (dtm->response_headers != NULL) {
        dd("free headers");
        for (size_t i = 0; i < dtm->n_response_headers; ++i) {
            dd("free: i=%lu, k: %s, v= %s", i, dtm->response_headers[i]->key, dtm->response_headers[i]->value);
            ngx_pfree(pool, dtm->response_headers[i]);

        }
        /* realloc was used for this memory */
        ngx_free(dtm->response_headers);
    }

    if (dtm->response_body.data != NULL) {
        ngx_pfree(pool, dtm->response_body.data);
    }
    if (dtm->app_name != NULL) {
        ngx_pfree(pool, dtm->app_name);
    }

    ngx_pfree(pool, dtm); 
}


static void
free_http_request_dtm(ngx_pool_t *pool, Contrast__Api__Connect__Request *dtm) 
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

    if (dtm->request_body.data != NULL) {
        ngx_pfree(pool, dtm->request_body.data);
    }

    if (dtm->app_name != NULL) {
        ngx_pfree(pool, dtm->app_name);
    }

    ngx_pfree(pool, dtm); 
}

static ngx_int_t 
send_connect_request_dtm(
        Contrast__Api__Connect__Request *dtm, 
        ngx_str_t socket_path,
        ngx_log_t *log,
        ngx_pool_t *pool)
{
    ngx_int_t deny = 0;
    ngx_str_t *response = NULL;
    Contrast__Api__Connect__Response *settings = NULL;

    size_t len = contrast__api__connect__request__get_packed_size(dtm);
    contrast_dbg_log(log, 0, "estimated size of packed message: %ld", len);

    void *buf = ngx_palloc(pool, len);

    if (buf == NULL) {
        contrast_log(ERR, log, 0,
                "error: could not allocate buffer size for protobuf message");
        goto fail;
    }


    size_t packed_size = contrast__api__connect__request__pack(dtm, buf);
    contrast_dbg_log(log, 0, "actual packed message size: %ld", packed_size);
    response = write_to_service(socket_path, buf, len, log);
    ngx_pfree(pool, buf);
    
    if (response == NULL) {
        contrast_log(ERR, log, 0, "error writing dtm to analysis engine");
        goto fail;
    }

    settings = contrast__api__connect__response__unpack(
        NULL, response->len, response->data);
    ngx_free(response->data);
    ngx_free(response);
    if (settings == NULL) {
        contrast_log(ERR, log, 0,
                "failed to deserialize analysis engine response");
        goto fail;
    }
    
    dd("SR connect-reponse dtm: uuid: %p , track: %d, exception: %d, &msg: %p",
            settings->uuid, settings->track_request, settings->security_exception,
            settings->security_message);

    if (settings->security_exception) {
        contrast_dbg_log(log, 0, "security exception: %s uuid=%s", 
            settings->security_message,
            settings->uuid);
        deny = 1;
    }

fail:
    if (settings) {
        ngx_free(settings);
    }

    return deny;
}


void
ngx_http_contrast_request_read(ngx_http_request_t *r) 
{
     ngx_http_contrast_ctx_t *ctx;

     ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);

     /* 
      * This is the main-request reference count. It was incremented when the
      * read_client_request_body was called from the preaccess handler.  I
      * don't know why it should be decremented here but I saw it done in
      * another module.
      *
      * My guess is that we are re-running the same phases of the state machine
      * in a round about way to make the request body fully buffer as the
      * preaccess phase and thus we don't want to represent the
      * read_client_request_body "phase" to represent holding a reference on
      * the request... because its really not.
      */
     r->main->count--;

     if (ctx->waiting_more_body)
     {   
         ctx->waiting_more_body = 0;
         ngx_http_core_run_phases(r);
     }   
}


/*
 * This is the main pre-access handler where recording data to be analyzed
 * begins. It's important to understand that this handler can be called
 * multiple times for the same overall request. This certainly occurs when the
 * client has issued an "Expect: 100-Continue" request to us, but may happen
 * for cases I don't yet know about.
 */
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

        /*
         * modules later in the nginx phases (such as 'mirror' at the
         * PRECONTENT phase) will generate a subrequest that goes back thru the
         * phase machine. Since the request body is typically read after module
         * like 'mirror', the mirror module will take a shortcut and generate a
         * subrequest before the client body has been read into the main
         * request. Since in this module, we read the client request body way
         * up in the PREACCESS phase, this subrequest is being created with the
         * client request body from the main request which is wrong.
         */
        if (!r->main->preserve_body && r->header_only) {
            /*
             * allocate fake request body to overwrite the real request body in
             * the subrequest only, but only if the main request doesn't want
             * to preserve its body... I still don't fully understand nginx
             * internals.
             */

            dd("allocating subrequest fake body since its a headers_only subrequest");
            r->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (r->request_body == NULL) {
                dd("failed alloc subrequest fake body");
                return NGX_ERROR;
            }
        }

        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);
    if (ctx == NULL) {
        ctx = ngx_http_contrast_create_ctx(r);
        if (ctx == NULL) {
            contrast_log(ERR, r->connection->log, 0, "ctx alloc failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        dd("setting a new context: %p", ctx);
        ngx_http_set_ctx(r, ctx, ngx_http_contrast_connector_module);
    } else {
        dd("reusing an existing ctx: %p", ctx);
    }

    if (ctx->waiting_more_body) {
        dd("still waiting on more body data before proceeding. count: %d",
            r->main->count);
        /*
         * NGINX has called this handler again on an existing request
         * in-progress that we wanted more data from.
         *
         * we return NGX_DONE here to tell the nginx that we have fully handled
         * the request and that it should not bother calling
         * ngx_http_finalize_request() to move to the next phase of request
         * processing. This is a lie.
         *
         * We do this because we need to buffer the entire request body so it
         * can be sent in one piece to speedracer. This buffering behavior is
         * opposite to nginx's design and will likely severely restrict its
         * ability to work in its high-performant nature when connection load
         * is high, but such is life currently in the name of security.
         * Returning NGX_DONE at this stage will force nginx to not process the
         * partial request buffer and make it stuck at this stage for the
         * request so the entire request is buffered.
         *
         */
        return NGX_DONE;
    }

    if (!ctx->body_requested) {
        ctx->body_requested = 1;

        dd("asking for request body, main count is: %d", r->main->count);
        /* 
         * read body into a single memory buffer. eh, why not? we are buffering
         * the whole thing
         */
        r->request_body_in_single_buf = 1;

        /* 
         * do not unlink the file immediately after creation. This file is able
         * to be moved to another directory if speedracer wanted to perform
         * scanning on large request bodies directly.  I'm not going to use
         * this yet, but may be an interesting optimization point later.
         *
         *  r->request_body_in_persistent_file = 1;
         */
        /*
         * unlink the file when request is finalized. Used in coordination with
         * the persistent flag above.
         *
         *  r->request_body_in_clean_file = 1;
         */
        rc = ngx_http_read_client_request_body(
            r, ngx_http_contrast_request_read);

        if (rc == NGX_AGAIN) {
            dd("nginx wants us to wait for more data");
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    /* check if this request is fully buffered and ready to be processed */
    if (!ctx->waiting_more_body)
    {
        /* 
         * If we requested more body from the above statement and either got it
         * all or there wasn't any more then we will hit this block
         */
        dd("all request body is received and ready to be processed");
        
        if (r->request_body->temp_file) {
            dd("request body in tempfile");
            /* 
             * I'm hoping that that the chain buffer processing will read the
             * data from the tempfile in the same way that it reads it from
             * memory. It should.
             */
        } else {
            dd("request body in memory");
        }

        off_t len = 0;
        for (ngx_chain_t *in = r->request_body->bufs; in; in = in->next) {
            len += ngx_buf_size(in->buf);
        }
        dd("request buffer total size: %ld bytes", len);
    
        Contrast__Api__Connect__Request * dtm = create_http_request_dtm(r->pool, r);
        if (dtm == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * request_body memory owned by dtm and will be freed in free_dtm. In the
         * future, I'd like for build_dtm_from_request to handle this or have the
         * analysis engine take the body in chunks... maybe
         */
        if (len) {
            dtm->request_body.data = ngx_pcalloc(r->pool, len);
            if (dtm->request_body.data == NULL) {
                contrast_log(ERR, r->connection->log, 0,"failed to alloc req body");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            chain_to_buffer(r->request_body->bufs, dtm->request_body.data, len);
            dtm->request_body.len = len;
        }
        ngx_int_t deny = send_connect_request_dtm(dtm, 
            conf->socket_path, 
            r->connection->log,
            r->pool);

        free_http_request_dtm(r->pool, dtm);

        contrast_dbg_log(r->connection->log, 0,
                "analysis result: %s", deny ? "blocked" : "allowed");
        if (deny) {
            contrast_log(INFO, r->connection->log, 0, "Blocked Request");
            return NGX_HTTP_FORBIDDEN;
        }
    }

return NGX_DECLINED;
}

/*
 * Postrequest handler.
 * This handler runs in the LOG phase only when the
 * contrast_enable_response_body is off. This means that response body
 * processing won't happen in the output body filter so we need to tell the
 * analysis engine about the response metadata (timing, size, status, etc) so
 * the analysis engine can close out the open transaction internally.
 */
ngx_int_t
ngx_http_contrast_connector_log_handler(ngx_http_request_t *r)
{
    contrast_dbg_log(r->connection->log, 0, "in LOG phase handler");
    ngx_http_contrast_connector_conf_t * conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);

    if (conf->enable_response_body) {
        contrast_dbg_log(r->connection->log, 0,
                "skipping log_phase processing because not enabled");
        return NGX_DECLINED;
    }

    /*
     * XXX: There are no intervention decisions made at this phase so we can
     * actually dispatch the notification to a background context so the nginx
     * worker doesn't block on the IO to the engine.
     */
    Contrast__Api__Connect__Request *http_resp_dtm = create_http_response_dtm(
            r->pool, r);
    send_connect_request_dtm(
        http_resp_dtm, conf->socket_path,
        r->connection->log,
        r->pool);

    free_http_response_dtm(r->pool, http_resp_dtm);

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
    ngx_sprintf((u_char*)ctx->uuid.uuid, "%08xD%08xD%08xD%08xD",
            (uint32_t) ngx_random(), (uint32_t) ngx_random(),
            (uint32_t) ngx_random(), (uint32_t) ngx_random());

    dd("created uuid '%s'", ctx->uuid.uuid);

    ctx->out_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE * 2, r->connection->log);
    if (ctx->out_pool == NULL) {
        contrast_log(ERR, r->connection->log, 0, "ctx mem allocation failed");
        ngx_pfree(r->pool, ctx);
        return NULL;
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

/* 
 * response headers come to us all at once in this callback.  There are no
 * multiple calls for partial header info. We /should/ be sending the current
 * header info for analysis before processing the full body, but we are not
 * yet.  We simply instruct nginx to buffer the body in memory and then
 * continue to the next header filter.
 *
 * XXX: I *think* this filter is being added to the top of the filter chain.
 * For full analysis of any dynamically added headers by other filters, we'd
 * want to be added to the bottom of the filter chain.
 */
static ngx_int_t
ngx_http_contrast_header_filter(ngx_http_request_t *r)
{
    ngx_http_contrast_connector_conf_t *cf = NULL;
    ngx_http_contrast_ctx_t *ctx = NULL;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);
    /* 
     * XXX: possible code needed...
     * if the output body filter changes the response body (because of error or
     * blocking it), then this header filter will need to set content_length_n
     * to -1.
     */

    if (r != r->main || !cf->enable) {
        return ngx_http_next_header_filter(r);
    }
    if (ctx && ctx->complete) {
        contrast_dbg_log(r->connection->log, 0,
                "request object already processed, hdr pass thru");
        return ngx_http_next_header_filter(r);
    }

    /* 
     * Tell nginx to buffer the header data in memory. By not calling the next
     * filter yet, we are forcing the buffering to occur. Setting the flag
     * below causes nginx to _not_ call the output after this filter.  I'm not
     * sure if this is necessary... it may only apply to following header
     * chunks arriving after this one.
     */
    r->filter_need_in_memory = 1;
    return ngx_http_next_header_filter(r);
}


/* 
 * we come into this filter function will all of the headers buffered in
 * memory. Before we pass control to the next body filter, we need to be sure
 * to call the next header filter so all of the header is written to the
 * client before the outgoing body. That occurs when simply passing the 
 * response though. If the response is going to be denied, then we finalize the
 * request at this stage right away with an error code which will cause nginx
 * to serve its error page to the client.
 *
 * Note that this filter function will be called on the actual client response
 * and also on any error response that we generate. To stop any recursive
 * cycles of us processing our own error response and taking action, we use the
 * context flag, ctx->complete, to let ourselves know that we have already
 * taken action on this request object and we should pass through to normal
 * nginx filters.
 */
static ngx_int_t
ngx_http_contrast_output_body_filter(ngx_http_request_t *r,  ngx_chain_t *in)
{
    ngx_int_t last_buf = 0;
    ngx_http_contrast_ctx_t *ctx = NULL;
    ngx_http_contrast_connector_conf_t *cf = NULL;
    ngx_log_t *log = r->connection->log;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_contrast_connector_module);

    /*
     * XXX: These checks could be compressed to one line, but I want to see
     * them separately for now
     */

    if (r != r->main) {
        contrast_dbg_log(log, 0, "bodyfilter, !r->main");
        return ngx_http_next_output_body_filter(r, in);
    } else if (!cf->enable || !cf->enable_response_body) {
        contrast_dbg_log(log, 0, "bodyfilter, disabled");
        return ngx_http_next_output_body_filter(r, in);
    } else if (ctx == NULL) {
        contrast_dbg_log(log, 0, "bodyfilter, ctx is NULL");
        return ngx_http_next_output_body_filter(r, in);
    } else if (ctx->complete) {
        contrast_dbg_log(log, 0,
                "this request object has already been decided on, pass thru");
        return ngx_http_next_output_body_filter(r, in);
    }

    for (ngx_chain_t *cl = in; cl != NULL; cl = cl->next) {
        ngx_chain_t *new_cl = NULL;
        ngx_buf_t *buf = cl->buf;
        off_t size = ngx_buf_size(buf);
        dd("cl m:%d, f:%d", ngx_buf_in_memory(buf), buf->in_file); 
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
            dd("creating tmp buf");
            new_cl->buf = ngx_create_temp_buf(ctx->out_pool, size);
            /* XXX: check alloc status */
            if (new_cl->buf == NULL) {
                dd("failed to alloc tmp buf");
            }
            dd("about to memcpy(%p, %p, %llu)",
                new_cl->buf->pos, cl->buf->pos, (unsigned long long)size);
            read_chain_buf(new_cl->buf->pos, cl->buf, size);
            dd("mem cpy done");
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
    if (!last_buf) {
        contrast_dbg_log(r->connection->log, 0, "body filter returning NGX_AGAIN");
        return NGX_AGAIN;
    }

    dd("FULL BUF gotten, now DTM it for analysis");

    /* 
     * this request/response object is now in memory a ready for processing.
     * Regardless of what we decide about the object, allow nginx to perform
     * normal processing on it from this point forward.
     */
    ctx->complete = 1;
    Contrast__Api__Connect__Request *http_resp_dtm = create_http_response_dtm(
            r->pool, r);
    ngx_int_t deny = send_connect_request_dtm(
        http_resp_dtm, cf->socket_path, 
        r->connection->log, 
        r->pool);

    free_http_response_dtm(r->pool, http_resp_dtm);

    dd("response check from SR is %ld", deny);
    if (deny)
    {
        dd("attempting to send 403 response");
        return ngx_http_filter_finalize_request(
                r, &ngx_http_contrast_connector_module,
                NGX_HTTP_FORBIDDEN);
    }
 
    contrast_dbg_log(r->connection->log, 0, "calling next body filter");
    /* send out the buffered body */
    return ngx_http_next_output_body_filter(r, ctx->output_chain);
}

