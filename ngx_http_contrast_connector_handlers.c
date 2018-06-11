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

/*
 * populate addr with information about a IPv6 address.
 * address is dynamically allocated and must be freed. 
 */
static ngx_int_t
read_ipv6_address(ngx_connection_t *connection, address_t *addr) {
    return NGX_ERROR;
}


static Contrast__Api__Dtm__RawRequest *
build_dtm_from_request(ngx_http_request_t *r) 
{
    ngx_log_t *log = r->connection->log;
    
    Contrast__Api__Dtm__RawRequest *dtm = ngx_pcalloc(
        r->pool, sizeof(Contrast__Api__Dtm__RawRequest));
    
    if (dtm == NULL) {
        contrast_log(ERR, log, 0, "failed to alloc dtm");
        return dtm;
    }

    contrast__api__dtm__raw_request__init(dtm);

    dtm->timestamp_ms = unix_millis();

    /* XXX: need to check on these copies. NGINX documentation made a comment
     * that ngx_str_t may not always be null terminated.  The pcalloc is 
     * side-stepping the problem, but it may not be necessary if we handle
     * the case explicitly
     */
    dtm->request_line = ngx_pcalloc(r->pool, r->request_line.len + 1);
    if (dtm->request_line != NULL) {
        strncpy(dtm->request_line, (char*)r->request_line.data,
                r->request_line.len);
        contrast_dbg_log(log, 0, "request_line: %s", dtm->request_line);
    }

    dtm->normalized_uri = ngx_pcalloc(r->pool, r->uri.len + 1);
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
    ngx_list_t list = r->headers_in.headers;
    if (list.nalloc > 0) {
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
                    r->pool, sizeof(Contrast__Api__Dtm__SimplePair));
            contrast__api__dtm__simple_pair__init(pair);

            pair->key = ngx_pcalloc(r->pool, entry->key.len + 1);
            if (pair->key == NULL) {
                ngx_pfree(r->pool, pair);
                continue;
            }
            strncpy(pair->key, (char*)entry->key.data, entry->key.len);

            pair->value = ngx_pcalloc(r->pool, entry->value.len + 1);
            if (pair->value == NULL) {
                ngx_pfree(r->pool, pair->key);
                ngx_pfree(r->pool, pair);
                continue;
            }
            strncpy(pair->value, (char*)entry->value.data, entry->value.len);

            dtm->request_headers = realloc(
                    dtm->request_headers, 
                    sizeof(Contrast__Api__Dtm__SimplePair *) * (dtm->n_request_headers + 1));
            if (dtm->request_headers == NULL) {
                contrast_log(ERR, log, 0,
                        "error: alloc or realloc failed for headers");
                ngx_pfree(r->pool, pair->key);
                ngx_pfree(r->pool, pair->value);
                ngx_pfree(r->pool, pair);
                dtm->n_request_headers = 0;
                break;
            }
            contrast_dbg_log(log, 0, "[header] %s=%s", pair->key, pair->value);
            dtm->request_headers[dtm->n_request_headers] = pair;
            dtm->n_request_headers++;
        }
    }

    return dtm;
}

static void
free_dtm(ngx_pool_t *pool, Contrast__Api__Dtm__RawRequest *dtm) 
{
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
    
    Contrast__Api__Dtm__RawRequest * dtm = build_dtm_from_request(r);
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

    free_dtm(r->pool, dtm);

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

    if (!conf->enable) {
        contrast_dbg_log(r->connection->log, 0,
                "skipping processing because not enabled");
        return NGX_DECLINED;
    }

    if (!r->main) {
        contrast_dbg_log(r->connection->log, 0,
                "skipping processing because not a main request");
        return NGX_DECLINED;
    }
 
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
    Contrast__Api__Dtm__RawRequest *dtm = build_dtm_from_request(r);
    if (dtm == NULL) {
        contrast_log(ERR, r->connection->log, 0, "failed dtm allocation");
        return NGX_DECLINED;
    }

    ngx_int_t deny = send_dtm_to_socket(
        dtm, conf->socket_path, 
        conf->app_name, 
        r->connection->log, 
        r->pool);

    free_dtm(r->pool, dtm);

    contrast_dbg_log(r->connection->log, 0,
        "analysis result: %s", deny ? "blocked" : "allowed");
    if (deny) {
        contrast_log(WARN, r->connection->log, 0, "Blocked Request");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}

