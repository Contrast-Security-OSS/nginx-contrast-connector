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

static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_output_header_filter;

typedef struct address_s {
    u_char * address;
    int32_t port;
    int32_t version;
} address_t;

/*
 * populate addr with information about a IPv4 address.
 * address is dynamically allocated and must be freed. 
 */
static ngx_int_t
read_address(
        struct sockaddr *sockaddr, address_t *addr, ngx_log_t *log)
{
    if (sockaddr && sockaddr->sa_family == AF_INET) {
        struct sockaddr_in * sin = (struct sockaddr_in *)sockaddr;
        if (sin != NULL) {
            addr->address = ngx_calloc(INET_ADDRSTRLEN, log);
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

/*
 * read body from chain; if returned value is not null it must be freed when complete
 */
static u_char *
read_body(ngx_chain_t *in, ngx_log_t *log)
{
    if (in == NULL || in->buf->pos == in->buf->last) {
        return NULL;
    }

    u_char * body = NULL;
    size_t body_len = 0;
    
    u_char * chunk = NULL;
    size_t chunk_len = 0;

    for (ngx_chain_t * chain = in; chain != NULL; chain = chain->next) {
        chunk = chain->buf->pos;
        chunk_len = chain->buf->last - chunk;

        body = realloc(body, body_len + chunk_len + 1);
        strncpy(body + body_len, chunk, chunk_len);

        body_len += chunk_len;
    }

    return body;
}


static Contrast__Api__Dtm__RawRequest *
build_dtm_from_request(ngx_http_request_t *r) 
{
    ngx_log_t * log = r->connection->log;

    Contrast__Api__Dtm__RawRequest * dtm = ngx_calloc(sizeof(Contrast__Api__Dtm__RawRequest), log);
    contrast__api__dtm__raw_request__init(dtm);

    dtm->timestamp_ms = unix_millis();

    dtm->request_line = ngx_calloc(r->request_line.len + 1, log);
    if (dtm->request_line != NULL) {
        strncpy(dtm->request_line, r->request_line.data, r->request_line.len);
        dd("request_line: %s", dtm->request_line);
    }

    dtm->normalized_uri = ngx_calloc(r->uri.len+1, log);
    if (dtm->normalized_uri != NULL) {
        strncpy(dtm->normalized_uri, r->uri.data, r->uri.len);
        dd("normalized_uri: %s", dtm->normalized_uri);
    }

    struct address_s client_address;
    if (read_address(r->connection->sockaddr, &client_address, log) == NGX_OK) {
        if (client_address.address != NULL) {
            dtm->client_ip = client_address.address;
            dtm->client_ip_version = client_address.version;
            dtm->client_port = client_address.port;
            dd("-> ip=%s (ipv%d) port=%d", dtm->client_ip, dtm->client_ip_version, dtm->client_port); 
        }
    }

    struct address_s server_address;
    if (read_address(r->connection->listening->sockaddr, &server_address, log) == NGX_OK) {
        if (server_address.address != NULL) {
            dtm->server_ip = server_address.address;
            dtm->server_ip_version = server_address.version;
            dtm->server_port = server_address.port;
            dd("<- ip=%s (ipv%d) port=%d", dtm->server_ip, dtm->server_ip_version, dtm->server_port); 
        }
    }

    dtm->request_body = NULL;

    dtm->n_request_headers = 0;
    ngx_list_t list = r->headers_in.headers;
    if (list.nalloc > 0) {
        ngx_list_part_t * curr = &list.part;
        ngx_table_elt_t * entry_ptr = (ngx_table_elt_t *)curr->elts;
        ngx_table_elt_t * entry = NULL;

        for(ngx_int_t count = 0; ; count++) {

            if (count >= curr->nelts) {
                if (curr->next == NULL) {
                    break;
                }

                curr = curr->next;
                entry_ptr = (ngx_table_elt_t *)curr->elts;
                count = 0;
            }

            entry = (&entry_ptr[count]);
        
            // initialize new pair
            Contrast__Api__Dtm__SimplePair * pair = ngx_calloc(
                    sizeof(Contrast__Api__Dtm__SimplePair), 
                    log);
            contrast__api__dtm__simple_pair__init(pair);

            // copy the header key
            pair->key = ngx_calloc(entry->key.len + 1, log);
            if (pair->key == NULL) {
                free(pair);
                continue;
            }
            strncpy(pair->key, entry->key.data, entry->key.len);

            // copy the header value
            pair->value = ngx_calloc(entry->value.len + 1, log);
            if (pair->value == NULL) {
                free(pair->key);
                free(pair);
                continue;
            }
            strncpy(pair->value, entry->value.data, entry->value.len);

            dtm->request_headers = realloc(dtm->request_headers, 
                    sizeof(Contrast__Api__Dtm__SimplePair *) * (dtm->n_request_headers+1));
            if (dtm->request_headers == NULL) {
                dd("[ERROR] alloc or realloc failed for headers");
                free(pair->key);
                free(pair->value);
                free(pair);
                dtm->n_request_headers = 0;
                break;
            }
            dd("[header] %s=%s", pair->key, pair->value);
            dtm->request_headers[dtm->n_request_headers] = pair;
            dtm->n_request_headers++;
        }
    }

    return dtm;
}

static void
free_dtm(Contrast__Api__Dtm__RawRequest *dtm) 
{
    if (dtm->request_line != NULL) {
        ngx_free(dtm->request_line);
    }

    if (dtm->normalized_uri != NULL) {
        ngx_free(dtm->normalized_uri);
    }

    if (dtm->client_ip != NULL) {
        ngx_free(dtm->client_ip);
    }

    if (dtm->server_ip != NULL) {
        ngx_free(dtm->server_ip);
    }

    if (dtm->request_headers != NULL) {
        for (ngx_int_t i = 0; i < dtm->n_request_headers; ++i) {
            ngx_free(dtm->request_headers[i]);
        }
        ngx_free(dtm->request_headers);
    }

    if (dtm->request_body != NULL) {
        ngx_free(dtm->request_body);
    }

    ngx_free(dtm); 
}

static int64_t message_count = 0;

static ngx_int_t 
send_dtm_to_socket(
        Contrast__Api__Dtm__RawRequest *dtm, 
        ngx_str_t socket_path,
        ngx_str_t app_name,
        ngx_log_t *log,
        ngx_pool_t *pool)
{
    ngx_int_t boom = 0;

    char * app_name_str = ngx_str_to_char(&app_name, pool);
    if (app_name_str == NULL) {
        dd("cannot determine appname from configuration");
        return boom;
    }

    Contrast__Api__Dtm__Message msg = CONTRAST__API__DTM__MESSAGE__INIT;
    msg.client_id = "NGINX";
    msg.pid = (int32_t)ngx_processes[ngx_process_slot].pid;
    msg.client_number = (int32_t)1;
    msg.client_total = (int32_t)1;
    msg.message_count = ++message_count;
    msg.app_name = app_name_str;
    msg.app_language = "Ruby";  // TODO: change this when Universal Agent is supported type
    msg.timestamp_ms = unix_millis();
    msg.event_case = CONTRAST__API__DTM__MESSAGE__EVENT_REQUEST;
    msg.request = dtm;
    dd("built parent message structure: %s (%s)", msg.app_name, msg.app_language);

    size_t len = contrast__api__dtm__message__get_packed_size(&msg);
    dd("estimated size of packed message: %ld", len);

    // store the response; this is allocated by the socket function so must be freed here
    ngx_str_t * response = NULL;

    // buffer for storing the serialized message
    void * buf = ngx_alloc(len, log);
    if (buf != NULL) {

        size_t packed_size = contrast__api__dtm__message__pack(&msg, buf);
        dd("actual packed message size: %ld", packed_size);
        if ((response = write_to_service(socket_path, buf, len, log)) == NULL) {
            dd("[ERROR] error from write_to_service");
        }
        free(buf);
    } else {
        dd("[ERROR] could not allocate buffer size for protobuf message");
    }

    // deserialize and parse response
    Contrast__Api__Settings__AgentSettings *settings = NULL;
    if (response != NULL) {
        dd("attempting to unpack agent settings: %ld", sizeof(*response));
        settings = contrast__api__settings__agent_settings__unpack(NULL, 
                response->len, 
                response->data);

        if (settings == NULL) {
            dd("[ERROR] settings was null!");
        } else {
            if (settings->protect_state == NULL) {
                dd("[ERROR] settings->protect_state was NULL!");
            } else {

                dd("what was security exception: exception=%d", 
                        settings->protect_state->security_exception);
                if (settings->protect_state->security_exception) {

                    // flag for NGX_boom!
                    dd("[BOOM!] security exception found: %s uuid=%s", 
                            settings->protect_state->security_message,
                            settings->protect_state->uuid);
                    boom = 1;
                } else {
                    dd("no security exception in settings");
                }
            }
        }

        free(settings);
        free(response->data);
        free(response);
    } else {
        dd("[WARN] response was null");
    }

    ngx_pfree(pool, app_name_str);
    return boom;
}


ngx_int_t
ngx_http_contrast_connector_preaccess_handler(ngx_http_request_t *r)
{
    ngx_http_contrast_connector_conf_t * conf = ngx_http_get_module_loc_conf(
            r, ngx_http_contrast_connector_module);
    if (!conf->enable) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "[contrast]: skipping processing because not enabled");
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_GET) {
        // TODO: for testing only; we should be more sophisticated about
        // whether we should decline at this point (e.g. checking Content-Length?)
        return NGX_DECLINED;
    }

    Contrast__Api__Dtm__RawRequest * dtm = build_dtm_from_request(r);
    if (dtm == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[contrast] failed dtm allocation");
        return NGX_DECLINED;
    }

    ngx_int_t perform_block = send_dtm_to_socket(
        dtm, conf->socket_path, 
        conf->app_name, 
        r->connection->log, 
        r->pool);

    free_dtm(dtm);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "[contrast]: analysis result: %s",
        perform_block ? "blocked" : "allowed");
    if (perform_block) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "[contrast] Blocked Request");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}

/*
 * the filter is called multiple times as needed to process chunks of the
 * request body recieved.
 *
 * XXX: We will likely need to buffer chunks in the context of the request 
 * object before passing the entire body to the rules processing engine. This
 * pattern is counter to the design of nginx so we should carefully consider
 * and measure our approach.
 */
static ngx_int_t
ngx_http_catch_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_log_t * log = r->connection->log;
    ngx_pool_t * pool = r->pool;
    ngx_http_contrast_connector_conf_t * conf = ngx_http_get_module_loc_conf(r, 
            ngx_http_contrast_connector_module);
    if (!conf->enable) {
        
        // early return if module it not enabled
        return ngx_http_next_request_body_filter(r, in);
    }

    Contrast__Api__Dtm__RawRequest * dtm = build_dtm_from_request(r);
    if (dtm == NULL) {
        return NGX_DECLINED;
    }

    // request body (if any)
    dtm->request_body = read_body(in, log);
    dd("request_body: %s", dtm->request_body);

    ngx_int_t boom = send_dtm_to_socket(dtm, 
        conf->socket_path, 
        conf->app_name, 
        log,
        pool);

    free_dtm(dtm);

    if (boom != 0) {
        dd("boom was true...");
        return NGX_HTTP_FORBIDDEN;
    }

    dd("boom was false...");
    return ngx_http_next_request_body_filter(r, in);
}

/*
 * examine headers and forward to speedracer
 */
static ngx_int_t
ngx_http_catch_header_filter(ngx_http_request_t * r) 
{
    dd("\n\nin ngx_http_catch_header_filter");
    return ngx_http_next_output_header_filter(r);
}
/*
 * update request body filter chain
 */
ngx_int_t ngx_http_catch_body_init(ngx_conf_t *cf)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_catch_body_filter;

#if 0
    ngx_http_next_output_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_catch_header_filter;
#endif
    return NGX_OK;
}
