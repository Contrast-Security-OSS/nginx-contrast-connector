#include "dtm.pb-c.h"
#include "settings.pb-c.h"
#include "ngx_http_contrast_connector_common.h"

 /*
  * static reference to next request body filter callback
  */
static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;

/*
 * temporary storage for a key value pair
 */
typedef struct pair_s {
	u_char * key;
	u_char * value;
    struct pair_s * next;
} pair_t;

static void free_pair(pair_t * head) 
{
	if (head->next != NULL) {
		free_pair(head->next);
	}

	// NOTE: values are pointers to ngx_str_t data elements so don't free

	free(head);
}

/*
 * read request headers and build a structure 
 */
static pair_t * read_headers(ngx_http_request_t * r) 
{
	pair_t * headers = NULL;
	pair_t * next_header = NULL;

	ngx_list_t list = r->headers_in.headers;
	if (list.nalloc > 0) {
		// dd("headers: list.nalloc = %ld", list.nalloc);	
		ngx_list_part_t * curr = &list.part;
		ngx_table_elt_t * entry_ptr = (ngx_table_elt_t *)curr->elts;
		ngx_table_elt_t * entry = NULL;

		for(int count = 0; ; count++) {

			// dd("headers: curr->nelts = %ld", curr->nelts);
			if (count >= curr->nelts) {
				if (curr->next == NULL) {
					break;
				}

				// dd("headers: geetting next block...");
				curr = curr->next;
				entry_ptr = (ngx_table_elt_t *)curr->elts;
				count = 0;
			}

			entry = (&entry_ptr[count]);
		
			pair_t * prev = next_header;	
			next_header = ngx_calloc(sizeof(pair_t), r->connection->log);
			next_header->key = entry->key.data;
			next_header->value = entry->value.data;
			if (prev == NULL) {
				headers = next_header;
			} else {
				prev->next = next_header;
			}
		}
	}

	return headers;
}

/*
 * temporary storage for an address
 */
typedef struct {
	u_char * address;
	int32_t port;
	int32_t version;
} address_t;

static void free_address(address_t * address) {
	if (address != NULL) {
		if (address->address != NULL) {
			free(address->address);
		}
		free(address);
	}
}

static ngx_int_t read_address(struct sockaddr * sockaddr, 
		address_t * addr, 
		ngx_log_t * log) {

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

static ngx_int_t read_ipv6_address(ngx_connection_t * connection, address_t * addr) {
	return NGX_ERROR;
}

/*
 * read body from chain; if returned value is not null it must be freed when complete
 */
static u_char * read_body(ngx_chain_t * in, ngx_log_t *log)
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

		if (body == NULL) {
			body = ngx_calloc(chunk_len + 1, log);
			strncpy(body, chunk, chunk_len);
		} else {
			u_char * tmp = realloc(body, body_len + chunk_len + 1);
			strncpy(tmp + body_len, chunk, chunk_len);
			body = tmp;
		}

		body_len += chunk_len;
	}

	return body;
}

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

	Contrast__Api__Dtm__RawRequest dtm = CONTRAST__API__DTM__RAW_REQUEST__INIT;

	// timestamp
	dtm.timestamp_ms = unix_millis();

	// request line
	dtm.request_line = r->request_line.data;
	dd("request_line: %s", dtm.request_line);

	// normalized uri
	dtm.normalized_uri = r->uri.data;
	dd("normalized_uri: %s", dtm.normalized_uri);

	// request body (if any)
	u_char * request_body = read_body(in, r->connection->log);
	dtm.request_body = request_body;

	// client address (if any)
	address_t * client_address = ngx_calloc(sizeof(address_t), r->connection->log);
	read_address(r->connection->sockaddr, client_address, r->connection->log);
	if (client_address != NULL && client_address->address != NULL) {
		dtm.client_ip = client_address->address;
		dtm.client_ip_version = client_address->version;
		dtm.client_port = client_address->port;
		dd("-> ip=%s (ipv%d) port=%d", dtm.client_ip, dtm.client_ip_version, dtm.client_port); 
	}

	// server address (if any) (address of service proxying to)
	address_t * server_address = ngx_calloc(sizeof(address_t), r->connection->log);
	read_address(r->connection->listening->sockaddr, server_address, r->connection->log);
	if (server_address != NULL && server_address->address != NULL) {
		dtm.server_ip = server_address->address;
		dtm.server_ip_version = server_address->version;
		dtm.server_port = server_address->port;
		dd("<- ip=%s (ipv%d) port=%d", dtm.server_ip, dtm.server_ip_version, dtm.server_port); 
	}

	// headers
	pair_t * headers = read_headers(r);

	// free headers
	if (headers != NULL) {
		for(pair_t * header = headers; header != NULL; header = header->next) {
			dd("header: %s=%s", header->key, header->value);
		}
		
		free_pair(headers);
	}

	// free request body
	if (request_body != NULL) {
		dd("read request body: %s", request_body);
		free(request_body);
	}	

	// free client address
	free_address(client_address);

	// free server address
	free_address(server_address);

	dd("next filter in chain");
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
