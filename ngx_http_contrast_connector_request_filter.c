#include "dtm.pb-c.h"
#include "settings.pb-c.h"
#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"

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
	size_t count; // HACK: keep track of the count in the root element
    struct pair_s * next;
} pair_t;

static void free_pair(pair_t * head) 
{
	if (head->next != NULL) {
		// NOTE: values are pointers to ngx_str_t data elements so don't free
		if (head->next->key != NULL) { free(head->next->key); }
		if (head->next->value != NULL) { free(head->next->value); }
		free_pair(head->next);
	}
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

			next_header->key = ngx_calloc(entry->key.len + 1, r->connection->log);
			strncpy(next_header->key, entry->key.data, entry->key.len);

			next_header->value = ngx_calloc(entry->value.len + 1, r->connection->log);
			strncpy(next_header->value, entry->value.data, entry->value.len);

			next_header->count = 0;
			if (prev == NULL) {
				headers = next_header;
			} else {
				prev->next = next_header;
			}
			headers->count++;
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

static int64_t message_count = 0;

/*
 * examine http request and forward to speedracer
 */
static ngx_int_t ngx_http_catch_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_log_t * log = r->connection->log;
    ngx_http_contrast_connector_conf_t * conf = ngx_http_get_module_loc_conf(r, 
			ngx_http_contrast_connector_module);
    if (!conf->enable) {
		
		// early return if module it not enabled
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
	u_char * request_body = read_body(in, log);
	dtm.request_body = request_body;

	// client address (if any)
	address_t * client_address = ngx_calloc(sizeof(address_t), log);
	read_address(r->connection->sockaddr, client_address, log);
	if (client_address != NULL && client_address->address != NULL) {
		dtm.client_ip = client_address->address;
		dtm.client_ip_version = client_address->version;
		dtm.client_port = client_address->port;
		dd("-> ip=%s (ipv%d) port=%d", dtm.client_ip, dtm.client_ip_version, dtm.client_port); 
	}

	// server address (if any) (address of service proxying to)
	address_t * server_address = ngx_calloc(sizeof(address_t), log);
	read_address(r->connection->listening->sockaddr, server_address, log);
	if (server_address != NULL && server_address->address != NULL) {
		dtm.server_ip = server_address->address;
		dtm.server_ip_version = server_address->version;
		dtm.server_port = server_address->port;
		dd("<- ip=%s (ipv%d) port=%d", dtm.server_ip, dtm.server_ip_version, dtm.server_port); 
	}

	// headers
	pair_t * headers = read_headers(r);
	if (headers != NULL && headers->count > 0) {
		dd("header count = %ld", headers->count);
		//dtm.n_request_headers = headers->count;
		//dtm.request_headers = ngx_calloc(sizeof(Contrast__Api__Dtm__SimplePair *) * headers->count, log);
		int idx = 0;
		for(pair_t * curr_header = headers; curr_header != NULL; curr_header = curr_header->next) {
			Contrast__Api__Dtm__SimplePair * pair = ngx_calloc(sizeof(Contrast__Api__Dtm__SimplePair), log);
			pair->key = curr_header->key;
			pair->value = curr_header->value;
			dd("[header %d] %s=%s", idx, pair->key, pair->value); 
		//	dtm.request_headers[idx++] = pair;
		}
	}

	// prepare and serialize protobuf messages
	Contrast__Api__Dtm__Message msg = CONTRAST__API__DTM__MESSAGE__INIT;
	msg.client_id = "NGINX";
	msg.client_number = (int32_t)ngx_process_slot;
	msg.client_total = (int32_t)1;
	msg.message_count = ++message_count;
	msg.app_name = "NGINX"; // TODO: configuration or other method for determining name?
	msg.app_language = "Ruby";  // TODO: change this when Universal Agent is supported type
	msg.timestamp_ms = unix_millis();
	msg.event_case = CONTRAST__API__DTM__MESSAGE__EVENT_REQUEST;
	msg.request = &dtm;
	dd("built parent message structure");

	// send message to service
	size_t len = contrast__api__dtm__message__get_packed_size(&msg);
	dd("estimated size of packed message: %ld", len);

	// store the response; this is allocated by the socket function so must be freed here
	u_char * response = NULL;

	// buffer for storing the serialized message
	void * buf = ngx_alloc(len, log);

	if (buf != NULL) {

		size_t packed_size = contrast__api__dtm__message__pack(&msg, buf);
		dd("actual packed message size: %ld", packed_size);
		if (write_to_service(conf->socket_path, buf, len, response, log) != NGX_OK) {
			if (response != NULL) {
				free(response);
				response = NULL;
				dd("[ERROR] error from write_to_service");
			}
		}
		free(buf);
	} else {
		dd("[ERROR] could not allocate buffer size for protobuf message");
	}

	// deserialize and parse response
	Contrast__Api__Settings__ProtectState *settings = NULL;
	ngx_int_t boom = 0;
	if (response != NULL) {
		settings = contrast__api__settings__protect_state__unpack(NULL, 
				sizeof(response), 
				response);

		if (settings != NULL) {

			if (settings->security_exception) {

				// flag for NGX_boom!
				dd("[BOOM!] security exception found: %s uuid=%s", 
						settings->security_message,
						settings->uuid);
				boom = 1;
			} else {
				dd("no security exception in settings");
			}
		} else {
			dd("[ERROR] could not parse settings");
		}

		// TODO: it appears response and the unpacked settings share the same memory (?)
		// so you only free one?
		free(response);
	}


	// free headers
	free_pair(headers);

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
	if (boom) {
		return NGX_HTTP_FORBIDDEN;
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
