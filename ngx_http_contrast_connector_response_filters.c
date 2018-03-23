#include "dtm.pb-c.h"
#include "settings.pb-c.h"
#include "ngx_http_contrast_connector_common.h"


/*
 * static reference to next header filter callback
 */
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

/*
 * static reference to next body filter callback
 */
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

/*
 * given buffer attempt to append from src; return ptr to new buffer location
 */
static u_char * append_request_body(u_char * dest, 
		size_t dest_len, 
		u_char * src, 
		size_t src_len, 
		ngx_log_t *log)
{
	size_t new_len = src_len + dest_len;
	u_char * tmp = NULL;

	if (dest == NULL) {
		dest = ngx_calloc(src_len + 1, log);
		strncpy(dest, src, src_len);
	} else {
		tmp = realloc(dest, new_len + 1);
		strncpy(tmp + dest_len, src, src_len);
		dest = tmp;
	}
	return dest;
}

/*
 * read the entire chain 
 */
static u_char * read_request_body(ngx_http_request_t * r, ngx_chain_t * in) 
{
	if (in == NULL) {
		return NULL;
	}

	u_char * dest = NULL;
	size_t dest_len = 0;

	ngx_chain_t * chain = NULL;
	u_char * src = NULL;
	size_t src_len = 0;

	for (chain = in; chain != NULL; chain = chain->next) {
		src = chain->buf->start;
		src_len = chain->buf->end - src;
		dd("buffer length = %ld", src_len);

		dest = append_request_body(dest, dest_len, src, src_len, r->connection->log);
		dest_len += src_len;
		dd("after append len=%ld: %s", dest_len, dest);
	}

	return dest;
}


/*
 * act as filter for headers in request
 */
static ngx_int_t ngx_http_contrast_connector_module_header_filter(ngx_http_request_t * r)
{
	dd("in response header fitler");
    return ngx_http_next_header_filter(r);
}

/*
 * act as filter for request body
 */
static ngx_int_t ngx_http_contrast_connector_module_body_filter(ngx_http_request_t * r, 
		ngx_chain_t * in)
{
	dd("in response body filter");

	int buffer_fully_loaded = 0;
	ngx_chain_t *chain = NULL;
	
    ngx_http_contrast_connector_conf_t * conf = NULL;
	ngx_http_headers_in_t hin = r->headers_in;
	ngx_list_t headers = hin.headers;
	ngx_list_part_t * curr = NULL;
	ngx_table_elt_t * entry_ptr = NULL;
	ngx_table_elt_t * entry = NULL;
	int count = 0;
	u_char * dest = NULL;
	size_t dest_len = 0;

	if (in == NULL) {
		dd("[WARN] chain was NULL");
		return ngx_http_next_body_filter(r, in);
	}

	for (chain = in; chain != NULL; chain = chain->next) {
		if (chain->buf->last_buf) { buffer_fully_loaded = 1; }
	}
	if (buffer_fully_loaded == 0) {
		dd("[WARN] buffer not fully loaded");	

		u_char * tmp = read_request_body(r, in);
		if (tmp != NULL) {
			dd("the current contents are: %s", tmp);
			free(tmp);
		}

		return ngx_http_next_body_filter(r, in);
	}
	
    conf = ngx_http_get_module_loc_conf(r, ngx_http_contrast_connector_module);
    if (conf == NULL) {
		dd("[WARN] current config was NULL");
		return ngx_http_next_body_filter(r, in);
    }

    if (conf->enable > 0) {
		Contrast__Api__Dtm__Message message = CONTRAST__API__DTM__MESSAGE__INIT;
		Contrast__Api__Dtm__RawRequest dtm = CONTRAST__API__DTM__RAW_REQUEST__INIT;
		Contrast__Api__Dtm__SimplePair pair = CONTRAST__API__DTM__SIMPLE_PAIR__INIT;

		struct timeval tv;
		gettimeofday(&tv, NULL);
		dtm.timestamp_ms = (tv.tv_sec * 1000 + tv.tv_usec / 1000);
		dd("timestap=%ld", dtm.timestamp_ms);

		dtm.request_line = r->request_line.data;
		dtm.normalized_uri = r->uri.data;
		dd("request_line=%s normalized_uri=%s", dtm.request_line, dtm.normalized_uri);

		struct sockaddr_in *sin;
		ngx_addr_t addr;
		char ipv4[INET_ADDRSTRLEN];

		addr.sockaddr = r->connection->sockaddr;
		addr.socklen = r->connection->socklen;
		if (addr.sockaddr->sa_family == AF_INET) {
			sin = (struct sockaddr_in *)addr.sockaddr;
			if (sin != NULL) {
				dtm.client_port = sin->sin_port;

				inet_ntop(AF_INET, &(sin->sin_addr), ipv4, INET_ADDRSTRLEN);
				dtm.client_ip = ipv4;
				dtm.client_ip_version = 4;
				dd("address from socket: %s:%d", dtm.client_ip, dtm.client_port);
			}
		}

		if (headers.nalloc > 0) {
			curr = &headers.part;
			entry_ptr = (ngx_table_elt_t *)curr->elts;
			for(count = 0; ; count++) {
				if (count >= curr->nelts) {
					if (curr->next == NULL) {
						break;
					}

					curr = curr->next;
					entry_ptr = (ngx_table_elt_t *)curr->elts;
					count = 0;
				}

				entry = (&entry_ptr[count]);
				pair.key = entry->key.data;
				pair.value = entry->value.data;
				dd("header: %s=%s (%d)", pair.key, pair.value, count);
			}
		}

		dtm.request_body = read_request_body(r, in);
		if (dtm.request_body != NULL) {
			dd("complete request body: %s", dtm.request_body);
			free(dtm.request_body);
		}
    }

    return ngx_http_next_body_filter(r, in);
}


