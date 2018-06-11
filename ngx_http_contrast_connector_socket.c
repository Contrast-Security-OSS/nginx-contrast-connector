/* Copyright (C) Contrast Security, Inc. */

#include "settings.pb-c.h"
#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"

/*
 * assign the values of a four byte array from the individual bytes of the length type
 */
#define len_to_msg(len, msg)  \
    (msg)[0] = (u_char)((len) >> 24); \
	(msg)[1] = (u_char)((len) >> 16); \
	(msg)[2] = (u_char)((len) >> 8); \
	(msg)[3] = (u_char)(len)

/*
 * convert an array of four bytes into an integer and assign it to the second argument
 */
#define msg_to_len(msg, len)  \
    (len = (msg[0] << 24) | (msg[1] << 16) | (msg[2] << 8) | msg[3])

/*
 * write a serialized protobuf instance to a unix socket
 */
ngx_str_t *
write_to_service(
        ngx_str_t socket_path, void *data, size_t data_len, ngx_log_t *log)
{
	contrast_dbg_log(log, 0, "write_to_service");
	struct sockaddr_un server;
	
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		contrast_log(ERR, log, 0, "socket not valid");
		return NULL;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, (char*)socket_path.data);
	if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
		contrast_log(ERR, log, 0, "cound not connect to stream socket");
		close(sock);
		return NULL;
	}

	u_char msg_prefix[4] = { 0, 0, 0, 0 };
	len_to_msg(data_len, msg_prefix);
	if (write(sock, msg_prefix, 4) < 0) {
		contrast_log(ERR, log, 0, "could not write message prefix");
		close(sock);
		return NULL;
	}

	if (write(sock, data, data_len) < 0) {
		contrast_log(ERR, log, 0, "could not write message: d: %p, sz: %lu",
                data, data_len);
		close(sock);
		return NULL;
	}

	u_char response_prefix[4] = { 0, 0, 0, 0 };
	if (read(sock, response_prefix, 4) < 4) {
	    contrast_log(ERR, log, 0,
                "could not read four bytes from response prefix");
		close(sock);
		return NULL;
	}

	size_t response_len = 0;
	msg_to_len(response_prefix, response_len);
	if (!response_len || response_len > 1000000) {
		contrast_log(ERR, log, 0,
                "response from analysis engine seems corrupt, len %d",
                response_len);
		close(sock);
		return NULL;
	}

	size_t actual_len = 0;
	u_char * response = ngx_alloc(response_len, log);
	if ((actual_len = read(sock, response, response_len)) < response_len) {
		contrast_log(ERR, log, 0,
                "expected len did not match acutal len(%ld != %ld)",
                actual_len, response_len);
		free(response);
		close(sock);
		return NULL;
	}

	close(sock);

	ngx_str_t *str = ngx_alloc(sizeof(ngx_str_t), log);
	str->data = response;
	str->len = actual_len;
	return str;
}	
