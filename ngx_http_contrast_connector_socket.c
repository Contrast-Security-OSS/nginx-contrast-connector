#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"

/*
 * assign the values of a four byte array from the individual bytes of the length type
 */
#define len_to_msg(len, msg) msg[0] = (char)(len >> 24); \
	msg[1] = (char)(len >> 16); \
	msg[2] = (char)(len >> 8); \
	msg[3] = (char)(len)

/*
 * convert an array of four bytes into an integer and assign it to the second argument
 */
#define msg_to_len(msg, len) (len = (msg[0] << 24) | (msg[1] << 16) | (msg[2] << 8) | msg[3])

/*
 * write a serialized protobuf instance to a unix socket
 */
ngx_int_t write_to_service(ngx_str_t socket_path, 
		void * data, 
		size_t data_len, 
		char * response,
		ngx_log_t * log)
{
	dd("write_to_service");
	struct sockaddr_un server;
	
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		dd("[ERROR] socket not valid");
		return NGX_ERROR;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, socket_path.data);
	if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
		dd("[ERROR] cound not connect to stream socket");
		close(sock);
		return NGX_ERROR;
	}

	char msg_prefix[4] = { 0, 0, 0, 0 };
	len_to_msg(data_len, msg_prefix);
	if (write(sock, msg_prefix, 4) < 0) {
		dd("[ERROR] could not write message prefix");
		close(sock);
		return NGX_ERROR;
	}

	if (write(sock, data, data_len) < 0) {
		dd("[ERROR] could not write message");
		close(sock);
		return NGX_ERROR;
	}

	char response_prefix[4] = { 0, 0, 0, 0 };
	if (read(sock, response_prefix, 4) < 4) {
		dd("[ERROR] could not read four bytes from response prefix");
		close(sock);
		return NGX_ERROR;
	}

	size_t response_len = 0;
	msg_to_len(response_prefix, response_len);
	if (response_len <= 0 || response_len > 1000000) {
		dd("[WARN] idiot check on response prefix (len=%ld) failed", response_len);
		close(sock);
		return NGX_ERROR;
	}

	size_t actual_len = 0;
	response = malloc(response_len);
	if ((actual_len = read(sock, response, response_len)) < response_len) {
		dd("[WARN] expected len did not match acutal len(%ld != %ld", actual_len, response_len);
		close(sock);
		return NGX_ERROR;
	}

	close(sock);
	return NGX_OK;
}	
