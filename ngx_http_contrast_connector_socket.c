/* Copyright (C) Contrast Security, Inc. */

#include "ngx_http_contrast_connector_common.h"
#include "ngx_http_contrast_connector_socket.h"
#include <arpa/inet.h>

/* We only supported 32/64bit intel x86 currently */
#if !defined(__i386__) && !defined(__amd64__)
#    error "Your architecture is not supported"
#endif

#define MAX_DATA_SZ (0xffffff)   /* (2**24) - 1 = 16,777,215 bytes */
#define CONTRAST_CONNECTOR_FLAG (0x80)

/* 
 * we wrap protobuf messages in a type of pkt format with a flags and 
 * length fields.
 * -------------------------------------------------------
 * | flags(1) |  len(3)   |   packed_protobuf_data(...)  |
 * -------------------------------------------------------
 * 
 * The msg_prefix is the flags + len portion and represents our packet header.
 */
struct sr_pkt_hdr {
    unsigned flags:8;
    unsigned len:24;
    uint8_t buf[];
} __attribute__((packed));

/*
 * write a serialized protobuf instance to a unix socket
 */
ngx_str_t *
write_to_service(
        ngx_str_t socket_path, void *data, size_t data_len, ngx_log_t *log)
{
	contrast_dbg_log(log, 0, "write_to_service");
	struct sockaddr_un server;
	ngx_str_t *str = NULL;
	
    /* in addition to the obvious verification, this also makes downgrading
     * the type to ssize_t for other comparisons below safe.
     * NOTE: those ssize_t checks may go away on proper non-blocking io
     * implementation.
     */
    if (data_len > MAX_DATA_SZ) {
        contrast_log(ERR, log, 0, "data too large for contrast packet format [0x%zx]", data_len);
        return NULL;
    }

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

    /* shifting by 8 because we are assigning to a 24bit value. */
    struct sr_pkt_hdr hdr = {.flags = CONTRAST_CONNECTOR_FLAG, .len = (htonl(data_len) >> 8)};

	if (write(sock, &hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
		contrast_log(ERR, log, 0, "could not write message header");
		close(sock);
		return NULL;
	}

    /* 
     * XXX: read and write need to be replaced with non-blocking versions that
     * timeout to be robust against the contrast-service getting out-of-sync
     * with this connector.
     */
	if (write(sock, data, data_len) < (ssize_t)data_len) {
		contrast_log(ERR, log, 0, "could not write message: d: %p, sz: %zu",
                data, data_len);
		close(sock);
		return NULL;
	}

    struct sr_pkt_hdr response_hdr;
	if (read(sock, &response_hdr, sizeof(response_hdr)) < (ssize_t)sizeof(response_hdr)) {
	    contrast_log(ERR, log, 0,
                "could not read four bytes from response prefix");
		close(sock);
		return NULL;
	}

	size_t response_len = 0;
	response_len = ntohl(response_hdr.len << 8);
    dd("[0x%x] -> value 0x%lx  (%ld)", response_hdr.len, response_len, response_len);

    /* 
     * XXX: when proper non-blocking/timeout reads are implemented, this check
     * just be wrapped up in timeout handling. Once malformed data is read on
     * socket, both sides become out of sync and must have their state-machine
     * re-sync'd. We have no design for this behavior in the comms protocol so
     * this situation will lead to fatal errors on both sides and require a
     * restart of both processes.
     *
     * XXX: arbitrary size chosen here. We should know the exact max-size of
     * the protobuf response we expect.
     */
	if (!response_len || response_len > 1000000) {
		contrast_log(ERR, log, 0,
                "response from analysis engine seems corrupt, len %d",
                response_len);
		close(sock);
		return NULL;
	}

    /* 
     * XXX: this should be using pooled allocation. Also, I'd rather be
     * returning a protobuf DTM rather than a raw buffer of bytes that the
     * caller unpacks to a protobuf DTM. Callers should only see DTM structures
     * and not deal with raw byte buffers of the comms protocol.
     */
	u_char *response = ngx_alloc(response_len, log);
    ssize_t actual;
	if ((actual = read(sock, response, response_len)) < (ssize_t)response_len) {
		contrast_log(ERR, log, 0,
                "less than expected sz read (0x%x != 0x%x) read: ", actual, response_len);
		ngx_free(response);
		close(sock);
		return NULL;
	}

	close(sock);

	str = ngx_alloc(sizeof(ngx_str_t), log);
	str->data = response;
	str->len = response_len;
	return str;
}	
