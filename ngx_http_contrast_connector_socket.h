/* Copyright (C) Contrast Security, Inc. */

#ifndef _CONTRAST_CONNECTOR_SOCKET_H_
#define _CONTRAST_CONNECTOR_SOCKET_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * write a serialized protobuf instance to a unix socket
 */
ngx_str_t * write_to_service(ngx_str_t socket_path, 
		void * data, 
		size_t data_len, 
		ngx_log_t * log);

#endif
