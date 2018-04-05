#ifndef _CONTRAST_CONNECTOR_SOCKET_H_
#define _CONTRAST_CONNECTOR_SOCKET_H_

/* Core stuff */
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>

/* Protobuf stuff */
#include <protobuf-c/protobuf-c.h>
#include "dtm.pb-c.h"
#include "settings.pb-c.h"

/* Unix Socket stuff */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

/*
 * write a serialized protobuf instance to a unix socket
 */
ngx_str_t * write_to_service(ngx_str_t socket_path, 
		void * data, 
		size_t data_len, 
		ngx_log_t * log);

#endif
