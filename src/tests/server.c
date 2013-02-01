/*
 * Copyright (c) 2011-2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2012 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * Copyright © 2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "cci.h"

int main(int argc, char *argv[])
{
	int ret, done = 0;
	uint32_t caps = 0;
	char *uri = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_os_handle_t *ep_fd = NULL;
	cci_connection_t *connection = NULL;

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, ep_fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_opt(endpoint,
			  CCI_OPT_ENDPT_URI, &uri);
	if (ret) {
		fprintf(stderr, "cci_get_opt() failed with %s\n", cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	printf("Opened %s\n", uri);

	while (!done) {
		int accept = 1;
		cci_event_t *event;

		ret = cci_get_event(endpoint, &event);
		if (ret != 0) {
			if (ret != CCI_EAGAIN)
				fprintf(stderr, "cci_get_event() returned %s\n",
					cci_strerror(endpoint, ret));
			continue;
		}
		switch (event->type) {
		case CCI_EVENT_RECV:{
				char buf[8192];
				char *data = "data:";
				int offset = 0;
				int len = event->recv.len;

				if (len == 3) {
					done = 1;
					continue;
				}

				memset(buf, 0, 8192);
				offset = strlen(data);
				memcpy(buf, data, offset);
				memcpy(buf + offset, event->recv.ptr, len);
				offset += len;
				fprintf(stderr, "recv'd \"%s\"\n", buf);
				ret =
				    cci_send(connection, buf, offset, NULL, 0);
				if (ret)
					fprintf(stderr, "send returned %s\n",
						cci_strerror(endpoint, ret));
				break;
			}
		case CCI_EVENT_SEND:
			fprintf(stderr, "completed send\n");
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			/* inspect conn_req_t and decide to accept or reject */
			if (accept) {
				/* associate this connect request with this endpoint */
				cci_accept(event, NULL);
			} else {
				cci_reject(event);
			}
			break;
		case CCI_EVENT_ACCEPT:
			fprintf(stderr, "completed accept\n");
            connection = event->accept.connection;
			break;
		default:
			printf("event type %d\n", event->type);
			break;
		}
		cci_return_event(event);
	}

	/* clean up */
	cci_destroy_endpoint(endpoint);
	cci_finalize();
	free(uri);

	return 0;
}
