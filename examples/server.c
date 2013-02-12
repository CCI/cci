/*
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
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
	int ret;
	uint32_t caps = 0;
	char *uri = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_os_handle_t ep_fd;
	cci_connection_t *connection = NULL;

	/* init */
	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_opt(endpoint,
			  CCI_OPT_ENDPT_URI, &uri);
	if (ret) {
		fprintf(stderr, "cci_get_opt() failed with %s\n", cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}
	printf("Opened %s\n", uri);

	while (1) {
		char *buffer;
		cci_event_t *event;

		ret = cci_get_event(endpoint, &event);
		if (ret != CCI_SUCCESS) {
			if (ret != CCI_EAGAIN) {
				fprintf(stderr, "cci_get_event() returned %s",
					cci_strerror(endpoint, ret));
			}
			continue;
		}
		switch (event->type) {
		case CCI_EVENT_RECV:
			{
				memcpy(buffer,
				       event->recv.ptr, event->recv.len);
				buffer[event->recv.len] = 0;
				printf("recv'd \"%s\"\n", buffer);

				/* echo the message to the client */
				ret = cci_send(connection,
					       event->recv.ptr,
					       event->recv.len, NULL, 0);
				if (ret != CCI_SUCCESS)
					fprintf(stderr,
						"send returned %s\n",
						cci_strerror(endpoint, ret));
				break;
			}
		case CCI_EVENT_SEND:
			printf("completed send\n");
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			{
				int accept = 1;

				if (accept) {
					ret = cci_accept(event, NULL);
					if (ret != CCI_SUCCESS) {
						fprintf(stderr,
							"cci_accept() returned %s",
							cci_strerror(endpoint, ret));
					}

				} else {
					cci_reject(event);
				}
			}
			break;
		case CCI_EVENT_ACCEPT:
			connection = event->accept.connection;
			if (!buffer) {
				buffer = calloc(1, connection->max_send_size + 1);
				/* check for buffer ... */
			}
			break;
		default:
			fprintf(stderr, "unexpected event %d", event->type);
			break;
		}
		cci_return_event(event);
	}

	/* clean up */
	cci_destroy_endpoint(endpoint);
	/* add cci_finalize() here */

	return 0;
}
