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

#include "cci.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int iters = 10;
int send_done = 0;
int recv_done = 0;

static void
poll_events(cci_endpoint_t * endpoint, cci_connection_t ** connection,
	    int *done)
{
	int ret;
	char buffer[8192];
	cci_event_t *event;

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS && event) {
		switch (event->type) {
		case CCI_EVENT_SEND:
			fprintf(stderr, "send %d completed with %d\n",
				(int)((uintptr_t) event->send.context),
				event->send.status);
			if (*done == 0)
				send_done++;
			else if (*done == 1)
				*done = 2;
			break;
		case CCI_EVENT_RECV:{
				int len = event->recv.len;

				memcpy(buffer, event->recv.ptr, len);
				buffer[len] = '\0';
				fprintf(stderr, "received \"%s\"\n", buffer);
				recv_done++;
				break;
			}
		case CCI_EVENT_CONNECT:
			*done = 1;
			*connection = event->connect.connection;
			break;
		default:
			fprintf(stderr, "ignoring event type %d\n",
				event->type);
		}
		cci_return_event(event);
		if (*done == 0 && send_done == iters && recv_done == iters)
			*done = 1;
	}
}

int main(int argc, char *argv[])
{
	int done = 0, ret, i = 0, c;
	uint32_t caps = 0;
	char *server_uri = NULL;
	cci_os_handle_t fd;
	cci_endpoint_t *endpoint = NULL;
	cci_connection_t *connection = NULL;
	uint32_t timeout = 30 * 1000000;

	while ((c = getopt(argc, argv, "h:")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			break;
		default:
			fprintf(stderr, "usage: %s -h <server_uri>\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!server_uri) {
		fprintf(stderr, "usage: %s -h <server_uri>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, &fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* set conn tx timeout */
	cci_set_opt(endpoint, CCI_OPT_ENDPT_SEND_TIMEOUT,
		    &timeout);
	if (ret) {
		fprintf(stderr, "cci_set_opt() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	/* initiate connect */
	ret =
	    cci_connect(endpoint, server_uri, "Hello World!", 12,
			CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
		fprintf(stderr, "cci_connect() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	/* poll for connect completion */
	while (!done)
		poll_events(endpoint, &connection, &done);

	if (!connection)
		exit(0);

	done = 0;

	/* begin communication with server */
	for (i = 0; i < iters; i++) {
		char data[128];

		memset(data, 0, sizeof(data));
		sprintf(data, "%4d", i);
		sprintf(data + 4, "Hello World!");
		ret = cci_send(connection, data, (uint32_t) strlen(data) + 4,
			       (void *)(uintptr_t) i, 0);
		if (ret)
			fprintf(stderr, "send %d failed with %s\n", i,
				cci_strerror(endpoint, ret));
	}
	while (!done)
		poll_events(endpoint, &connection, &done);

	ret = cci_send(connection, "bye", 3, NULL, 0);
	if (ret)
		fprintf(stderr, "sending \"bye\" failed with %s\n",
			cci_strerror(endpoint, ret));

	while (done != 2)
		poll_events(endpoint, &connection, &done);

	/* clean up */
	ret = cci_destroy_endpoint(endpoint);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "cci_finalize() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	return 0;
}
