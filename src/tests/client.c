/*
 * Copyright (c) 2011-2013 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2013 Oak Ridge National Labs.  All rights reserved.
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
#include <assert.h>

int iters = 10;
int send_done = 0;
int recv_done = 0;
int flags = 0;
/* By default the connection is reliable ordered; users can change the
   connection type via the command line */
cci_conn_attribute_t attr = CCI_CONN_ATTR_RO;

#define CONNECT_CONTEXT (void*)0xdeadbeef

static void
poll_events(cci_endpoint_t * endpoint, cci_connection_t ** connection,
	    int *done)
{
	int ret;
	char buffer[8192];
	cci_event_t *event;
	static int i = 0;

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS && event) {
		switch (event->type) {
		case CCI_EVENT_SEND:
			fprintf(stderr, "send %d completed with %d\n",
				(int)((uintptr_t) event->send.context),
				event->send.status);

			assert(event->send.context == (void *)(uintptr_t)i);
			i++;
			assert(event->send.connection == *connection);
			assert(event->send.connection->context == CONNECT_CONTEXT);

			if (*done == 0)
				send_done++;
			else if (*done == 1)
				*done = 2;
			break;
		case CCI_EVENT_RECV:{
				int len = event->recv.len;

				assert(event->recv.connection == *connection);
				assert(event->recv.connection->context == CONNECT_CONTEXT);

				memcpy(buffer, event->recv.ptr, len);
				buffer[len] = '\0';
				fprintf(stderr, "received \"%s\"\n", buffer);
				recv_done++;
				break;
			}
		case CCI_EVENT_CONNECT:
			*done = 1;

			assert(event->connect.connection != NULL);
			assert(event->connect.connection->context == CONNECT_CONTEXT);

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
	cci_os_handle_t *fd = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_connection_t *connection = NULL;
	uint32_t timeout = 30 * 1000000;

	while ((c = getopt(argc, argv, "h:c:b")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			break;
		case 'c':
			if (strncasecmp ("ru", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RU;
			else if (strncasecmp ("ro", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RO;
			else if (strncasecmp ("uu", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_UU;
			break;
		case 'b':
			flags |= CCI_FLAG_BLOCKING;
			break;
		default:
			fprintf(stderr, "usage: %s -h <server_uri> [-c <type>]\n",
			        argv[0]);
			fprintf(stderr, "\t-c\tConnection type (UU, RU, or RO) "
			                "set by client; RO by default\n");
			exit(EXIT_FAILURE);
		}
	}

	if (!server_uri) {
		fprintf(stderr, "usage: %s -h <server_uri> [-c <type>]\n", argv[0]);
		fprintf(stderr, "\t-c\tConnection type (UU, RU, or RO) "
                                        "set by client; RO by default\n");
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, fd);
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
			attr, CONNECT_CONTEXT, 0, NULL);
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
			       (void *)(uintptr_t) i, flags);
		if (ret)
			fprintf(stderr, "send %d failed with %s\n", i,
				cci_strerror(endpoint, ret));
		if (flags & CCI_FLAG_BLOCKING)
			fprintf(stderr, "send %d completed with %d\n", i, ret);

	}
	if (flags == CCI_FLAG_BLOCKING)
		send_done = iters;

	while (!done)
		poll_events(endpoint, &connection, &done);

	ret = cci_send(connection, "bye", 3, (void *)(uintptr_t) iters, flags);
	if (ret)
		fprintf(stderr, "sending \"bye\" failed with %s\n",
			cci_strerror(endpoint, ret));

	if (flags & CCI_FLAG_BLOCKING)
		done = 2;

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
