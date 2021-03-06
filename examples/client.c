/*
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char *proc_name = NULL;

static void usage(void)
{
	fprintf(stderr, "usage: %s -h <server_uri>\n", proc_name);
	fprintf(stderr, "where server_uri is a valid CCI uri\n");
	fprintf(stderr, "such as ip://1.2.3.4:5678\n");
	exit(EXIT_FAILURE);
}

static void
poll_events(cci_endpoint_t * endpoint, cci_connection_t ** connection,
	    int *done)
{
	int ret;
	char buffer[8192];
	cci_event_t *event;

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS) {
		switch (event->type) {
		case CCI_EVENT_SEND:
			printf("send %d completed with %s\n",
			       (int)((uintptr_t) event->send.context),
			       cci_strerror(endpoint, event->send.status));
			break;
		case CCI_EVENT_RECV:
			memcpy(buffer, event->recv.ptr, event->recv.len);
			buffer[event->recv.len] = '\0';
			fprintf(stderr, "received \"%s\"\n", buffer);
			*done = 1;
			break;
		case CCI_EVENT_CONNECT:
			*done = 1;
			if (event->connect.status == CCI_SUCCESS)
				*connection = event->connect.connection;
			else
				*connection = NULL;
			break;
		default:
			fprintf(stderr, "ignoring event type %d\n",
				event->type);
		}
		cci_return_event(event);
	}
}

int main(int argc, char *argv[])
{
	int done = 0, ret, i = 0, c;
	uint32_t caps = 0;
	char *server_uri = NULL;	/* ip://1.2.3.4 */
	char *uri = NULL;
	cci_os_handle_t fd;
	cci_endpoint_t *endpoint = NULL;
	cci_connection_t *connection = NULL;
	uint32_t timeout_us = 30 * 1000000;	/* microseconds */

	proc_name = argv[0];

	while ((c = getopt(argc, argv, "h:")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			break;
		default:
			usage();
		}
	}

	/* init */
	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() returned %s\n", cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, &fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() returned %s\n",
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

	/* set endpoint tx timeout */
	cci_set_opt(endpoint, CCI_OPT_ENDPT_SEND_TIMEOUT,
		    &timeout_us);
	if (ret) {
		fprintf(stderr, "cci_set_opt() returned %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, "Hello World!", 12,
			  CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
		fprintf(stderr, "cci_connect() returned %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	/* poll for connect completion */
	while (!done)
		poll_events(endpoint, &connection, &done);

	if (!connection) {
		fprintf(stderr, "no connection\n");
		exit(EXIT_FAILURE);
	}

	/* begin communication with server */
	for (i = 0; i < 10; i++) {
		char data[128];

		memset(data, 0, sizeof(data));
		sprintf(data, "Hello World!");
		ret = cci_send(connection, data, (uint32_t) strlen(data),
			       (void *)(uintptr_t) i, 0);
		if (ret)
			fprintf(stderr, "send %d returned %s\n", i,
				cci_strerror(endpoint, ret));

		done = 0;
		while (!done)
			poll_events(endpoint, &connection, &done);
	}

	/* clean up */
	ret = cci_disconnect(connection);
	if (ret) {
		fprintf(stderr, "cci_disconnect() returned %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}
	ret = cci_destroy_endpoint(endpoint);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() returned %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	/* add cci_finalize() here */

	return 0;
}
