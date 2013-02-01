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

int iters = 10;

void server()
{
	int ret, done = 0, num_recv = 0;
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
	fflush(stdout);

	while (!done) {
		cci_event_t *event;

		ret = cci_get_event(endpoint, &event);
		if (ret != 0) {
			if (ret != CCI_EAGAIN)
				fprintf(stderr, "cci_get_event() returned %s\n",
					cci_strerror(endpoint, ret));
			continue;
		}
		switch (event->type) {
		case CCI_EVENT_RECV:
			{
				char buf[32];
				int len = event->recv.len;
				const void *ptr = event->recv.ptr;

				memset(buf, 0, sizeof(buf));
				memcpy(buf, ptr, len);
				fprintf(stderr, "received \"%s\"\n", buf);
				if (buf[0] - '0' != strlen(buf) - 1) {
					fprintf(stderr, "data does not match!\n");
					exit(EXIT_FAILURE);
				}	
				if (++num_recv >= iters) done = 1;

				if (connection) {
					ret = cci_send(connection, buf, len, NULL, 0);
					if (ret)
						fprintf(stderr, "send returned %s\n",
							cci_strerror(endpoint, ret));
				} else {
					fprintf(stderr, "connection not set up\n");
					exit(EXIT_FAILURE);
				}
				break;
			}
		case CCI_EVENT_SEND:
			fprintf(stderr, "completed send\n");
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			/* associate this connect request with this endpoint */
			cci_accept(event, NULL);
			break;
		case CCI_EVENT_ACCEPT:
			fprintf(stderr, "completed accept\n");
			connection = event->accept.connection;
			break;
		default:
			printf("ignoring event type %d\n", event->type);
			break;
		}
		cci_return_event(event);
	}

	sleep(3);
	printf("test passed\n");

server_cleanup:
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
	free(uri);
}

int send_done;
int recv_done;

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
			send_done++;
                        break;
                case CCI_EVENT_RECV:
			{
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

void client(char *server_uri)
{
	int done = 0, ret, i = 0, c;
        uint32_t caps = 0;
        cci_os_handle_t *fd = NULL;
        cci_endpoint_t *endpoint = NULL;
        cci_connection_t *connection = NULL;
        uint32_t timeout = 10 * 1000000;

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
		cci_connect(endpoint, server_uri, NULL, 0,
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
                exit(EXIT_FAILURE);

	sleep(1);

        /* begin communication with server*/
        for (i = 0; i < iters; i++) {
                char data[32];

                memset(data, 0, sizeof(data));
		/* send messages of different lengths */
		sprintf(data, "%d", i);
		strncpy(data + 1, "abcdefghi", i);	
                ret = cci_send(connection, data, (uint32_t) strlen(data),
                               (void *)(uintptr_t) i, 0);
                if (ret) {
                        fprintf(stderr, "send %d failed with %s\n", i,
                                cci_strerror(endpoint, ret));
			exit(EXIT_FAILURE);
		}
	}

        done = 0;
	while (!done)
                poll_events(endpoint, &connection, &done);

	printf("test passed\n");

client_cleanup:
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
}

void usage_exit(char *progname)
{
	fprintf(stderr, "Usage: %s [args]\n", progname);
	fprintf(stderr, "\t-h <server_uri>   URI output from server\n", progname);
	fprintf(stderr, "\t-s                run as server\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c, isserver = 0;
	char *server_uri = NULL;

	while ((c = getopt(argc, argv, "h:i:s?")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			break;
		case 's':
			isserver = 1;
			break;
		default:
			usage_exit(argv[0]);
		}
	}

	if (!isserver && server_uri == NULL) {
		fprintf(stderr, "%s: server URI must be specified when running as client\n", argv[0]);
		usage_exit(argv[0]);
	}

	if (isserver) {
		server();
	} else {
		client(server_uri);
	}

	return 0;
}
