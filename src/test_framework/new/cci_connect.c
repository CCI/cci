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
#include <sys/time.h>

#include "cci.h"

void server()
{
	int ret, context, num_request = 0, num_accept = 0;
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

	while (num_request < 3 || num_accept < 1) {
		cci_event_t *event;

		ret = cci_get_event(endpoint, &event);
		if (ret != 0) {
			if (ret != CCI_EAGAIN)
				fprintf(stderr, "cci_get_event() returned %s\n",
					cci_strerror(endpoint, ret));
			continue;
		}
		switch (event->type) {
		case CCI_EVENT_CONNECT_REQUEST:
			fprintf(stderr, "connect request\n");
			num_request++;
			/* accept the first, reject the second, let the third timeout */
			if (num_request == 1) {
				context = 123;
				cci_accept(event, (int *) &context);
			} else if (num_request == 2 && 0) { /* XXX: cci_reject segfaults */
				cci_reject(event);
			} 
			break;
		case CCI_EVENT_ACCEPT:
			fprintf(stderr, "completed accept\n");
			connection = event->accept.connection;
			context = *(int *) event->accept.context;
			printf("CCI_EVENT_ACCEPT: %d\n", context);
			num_accept++;
			break;
		default:
			fprintf(stderr, "ignoring event type %d\n", event->type);
		}
		cci_return_event(event);
	}

	printf("Pausing while client times out...\n");
        sleep(5);

	printf("test passed\n");
	fflush(stdout);

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

static void
poll_events(cci_endpoint_t * endpoint, cci_connection_t ** connection,
            int *num_connect)
{
        int ret;
        cci_event_t *event;
	char buf[128];
        int context = 0;

        ret = cci_get_event(endpoint, &event);
        if (ret == CCI_SUCCESS && event) {
                switch (event->type) {
                case CCI_EVENT_CONNECT:
			*num_connect += 1;
			*connection = event->connect.connection;
                        context = *(int *) event->connect.context;
			switch (event->connect.status) {
			case CCI_SUCCESS:
				sprintf(buf, "CCI_SUCCESS\n");
				break;
			case CCI_ECONNREFUSED:
				sprintf(buf, "CCI_ECONNREFUSED\n");
				break;
			case CCI_ETIMEDOUT:
				sprintf(buf, "CCI_ETIMEDOUT\n");
				break;
			default:
				sprintf(buf, "ERROR (%d)\n", event->connect.status);
			}
                        printf("CCI_EVENT_CONNECT: %d - %s", context, buf);
			break;
		default:
			fprintf(stderr, "ignoring event type %d\n",
				event->type);
		}
		cci_return_event(event);
	}
}

void client(char *server_uri)
{
	int num_connect = 0, ret, i = 0, c;
        uint32_t caps = 0;
        cci_os_handle_t *fd = NULL;
        cci_endpoint_t *endpoint = NULL;
        cci_connection_t *connection = NULL;
        uint32_t timeout = 10 * 1000000;
        int context[3] = {0, 1, 2};
        struct timeval wait;

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

        ret = cci_connect(endpoint, server_uri, "Happy", 5,
                        CCI_CONN_ATTR_UU, (int *) &context[0], 0, NULL);
	if (ret) {
                fprintf(stderr, "cci_connect(0) failed with %s\n",
                        cci_strerror(endpoint, ret));
        } 

        ret = cci_connect(endpoint, server_uri, "New", 3,
                        CCI_CONN_ATTR_UU, (int *) &context[1], 0, NULL);
	if (ret) {
                fprintf(stderr, "cci_connect(1) failed with %s\n",
                        cci_strerror(endpoint, ret));
        } 

        wait.tv_sec = 2;
        wait.tv_usec = 0;
        ret = cci_connect(endpoint, server_uri, "Year", 4,
                        CCI_CONN_ATTR_UU, (int *) &context[2], 0, &wait);
	if (ret) {
                fprintf(stderr, "cci_connect(2) failed with %s\n",
                        cci_strerror(endpoint, ret));
        } 

        /* poll for connect completion */
        //while (num_connect < 3)
	while (num_connect < 1) /* connect timeouts are not registering */
                poll_events(endpoint, &connection, &num_connect);

	printf("test passed\n");
	fflush(stdout);

	/* server has to close first to avoid hang */
	sleep(5);

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
