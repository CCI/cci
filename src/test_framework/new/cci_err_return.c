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
	int ret, done = 0, num_recv = 0;
	uint32_t caps = 0;
	char *uri = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_os_handle_t *ep_fd = NULL;
	cci_connection_t *connection = NULL;
	int num_exp_conns = 3;

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

	while (done != num_exp_conns) {
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
			/* associate this connect request with this endpoint */
			fprintf(stderr, "connect request\n");
			cci_accept(event, NULL);
			break;
		case CCI_EVENT_ACCEPT:
			fprintf(stderr, "completed accept\n");
			connection = event->accept.connection;
			done++;
			break;
		default:
			printf("ignoring event type %d\n", event->type);
			break;
		}
		cci_return_event(event);
	}

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
            int *done)
{
        int ret;
        cci_event_t *event;

        ret = cci_get_event(endpoint, &event);
        if (ret == CCI_SUCCESS && event) {
                switch (event->type) {
                case CCI_EVENT_CONNECT:
			*done += 1;
			*connection = event->connect.connection;
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

	/* test cci_connect input */
	printf("cci_connect: normal call\n");
        ret = cci_connect(endpoint, server_uri, NULL, 0,
                        CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        } else {
		printf("\tsuccess\n");
	}

	printf("cci_connect: data_len > 1024\n");
        ret = cci_connect(endpoint, server_uri, NULL, 1025,
                        CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        } else {
		printf("\tsuccess\n");
	}

	printf("cci_connect: NULL endpoint\n");
	printf("\tskipped (segfault)\n");
#if 0 /* NULL values segfault */
        ret = cci_connect(NULL, server_uri, NULL, 0,
                        CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        }
#endif

	printf("cci_connect: NULL server URI\n");
	printf("\tskipped (segfault)\n");
#if 0 /* NULL values segfault */
        ret = cci_connect(endpoint, NULL, NULL, 0,
                        CCI_CONN_ATTR_UU, NULL, 0, NULL);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        }
#endif

	printf("cci_connect: undefined attribute value 123\n");
        ret = cci_connect(endpoint, server_uri, NULL, 0,
                        123, NULL, 0, NULL);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        } else {
		printf("\tsuccess\n");
	}

	printf("cci_connect: negative timeout\n");
	struct timeval testtime;
	testtime.tv_sec = -1;
	testtime.tv_usec = 0;
        ret = cci_connect(endpoint, server_uri, NULL, 0,
                        CCI_CONN_ATTR_UU, NULL, 0, &testtime);
	if (ret) {
                fprintf(stderr, "\tfailed with %s\n",
                        cci_strerror(endpoint, ret));
        } else {
		printf("\tsuccess\n");
	}

        /* poll for connect completion */
	int num_exp_conns = 3;
        while (done != num_exp_conns)
                poll_events(endpoint, &connection, &done);

	printf("test passed\n");
	fflush(stdout);

	/* server has to close first to avoid hang */
	sleep(1);

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
