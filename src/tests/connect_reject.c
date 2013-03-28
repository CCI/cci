/*
 * Copyright (c) 2013	UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2013	Oak Ridge National Laboratory.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/select.h>

#include "cci.h"

int connect_done = 0;
int done = 0;
int ready = 0;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
int is_server = 0;
char *server_uri, *name;
cci_conn_attribute_t attr = CCI_CONN_ATTR_RO;

typedef struct options {
        struct cci_rma_handle rma_handle;
        uint32_t max_rma_size;
#define MSGS      0
#define RMA_WRITE 1
#define RMA_READ  2
        uint32_t method;
        int flags;
        int pad;
} options_t;

options_t opts;

static inline void check_return(cci_endpoint_t * endpoint, char *func, int ret, int need_exit)
{
        if (ret) {
                fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
                if (need_exit)
                        exit(EXIT_FAILURE);
        }
        return;
}

static inline void print_usage (void)
{
	fprintf (stderr, "usage: %s -h <server_uri> [-s]\n", name);
	fprintf (stderr, "where:\n");
	fprintf (stderr, "\t-h\tServer's URI\n");
	fprintf (stderr, "\t-s\tSet to run as the server\n");
	exit (EXIT_FAILURE);
}

static inline void poll_events (void)
{
	int ret;
	cci_event_t *event;

	ret = cci_get_event (endpoint, &event);
	if (ret == CCI_SUCCESS) {
		assert (event);
		switch (event->type) {
			case CCI_EVENT_CONNECT:
				if (!is_server) {
					connect_done = 1;
					connection = event->connect.connection;
				}
				break;
			default:
				fprintf (stderr, "ignoring event type %d\n",
				         event->type);
		}
	}

	return;
}

static inline void do_server (void)
{
	int ret;

	while (!done) {
		cci_event_t *event;

		ret = cci_get_event (endpoint, &event);
		if (ret == CCI_SUCCESS) {
			switch (event->type) {
				case CCI_EVENT_CONNECT_REQUEST:
					ret = cci_reject (event);
					check_return (endpoint,
					              "cci_reject",
					              ret, 1);
					done = 1;
					break;
				default:
					fprintf (stderr, "cci_return_event() failed with %s\n",
					                 cci_strerror (endpoint, ret));
			}
		}
	}

	return;
}

static inline void do_client (void)
{
	int ret;

	ret = cci_connect (endpoint, server_uri, &opts, sizeof (opts), attr,
	                   NULL, 0, NULL);
	check_return (endpoint, "cci_connect", ret, 1);

	while (!connect_done)
		poll_events ();

	if (!connection) {
		fprintf (stderr, "no connection\n");
		return;
	}

	while (!ready)
		poll_events ();

	return;
}

int main (int argc, char *argv[])
{
	int ret, c;
	uint32_t caps = 0;
	char *uri = NULL;

	name = argv[0];

	while ((c = getopt (argc, argv, "h:s")) != -1) {
		switch (c) {
			case 'h':
				server_uri = strdup (optarg);
				break;
			case 's':
				is_server = 1;
				break;
			default:
				print_usage ();
		}
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
        if (ret) {
                fprintf(stderr, "cci_init() failed with %s\n",
                        cci_strerror(NULL, ret));
                exit(EXIT_FAILURE);
        }

        /* create an endpoint */
        ret = cci_create_endpoint(NULL, 0, &endpoint, NULL);
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

	if (is_server)
		do_server ();
	else
		do_client ();

	ret = cci_destroy_endpoint (endpoint);
	if (ret) {
		fprintf (stderr, "cci_destroy_endpoint() failed with %s\n",
		         cci_strerror (NULL, ret));
		exit (EXIT_FAILURE);
	}

	free (server_uri);

	ret = cci_finalize ();
	if (ret) {
		fprintf (stderr, "cci_finalize() failed with %s\n",
		         cci_strerror (NULL, ret));
		exit (EXIT_FAILURE);
	}

	return 0;
}
