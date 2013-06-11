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
#include <limits.h>

#include "cci.h"

#define MAX_MSGS 3000

int connect_done 		= 0;
int done 			= 0;
cci_endpoint_t *endpoint 	= NULL;
cci_connection_t *connection 	= NULL;
int is_server 			= 0;
cci_conn_attribute_t attr 	= CCI_CONN_ATTR_RO;
char *server_uri, *name, *test_uri, *uri;
int nb_msgs = 0;

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

static inline int send_msgs (void)
{
	int ret;
	uint32_t value = 1;
	int i;

	for (i = 0; i < MAX_MSGS; i++) {
		fprintf (stderr, "Sending msg %d/%d %u\n", i, MAX_MSGS-1, value);
		ret = cci_send (connection, &value, sizeof (uint32_t), NULL, 0);
		check_return (endpoint, "send_msgs", ret, 1);
		if (value >= INT_MAX)
			value = 1;
		else
			value = value * 2;
	}

	return 0;
}

static inline void poll_events (void)
{
	cci_event_t *event;
	int ret;

	ret = cci_get_event (endpoint, &event);
	if (ret == CCI_SUCCESS) {
		switch (event->type) {
			case CCI_EVENT_CONNECT_REQUEST:
				opts = *((options_t *) event->request.data_ptr);
				ret = cci_accept (event, NULL);
				check_return (endpoint, "cci_accept", ret, 1);
				break;
			case CCI_EVENT_ACCEPT:
				connection = event->accept.connection;
				break;
			case CCI_EVENT_RECV: {
				if (is_server && strncmp (event->recv.ptr, "start", 5) == 0) {
					break;
				}
				if (strncmp (event->recv.ptr, "bye", 3) == 0) {
					done = 1;
					break;
				}
				fprintf (stderr, "Msg recv'd (%d/%d): %u\n", nb_msgs, MAX_MSGS-1, *(uint32_t*)event->recv.ptr);
				nb_msgs++;
				if (!is_server && nb_msgs == MAX_MSGS)  {
					fprintf (stderr, "Sending bye msg...\n");
					ret = cci_send(connection, "bye", 3, (void *)0xdeadbeef, opts.flags);
        				check_return(endpoint, "cci_send", ret, 0);
					done = 1;
				}
				if (is_server && nb_msgs == MAX_MSGS) {
					send_msgs ();
				}
				break;
			}
			case CCI_EVENT_CONNECT:
				if (!is_server) {
					connection = event->connect.connection;
					send_msgs ();
				}
				break;
			case CCI_EVENT_SEND:
				break;
			default:
				fprintf (stderr, "Ignoring event type %d\n",
				         event->type);
		}
		cci_return_event (event);
	}
}

static inline void do_server (void)
{
	while (!done) {
		poll_events();
	}

	sleep (1);

	return;
}

static inline void do_client (void)
{
	int ret;

	ret = cci_connect (endpoint, server_uri, &opts, sizeof (opts), attr,
	                   NULL, 0, NULL);
	check_return (endpoint, "cci_connect", ret, 1);

	while (!done) {
		poll_events();
	}

	fprintf (stderr, "Test Completed\n");

	sleep (1);

	return;
}

int main (int argc, char *argv[])
{
	int ret, c;
	uint32_t caps	= 0;

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

	/* Create the endpoint for the control connection */
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
        printf("Opened connection %s\n", uri);

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
