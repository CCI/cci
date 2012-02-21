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
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h>

#include "cci.h"

#define MPI_DEBUG 0

#if MPI_DEBUG
#include "mpi.h"
#endif

#define ITERS       100000
#define TIMEOUT     30		/* seconds */
#define MAX_PENDING 16

/* Globals */
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int send = 0, recv = 0;
int send_completed = 0;
char *name;
char *server_uri;
char *buffer;
int timeout = TIMEOUT;
int running = 1;
pthread_mutex_t lock;
uint32_t current_size = 32;
cci_device_t **devices = NULL;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_UU;
struct timeval start, end;

#if 1
#define LOCK
#define UNLOCK
#else
#define LOCK   pthread_mutex_lock(&lock);
#define UNLOCK pthread_mutex_unlock(&lock);
#endif

void print_usage()
{
	fprintf(stderr, "usage: %s -h <server_uri> [-s] [-c <type>]\n", name);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-h\tServer's URI\n");
	fprintf(stderr, "\t-s\tSet to run as the server\n");
	fprintf(stderr,
		"\t-c\tConnection type (UU, RU, or RO) set by client only\n");
	fprintf(stderr, "\t-t\tTimeout in seconds (default %d)\n\n", TIMEOUT);
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "server$ %s -h ip://foo -p 2211 -s\n", name);
	fprintf(stderr, "client$ %s -h ip://foo -p 2211\n", name);
	exit(EXIT_FAILURE);
}

double usecs(struct timeval start, struct timeval end)
{
	return ((double)(end.tv_sec - start.tv_sec)) * 1000000.0 +
	    ((double)(end.tv_usec - start.tv_usec));
}

static void poll_events(void)
{
	int ret;
	cci_event_t *event;

	ret = cci_get_event(endpoint, &event);
	if (ret != 0) {
		if (ret != CCI_EAGAIN) {
			fprintf(stderr, "cci_get_event() returned %s\n",
				cci_strerror(ret));
		}
		return;
	}
	assert(event);
	switch (event->type) {
	case CCI_EVENT_SEND:
		if (!is_server) {
			send_completed++;
			LOCK;
			if (running) {
				UNLOCK;
				ret =
				    cci_send(connection, buffer,
					     current_size, NULL, 0);
				if (ret && 1) {
					fprintf(stderr,
						"%s: send returned %s\n",
						__func__, cci_strerror(ret));
				} else
					send++;

				LOCK;
			}
			UNLOCK;
		}
		break;
	case CCI_EVENT_RECV:
		{
			if (!ready) {
				ready = 1;
			} else {
				if (event->recv.len == current_size)
					recv++;
				if (is_server) {
					if (event->recv.len >
					    current_size
					    || event->recv.len == 3) {
						gettimeofday(&end, NULL);
						printf
						    ("recv: %5d\t\t%6d\t\t%6.2lf Mb/s\n",
						     current_size, recv,
						     (double)recv * (double)
						     current_size *
						     8.0 / usecs(start, end));
						current_size = event->recv.len;
						gettimeofday(&start, NULL);
						recv = 1;
					}
					if (event->recv.len == 3) {
						done = 1;
					}
				}
			}
			break;
		}
	case CCI_EVENT_CONNECT_ACCEPTED:
		if (!is_server) {
			connect_done = 1;
			connection = event->accepted.connection;
		}
		break;
	case CCI_EVENT_CONNECT_FAILED:
	case CCI_EVENT_CONNECT_REJECTED:
		if (!is_server) {
			connect_done = 1;
			connection = NULL;
		}
		break;
	case CCI_EVENT_CONNECT_REQUEST:{
			ready = 1;
			cci_accept(event, NULL, &connection);

			buffer = calloc(1, connection->max_send_size);
			if (!buffer) {
				fprintf(stderr, "unable to alloc buffer\n");
				return;
			}
			gettimeofday(&start, NULL);
			cci_send(connection, buffer, current_size, NULL, 0);
			printf("Bytes\t\t# Rcvd\t\tRcvd\n");
			break;
		}
	default:
		fprintf(stderr, "ignoring event type %d\n", event->type);
	}
	cci_return_event(event);
	return;
}

void handle_alarm(int sig)
{
	LOCK;
	running = 0;
	UNLOCK;
	return;
}

void do_client()
{
	int ret;

	sleep(3);

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, NULL, 0, attr, NULL, 0, NULL);
	if (ret) {
		fprintf(stderr, "cci_connect() returned %s\n",
			cci_strerror(ret));
		return;
	}

	/* poll for connect completion */
	while (!connect_done)
		poll_events();

	if (!connection) {
		fprintf(stderr, "no connection\n");
		return;
	}

	buffer = calloc(1, connection->max_send_size);
	if (!buffer) {
		fprintf(stderr, "unable to alloc buffer\n");
		return;
	}

	while (!ready)
		poll_events();

	printf("Bytes\t\t# Sent\t\tSent\n");

	signal(SIGALRM, handle_alarm);

	/* begin communication with server */
	for (current_size = 32; current_size <= connection->max_send_size;) {
		int i;

		send = send_completed = recv = 0;
		LOCK;
		running = 1;
		UNLOCK;

		alarm(timeout);
		gettimeofday(&start, NULL);

		for (i = 0; i < MAX_PENDING; i++) {
			ret =
			    cci_send(connection, buffer, current_size, NULL, 0);
			if (!ret)
				send++;
		}

		LOCK;
		while (running || send_completed < send) {
			UNLOCK;
			poll_events();
			LOCK;
		}
		UNLOCK;

		gettimeofday(&end, NULL);

		printf("sent: %5d\t\t%6d\t\t%6.2lf Mb/s\n",
		       current_size, send,
		       (double)send * (double)current_size * 8.0 /
		       usecs(start, end));

		if (current_size == 0)
			current_size++;
		else
			current_size *= 2;

		//cci_send(connection, "reset", 5, &current_size, sizeof(current_size), NULL, 0);
		sleep(1);
	}
	cci_send(connection, "bye", 3, NULL, 0);

	return;
}

void do_server()
{
	while (!done)
		poll_events();

	return;
}

int main(int argc, char *argv[])
{
	int ret, c;
	uint32_t caps = 0;
	cci_os_handle_t ep_fd;

	name = argv[0];

	while ((c = getopt(argc, argv, "h:p:sc:t:")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			break;
		case 's':
			is_server = 1;
			break;
		case 'c':
			if (strncasecmp("ru", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RU;
			else if (strncasecmp("ro", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RO;
			else if (strncasecmp("uu", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_UU;
			else
				print_usage();
			printf("Using %s connection\n",
			       attr == CCI_CONN_ATTR_UU ? "UU" : attr ==
			       CCI_CONN_ATTR_RU ? "RU" : "RO");
			break;
		case 't':
			timeout = (int)strtoul(optarg, NULL, 0);
			if (timeout <= 0) {
				fprintf(stderr, "timeout %d is invalid\n",
					timeout);
				print_usage();
			}
			break;
		default:
			print_usage();
		}
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_devices((cci_device_t const ***const)&devices);
	if (ret) {
		fprintf(stderr, "cci_get_devices() failed with %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}
	printf("opened %s\n", endpoint->name);

#if MPI_DEBUG
	MPI_Init(&argc, &argv);
#endif

	if (is_server)
		do_server();
	else
		do_client();

	/* clean up */
	ret = cci_destroy_endpoint(endpoint);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (buffer)
		free(buffer);
	ret = cci_free_devices((cci_device_t const **)devices);
	if (ret) {
		fprintf(stderr, "cci_free_devices() failed with %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}

	free(server_uri);

	return 0;
}
