/*
 * Copyright (c) 2011-2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2012 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
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

#define TIMEOUT     10		/* seconds */
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
uint32_t current_size = 1;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *control_conn = NULL;
cci_connection_t *test_conn = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_UU;
struct timeval start, end;
int in_flight = MAX_PENDING;
int blocking = 0;
cci_os_handle_t fd = 0;
int ignore_os_handle = 0;
int nfds = 0;
fd_set rfds;

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
	fprintf(stderr, "\t-t\tTimeout in seconds (default %d)\n", TIMEOUT);
	fprintf(stderr, "\t-i\tMax number of messages in-flight (default %d)\n", MAX_PENDING);
	fprintf(stderr, "\t-b\tBlock using the OS handle instead of polling\n");
	fprintf(stderr, "\t-o\tGet OS handle but don't use it\n\n");
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

	if (blocking) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

again:
		ret = select(nfds, &rfds, NULL, NULL, NULL);
		if (ret == -1 && errno == EINTR)
			goto again;
		else if (ret < 1)
			return;
	}

	ret = cci_get_event(endpoint, &event);
	if (ret != 0) {
		if (ret != CCI_EAGAIN) {
			fprintf(stderr, "cci_get_event() returned %s\n",
				cci_strerror(endpoint, ret));
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
				    cci_send(test_conn, buffer,
					     current_size, NULL, 0);
				if (ret && 1) {
					fprintf(stderr,
						"%s: send returned %s\n",
						__func__, cci_strerror(endpoint, ret));
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
						double mbs = 0.0;

						gettimeofday(&end, NULL);

						mbs = (double)recv * (double)current_size
							* 8.0 / usecs(start, end);
						printf
						    ("recv: %7d\t%12d\t%8.2lf Mb/s\t%8.2lf MB/s\n",
						     current_size, recv,
						     mbs, mbs / 8.0);
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
	case CCI_EVENT_CONNECT:
		if (!is_server) {
			cci_connection_t **conn = event->connect.context;
			*conn = event->connect.connection;
			connect_done++;
		}
		break;
	case CCI_EVENT_CONNECT_REQUEST:{
			uintptr_t control = event->request.data_len ? 1 : 0;
			ret = cci_accept(event, (void*)control);
			break;
		}
	case CCI_EVENT_ACCEPT:{
			ready++;
			if (event->accept.context) {
				control_conn = event->accept.connection;
			} else {
				test_conn = event->accept.connection;
				buffer = calloc(1, test_conn->max_send_size);
				if (!buffer) {
					fprintf(stderr, "unable to alloc buffer\n");
					return;
				}
			}
			if (ready == 2) {
				gettimeofday(&start, NULL);
				cci_send(control_conn, buffer, current_size, NULL, 0);
				printf("\tBytes\t     # Rcvd\t     Rcvd\n");
			}
			break;
		}
	default:
		fprintf(stderr, "ignoring event type %d (\n", event->type);
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
	int control = 1;

#if MPI_DEBUG
	sleep(1);
#endif

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, &control, sizeof(control),
				CCI_CONN_ATTR_RU, &control_conn, 0, NULL);
	if (ret) {
		fprintf(stderr, "cci_connect() returned %s\n",
			cci_strerror(endpoint, ret));
		return;
	}

	ret = cci_connect(endpoint, server_uri, NULL, 0, attr,
			&test_conn, 0, NULL);
	if (ret) {
		fprintf(stderr, "cci_connect() returned %s\n",
			cci_strerror(endpoint, ret));
		return;
	}

	/* poll for connect completion */
	while (connect_done < 2)
		poll_events();

	if (!control_conn || !test_conn) {
		fprintf(stderr, "no connection\n");
		return;
	}

	buffer = calloc(1, test_conn->max_send_size);
	if (!buffer) {
		fprintf(stderr, "unable to alloc buffer\n");
		return;
	}

	while (!ready)
		poll_events();

	printf("\tBytes\t     # Sent\t     Sent\n");

	signal(SIGALRM, handle_alarm);

	/* begin communication with server */
	for (; current_size <= test_conn->max_send_size;) {
		int i;
		double mbs = 0.0;

		send = send_completed = recv = 0;
		LOCK;
		running = 1;
		UNLOCK;

		alarm(timeout);
		gettimeofday(&start, NULL);

		for (i = 0; i < in_flight; i++) {
			ret =
			    cci_send(test_conn, buffer, current_size, NULL, 0);
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

		mbs = (double)send * (double)current_size * 8.0 / usecs(start, end);

		printf("sent: %7d\t%12d\t%8.2lf Mb/s\t%8.2lf MB/s\n",
		       current_size, send,
		       mbs, mbs / 8.0);

		current_size *= 2;
	}
	cci_send(control_conn, "bye", 3, NULL, 0);

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
	//cci_os_handle_t ep_fd;
	char *uri = NULL;
	cci_os_handle_t *os_handle = NULL;

	name = argv[0];

	while ((c = getopt(argc, argv, "h:p:sc:t:i:bc:o")) != -1) {
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
		case 'i':
			in_flight = strtol(optarg, NULL, 0);
			break;
		case 'b':
			blocking = 1;
			os_handle = &fd;
			break;
		case 'o':
			ignore_os_handle = 1;
			os_handle = &fd;
			break;
		default:
			print_usage();
		}
	}

	if (!is_server && !server_uri) {
		fprintf(stderr, "Must select -h or -s\n");
		print_usage();
	}

	if (blocking && ignore_os_handle) {
		fprintf(stderr, "-b and -o are not compatible.\n");
		fprintf(stderr, "-b will block using select() using the OS handle.\n");
		fprintf(stderr, "-o will obtain the OS handle, but not use it to wait.\n");
		print_usage();
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, os_handle);
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

	if (blocking) {
		nfds = fd + 1;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
	}

#if MPI_DEBUG
	MPI_Init(&argc, &argv);

	MPI_barrier(MPI_COMM_WORLD);
#endif

	if (is_server)
		do_server();
	else
		do_client();

	/* clean up */
	ret = cci_destroy_endpoint(endpoint);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	if (buffer)
		free(buffer);

	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "cci_finalize() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	free(server_uri);
	free(uri);

#if MPI_DEBUG
	MPI_Finalize();
#endif

	return 0;
}
