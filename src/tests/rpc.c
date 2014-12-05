/*
 * Copyright (c) 2011-2014 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * Copyright © 2012 Inria.  All rights reserved.
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

/* To test using MPI for connection setup, compile with -DUSE_MPI */
#ifdef USE_MPI
#include "mpi.h"
#endif

#define ITERS		(1000)
#define WARMUP		(100)
#define REQ_SIZE	(9000)
#define TRANSFER_SIZE	(16 * 1024 * 1024)
#define ACK_SIZE	(9000)

/* Globals */
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int count = 0;
int completed = 0;
int concurrent = 1;
int inflight = 0;
char *name;
char *uri = NULL;
char server_uri[256];
char *request;
char *buffer;
char *ack;
int flags = 0;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
cci_rma_handle_t *local;
cci_rma_handle_t *remote;
int attempt = 1;
int suppress = 0;
int *msg = NULL;

#ifdef USE_MPI
int rank = 0;
#endif

typedef struct options {
	struct cci_rma_handle rma_handle;
	int32_t iters;
	int32_t warmup;
	uint32_t rma_flags;
	uint32_t req_size;
	uint32_t transfer_size;
	uint32_t ack_size;
} options_t;

options_t opts;

static void print_usage(void)
{
	fprintf(stderr, "usage: %s [-h <server_uri> | [-s]] "
			"[-i <iters>] [-W <warmup>] [-w | -r] "
			"-R <request_size> -T <transfer_size> -A <ack_size>\n", name);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-h\tServer's URI (if not using MPI)\n");
	fprintf(stderr, "\t-s\tSet to run as the server (if not using MPI)\n");
	fprintf(stderr, "\t-t\tUse CCI transport (e.g. tcp, sm, verbs, gni)\n");
	fprintf(stderr, "The remaining options are set by the client only:\n");
	fprintf(stderr, "\t-i\tRun this number of iterations\n");
	fprintf(stderr, "\t-W\tRun this number of warmup iterations\n");
	fprintf(stderr, "\t-c\tNumber of concurrent RPCs\n");
	fprintf(stderr, "\t-w\tClient writes (server gets)\n");
	fprintf(stderr, "\t-r\tClient reads (server puts)\n");
	fprintf(stderr, "\t-R\tRequest size (client -> server)\n");
	fprintf(stderr, "\t-T\tTransfer size (RMA read or write)\n");
	fprintf(stderr, "\t-A\tAck size (client <- server)\n");
	fprintf(stderr, "\t-S\tSuppress output header\n");
	exit(EXIT_FAILURE);
}

static void check_return(cci_endpoint_t * endpoint, char *func, int ret, int need_exit)
{
	if (ret) {
		fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
		if (need_exit) {
			cci_finalize();
			exit(EXIT_FAILURE);
		}
	}
	return;
}

static int
send_request(int cnt)
{
	int ret = 0;

	assert(!is_server);

	/* Send the count in the request */
	*msg = cnt;

	ret = cci_send(connection, request, opts.req_size, (void*)((uintptr_t)cnt), 0);
	check_return(endpoint, "cci_send", ret, 0);

	return ret;
}

static void progress_client(int iters)
{
	int ret;
	cci_event_t *event;

	while (completed < iters || (iters == 0 && !done)) {
		ret = cci_get_event(endpoint, &event);
		if (ret == CCI_SUCCESS) {
			assert(event);
			switch (event->type) {
			case CCI_EVENT_SEND:
			{
				int cnt = (int)((uintptr_t)event->send.context);

				if (event->send.status == CCI_SUCCESS) {
					inflight--;
					if (cnt == (int) 0xdeadbeef)
						done = 1;
				} else {
					send_request(cnt);
				}
			}
				break;
			case CCI_EVENT_RECV:
				completed++;
				while (count < iters && inflight < concurrent) {
					ret = send_request(count);
					if (!ret) {
						count++;
						inflight++;
					} else {
						break;
					}
				}
				break;
			default:
				fprintf(stderr, "ignoring event type %d\n",
					event->type);
			}
			cci_return_event(event);
		}
	}
	return;
}

static double usecs(struct timeval start, struct timeval end)
{
	return ((double)(end.tv_sec - start.tv_sec)) * 1000000.0 +
	    ((double)(end.tv_usec - start.tv_usec));
}

static void
recv_uri(void)
{
#ifdef USE_MPI
	MPI_Status status;

	MPI_Recv(server_uri, sizeof(server_uri), MPI_CHAR, rank == 0 ? 1 : 0, 123,
			MPI_COMM_WORLD, &status);
#endif
	return;
}

static void
connect_to_server(void) {
	int ret = 0;
	cci_conn_attribute_t attr = CCI_CONN_ATTR_RO;

	recv_uri();

again:
	ret = cci_connect(endpoint, server_uri, &opts, sizeof(opts),
			attr, NULL, 0, NULL);
	check_return(endpoint, "cci_connect", ret, 1);

	while (!connection) {
		cci_event_t *event = NULL;

		ret = cci_get_event(endpoint, &event);
		if (ret == CCI_SUCCESS) {
			assert(event->type == CCI_EVENT_CONNECT);

			connection = event->connect.connection;
			if (!connection) {
				cci_return_event(event);
				fprintf(stderr, "Connecting to %s failed\n", server_uri);
				attempt *= 2;
				sleep(attempt);
				goto again;
			}
			cci_return_event(event);
		}
	}

	return;
}

static void do_client(void)
{
	int ret, i = 0;
	struct timeval start, end;
	double lat = 0.0;
	double bw = 0.0;

	ret = posix_memalign((void **)&request, 4096, opts.req_size);
	check_return(endpoint, "memalign buffer", ret, 1);

	msg = (int*) request;

	ret = posix_memalign((void **)&buffer, 4096, opts.transfer_size);
	check_return(endpoint, "memalign buffer", ret, 1);

	memset(buffer, 'b', opts.transfer_size);

	ret = cci_rma_register(endpoint, buffer, opts.transfer_size,
				opts.rma_flags, &local);
	check_return(endpoint, "cci_rma_register", ret, 1);

	memcpy(&opts.rma_handle, local, sizeof(*local));

	connect_to_server();

	if (connection->max_send_size < opts.req_size)
		opts.req_size = connection->max_send_size;

	if (!suppress)
		printf("Bytes\t\tLatency (per rpc)\tThroughput (per rpc)\n");

	/* begin communication with server */
	ret = send_request(count);
	check_return(endpoint, "send first request", ret, 1);
	if (!ret) {
		count++;
		inflight++;
	}

	progress_client(opts.warmup);

	count = 0;
	completed = 0;

	gettimeofday(&start, NULL);

	for (i = 0; i < concurrent; i++) {
		ret = send_request(count);
		if (!ret) {
			count++;
			inflight++;
		}
		check_return(endpoint, "send first request", ret, 0);
	}

	progress_client(opts.iters);

	gettimeofday(&end, NULL);

	lat = usecs(start, end) / (double)opts.iters;

	bw = (double)opts.transfer_size / lat;
	printf("%8d\t%8.2f us\t\t%8.2f MB/s\n", opts.transfer_size, lat, bw);

	ret = cci_send(connection, "bye", 3, (void *)0xdeadbeef, 0);
	check_return(endpoint, "cci_send", ret, 1);

	progress_client(0);

	ret = cci_rma_deregister(endpoint, local);
	check_return(endpoint, "cci_rma_deregister", ret, 1);

	if (!suppress)
		printf("client done\n");

	return;
}

static void
send_uri(void)
{
#ifdef USE_MPI
	MPI_Status status;

	MPI_Send(uri, strlen(uri), MPI_CHAR, rank == 0 ? 1 : 0, 123,
			MPI_COMM_WORLD, &status);
#endif
	return;
}

static void
accept_connection(void)
{
	send_uri();

	while (!connection) {
		int ret = 0;
		cci_event_t *event = NULL;

		ret = cci_get_event(endpoint, &event);
		if (ret == CCI_SUCCESS) {
			switch (event->type) {
			case CCI_EVENT_CONNECT_REQUEST:
				opts = *((options_t *) event->request.data_ptr);
				cci_accept(event, NULL);
				break;
			case CCI_EVENT_ACCEPT:
				assert(event->accept.status == CCI_SUCCESS);
				connection = event->accept.connection;
				ret = posix_memalign((void **)&buffer, 4096,
						opts.transfer_size);
				check_return(endpoint, "memalign buffer", ret, 1);

				memset(buffer, 'a', opts.transfer_size);

				ret = posix_memalign((void **)&ack, 4096, opts.ack_size);
				check_return(endpoint, "memalign buffer", ret, 1);

				memset(buffer, 'b', opts.ack_size);

				ret = cci_rma_register(endpoint,
						     buffer,
						     opts.transfer_size,
						     CCI_FLAG_WRITE|CCI_FLAG_READ,
						     &local);
				check_return(endpoint, "cci_rma_register",
						     ret, 1);
				remote = &opts.rma_handle;
				break;
			default:
				fprintf(stderr, "%s: got %s event\n", __func__,
						cci_event_type_str(event->type));
			}

			cci_return_event(event);
		}
	}

	return;
}

static int
transfer_data(int cookie)
{
	int ret = 0;

	assert(is_server);

	ret = cci_rma(connection, ack, opts.ack_size, local, 0,
			remote, 0, opts.transfer_size,
			(void*)((uintptr_t)cookie), opts.rma_flags);
	check_return(endpoint, "cci_rma", ret, 0);

	return ret;
}

static void
progress_server(void)
{
	int ret;
	cci_event_t *event;

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS) {
		assert(event);
		switch (event->type) {
		case CCI_EVENT_RECV:
			if (event->recv.len != 3) {
				msg = (void*)event->recv.ptr;
				transfer_data(*msg);
			} else {
				done = 1;
			}
			break;
		case CCI_EVENT_SEND:
			if (event->send.status != CCI_SUCCESS) {
				int cnt = (int)((uintptr_t)event->send.status);

				transfer_data(cnt);
			}
			break;
		default:
			fprintf(stderr, "ignoring event type %d\n",
				event->type);
		}
		cci_return_event(event);
	}
	return;
}

static void do_server(void)
{
	int ret = 0, i = 0;

	accept_connection();

	if (connection->max_send_size < opts.ack_size)
		opts.ack_size = connection->max_send_size;

	while (!done)
		progress_server();

	for (i = 0; i < 1000; i++)
		progress_server();

	ret = cci_rma_deregister(endpoint, local);
	check_return(endpoint, "cci_rma_deregister", ret, 1);

	if (!suppress)
		printf("server done\n");

	return;
}

int main(int argc, char *argv[])
{
	int ret, c;
	uint32_t caps = 0;
	char *transport = NULL;
	cci_device_t * const *devices = NULL, *device = NULL;

	name = argv[0];

	opts.iters = ITERS;
	opts.warmup = WARMUP;
	opts.req_size = REQ_SIZE;
	opts.transfer_size = TRANSFER_SIZE;
	opts.ack_size = ACK_SIZE;

	while ((c = getopt(argc, argv, "h:st:i:W:c:wrR:T:A:S")) != -1) {
		switch (c) {
		case 'h':
			strncpy(server_uri, optarg, sizeof(server_uri));
			break;
		case 's':
			is_server = 1;
			break;
		case 't':
			transport = strdup(optarg);
			break;
		case 'i':
			opts.iters = strtoul(optarg, NULL, 0);
			break;
		case 'W':
			opts.warmup = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			concurrent = strtoul(optarg, NULL, 0);
			if (concurrent > 64)
				concurrent = 64;
			break;
		case 'w':
			/* The client wants to write. The server will RMA Read. */
			opts.rma_flags = CCI_FLAG_READ;
			break;
		case 'r':
			/* The client wants to read. The server will RMA Write. */
			opts.rma_flags = CCI_FLAG_WRITE;
			break;
		case 'R':
			opts.req_size = strtoul(optarg, NULL, 0);
			if (opts.req_size > REQ_SIZE)
				opts.req_size = REQ_SIZE;
			break;
		case 'T':
			opts.transfer_size = strtoul(optarg, NULL, 0);
			break;
		case 'A':
			opts.ack_size = strtoul(optarg, NULL, 0);
			if (opts.ack_size > ACK_SIZE)
				opts.ack_size = ACK_SIZE;
			break;
		case 'S':
			suppress = 1;
			break;
		default:
			print_usage();
		}
	}

	if (!opts.rma_flags)
		opts.rma_flags = CCI_FLAG_READ;

	if (!opts.transfer_size)
		opts.transfer_size = TRANSFER_SIZE;

#ifndef USE_MPI
	if (!is_server && server_uri[0] == '\0') {
		fprintf(stderr, "Must select -h or -s\n");
		print_usage();
	}
#else
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);

	if (rank == 0)
		is_server = 1;
#endif

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	check_return(NULL, "cci_init", ret, 1);

	if (transport) {
		int i = 0;
		ret = cci_get_devices(&devices);
		check_return(NULL, "cci_get_devices", ret, 1);

		/* Select first device that matches transport. */
		for (i = 0; ; i++) {
			device = devices[i];

			if (!device)
				break;

			if (strncmp(device->transport, transport, strlen(device->transport)) == 0)
				break;
		}
	}

	/* create an endpoint */
	ret = cci_create_endpoint(device, 0, &endpoint, NULL);
	check_return(NULL, "cci_create_endpoint", ret, 1);

	ret = cci_get_opt(endpoint, CCI_OPT_ENDPT_URI, &uri);
	check_return(endpoint, "cci_get_opt", ret, 1);

	if (!suppress)
		printf("Opened %s\n", uri);

	if (is_server)
		do_server();
	else
		do_client();

	/* clean up */
	ret = cci_destroy_endpoint(endpoint);
	check_return(endpoint, "cci_destroy_endpoint", ret, 1);

	if (buffer)
		free(buffer);

	free(transport);
	free(uri);

	ret = cci_finalize();
	check_return(NULL, "cci_finalize", ret, 1);

#ifdef USE_MPI
	MPI_Barrier();
	MPI_Finalize();
#endif
	return 0;
}
