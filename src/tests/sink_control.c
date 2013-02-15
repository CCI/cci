/* vim: set tabstop=8:softtabstop=8:shiftwidth=8:noexpandtab */

/*
 * Copyright (c) 2011-2013 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2013 Oak Ridge National Laboratory.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * Copyright © 2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 *
 */

/* This unit test initiate a pipeline of RMA read operations from one peer to
   two targets. We first fill-up the pipeline for the two targets and then,
   initiate a new RMA read operation upon each completion for each target.
   It is also possible to initiate a application-level flow control: upon
   completion of RMA read, we ensure that the numbers of RMA read operations
   between the two targets is balanced. If it is not balanced, we try to
   initiate additional RMA read operations to the target that "is behind" (we
   try to "speed up the slower connection" rather than "slow down the laster
   connection). */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/select.h>
#include <pthread.h>

#include "cci.h"

/* Activate/deactivate application-level flow control */
#define WITH_FLOW_CONTROL	(0)

/* Define the acceptable difference between the number of messages completed
   between the two targets */
#define FCW			(1)

#define ITERS		(16 * 1024)
/*#define WINDOW		(64 * 1024 * 1024)*/
#define WINDOW		(0)
#define MIN_RMA_SIZE    (4 * 1024 * 1024)
#define MAX_RMA_SIZE    (4 * 1024 * 1024)

#define PIPELINE_DEPTH 	(2)

#define DEBUG		(0)

/* Globals */
int connect_done = 0, done = 0;
int comm_done = 0;
int is_server = 0;
int accept = 1;
int count = 0;
int comp = 0;
int iters = ITERS;
int window = WINDOW;
int pipeline_depth = PIPELINE_DEPTH;
char *name;
char *sink1_uri;
char *sink2_uri;
char *buffer1;
char *buffer2;
uint32_t current_size = 8*1024;
cci_device_t **devices = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_RO;
cci_rma_handle_t *server_rma_handle;
int remote_completion = 0;
void *rmt_comp_msg = NULL;
uint32_t rmt_comp_len = 0;
cci_os_handle_t fd = 0;
int blocking = 0;
int nfds = 0;
fd_set rfds;
struct timeval start, end;
uint32_t min_size = MIN_RMA_SIZE;
pthread_t bw_thread;
int loops = 0;

#define PIPELINE_MULTIPLICATOR	(15)
#define MAX_MSGS		(pipeline_depth * PIPELINE_MULTIPLICATOR)

typedef struct options {
	struct cci_rma_handle rma_handle;
	uint32_t max_rma_size;
#define MSG       0
#define RMA_WRITE 1
#define RMA_READ  2
	uint32_t method;
	int flags;
	int pad;
} options_t;

typedef struct target {
	cci_endpoint_t      	*ep;
	cci_connection_t    	*conn;
	cci_rma_handle_t    	*rma_handle;
	options_t           	opts;
	int                 	ready;
	int			comp_msgs;
	int			prev_comp_msgs;
} target_t;
target_t targets[2];

/* Function declaration */
void print_usage(void);
void check_return(cci_endpoint_t *, char *, int, int);
double usecs(struct timeval, struct timeval);
void* calc_bw (void *);
void do_client(void);
void do_server(target_t *);

void print_usage()
{
	fprintf(stderr, "usage: %s -h <server_uri> [-s] [-i <iters>] "
		"[-W <window>] [-c <type>] [-n] "
		"[[-w | -r] [-m <max_rma_size> [-C]]]\n", name);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-g\tFirst server's URI\n");
	fprintf(stderr, "\t-h\tSecond server's URI\n");
	fprintf(stderr, "\t-s\tSet to run as the server\n");
	fprintf(stderr, "\t-R\tServer option to reject connect request\n");
	fprintf(stderr, "\t-i\tRun this number of iterations\n");
	fprintf(stderr, "\t-W\tKeep this amount of data in-flight\n");
	fprintf(stderr,
		"\t-c\tConnection type (UU, RU, or RO) set by client only\n");
	fprintf(stderr, "\t-n\tSet CCI_FLAG_NO_COPY ito avoid copying\n");
	fprintf(stderr, "\t-m\tTest RMA messages up to max_rma_size\n");
	fprintf(stderr, "\t-p\tPayload size in bytes (by default 8K)\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "server$ %s -h ip://foo -p 2211 -s\n", name);
	fprintf(stderr, "client$ %s -h ip://foo -p 2211\n", name);
	exit(EXIT_FAILURE);
}

void check_return(cci_endpoint_t * endpoint, char *func, int ret, int need_exit)
{
	if (ret) {
		fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
		if (need_exit)
			exit(EXIT_FAILURE);
	}
	return;
}

static void poll_events(target_t *target)
{
	int ret;
	cci_event_t *event;
	char *func;
	cci_endpoint_t *endpoint = target->ep;

	func = "cci_rma";

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS) {
		assert(event);
		switch (event->type) {
		case CCI_EVENT_SEND:
			assert(event->send.status == CCI_SUCCESS);
			if (!is_server
			    && event->send.context == (void * )1) {
				/* As soon as a RMA_READ complete, we start a new one */
				if (comp < iters) {
					cci_connection_t *conn = target->conn;
/* With built-in flow control (i.e., application level flow control, if for
   any reason, communications with one of the targets if ahead of another,
   we artificially "progress" the other target. Note that progressing the other
   target allows us to avoid a deadlock where we skip a message to a target and
   then never send anything back to that target because of no new event related
   to that target */
#if WITH_FLOW_CONTROL == 1
					if (target == &targets[0] && targets[0].comp_msgs >= targets[1].comp_msgs + FCW) {
						conn = targets[1].conn;
					}
					if (target == &targets[1] && targets[1].comp_msgs >= targets[0].comp_msgs + FCW) {
						conn = targets[0].conn;
					}
#endif
					ret = cci_rma(conn, rmt_comp_msg, rmt_comp_len,
					              target->rma_handle, 0,
					              &(target->opts.rma_handle), 0,
					              current_size, (void *)1, target->opts.flags);
					check_return(endpoint, func, ret, 1);
				}
				count++;
				comp++;
				target->comp_msgs++;
#if DEBUG == 1
				printf ("Sent %d RMA msgs (current size: %lu)\n", comp, current_size);
#endif
			}
			if (!is_server && event->send.context == (void *)0xdeadbeef)
				done++;
			break;
		case CCI_EVENT_RECV:
			{
				if (!target->ready) {
					target->ready = 1;
					if (!is_server) {
						/* get server_rma_handle */
						target->opts = *((options_t *) event->recv.ptr);
					}
				} else if (is_server && event->recv.len == 3) {
					printf ("Received bye msg\n");
					done++;
					break;
				}
				break;
			}
		case CCI_EVENT_CONNECT:
			if (!is_server) {
				connect_done++;
				target->conn = event->connect.connection;
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

double usecs(struct timeval start, struct timeval end)
{
	return ((double)(end.tv_sec - start.tv_sec)) * 1000000.0 +
	    ((double)(end.tv_usec - start.tv_usec));
}

void* calc_bw (void *ptr)
{
	struct timeval tv;
	uint32_t bw;

	while (done != 2) {
		bw = 0;
        	/* Wake up every second */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
        	select(0, NULL, NULL, NULL, &tv);
		loops++;
		if (targets[0].prev_comp_msgs != targets[0].comp_msgs) {
/*
			printf ("Target 0: %d msgs completed (previously %d) (%lu bytes total)\n",
			        targets[0].comp_msgs,
			        targets[0].prev_comp_msgs,
			        targets[0].comp_msgs * current_size);
			printf ("Test0: %d %d %d %d\n", targets[0].comp_msgs, targets[0].prev_comp_msgs, current_size, loops);
*/
			bw += (targets[0].comp_msgs - targets[0].prev_comp_msgs) * current_size / loops;
/*
			printf ("Target 0 bandwidth: %lu (bytes/s)\n", bw);
*/
			targets[0].prev_comp_msgs = targets[0].comp_msgs;
		}
		if (targets[1].prev_comp_msgs != targets[1].comp_msgs) {
/*
			printf ("Target 1: %d msgs completed (previously %d) (%lu bytes total)\n",
			        targets[1].comp_msgs,
				targets[1].prev_comp_msgs,
			        targets[1].comp_msgs * current_size);
			printf ("Test1: %d %d %d %d\n", targets[1].comp_msgs, targets[1].prev_comp_msgs, current_size, loops);
*/
			bw += (targets[1].comp_msgs - targets[1].prev_comp_msgs) * current_size / loops;
/*
			printf ("Target 1 bandwidth: %lu (bytes/s)\n", (targets[1].comp_msgs - targets[1].prev_comp_msgs) * current_size / loops);
*/
			targets[1].prev_comp_msgs = targets[1].comp_msgs;
		}
		printf ("%d bytes/s or %d MB/s\n", bw, bw / (1024*1024));
    	}

    	pthread_exit (0);
}

void do_client()
{
	int ret;
	uint32_t max1, max2;
	char *func;
	char *header = "Done";

	/* Initialization of a few variables */
	targets[0].ready = 0;
	targets[1].ready = 0;
	targets[0].comp_msgs = 0;
	targets[1].comp_msgs = 0;
	targets[0].prev_comp_msgs = 0;
	targets[1].prev_comp_msgs = 0;

	/* initiate connect to the two sink targets */
	ret = cci_connect(targets[0].ep, sink1_uri, &(targets[0].opts),
                      sizeof(options_t), attr, NULL, 0, NULL);
	check_return(targets[0].ep, "cci_connect", ret, 1);

	ret = cci_connect(targets[1].ep, sink2_uri, &(targets[1].opts),
                      sizeof(options_t), attr, NULL, 0, NULL);
	check_return(targets[1].ep, "cci_connect", ret, 1);

	/* poll for connect completion */
	while (connect_done < 2) {
		poll_events (&targets[0]);
		poll_events (&targets[1]);
	}

	if (!targets[0].conn || !targets[1].conn) {
		fprintf(stderr, "no connection\n");
		return;
	}

	while (!targets[0].ready || !targets[1].ready) {
		if (!targets[0].ready)
			poll_events (&targets[0]);
		if (!targets[1].ready)
			poll_events (&targets[1]);
	}

	printf ("Starting RMA pipeline (pipeline size: %d)\n", pipeline_depth);

	func = "cci_rma";
	max1 = targets[0].opts.max_rma_size;
   	max2 = targets[1].opts.max_rma_size;

	ret = posix_memalign ((void **)&buffer1, 4096, max1);
	check_return (targets[0].ep, "memalign buffer", ret, 1);

	ret = posix_memalign ((void **)&buffer2, 4096, max2);
	check_return (targets[1].ep, "memalign buffer", ret, 1);
	
	memset (buffer1, 'b', max1);
	memset (buffer2, 'b', max2);

	{
		int flags = 0;

		flags = CCI_FLAG_READ;
		targets[0].opts.flags |= CCI_FLAG_READ;
		targets[1].opts.flags |= CCI_FLAG_READ;

		ret = cci_rma_register(targets[0].ep, buffer1, max1, flags,
		                       &(targets[0].rma_handle));
		check_return(targets[0].ep, "cci_rma_register", ret, 1);
		fprintf(stderr, "local_rma_handle is %p\n", (void*)targets[0].rma_handle);

		ret = cci_rma_register(targets[1].ep, buffer2, max2, flags,
		                       &(targets[1].rma_handle));
		check_return(targets[1].ep, "cci_rma_register", ret, 1);
		fprintf(stderr, "local_rma_handle is %p\n", (void*)targets[1].rma_handle);
	}

	if (remote_completion) {
		rmt_comp_msg = header;
		rmt_comp_len = 4;
	}

	/* We are now ready to start the actual test so we create a thread
	   that calculate the bandwidth */
        pthread_create (&bw_thread, NULL, &calc_bw, NULL);

	for (count = 0; count < pipeline_depth; count++) {
		/* Starting the pipeline with the two targets */
		ret = cci_rma(targets[0].conn, rmt_comp_msg, rmt_comp_len,
		              targets[0].rma_handle, 0,
		              &(targets[0].opts.rma_handle), 0,
		              current_size, (void *)1, targets[0].opts.flags);
		check_return(targets[0].ep, func, ret, 1);

		ret = cci_rma(targets[1].conn, rmt_comp_msg, rmt_comp_len,
		              targets[1].rma_handle, 0,
		              &(targets[1].opts.rma_handle), 0,
		              current_size, (void *)1, targets[1].opts.flags);
		check_return(targets[1].ep, func, ret, 1);
	}

	printf ("Waiting for the %d msgs to complete\n", iters);
	while (comp < iters) {
		poll_events (&targets[0]);
		poll_events (&targets[1]);
	}
    
	printf ("Sending bye msg to first target\n");
	ret = cci_send(targets[0].conn, "bye", 3, (void *)0xdeadbeef, targets[0].opts.flags);
	check_return(targets[0].ep, "cci_send", ret, 0);

	printf ("Sending bye msg to second target\n");
	ret = cci_send(targets[1].conn, "bye", 3, (void *)0xdeadbeef, targets[1].opts.flags);
	check_return(targets[1].ep, "cci_send", ret, 0);
	
	while (done != 2) {
		poll_events(&targets[0]);
		poll_events(&targets[1]);
	}

	printf("client done\n");
    
	pthread_join(bw_thread, NULL);
	sleep(1);
	
	ret = cci_destroy_endpoint(targets[0].ep);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
				cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	
	ret = cci_destroy_endpoint(targets[1].ep);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
				cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	return;
}

void do_server(target_t *target)
{
	int ret, len;

	while (!target->ready) {
		cci_event_t *event;

		if (blocking) {
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);

			ret = select(nfds, &rfds, NULL, NULL, NULL);
			if (!ret)
				return;
		}

		ret = cci_get_event(target->ep, &event);
		if (ret == CCI_SUCCESS) {
			switch (event->type) {
			case CCI_EVENT_CONNECT_REQUEST:
				if (accept) {
					target->opts = *((options_t *) event->request.data_ptr);
					ret = cci_accept(event, NULL);
					check_return(target->ep, "cci_accept", ret, 1);
				} else {
					ret = cci_reject(event);
					check_return(target->ep, "cci_accept", ret, 1);
				}
				break;
			case CCI_EVENT_ACCEPT:
				target->ready = 1;
				target->conn = event->accept.connection;

				len = target->opts.max_rma_size;

				/* on the server side, only one buffer is used */
				ret = posix_memalign((void **)&buffer1, 4096, len);
				check_return(target->ep, "memalign buffer", ret, 1);

				memset(buffer1, 'a', len);

				if (target->ep == NULL)
					printf ("EP is NULL\n");
				if (buffer1 == NULL)
					printf ("Buffer is NULL\n");
				printf ("RMA size: %d\n", target->opts.max_rma_size);
				ret = cci_rma_register(target->ep, buffer1,
				                       target->opts.max_rma_size,
				                       CCI_FLAG_READ,
				                       &server_rma_handle);
				check_return(target->ep, "cci_rma_register", ret, 1);
				memcpy (&(target->opts.rma_handle), server_rma_handle,
				        sizeof(*server_rma_handle));

				ret = cci_send(target->conn, &(target->opts), sizeof(target_t), NULL, 0);
				check_return(target->ep, "cci_send", ret, 1);
				break;
			default:
				fprintf(stderr,
					"%s: ignoring unexpected event %d\n",
					__func__, event->type);
				break;
			}
			ret = cci_return_event(event);
			if (ret)
				fprintf(stderr, "cci_return_event() failed with %s\n",
						cci_strerror(target->ep, ret));
		}
	}

	while (!done)
		poll_events(target);

	ret = cci_rma_deregister (target->ep, server_rma_handle);
	check_return (target->ep, "cci_rma_deregister", ret, 1);
	
	printf("server done\n");
	
	/* Destroy the endpoint */
	ret = cci_destroy_endpoint(target->ep);
	if (ret) {
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
				cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}
	
	return;
}

int main(int argc, char *argv[])
{
	int ret, c;
	uint32_t caps = 0;
	cci_os_handle_t *os_handle = NULL;
	char *uri = NULL;
	int max_rma_size = 0;

	name = argv[0];

	while ((c = getopt(argc, argv, "h:g:sRc:wrm:Ci:p:d:W:")) != -1) {
		switch (c) {
		case 'h':
			sink1_uri = strdup(optarg);
			break;
		case 'g':
			sink2_uri = strdup(optarg);
			break;
		case 's':
			is_server = 1;
			break;
		case 'R':
			accept = 0;
			break;
		case 'i':
			iters = strtoul(optarg, NULL, 0);
			break;
		case 'W':
			window = strtoul(optarg, NULL, 0);
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
		case 'd':
			pipeline_depth = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			max_rma_size = strtoul(optarg, NULL, 0);
			break;
		case 'C':
			remote_completion = 1;
			break;
		case 'p':
			{
			int toto;
			printf ("[%s:%d] Check\n", __func__, __LINE__);
			current_size = strtoul(optarg, NULL, 0);
			printf ("[%s:%d] Check\n", __func__, __LINE__);
			break;
			}
		default:
			print_usage();
		}
	}

	if (!is_server && (!sink1_uri || !sink2_uri)) {
		fprintf(stderr, "Must select -h/-g or -s\n");
		print_usage();
	}

	if (window) {
		pipeline_depth = window / min_size;

		if (iters < pipeline_depth)
			iters = pipeline_depth * 2;
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	if (is_server) {
		target_t target;
		target.opts.method = RMA_READ;
		target.ready = 0;

		if (!max_rma_size)
			target.opts.max_rma_size = MAX_RMA_SIZE;
		else
			target.opts.max_rma_size = max_rma_size;

		/* create an endpoint */
		ret = cci_create_endpoint(NULL, 0, &target.ep, NULL);
		if (ret) {
			fprintf(stderr, "cci_create_endpoint() failed with %s\n",
					cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		
		ret = cci_get_opt(target.ep, CCI_OPT_ENDPT_URI, &uri);
		if (ret) {
			fprintf(stderr, "cci_get_opt() failed with %s\n", 
					cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		printf("Opened %s\n", uri);
		
		do_server(&target);
	} else {
		targets[0].opts.method = RMA_READ;
		targets[1].opts.method = RMA_READ;
		if (!max_rma_size) {
			targets[0].opts.max_rma_size = MAX_RMA_SIZE;
			targets[1].opts.max_rma_size = MAX_RMA_SIZE;
		} else {
			targets[0].opts.max_rma_size = max_rma_size;
			targets[1].opts.max_rma_size = max_rma_size;
		}

		printf ("Connecting to %s and %s...\n", sink1_uri, sink2_uri);
		/* create endpoints */
		ret = cci_create_endpoint(NULL, 0, &targets[0].ep, os_handle);
		if (ret) {
			fprintf(stderr, "cci_create_endpoint() failed with %s\n",
					cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		
		ret = cci_get_opt(targets[0].ep, CCI_OPT_ENDPT_URI, &uri);
		if (ret) {
			fprintf(stderr, "cci_get_opt() failed with %s\n", cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		printf("Opened %s\n", uri);
		
		ret = cci_create_endpoint(NULL, 0, &targets[1].ep, os_handle);
		if (ret) {
			fprintf(stderr, "cci_create_endpoint() failed with %s\n",
					cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		
		ret = cci_get_opt(targets[1].ep, CCI_OPT_ENDPT_URI, &uri);
		if (ret) {
			fprintf(stderr, "cci_get_opt() failed with %s\n", cci_strerror(NULL, ret));
			exit(EXIT_FAILURE);
		}
		printf("Opened %s\n", uri);		
		
		do_client();
	}

	/* clean up */
	if (buffer1)
		free(buffer1);
	
	if (buffer2)
		free(buffer2);

	free(uri);
	free(sink1_uri);
	free(sink2_uri);

	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "cci_finalize() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	return 0;
}
