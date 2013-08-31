/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2013 Oak Ridge National Laboratory.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * Copyright © 2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 *
 */

/*
 * This unit test does the following:
 * - a client connects to a server
 * - the server register 2 buffers for RMA operations and send the handle to the client
 * - when the client receives a new handle from the server, it starts a new RMA operations
 * - when the server receives a RMA message, the buffer is deregistered, a new one registered and the handle is sent to the client
 * - once this happens a certain number of time, the client sends a bye message, the test finishes
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

#define ITERS			(15)
#define MAX_RMA_SIZE    	(8 * 1024 * 1024)

int cnt				= 0;
int done			= 0;
int ready			= 0;
int is_server			= 0;
int connect_done		= 0;
uint32_t max			= 0;
char *server_uri		= NULL;
char *buffer			= NULL;
char *buffer2			= NULL;
cci_endpoint_t *endpoint 	= NULL;
cci_connection_t *connection 	= NULL;
cci_conn_attribute_t attr 	= CCI_CONN_ATTR_RU;

cci_rma_handle_t *local_rma_handle;
cci_rma_handle_t *local_rma_handle2;
struct cci_rma_handle *server_rma_handle;
struct cci_rma_handle *server_rma_handle2;

typedef struct options {
        struct cci_rma_handle rma_handle;
	int handle1_inuse;
	int complete_msg1;
	struct cci_rma_handle rma_handle2;
	int handle2_inuse;
	int complete_msg2;
        uint32_t max_rma_size;
#define MSGS      0
#define RMA_WRITE 1
#define RMA_READ  2
        uint32_t method;
        int flags;
        int pad;
} options_t;

options_t opts;

typedef struct hd_info {
	struct cci_rma_handle handle;
	uint8_t num;
} handle_info_t;

handle_info_t info1, info2;

static void print_usage(void)
{
	/* TODO */
}

static void check_return(cci_endpoint_t * endpoint, char *func, int ret, int need_exit)
{
        if (ret) {
                fprintf(stderr, "%s() returned %s\n", func, cci_strerror(endpoint, ret));
                if (need_exit)
                        exit(EXIT_FAILURE);
        }
        return;
}

static void poll_events(void)
{
        int ret;
        cci_event_t *event;

        ret = cci_get_event(endpoint, &event);
        if (ret == CCI_SUCCESS) {
                assert(event);

                switch (event->type) {
		case CCI_EVENT_SEND: {
			if (!is_server && event->send.context == (void *)0xdeadbeef)
                                done = 1;
			if (!is_server && event->send.context == (void *)1) {
				opts.complete_msg1++;
				fprintf (stdout, "RMA op on handle 1 completed (%d/%d)\n", opts.complete_msg1, ITERS);
			}
			if (!is_server && event->send.context == (void *)2) {
				opts.complete_msg2++;
				fprintf (stdout, "RMA op on handle 2 completed (%d/%d)\n", opts.complete_msg2, ITERS);
			}
			if (opts.complete_msg1 == ITERS && opts.complete_msg2 == ITERS) {
				/* Send the termination message */
				fprintf (stdout, "Sending bye message\n");
				ret = cci_send(connection, "bye", 3, (void *)0xdeadbeef, opts.flags);
				check_return(endpoint, "cci_send", ret, 0);
			}
			break;
		}
                case CCI_EVENT_RECV: {
			if (is_server && event->recv.len == 3) {
				done = 1;
				break;
			}
			/* We received a RMA msg on the first handle */
			if (strncmp (event->recv.ptr, "Done1", 5) == 0) {
				handle_info_t rma_info;

				opts.complete_msg1++;
				fprintf (stdout, "Rcv'ed RMA msg for handle 1 (%d/%d)\n", opts.complete_msg1, ITERS);
				/* Deregister the memory */
				ret = cci_rma_deregister (endpoint, local_rma_handle);
				check_return (endpoint, "cci_rma_deregister", ret, 1);

				/* Register new memory and send the handle to the client */
				ret = cci_rma_register (endpoint, buffer, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle);
				check_return (endpoint, "cci_rma_register", ret, 1);

				memcpy (&rma_info.handle, local_rma_handle, sizeof(cci_rma_handle_t));
				rma_info.num = 1;
				fprintf (stdout, "Sending handle 1 info...\n");
				ret = cci_send (connection, &rma_info, sizeof (handle_info_t), NULL, 0);
				check_return (endpoint, "cci_send", ret, 1);
			}
			/* We received a RMA msg on the second handle */
			else if (strncmp (event->recv.ptr, "Done2", 5) == 0) {
				handle_info_t rma_info;

				opts.complete_msg2++;
				fprintf (stdout, "Rcv'ed RMA msg for handle 2 (%d/%d)\n", opts.complete_msg2, ITERS);
				/* Deregister the memory */
				ret = cci_rma_deregister (endpoint, local_rma_handle2);
                                check_return (endpoint, "cci_rma_deregister", ret, 1);

				/* Register new memory and send the handle to the client */
				ret = cci_rma_register (endpoint, buffer2, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle2);
                                check_return (endpoint, "cci_rma_register", ret, 1);

				memcpy (&rma_info.handle, local_rma_handle2, sizeof(cci_rma_handle_t));
                                rma_info.num = 2;
				fprintf (stdout, "Sending handle 2 info...\n");
                                ret = cci_send (connection, &rma_info, sizeof (handle_info_t), NULL, 0);
                                check_return (endpoint, "cci_send", ret, 1);
			}
			/* Otherwise it is a message to receive a new handle */
			else {
				handle_info_t info = *((handle_info_t*)event->recv.ptr);

				if (info.num == 1) {
					fprintf (stdout, "Rcv'ed info about server handle 1\n");
					/* Save the remote handle */
					if (server_rma_handle == NULL)
						server_rma_handle = malloc (sizeof (struct cci_rma_handle));
					memcpy (server_rma_handle, &info.handle, sizeof(struct cci_rma_handle));
					/* Start the RMA operation */
					if (opts.handle1_inuse == 1) {
						/* Deregister first */
						opts.handle1_inuse = 0;
						ret = cci_rma_deregister(endpoint, local_rma_handle);
						check_return (endpoint, "cci_rma_deregister", ret, 1);
					}
					if (opts.complete_msg1 < ITERS) {
						ret = cci_rma_register(endpoint, buffer, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle);
                                        	check_return(endpoint, "cci_rma_register", ret, 1);
						opts.handle1_inuse = 1;
						fprintf (stdout, "Starting RMA on handle 1\n");
						ret = cci_rma (connection, "Done1", 5, local_rma_handle, 0, server_rma_handle, 0, max, (void*)1, CCI_FLAG_WRITE);
						check_return (endpoint, "cci_rma", ret, 1);
					}
				} else if (info.num == 2) {
					fprintf (stdout, "Rcv'ed info about server handle 2\n");
					/* Save the remote handle */
					if (server_rma_handle2 == NULL)
                                                server_rma_handle2 = malloc (sizeof (struct cci_rma_handle));
					memcpy (server_rma_handle2, &info.handle, sizeof(struct cci_rma_handle));
					/* Start the RMA operation */
					if (opts.handle2_inuse == 1) {
						/* Deregister first */
						opts.handle2_inuse = 0;
						ret = cci_rma_deregister(endpoint, local_rma_handle2);
                                                check_return (endpoint, "cci_rma_deregister", ret, 1);
					}
					if (opts.complete_msg2 < ITERS) {
						ret = cci_rma_register(endpoint, buffer2, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle2);
                				check_return(endpoint, "cci_rma_register", ret, 1);
						opts.handle2_inuse = 1;
						fprintf (stdout, "Starting RMA on handle 2\n");
						ret = cci_rma (connection, "Done2", 5, local_rma_handle2, 0, server_rma_handle2, 0, max, (void*)2, CCI_FLAG_WRITE);
                                        	check_return (endpoint, "cci_rma", ret, 1);
					}
				} else {
					fprintf (stderr, "ERROR: Invalid handle # (%d)\n", info.num);
					exit (EXIT_FAILURE);
				}
			}
			break;
		}
		case CCI_EVENT_CONNECT:
                        if (!is_server) {
                                connect_done = 1;
                                connection = event->connect.connection;
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
static void do_server (void)
{
	int ret;

        while (!ready) {
                cci_event_t *event;

		ret = cci_get_event(endpoint, &event);
                if (ret == CCI_SUCCESS) {
                        switch (event->type) {
                        case CCI_EVENT_CONNECT_REQUEST:
                                opts = *((options_t *) event->request.data_ptr);
				ret = cci_accept(event, NULL);
				check_return(endpoint, "cci_accept", ret, 1);
                                break;
                        case CCI_EVENT_ACCEPT: {
				ready = 1;
				connection = event->accept.connection;

				assert (endpoint);
				assert (max);

				/* Register memory and send handle info */
				fprintf (stdout, "Registering buffer1 and sending RMA handle info...\n");
				ret = posix_memalign ((void**)&buffer, 4096, max);
				check_return (endpoint, "posix_memalign", ret, 1);
				assert (buffer);
				memset (buffer, 'a', max);
				ret = cci_rma_register (endpoint, buffer, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle);
				check_return (endpoint, "cci_rma_register", ret, 1);
				info1.num = 1;
				memcpy (&info1.handle, local_rma_handle, sizeof(*local_rma_handle));
				ret = cci_send (connection, &info1, sizeof (info1), NULL, 0);
				check_return (endpoint, "cci_send", ret, 1);

				fprintf (stdout, "Registering buffer2 and sending RMA handle info...\n");
				ret = posix_memalign ((void**)&buffer2, 4096, max);
				check_return (endpoint, "posix_memalign", ret, 1);
				assert (buffer2);
				memset (buffer2, 'b', max);
				ret = cci_rma_register (endpoint, buffer2, max, CCI_FLAG_WRITE|CCI_FLAG_READ, &local_rma_handle2);
				check_return (endpoint, "cci_rma_register", ret, 1);
				info2.num = 2;
				memcpy (&info2.handle, local_rma_handle2, sizeof(*local_rma_handle2));
				ret = cci_send (connection, &info2, sizeof (info2), NULL, 0);
				check_return (endpoint, "cci_send", ret, 1);
				break;
			}
			default:
                                fprintf(stderr,
                                        "%s: ignoring unexpected event %d\n",
                                        __func__, event->type);
                                break;
                        }
                        ret = cci_return_event(event);
                        if (ret)
                                fprintf(stderr, "cci_return_event() failed with %s\n",
                                                cci_strerror(endpoint, ret));
                }
        }

	fprintf (stdout, "Server ready\n\n");
        while (!done)
                poll_events();

	printf("server done\n");
        sleep(1);

        return;
}

static void do_client (void)
{
	int ret;

	ret = cci_connect(endpoint, server_uri, &opts, sizeof(opts), attr, NULL, 0, NULL);
	check_return (endpoint, "cci_connect", ret, 1);

	/* poll for connect completion */
        while (!connect_done)
                poll_events();

        if (!connection) {
                fprintf(stderr, "no connection\n");
                return;
        }

	ready = 1; /* for now */
	while (!ready)
                poll_events();

	ret = posix_memalign((void **)&buffer, 4096, max);
        check_return(endpoint, "memalign buffer", ret, 1);
        memset(buffer, 'b', max);

	ret = posix_memalign((void **)&buffer2, 4096, max);
        check_return(endpoint, "memalign buffer2", ret, 1);
        memset(buffer2, 'b', max);

        while (!done)
                poll_events();

        printf("client done\n");
        sleep(1);

        return;
}

int main(int argc, char *argv[])
{
	int ret, c;
	char *uri 	= NULL;
	uint32_t caps	= 0;

        while ((c = getopt(argc, argv, "h:s")) != -1) {
                switch (c) {
                case 'h':
                        server_uri = strdup(optarg);
                        break;
                case 's':
                        is_server = 1;
                        break;
		default:
                        print_usage();
		}
	}

	opts.handle1_inuse = 0;
	opts.complete_msg1 = 0;
	opts.handle2_inuse = 0;
	opts.complete_msg2 = 0;

	if (!opts.max_rma_size)
		opts.max_rma_size = MAX_RMA_SIZE;

	max = opts.max_rma_size;

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
	assert (endpoint);

        ret = cci_get_opt(endpoint,
                          CCI_OPT_ENDPT_URI, &uri);
        if (ret) {
                fprintf(stderr, "cci_get_opt() failed with %s\n", cci_strerror(NULL, ret));
                exit(EXIT_FAILURE);
        }
        printf("Opened %s\n", uri);

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

        free(uri);
        free(server_uri);

	if (server_rma_handle == NULL)
		free (server_rma_handle);
	if (server_rma_handle2 == NULL)
		free (server_rma_handle2);

        ret = cci_finalize();
        if (ret) {
                fprintf(stderr, "cci_finalize() failed with %s\n",
                        cci_strerror(NULL, ret));
                exit(EXIT_FAILURE);
        }

        return 0;
}

