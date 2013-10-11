/*
 * Copyright (c) 2011-2013 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2013 Oak Ridge National Labs.  All rights reserved.
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
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "cci.h"

#define ITERS		(1)
#define RMA_REG_LEN	(4 * 1024 * 1024)

/* Globals */
int verbose = 0;
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int is_client = 0;
int count = 0;
int *tcount = NULL;
int iters = ITERS;
char *name = NULL;
char *server_uri = NULL;
char *buffer = NULL;
uint32_t current_size = 0;
uint64_t local_offset = 0;
uint64_t remote_offset = 0;
uint64_t length = 0;
cci_device_t **devices = NULL;
cci_endpoint_t *endpoint = NULL;
#define CONTROL 1
#define TEST 2
cci_connection_t *control = NULL;
cci_connection_t *test = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_RU;
cci_rma_handle_t *local_rma_handle = NULL;
cci_rma_handle_t remote_rma_handle;
cci_os_handle_t fd = 0;
int ignore_os_handle = 0;
int blocking = 0;
int nfds = 0;
fd_set rfds;
int client_threads = 1;
int server_threads = 1;
pthread_t *tid = NULL;	/* client: RMA thread(s) */
sem_t *sem = NULL;	/* client: to notify RMA thread of completion */
int running = 1;

typedef struct options {
	uint64_t length;
	uint64_t reg_len;
#define RMA_WRITE 1
#define RMA_READ  2
	uint32_t method;
	int flags;
	int threads;
} options_t;

options_t opts;

typedef enum msg_type {
	MSG_CONTROL,
	MSG_CONN_REQ,
	MSG_CONN_REPLY,
	MSG_RMA_CHK,
	MSG_RMA_STATUS
} msg_type_t;

typedef union hdr {
	struct generic_hdr {
		msg_type_t type;
	} generic;

	struct conn_req_hdr {
		msg_type_t type;
		options_t opts;
	} request;

	struct conn_reply_hdr {
		msg_type_t type;
		struct cci_rma_handle handle;
	} reply;

	struct rma_chk_hdr {
		msg_type_t type;
		uint64_t offset;
		uint64_t len;
		uint32_t crc;
		int thread;
	} check;

	struct status_hdr {
		msg_type_t type;
		uint32_t crc;
		int thread;
	} status;
} hdr_t;

hdr_t *msg;
uint32_t *msg_len = 0;

extern uint32_t
crc32(uint32_t crc, const void *buf, size_t size);

static void print_usage(void)
{
	fprintf(stderr, "usage: %s -h <server_uri> [-s] [-i <iters>] "
		"[-c <type>] [-B|-I] [-o <local_offset>] [-O <remote_offset>"
		"[[-w | -r] [-R <reg_len>] [-l <max_len>]] "
		"[-T <client_threads>]\n", name);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-h\tServer's URI\n");
	fprintf(stderr, "\t-s\tSet to run as the server\n");
	fprintf(stderr, "\t-i\tRun this number of iterations (default %d)\n", iters);
	fprintf(stderr, "\t-c\tConnection type (RU or RO) set by client only\n");
	fprintf(stderr, "\t-w\tUse RMA WRITE (default)\n");
	fprintf(stderr, "\t-r\tUse RMA READ instead of RMA WRITE\n");
	fprintf(stderr, "\t-l\tTest RMA up to length\n");
	fprintf(stderr, "\t-R\tRegister RMA length (default max_len))\n");
	fprintf(stderr, "\t-o\tRMA local offset (default 0)\n");
	fprintf(stderr, "\t-O\tRMA remote offset (default 0)\n");
	fprintf(stderr, "\t-B\tBlock using the OS handle instead of polling\n");
	fprintf(stderr, "\t-I\tGet OS handle but ignore it\n\n");
	fprintf(stderr, "\t-T\tNumber of client RMA threads (default 1)\n");
	fprintf(stderr, "\t-t\tNumber of server threads (default 1) set by server only\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "server$ %s -h sock://foo -p 2211 -s\n", name);
	fprintf(stderr, "client$ %s -h sock://foo -p 2211\n", name);
	exit(EXIT_FAILURE);
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

static void
init_buffer(int is_client)
{
	int i = 0, len = 0, count = 0;
	uint32_t *r = (uint32_t*)buffer;

	len = opts.reg_len * opts.threads;
	count = len / sizeof(uint32_t);

	memset(buffer, 0, len);

	if ((is_client && opts.method == RMA_WRITE) ||
		(!is_client && opts.method == RMA_READ)) {
		for (i = 0; i < count; i++) {
			*r = random();
			r++;
		}
	}

	return;
}

static void
print_buffer(int id, void *buf, int len)
{
	int i = 0;
	uint8_t *c = (uint8_t *)buf;

	if (len > 128 || !verbose)
		return;

	fprintf(stderr, "%d: ** ", id);
	for (i = 0; i < len; i++) {
		fprintf(stderr, "0x%02x ", *c);
		if ((i % 16) == 15) fprintf(stderr, "\n%d: ** ", id);
		c++;
	}
	fprintf(stderr, "\n");
	return;
}

static void poll_events(void)
{
	int ret;
	cci_event_t *event;

	if (blocking) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		ret = select(nfds, &rfds, NULL, NULL, NULL);
		if (!ret)
			return;
	}

	ret = cci_get_event(endpoint, &event);
	if (ret == CCI_SUCCESS) {
		assert(event);
		switch (event->type) {
		case CCI_EVENT_SEND:
			if (event->send.status != CCI_SUCCESS) {
				fprintf(stderr, "RMA failed with %s.\n",
					cci_strerror(endpoint, event->send.status));
				cci_disconnect(test);
				test = NULL;
				done = 1;
			}
			if (is_server)
				break;
			/* Client */
			if (event->send.context == (void *)0xdeadbeef) {
				done = 1;
				break;
			}
			break;
		case CCI_EVENT_RECV:
			if (is_client) {
				hdr_t *h = (void*)event->recv.ptr;

				if (!ready) {
					ready = 1;
					memcpy((void*)&remote_rma_handle,
						&h->reply.handle,
						sizeof(remote_rma_handle));
				} else {
					int i = h->status.thread;

					/* RMA status msg */
					if (opts.method == RMA_WRITE) {
						hdr_t *m = &msg[i];

						if (h->status.crc != m->check.crc) {
							fprintf(stderr, "Server reported "
								"CRC failed.\n"
								"Local CRC 0x%x != "
								"remote CRC 0x%x.\n"
								"count=%d current_size=%u\n",
								m->check.crc, h->status.crc,
								count, current_size);
						}
					} else { /* RMA_READ */
						uint32_t crc = 0;
						void *ptr = (void*)((uintptr_t)buffer +
							(h->status.thread * length) +
							local_offset);

						/* Compute the CRC only on a valid buffer */
						if (current_size + local_offset <= opts.reg_len)
							crc = crc32(0, ptr, current_size);
						else
							crc = 0;
						if (crc != h->status.crc) {
							fprintf(stderr, "Server reported "
								"CRC failed.\n"
								"Local CRC 0x%x != "
								"remote CRC 0x%x.\n"
								"count=%d current_size=%u\n",
								crc, h->status.crc,
								count, current_size);
						}
					}
					/* RMA completed */
					count++;
					tcount[i]++;
					if (tcount[i] < iters) {
						sem_t *s = &sem[i];
						sem_post(s);
					}
				}
			} else { /* is_server */
				hdr_t *h = (void*)event->recv.ptr;

				if (event->recv.len == 3) {
					done = 1;
				} else {
					uint32_t crc = 0;
					void *ptr = (void*)((uintptr_t)buffer +
							(h->check.thread * opts.length) +
							h->check.offset);
					hdr_t m;

					/* RMA check request */
					if ((h->check.len + h->check.offset) <= opts.reg_len)
						crc = crc32(0, ptr, h->check.len);
					else
						crc = 0;
					m.status.type = MSG_RMA_STATUS;
					m.status.crc = crc;
					m.status.thread = h->check.thread;
					if (opts.method == RMA_WRITE) {
						if (crc != h->check.crc || verbose) {
						fprintf(stderr, "server: client %d crc=0x%08x "
							"server crc=0x%08x %s\n",
							h->check.thread,
							h->check.crc,
							crc, crc == h->check.crc ?
							"(ok)" : "(FAIL)");
						}
					}
					print_buffer(0, ptr, h->check.len);
					ret = cci_send(test, &m, sizeof(m.status),
							NULL, CCI_FLAG_SILENT);
					check_return(endpoint, "cci_send", ret, 1);
				}
			}
			break;
		case CCI_EVENT_CONNECT:
			if (event->connect.status != CCI_SUCCESS)
			{
				fprintf(stderr, "Connection rejected.\n");
				exit(0);
			}
			if ((uintptr_t)event->connect.context == (uintptr_t)CONTROL) {
				control = event->connect.connection;
			} else {
				test = event->connect.connection;
			}
			if (control && test)
				connect_done = 1;
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			fprintf(stderr, "Peer is reconnecting? Rejecting.\n");
			cci_reject(event);
			break;
		default:
			fprintf(stderr, "ignoring event type %s\n",
				cci_event_type_str(event->type));
		}
		cci_return_event(event);
	}
	return;
}

static void *rma_thread(void *arg)
{
	int i = (int)((uintptr_t)arg), ret = 0;
	sem_t *s = &sem[i];
	hdr_t *m = &msg[i];
	uint32_t *mlen = &msg_len[i];
	uint64_t loffset = local_offset + (length * i);
	uint64_t roffset = remote_offset + (length * i);


	while (running) {
		sem_wait(s);

		if (!running)
			break;

		ret = cci_rma(test, m, *mlen,
			      local_rma_handle, loffset,
			      &remote_rma_handle, roffset,
			      current_size, (void*)((uintptr_t)i), opts.flags);
		check_return(endpoint, "cci_rma", ret, 1);
	}

	pthread_exit(NULL);
}

static void do_client(void)
{
	int ret, i = 0;
	uint32_t min = 1;

	/* initiate connect */
	msg[0].request.type = MSG_CONTROL;

	ret =
	    cci_connect(endpoint, server_uri, msg, sizeof(msg[0].generic), attr,
			(void*)(uintptr_t)CONTROL, 0, NULL);
	check_return(endpoint, "cci_connect", ret, 1);

	msg[0].request.type = MSG_CONN_REQ;
	msg[0].request.opts = opts;

	ret =
	    cci_connect(endpoint, server_uri, msg, sizeof(msg[0].request), attr,
			(void*)(uintptr_t)TEST, 0, NULL);
	check_return(endpoint, "cci_connect", ret, 1);
	/* poll for connect completion */
	while (!connect_done)
		poll_events();

	if (!test) {
		fprintf(stderr, "no connection\n");
		return;
	}

	while (!ready)
		poll_events();

	ret = posix_memalign((void **)&buffer, 4096, opts.reg_len * client_threads);
	check_return(endpoint, "memalign buffer", ret, 1);

	memset(buffer, 0xaa, opts.reg_len * client_threads);

	init_buffer(1);
	print_buffer(0, buffer, (int) opts.reg_len);

	/* for the client, we do not need remote access flags */

	ret = cci_rma_register(endpoint, buffer, opts.reg_len * client_threads,
			0, &local_rma_handle);
	check_return(endpoint, "cci_rma_register", ret, 1);

	if (opts.method == RMA_WRITE)
		opts.flags = CCI_FLAG_WRITE;
	else
		opts.flags = CCI_FLAG_READ;

	/* spawn RMA threads */
	for (i = 0; i < client_threads; i++) {
		ret = pthread_create(&tid[i], NULL, &rma_thread,
				(void*)((uintptr_t)i));
		if (ret) {
			fprintf(stderr, "failed to create thread %d with %s\n",
				i, strerror(ret));
			exit(EXIT_FAILURE);
		}
	}

	/* begin communication with server */
	for (current_size = min; current_size <= length;) {

		fprintf(stderr, "Testing length %9u ... \n", current_size);

		for (i = 0; i < client_threads; i++) {
			sem_t *s = &sem[i];
			hdr_t *m = &msg[i];
			uint32_t *mlen = &msg_len[i];
			void *ptr = (void*)((uintptr_t)buffer + local_offset +
					(i * length));


			m->check.type = MSG_RMA_CHK;
			m->check.offset = remote_offset;
			m->check.len = current_size;
			m->check.thread = i;

			if (current_size + local_offset <= opts.reg_len) {
				m->check.crc = crc32(0, ptr, current_size);
			} else {
				m->check.crc = 0;
			}
			*mlen = sizeof(m->check);
			print_buffer(i, ptr, current_size);

			sem_post(s);
		}

		while (count < (iters * client_threads))
			poll_events();

		if (test)
			fprintf(stderr, "success.\n");
		else
			goto out;

		memset(tcount, 0, sizeof(int) * client_threads);
		count = 0;
		current_size *= 2;

		if (current_size >= 64 * 1024) {
			if (iters >= 32)
				iters /= 2;
		}
	}
	running = 0;

out:
	ret = cci_send(control, "bye", 3, (void *)0xdeadbeef, 0);
	check_return(endpoint, "cci_send", ret, 0);

	while (!done)
		poll_events();

	ret = cci_rma_deregister(endpoint, local_rma_handle);
	check_return(endpoint, "cci_rma_deregister", ret, 1);

	printf("client done\n");
	sleep(1);

	return;
}

static void *server_thread(void *arg)
{
	int i = (int)((uintptr_t)arg);

	while (!done)
		poll_events();

	fprintf(stderr, "Thread %d exiting\n", i);

	pthread_exit(NULL);
}

static void do_server(void)
{
	int ret = 0, i = 0;
	hdr_t *h = NULL;

	while (!ready) {
		cci_event_t *event;

		if (blocking) {
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);

			ret = select(nfds, &rfds, NULL, NULL, NULL);
			if (!ret)
				return;
		}

		ret = cci_get_event(endpoint, &event);
		if (ret == CCI_SUCCESS) {
			switch (event->type) {
			case CCI_EVENT_CONNECT_REQUEST:
			{
				int which = 0;

				h = (void*)event->request.data_ptr;
				if (h->generic.type == MSG_CONN_REQ) {
					opts = h->request.opts;
					which = TEST;
				} else {
					which = CONTROL;
				}
				ret = cci_accept(event, (void*)((uintptr_t)which));
				check_return(endpoint, "cci_accept", ret, 1);
				break;
			}
			case CCI_EVENT_ACCEPT:
			{
				if ((uintptr_t)event->accept.context == (uintptr_t)CONTROL) {
					control = event->accept.connection;
				} else {
					uint64_t len;

					test = event->accept.connection;

					len = opts.reg_len * opts.threads;

					ret =
					    posix_memalign((void **)&buffer,
							   4096, len);
					check_return(endpoint, "memalign buffer", ret, 1);

					init_buffer(0);
					print_buffer(0, buffer, opts.reg_len);

					ret = cci_rma_register(endpoint,
							     buffer,
							     len,
							     opts.method,
							     &local_rma_handle);
					check_return(endpoint, "cci_rma_register",
							     ret, 1);
				}
				if (test && control) {
					hdr_t m;

					ready = 1;
					m.reply.type = MSG_CONN_REPLY;
					m.reply.handle = *local_rma_handle;

					ret = cci_send(test, &m,
						     sizeof(m.reply), NULL, 0);
					check_return(endpoint, "cci_send", ret, 1);
				}
				break;
			}
			default:
				fprintf(stderr,
					"%s: ignoring unexpected event %s\n",
					__func__, cci_event_type_str(event->type));
				break;
			}
			ret = cci_return_event(event);
			if (ret)
				fprintf(stderr, "cci_return_event() failed with %s\n",
						cci_strerror(endpoint, ret));
		}
	}

	/* spawn server threads */
	for (i = 1; i < server_threads; i++) {
		ret = pthread_create(&tid[i], NULL, &server_thread,
				(void*)((uintptr_t)i));
		if (ret) {
			fprintf(stderr, "failed to create thread %d with %s\n",
				i, strerror(ret));
			exit(EXIT_FAILURE);
		}
	}

	while (!done)
		poll_events();

	ret = cci_rma_deregister(endpoint, local_rma_handle);
	check_return(endpoint, "cci_rma_deregister", ret, 1);

	printf("server done\n");
	sleep(1);

	return;
}

int main(int argc, char *argv[])
{
	int ret, c;
	uint32_t caps = 0;
	cci_os_handle_t *os_handle = NULL;
	char *uri = NULL;
	pid_t pid = 0;

	pid = getpid();
	srandom(pid);

	name = argv[0];

	while ((c = getopt(argc, argv, "h:si:c:wrl:o:O:R:BIT:t:v")) != -1) {
		switch (c) {
		case 'h':
			server_uri = strdup(optarg);
			is_client = 1;
			break;
		case 's':
			is_server = 1;
			break;
		case 'i':
			iters = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			if (strncasecmp("ru", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RU;
			else if (strncasecmp("ro", optarg, 2) == 0)
				attr = CCI_CONN_ATTR_RO;
			else
				print_usage();
			printf("Using %s connection\n",
			       attr == CCI_CONN_ATTR_RU ? "RU" : "RO");
			break;
		case 'w':
			opts.method = RMA_WRITE;
			break;
		case 'r':
			opts.method = RMA_READ;
			break;
		case 'l':
			length = strtoul(optarg, NULL, 0);
			break;
		case 'R':
			opts.reg_len = strtoul(optarg, NULL, 0);
			break;
		case 'o':
			local_offset = strtoul(optarg, NULL, 0);
			break;
		case 'O':
			remote_offset = strtoul(optarg, NULL, 0);
			break;
		case 'B':
			blocking = 1;
			os_handle = &fd;
			break;
		case 'I':
			ignore_os_handle = 1;
			os_handle = &fd;
			break;
		case 'T':
			opts.threads = client_threads = strtoul(optarg, NULL, 0);
			break;
		case 't':
			server_threads = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			print_usage();
		}
	}

	if (!is_server && !server_uri) {
		fprintf(stderr, "Must select -h or -s\n");
		print_usage();
	}

	if (is_server && is_client) {
		fprintf(stderr, "Must select -h or -s, not both\n");
		print_usage();
	}

	if (blocking && ignore_os_handle) {
		fprintf(stderr, "-B and -I are not compatible.\n");
		fprintf(stderr, "-B will block using select() using the OS handle.\n");
		fprintf(stderr, "-I will obtain the OS handle, but not use it to wait.\n");
		print_usage();
	}

	if (!opts.threads)
		opts.threads = 1;

	if (!opts.method)
		opts.method = RMA_WRITE;

	if (!opts.reg_len) {
		if (!length) {
			opts.reg_len = RMA_REG_LEN;
		} else {
			opts.reg_len = length;
		}
	}

	if (!length) {
		if (!opts.reg_len)
			length = RMA_REG_LEN;
		else
			length = opts.reg_len;
	}
	opts.length = length;

	if (opts.reg_len == length) {
		if (local_offset || remote_offset) {
			fprintf(stderr, "*** RMA registration length == RMA length "
					"and an offset was requested. ***\n"
					"*** This should cause an error. ***\n");
		}
	}

	/* Default is one which allows the server to have one as well */
	msg = calloc(client_threads, sizeof(*msg));
	if (!msg) {
		fprintf(stderr, "no memory for msgs\n");
		exit(EXIT_FAILURE);
	}

	msg_len = calloc(client_threads, sizeof(*msg_len));
	if (!msg_len) {
		fprintf(stderr, "no memory for msg lens\n");
		exit(EXIT_FAILURE);
	}

	if (is_client) {
		int i = 0;

		tcount = calloc(client_threads, sizeof(*tcount));
		if (!tcount) {
			fprintf(stderr, "Unable to alloc memory for thread counts\n");
			exit(EXIT_FAILURE);
		}

		tid = calloc(client_threads, sizeof(*tid));
		if (!tid) {
			fprintf(stderr, "Unable to alloc memory for thread ids\n");
			exit(EXIT_FAILURE);
		}

		sem = calloc(client_threads, sizeof(*sem));
		if (!sem) {
			fprintf(stderr, "Unable to alloc memory for semaphores\n");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < client_threads; i++) {
			ret = sem_init(&sem[i], 0, 0);
			if (ret) {
				fprintf(stderr, "sem_init(%d) failed with %s\n",
					i, strerror(errno));
			}
		}

		fprintf(stderr, "Testing with local_offset %"PRIu64" "
				"remote_offset %"PRIu64" "
				"reg_len %"PRIu64" length %"PRIu64"\n",
				local_offset, remote_offset, opts.reg_len, length);
	} else { /* is server */
		tid = calloc(server_threads, sizeof(*tid));
		if (!tid) {
			fprintf(stderr, "Unable to alloc memory for thread ids\n");
			exit(EXIT_FAILURE);
		}
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
	free(buffer);
	free(uri);
	free(server_uri);

	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "cci_finalize() failed with %s\n",
			cci_strerror(NULL, ret));
		exit(EXIT_FAILURE);
	}

	return 0;
}
