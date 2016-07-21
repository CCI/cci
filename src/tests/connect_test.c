/*
 * Copyright (c) 2016 UT-Battelle, LLC.  All rights reserved.
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
#include <bsd/queue.h>
#include <pthread.h>

#include "cci.h"

#define NUM_EPS		(1)
#define NUM_EP_THREADS	(1)
#define NUM_EP_CONNS	(8)
#define CONN_MAX	(10000)

char *name;			/* argv[0] */

cci_device_t **devices = NULL;
int blocking = 0;
int nfds = 0;
fd_set rfds;
int attempts = 0;

/* The client sends the CCI RMA handle for its test->control->buffer */
typedef enum msg_type {
	SERVER_INFO	= 0,	/* client <- server */
	SEND,
	RMA_DONE,
	SHUTDOWN
} msg_type_t;

/* Must be four-byte aligned */
typedef struct server_info {
	cci_rma_handle_t handle;	/* server's RMA handle */
	uint32_t len;			/* length of endpoint URI */
	char uri[1];			/* start of URI */
} info_t;

typedef union msg {
	struct msg_generic {
		uint32_t type	:  4;	/* msg_type */
		uint32_t pad	: 28;
	} generic;

	struct msg_server_info {
		uint32_t type	:  4;	/* SERVER_INFO */
		uint32_t count	:  8;	/* number of server infos */
		uint32_t pad	: 20;
	} info;

	struct msg_shutdown {
		uint32_t type	:  4;	/* SHUTDOWN */
		uint32_t pad	: 28;
	} shutdown;
} msg_t;

typedef struct conn conn_t;
typedef struct thread thread_t;
typedef struct ep ep_t;
typedef struct server server_t;
typedef struct test test_t;

struct conn {
	cci_connection_t *c;
	char *server_uri;
	TAILQ_ENTRY(conn) entry;	/* hang on ep->conns */
	cci_conn_attribute_t attr;
	int pattern;
	int number;
};

struct thread {
	ep_t *ep;			/* owning endpoint */
	TAILQ_ENTRY(thread) entry;	/* hang on ep->threads */
	pthread_t tid;
	int id;
	int conns_open;
	int conns_closed;
};

struct ep {
	test_t *test;
	cci_endpoint_t *e;
	TAILQ_HEAD(t, thread) threads;	/* running threads */
	TAILQ_HEAD(c, conn) conns;	/* test connections */
	TAILQ_ENTRY(ep) entry;		/* hang on test->eps */
	pthread_mutex_t lock;		/* threads, conns, conns_open, conns_closed */
	void *buffer;			/* RMA buffer */
	cci_rma_handle_t *handle;
	char *uri;
	int id;
	int conns_open;		/* aggregate of all threads */
	int conns_closed;	/* aggregate of all threads */
	int fd;
};

struct server {
	cci_rma_handle_t *handle;
	char *uri;		/* server's CCI endpoint URI */
};

struct test {
	TAILQ_HEAD(e, ep) eps;		/* open CCI endpoints */
	server_t *servers;		/* array of server endpoints */
	pthread_mutex_t lock;		/* eps, next_conn */
	ep_t *control;			/* control endpoint - not used for tests */
	int num_eps;			/* open this many endpoints */
	int num_ep_threads;		/* use this many threads per endpoint */
	int num_ep_conns;		/* open conns per endpoint */
	int next_conn;			/* incremental conn IDs */
	int num_servers;		/* number of servers in array */
	int conn_max;		/* End test after this many connections... */
	int secs;		/*     or this many seconds                */
	int blocking;
#define ROLE_SERVER	(1)
#define ROLE_CLIENT	(2)
	int role;
	int ready;
	int done;
};


static void print_usage(void)
{
	fprintf(stderr, "usage: %s "
			"[-e <num_endpoints>] "
			"[-t <threads_per_enpoint>] "
			"[-c <open_conns_per_endpoint>] "
			"[-h <server_uri> | -s] "
			"[-S <service>] "
			"[-n <num_conns> | -T <secs>] "
			"[-b]\n", name);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-e\tOpen this number of CCI endpoints (default %d)\n", NUM_EPS);
	fprintf(stderr, "\t-t\tThreads per CCI endpoint (default %d)\n", NUM_EP_THREADS);
	fprintf(stderr, "\t-c\tNumber of open connections per endpoint "
			"(client only) (default %d)\n", NUM_EP_CONNS);
	fprintf(stderr, "\t-h\tRun as client and connect to server at this URI\n");
	fprintf(stderr, "\t-s\tRun as the server\n");
	fprintf(stderr, "\t-S\tSpecify a service hint for the control endpoint()\n\n");
	fprintf(stderr, "\t-n\tTest this number of connections (default %d)\n", CONN_MAX);
	fprintf(stderr, "\t-T\tRun for this number of seconds\n");
	fprintf(stderr, "\t-b\tBlock using the OS handle instead of polling\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "server$ %s -s -S 5000 -e 2 -t 8\n", name);
	fprintf(stderr, "client$ %s -h tcp://host:5000 -e 1 -t 4 -c 20\n", name);
	exit(EXIT_FAILURE);
}

static void check_return(test_t *test, char *func, int ret, int need_exit)
{
	conn_t *conn = TAILQ_FIRST(&test->control->conns);

	if (ret) {
		fprintf(stderr, "%s() returned %s\n", func,
				cci_strerror(test->control->e, ret));
		if (need_exit) {
			cci_send(conn->c, "bye", 3, (void *)0xdeadbeef, CCI_FLAG_BLOCKING);
			cci_finalize();
			exit(EXIT_FAILURE);
		}
	}
	return;
}

static void
do_client(test_t *test)
{
	int ret = 0, try = 0, i = 0, done = 0;
	conn_t *conn = TAILQ_FIRST(&test->control->conns);
	cci_event_t *event = NULL;
	msg_t *msg = NULL;
	uintptr_t offset = 0;

	/* connect to server */
	do {
		ret = cci_connect(test->control->e, conn->server_uri,
				(void*)test->control->handle,
				sizeof(*test->control->handle),
				CCI_CONN_ATTR_RO, NULL, 0, NULL);
		if (ret) {
			fprintf(stderr, "cci_connect() failed with %s\n",
					cci_strerror(test->control->e, ret));
			continue;
		}

		do {
			ret = cci_get_event(test->control->e, &event);
		} while (ret);

		assert(event->type == CCI_EVENT_CONNECT);

		conn->c = event->connect.connection;

		if (event->connect.status)
			fprintf(stderr, "CONNECT event status is %d\n",
					event->connect.status);

		cci_return_event(event);

		if (!conn->c)
			sleep(1);

	} while (!conn->c && try++ < 60);

	if (!conn->c)
		return;

	/* wait for server's endpoint info */
	do {
		cci_get_event(test->control->e, &event);
	} while (!event);

	assert(event->type == CCI_EVENT_RECV);

	msg = (void*) event->recv.ptr;
	assert(msg->info.type == SERVER_INFO);

	/* store server info */
	test->num_servers = msg->info.count;

	test->servers = calloc(test->num_servers, sizeof(*test->servers));
	if (!test->servers) {
		fprintf(stderr, "%s: calloc(test->servers) failed\n", __func__);
		goto out;
	}

	offset = (uintptr_t)test->control->buffer;

	for (i = 0; i < test->num_servers; i++) {
		info_t *info = NULL;
		server_t *server = NULL;

		server = &test->servers[i];
		server->handle = calloc(1, sizeof(*server->handle));
		if (!server->handle) {
			fprintf(stderr, "%s: calloc(server->handle[%d]) failed\n",
					__func__, i);
			break;
		}

		info = (void*)offset;

		memcpy(&server->handle, &info->handle, sizeof(*server->handle));

		server->uri = calloc(1, info->len + 1);
		if (!server->uri) {
			fprintf(stderr, "%s: calloc(server->uri[%d]) failed\n",
					__func__, i);
			break;
		}
		memcpy(server->uri, info->uri, info->len);

		offset = (uintptr_t)&info->uri; /* move to the start of the URI */
		offset += info->len; /* move to the end of the URI */
		if (offset % 8) {
			/* if not 8-byte aligned, align it */
			offset += (8 - (offset % 8));
			assert((offset % 8) == 0);
		}
	}

	cci_return_event(event);

	/* we are ready to go */

	pthread_mutex_lock(&test->lock);
	test->ready = 1;
	pthread_mutex_unlock(&test->lock);

	do {
		int shutdown = 0;

		sleep(1);

		ret = cci_get_event(test->control->e, &event);
		if (!ret) {
			msg_t *msg = NULL;

			assert(event->type == CCI_EVENT_RECV);

			msg = (void*)event->recv.ptr;
			assert(msg->shutdown.type == SHUTDOWN);

			cci_return_event(event);

			shutdown = 1;
			done++;
		}

		pthread_mutex_lock(&test->lock);
		if (test->done)
			done++;

		if (shutdown)
			test->done = 1;
		pthread_mutex_unlock(&test->lock);

		if (!shutdown) {
			msg_t shutdown;

			shutdown.shutdown.type = SHUTDOWN;

			ret = cci_send(conn->c, &shutdown, sizeof(shutdown),
					(void*)0x987654321, 0);
			check_return(test, "cci_send(shutdown)", ret, 1);

			while (1) {
				ret = cci_get_event(test->control->e, &event);
				if (ret) continue;

				if (event->type == CCI_EVENT_SEND) {
					if (event->send.context == (void*)0x987654321)
						break;
				}

				cci_return_event(event);
			}
		}
	} while (!done);

    out:
	cci_disconnect(conn->c);

	return;
}

static void *
server_thread(void *arg)
{
	pthread_exit(NULL);
}

static void
do_server(test_t *test)
{
	int ret = 0, len = 0, done = 0;
	ep_t *ep = NULL;
	conn_t *conn = TAILQ_FIRST(&test->control->conns);
	cci_event_t *event = NULL;
	msg_t msg;
	uintptr_t offset = 0;
	info_t *info = NULL;
	cci_rma_handle_t client_handle;

	/* wait for client to connect */
	do {
		ret = cci_get_event(test->control->e, &event);
	} while (ret);

	assert(event->type == CCI_EVENT_CONNECT_REQUEST);

	memcpy((void*)&client_handle, event->request.data_ptr, event->request.data_len);

	ret = cci_accept(event, NULL);
	if (ret) {
		fprintf(stderr, "%s: cci_accept() failed with %s\n",
				__func__, cci_strerror(test->control->e, ret));
		goto out;
	}

	ret = cci_return_event(event);
	if (ret) {
		fprintf(stderr, "%s: cci_return_event() failed with %s\n",
				__func__, cci_strerror(test->control->e, ret));
		goto out;
	}

	/* wait for the accept event */
	do {
		cci_get_event(test->control->e, &event);
	} while (!event);

	assert(event->type == CCI_EVENT_ACCEPT);

	conn->c = event->accept.connection;

	if (event->accept.status)
		fprintf(stderr, "%s: ACCEPT failed with %s\n",
				__func__, cci_strerror(test->control->e,
					event->accept.status));

	assert(conn->c);

	/* send endpoint info */

	TAILQ_FOREACH(ep, &test->eps, entry) {
		len += sizeof(*info) + strlen(ep->uri) + 1;
		if (len % 8)
			len += (8 - (len % 8));
	}

	msg.info.type = SERVER_INFO;
	msg.info.count = test->num_eps;

	offset = (uintptr_t)test->control->buffer;

	TAILQ_FOREACH(ep, &test->eps, entry) {
		info = (void*)offset;

		memcpy((void*)&info->handle, ep->handle, sizeof(info->handle));
		info->len = strlen(ep->uri);
		memcpy(info->uri, ep->uri, info->len);

		/* ensure the offset is 8-byte aligned */
		offset = (uintptr_t)&info->uri; /* move to the start of the URI */
		offset += info->len; /* move to the end of the URI */
		if (offset % 8) {
			/* if not 8-byte aligned, align it */
			offset += (8 - (offset % 8));
			assert((offset % 8) == 0);
		}
	}

	ret = cci_rma(conn->c, &msg, sizeof(msg),
			test->control->handle, 0,
			&client_handle, 0,
			(uint64_t)(offset - (uintptr_t)test->control->buffer),
			NULL, CCI_FLAG_WRITE);
	check_return(test, "cci_rma", ret, 1);

	do {
		cci_get_event(test->control->e, &event);
	} while (!event);

	assert(event->type == CCI_EVENT_SEND);

	ret = cci_return_event(event);
	check_return(test, "cci_return_event(rma)", ret, 1);

	do {
		int shutdown = 0;

		sleep(1);

		ret = cci_get_event(test->control->e, &event);
		if (!ret) {
			msg_t *msg = NULL;

			assert(event->type == CCI_EVENT_RECV);

			msg = (void*)event->recv.ptr;
			assert(msg->shutdown.type == SHUTDOWN);

			cci_return_event(event);

			shutdown = 1;
			done++;
		}

		pthread_mutex_lock(&test->lock);
		if (test->done)
			done++;

		if (shutdown)
			test->done = 1;
		pthread_mutex_unlock(&test->lock);

		if (!shutdown) {
			msg_t shutdown;

			shutdown.shutdown.type = SHUTDOWN;

			ret = cci_send(conn->c, &shutdown, sizeof(shutdown),
					(void*)0x987654321, 0);
			check_return(test, "cci_send(shutdown)", ret, 1);

			while (1) {
				ret = cci_get_event(test->control->e, &event);
				if (ret) continue;

				if (event->type == CCI_EVENT_SEND) {
					if (event->send.context == (void*)0x987654321)
						break;
				}

				cci_return_event(event);
			}
		}
	} while (!done);

    out:
	pthread_mutex_lock(&test->lock);
	test->done = 1;
	pthread_mutex_unlock(&test->lock);

	return;
}

static void *
client_thread(void *arg)
{
	pthread_exit(NULL);
}

static int
create_threads(test_t *test, ep_t *ep)
{
	int ret = 0, i = 0;
	void *(*func)(void*) = test->role == ROLE_SERVER ? server_thread : client_thread;

	for (i = 0; i < test->num_ep_threads; i++) {
		thread_t *thread = NULL;

		thread = calloc(1, sizeof(*thread));
		if (!thread) {
			ret = ENOMEM;
			goto out;
		}

		thread->ep = ep;
		thread->id = i;
		TAILQ_INSERT_TAIL(&ep->threads, thread, entry);
		ret = pthread_create(&thread->tid, NULL, func, (void*)thread);
		if (ret) {
			fprintf(stderr, "%s: pthread_create(%d) failed with %s\n",
					__func__, i, strerror(ret));
			goto out;
		}
	}

    out:
	return ret;
}

static int
create_endpoints(test_t *test)
{
	int ret = 0, i = 0;

	for (i = 0; i < test->num_eps; i++) {
		ep_t *ep = NULL;
		cci_os_handle_t *fd = NULL;

		if (test->blocking)
			fd = &ep->fd;

		ep = calloc(1, sizeof(*ep));
		if (!ep) {
			fprintf(stderr, "%s: calloc(ep%d) failed\n", __func__, i);
			ret = ENOMEM;
			goto out;
		}

		ep->test = test;

		ret = cci_create_endpoint(NULL, 0, &ep->e, fd);
		if (ret) {
			fprintf(stderr, "%s: cci_create_endpoint(%d) failed with %s (%d)\n",
				__func__, i, cci_strerror(NULL, ret), ret);
			goto out;
		}

		TAILQ_INIT(&ep->threads);
		TAILQ_INIT(&ep->conns);
		ret = pthread_mutex_init(&ep->lock, NULL);
		if (ret) {
			fprintf(stderr, "%s: calloc(ep%d) failed with %s\n",
					__func__, i, strerror(ret));
			goto out;
		}

		ep->buffer = malloc(1024*1024);
		if (!ep->buffer) {
			fprintf(stderr, "%s: malloc(ep%d) failed\n", __func__, i);
			ret = ENOMEM;
			goto out;
		}

		ret = cci_rma_register(ep->e, ep->buffer, 1024*1024,
				CCI_FLAG_READ|CCI_FLAG_WRITE, &ep->handle);
		if (ret) {
			fprintf(stderr, "%s: cci_rma_register(%d) failed with %s (%d)\n",
				__func__, i, cci_strerror(ep->e, ret), ret);
			goto out;
		}
		ret = cci_get_opt(ep->e, CCI_OPT_ENDPT_URI, &ep->uri);
		if (ret) {
			fprintf(stderr, "%s: cci_get_opt(%d) failed with %s\n",
					__func__, i, cci_strerror(ep->e, ret));
			goto out;
		}
		ep->id = i;

		TAILQ_INSERT_TAIL(&test->eps, ep, entry);

		ret = create_threads(test, ep);
		if (ret) goto out;
	}

    out:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret, c, is_server = 0;
	uint32_t caps = 0;
	char *service = NULL;
	cci_os_handle_t *os_handle = NULL;
	test_t *test = NULL;
	conn_t *conn = NULL;

	name = argv[0];

	test = calloc(1, sizeof(*test));
	if (!test) {
		fprintf(stderr, "calloc(test) failed\n");
		exit(EXIT_FAILURE);
	}
	TAILQ_INIT(&test->eps);
	ret = pthread_mutex_init(&test->lock, NULL);
	if (ret) {
		fprintf(stderr, "pthread_mutex_init(test->lock) failed with %s\n",
				strerror(ret));
		goto out_w_test;
	}
	test->num_eps = NUM_EPS;
	test->num_ep_threads = NUM_EP_THREADS;
	test->num_ep_conns = NUM_EP_CONNS;
	test->conn_max = CONN_MAX;
	test->secs = 0;

	test->control = calloc(1, sizeof(*test->control));
	if (!test->control) {
		fprintf(stderr, "calloc(test->control) failed\n");
		goto out_w_test;
	}
	test->control->test = test;
	TAILQ_INIT(&test->control->threads);
	TAILQ_INIT(&test->control->conns);
	ret = pthread_mutex_init(&test->control->lock, NULL);
	if (ret) {
		fprintf(stderr, "pthread_mutex_init(test->control->lock) failed with %s\n",
				strerror(ret));
		goto out_w_control;
	}
	test->control->buffer = calloc(1, 1024*1024);
	if (!test->control->buffer) {
		fprintf(stderr, "calloc(control->buffer) failed\n");
		goto out_w_control;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		fprintf(stderr, "calloc(conn) failed\n");
		goto out_w_buffer;
	}
	TAILQ_INSERT_TAIL(&test->control->conns, conn, entry);

	while ((c = getopt(argc, argv, "e:t:c:h:sS:n:T:b")) != -1) {
		switch (c) {
		case 'e':
			test->num_eps = strtol(optarg, NULL, 0);
			/* the msg->info.count uses 8 bits */
			assert(test->num_eps < 256);
			break;
		case 't':
			test->num_ep_threads = strtol(optarg, NULL, 0);
			break;
		case 'c':
			test->num_ep_conns = strtol(optarg, NULL, 0);
			break;
		case 'h':
			test->role = ROLE_CLIENT;
			conn->server_uri = strdup(optarg);
			break;
		case 's':
			test->role = ROLE_SERVER;
			is_server = 1;
			break;
		case 'S':
			service = strdup(optarg);
			if (!service)
				fprintf(stderr, "strdup(service) failed.\n");
			break;
		case 'n':
			test->conn_max = strtoul(optarg, NULL, 0);
			break;
		case 'T':
			test->secs = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			test->blocking = 1;
			os_handle = &test->control->fd;
			break;
		default:
			print_usage();
		}
	}

	if (!is_server && !conn->server_uri) {
		fprintf(stderr, "Must select -h or -s\n");
		print_usage();
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(NULL, ret));
		goto out_w_conn;
	}

	/* create an endpoint */
	if (service) {
		cci_device_t * const * devices = NULL;
		ret = cci_get_devices(&devices);
		if (ret != CCI_SUCCESS) {
			fprintf(stderr, "%s: cci_get_devices() failed with %s\n,",
				__func__, cci_strerror(NULL, ret));
		}

		ret = cci_create_endpoint_at(devices[0], service, 0, &test->control->e, os_handle);
	} else {
		ret = cci_create_endpoint(NULL, 0, &test->control->e, os_handle);
	}
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s (%d)\n",
			cci_strerror(NULL, ret), ret);
		goto out_w_cci;
	}

	ret = cci_rma_register(test->control->e, test->control->buffer, 1024*1024,
			CCI_FLAG_WRITE, &test->control->handle);
	check_return(test, "cci_rma_register(control->buffer)", ret, 1);

	ret = cci_get_opt(test->control->e, CCI_OPT_ENDPT_URI, &test->control->uri);
	check_return(test, "cci_get_opt", ret, 1);

	fprintf(stderr, "Opened %s\n", test->control->uri);

	ret = create_endpoints(test);
	if (ret) goto out_w_ep;

	if (is_server)
		do_server(test);
	else
		do_client(test);

    out_w_ep:
	free(test->control->uri);
	ret = cci_destroy_endpoint(test->control->e);
	if (ret)
		fprintf(stderr, "cci_destroy_endpoint() failed with %s\n",
			cci_strerror(NULL, ret));

    out_w_cci:
	ret = cci_finalize();
	if (ret)
		fprintf(stderr, "cci_finalize() failed with %s\n",
			cci_strerror(NULL, ret));

    out_w_conn:
	free(conn);

    out_w_buffer:
	free(test->control->buffer);

    out_w_control:
	free(service);
	free(test->control);

    out_w_test:
	free(test);

	return 0;
}
