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

#include "cci.h"

#define DFLT_PORT   54321
#define ITERS       100000
#define WARMUP      100
#define MIN_BUFSIZE (1024)
#define MAX_BUFSIZE (4 * 1024 * 1024)

/* Globals */
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int warmup = 0;
int count = 0;
char *name;
char *server_uri;
char *buffer;
uint32_t port = DFLT_PORT;
uint32_t current_size = 0;
cci_device_t **devices = NULL;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_RU;
uint64_t rma_handle = 0ULL;
uint64_t local_handle = 0ULL;
uint64_t local_offset = 0ULL;
uint64_t remote_handle = 0ULL;
uint64_t remote_offset = 0ULL;
uint32_t min_size = MIN_BUFSIZE;
uint32_t max_size = MAX_BUFSIZE;

void
print_usage()
{
    fprintf(stderr, "usage: %s -h <server_uri> [-p <port>] [-s] [-c <type>]\n", name);
    fprintf(stderr, "where:\n");
    fprintf(stderr, "\t-h\tServer's URI\n");
    fprintf(stderr, "\t-p\tPort of the server's connection service (default %d)\n", DFLT_PORT);
    fprintf(stderr, "\t-s\tSet to run as the server\n");
    fprintf(stderr, "\t-c\tConnection type (RU or RO) set by client only\n");
    fprintf(stderr, "\t-z\tStarting RMA size\n");
    fprintf(stderr, "\t-Z\tEnding RMA size\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "server$ %s -h ip://foo -p 2211 -s\n", name);
    fprintf(stderr, "client$ %s -h ip://foo -p 2211\n", name);
    exit(EXIT_FAILURE);
}

static void
poll_events(void)
{
    int ret;
    cci_event_t *event;

again:
    ret = cci_get_event(endpoint, &event, 0);
    if (ret == CCI_SUCCESS) {
        assert(event);
        switch (event->type) {
        case CCI_EVENT_SEND:
            if (!is_server) {
                if ((uint32_t)(uintptr_t)event->info.send.context == current_size) {
                    if (event->info.send.status == CCI_SUCCESS)
                        count++;
                    else
                        fprintf(stderr, "rma of size %d failed with %s",
                                (uint32_t)(uintptr_t)event->info.send.context,
                                cci_strerror(event->info.send.status));
                }
                do {
                    ret = cci_rma(connection, NULL, 0,
                                  local_handle, local_offset,
                                  remote_handle, remote_offset,
                                  current_size,
                                  (void*)(uintptr_t)current_size, CCI_FLAG_WRITE);
                } while (ret != 0);
            }
            break;
        case CCI_EVENT_RECV:
        {
            if (is_server) {
                if (event->info.recv.header_len == 3) {
                    done = 1;
                    return;
                }
                fprintf(stderr, "unknown recv\n");
            } else {
                remote_handle = *((uint64_t*)event->info.recv.header_ptr);
                ready = 1;
            }
            break;
        }
        case CCI_EVENT_CONNECT_SUCCESS:
            if (!is_server) {
                connect_done = 1;
                connection = event->info.other.u.connect.connection;
            }
            break;
        case CCI_EVENT_CONNECT_TIMEOUT:
        case CCI_EVENT_CONNECT_REJECTED:
            if (!is_server) {
                connect_done = 1;
                connection = NULL;
            }
            break;
        default:
            fprintf(stderr, "ignoring event type %d\n", event->type);
        }
        cci_return_event(endpoint, event);
        goto again;
    }
    return;
}

double
usecs(struct timeval start, struct timeval end)
{
    return ((double) (end.tv_sec  - start.tv_sec)) * 1000000.0 +
           ((double) (end.tv_usec - start.tv_usec));
}

void
do_client()
{
    int ret;
    struct timeval start, end;

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, port, NULL, 0, attr, NULL, 0, NULL);
    if (ret) {
        fprintf(stderr, "cci_connect() returned %d\n", ret);
        return;
    }

	/* poll for connect completion */
	while (!connect_done)
        poll_events();

    if (!connection) {
        fprintf(stderr, "no connection\n");
        return;
    }

    while (!ready)
        poll_events();

    local_handle = rma_handle;

    printf("Bytes\t\tLatency (one-way)\tThroughput\n");

	/* begin communication with server */
    for (current_size = min_size;
         current_size <= max_size;
         current_size *= 2) {

        warmup = 0;
        count = 0;

        do {
            ret = cci_rma(connection, NULL, 0,
                          local_handle, local_offset,
                          remote_handle, remote_offset,
                          current_size,
                          (void*)(uintptr_t)current_size, CCI_FLAG_WRITE);
        } while (ret != 0);

        while (count < WARMUP)
            poll_events();

        gettimeofday(&start, NULL);

        while (count < ITERS)
            poll_events();

        gettimeofday(&end, NULL);

        printf("%7d\t\t%9.2lf us\t\t%8.2lf Mb/s\n",
               current_size, usecs(start, end) / (double) ITERS,
               (double) ITERS * (double) current_size * 8.0 / usecs(start, end));
    }
    cci_send(connection, "bye", 3, NULL, 0, NULL, 0);

    return;
}

void
do_server()
{
    int ret, accept = 0;
    cci_os_handle_t bind_fd;
    cci_service_t *service = NULL;

    /* we don't associate the endpoint with the service? */
    ret = cci_bind(devices[0], 10, &port, &service, &bind_fd);
    if (ret) {
        fprintf(stderr, "cci_bind() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    while (!accept) {
        cci_conn_req_t *conn_req;

        ret = cci_get_conn_req(service, &conn_req);
        if (ret == 0 && conn_req) {
            accept = 1;
            ready = 1;
            cci_accept(conn_req, endpoint, &connection);

            cci_send(connection, (void*)&rma_handle, sizeof(rma_handle), NULL, 0, NULL, 0);
        }
    }

    while (!done)
        poll_events();

    /* clean up */
    cci_unbind(service, NULL);
    return;
}

int main(int argc, char *argv[])
{
    int ret, c, tmp;
    uint32_t caps = 0;
    cci_os_handle_t ep_fd;

    name = argv[0];

    while ((c = getopt(argc, argv, "h:p:sc:z:Z:")) != -1) {
        switch (c) {
        case 'h':
            server_uri = strdup(optarg);
            break;
        case 'p':
            port = strtoul(optarg, NULL, 0);
            break;
        case 's':
            is_server = 1;
            break;
        case 'c':
            if (strncasecmp("ru", optarg, 2) == 0)
                attr = CCI_CONN_ATTR_RU;
            else if (strncasecmp("ro", optarg, 2) == 0)
                attr = CCI_CONN_ATTR_RO;
            else
                print_usage();
            printf("Using %s connection\n",
                   attr == CCI_CONN_ATTR_UU ? "UU" : attr == CCI_CONN_ATTR_RU ? "RU" : "RO");
            break;
        case 'z':
            tmp = strtoul(optarg, NULL, 0);
            if (tmp >= MIN_BUFSIZE && tmp <= MAX_BUFSIZE && tmp <= max_size)
                min_size = tmp;
            break;
        case 'Z':
            tmp = strtoul(optarg, NULL, 0);
            if (tmp >= MIN_BUFSIZE && tmp <= MAX_BUFSIZE && tmp >= min_size)
                max_size = tmp;
            break;
        default:
            print_usage();
        }
    }

    ret = cci_init(CCI_ABI_VERSION, 0, &caps);
    if (ret) {
        fprintf(stderr, "cci_init() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    ret = cci_get_devices((cci_device_t const *** const) &devices);
    if (ret) {
        fprintf(stderr, "cci_get_devices() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* create an endpoint? */
    ret = cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);
    if (ret) {
        fprintf(stderr, "cci_create_endpoint() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    buffer = calloc(1, MAX_BUFSIZE);
    if (!buffer) {
        fprintf(stderr, "calloc() failed with %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = cci_rma_register(endpoint, NULL, buffer, MAX_BUFSIZE, &rma_handle);
    if (ret) {
        fprintf(stderr, "cci_rma_register() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    if (is_server)
        do_server();
    else
        do_client();

    ret = cci_rma_deregister(rma_handle);
    if (ret) {
        fprintf(stderr, "cci_deregister() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* clean up*/
    ret = cci_destroy_endpoint(endpoint);
    if (ret) {
        fprintf(stderr, "cci_destroy_endpoint() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }
    if (buffer)
        free(buffer);
    ret = cci_free_devices((cci_device_t const **) devices);
    if (ret) {
        fprintf(stderr, "cci_free_devices() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    free(server_uri);

    return 0;
}
