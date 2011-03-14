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
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>

#include "cci.h"

#define DFLT_PORT   54321
#define ITERS       100000
#define WARMUP      1000

/* Globals */
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int send = 0, recv = 0;
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

void
print_usage()
{
    fprintf(stderr, "usage: %s -h <server_uri> [-p <port>] [-s]\n", name);
    fprintf(stderr, "where:\n");
    fprintf(stderr, "\t-h\tServer's URI\n");
    fprintf(stderr, "\t-p\tPort of the server's connection service (default %d)\n", DFLT_PORT);
    fprintf(stderr, "\t-s\tSet to run as the server\n\n");
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
            send--;
            break;
        case CCI_EVENT_RECV:
        {
            if (!ready) {
                ready = 1;
            } else {
                recv--;
                if (!is_server) {
                    if (event->info.recv.data_len == current_size) {
                        if (warmup < WARMUP)
                            warmup++;
                        else
                            count++;
                    }
                } else {
                    if (event->info.recv.data_len > current_size)
                        current_size = event->info.recv.data_len;
                }
                if (is_server ||
                    count < ITERS) {
                    send++;
                    recv++;
                    if (is_server && event->info.recv.header_len == 3) {
                        done = 1;
                        return;
                    }
                    ret = cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
                    if (ret)
                        fprintf(stderr, "%s: send returned %s\n", __func__, cci_strerror(ret));
                }
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
    cci_conn_attribute_t type = CCI_CONN_ATTR_UU;

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, port, NULL, 0, type, NULL, 0, NULL);
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

    buffer = calloc(1, connection->max_send_size);
    if (!buffer) {
        fprintf(stderr, "unable to alloc buffer\n");
        return;
    }

    while (!ready)
        sleep(1);

    printf("Bytes\tLatency (one-way)\tThroughput\n");

	/* begin communication with server */
    for (current_size = 0;
         current_size <= connection->max_send_size;
        ) {

        send++;
        recv++;
        ret = cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
        if (ret) fprintf(stderr, "send returned %d\n", ret);

        while (count < WARMUP)
            poll_events();

        gettimeofday(&start, NULL);

        while (count < ITERS)
            poll_events();

        gettimeofday(&end, NULL);

        printf("%4d\t%6.2lf us\t\t%6.2lf Mb/s\n",
               current_size, usecs(start, end) / (double) ITERS / 2.0,
               (double) ITERS * (double) current_size * 8.0 / usecs(start, end) / 2.0);

        count = 0;
        warmup = 0;

        if (current_size == 0)
            current_size++;
        else
            current_size *= 2;
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

            buffer = calloc(1, connection->max_send_size);
            if (!buffer) {
                fprintf(stderr, "unable to alloc buffer\n");
                return;
            }
            cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
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
    int ret, c;
    uint32_t caps = 0;
    cci_os_handle_t ep_fd;

    name = argv[0];

    while ((c = getopt(argc, argv, "h:p:s")) != -1) {
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

    if (is_server)
        do_server();
    else
        do_client();

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
