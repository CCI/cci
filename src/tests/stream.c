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

#define DFLT_PORT   54321
#define ITERS       100000
#define TIMEOUT     30  /* seconds */
#define MAX_PENDING 128

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
uint32_t port = DFLT_PORT;
uint32_t current_size = 32;
cci_device_t **devices = NULL;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_UU;
struct timeval start, end;

#define LOCK   pthread_mutex_lock(&lock);
#define UNLOCK pthread_mutex_unlock(&lock);

void
print_usage()
{
    fprintf(stderr, "usage: %s -h <server_uri> [-p <port>] [-s] [-c <type>]\n", name);
    fprintf(stderr, "where:\n");
    fprintf(stderr, "\t-h\tServer's URI\n");
    fprintf(stderr, "\t-p\tPort of the server's connection service (default %d)\n", DFLT_PORT);
    fprintf(stderr, "\t-s\tSet to run as the server\n");
    fprintf(stderr, "\t-c\tConnection type (UU, RU, or RO) set by client only\n");
    fprintf(stderr, "\t-t\tTimeout in seconds (default %d)\n\n", TIMEOUT);
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "server$ %s -h ip://foo -p 2211 -s\n", name);
    fprintf(stderr, "client$ %s -h ip://foo -p 2211\n", name);
    exit(EXIT_FAILURE);
}

double
usecs(struct timeval start, struct timeval end)
{
    return ((double) (end.tv_sec  - start.tv_sec)) * 1000000.0 +
           ((double) (end.tv_usec - start.tv_usec));
}

static void
poll_events(void)
{
    int ret;
    cci_event_t *event;

again:
    LOCK;
    if (!running) {
        UNLOCK;
        return;
    }
    UNLOCK;

    ret = cci_get_event(endpoint, &event, 0);
    if (ret == CCI_SUCCESS) {
        assert(event);
        switch (event->type) {
        case CCI_EVENT_SEND:
            if (!is_server) {
                send_completed++;
                LOCK;
                if (running) {
                    UNLOCK;
                    ret = cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
                    if (ret && 0) {
                        fprintf(stderr, "%s: send returned %s\n", __func__, cci_strerror(ret));
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
                if (event->info.recv.data_len == current_size)
                    recv++;
                if (is_server) {
                    if (event->info.recv.data_len > current_size ||
                        event->info.recv.header_len == 3) {
                        gettimeofday(&end, NULL);
                        printf("%5d\t\t%6d\t\t%6.2lf Mb/s\n",
                               current_size, recv,
                               (double) recv * (double) current_size * 8.0 /
                                    usecs(start, end));
                        current_size = event->info.recv.data_len;
                        gettimeofday(&start, NULL);
                        recv = 1;
                    }
                    if (event->info.recv.header_len == 3) {
                        done = 1;
                        return;
                    }
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

void handle_alarm(int sig)
{
    LOCK;
    running = 0;
    UNLOCK;
    return;
}

void
do_client()
{
    int ret;

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
    for (current_size = 32;
         current_size <= connection->max_send_size;
        ) {
        int i;

        send = send_completed = recv = 0;
        LOCK;
        running = 1;
        UNLOCK;

        alarm(timeout);
        gettimeofday(&start, NULL);

        for (i = 0; i < MAX_PENDING; i++) {
            ret = cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
            if (!ret)
                send++;
        }

        LOCK;
        while (running) {
            UNLOCK;
            poll_events();
            LOCK;
        }
        UNLOCK;

        gettimeofday(&end, NULL);

        printf("%5d\t\t%6d\t\t%6.2lf Mb/s\n",
               current_size, send,
               (double) send * (double) current_size * 8.0 /
                    usecs(start, end));

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
            gettimeofday(&start, NULL);
            cci_send(connection, NULL, 0, buffer, current_size, NULL, 0);
            printf("Bytes\t\t# Rcvd\t\tRcvd\n");
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

    while ((c = getopt(argc, argv, "h:p:sc:t:")) != -1) {
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
            else if (strncasecmp("uu", optarg, 2) == 0)
                attr = CCI_CONN_ATTR_UU;
            else
                print_usage();
            printf("Using %s connection\n",
                   attr == CCI_CONN_ATTR_UU ? "UU" : attr == CCI_CONN_ATTR_RU ? "RU" : "RO");
            break;
        case 't':
            timeout = (int) strtoul(optarg, NULL, 0);
            if (timeout <= 0) {
                fprintf(stderr, "timeout %d is invalid\n", timeout);
                print_usage();
            }
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
