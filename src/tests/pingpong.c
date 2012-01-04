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
#include <inttypes.h>
#include <assert.h>
#include <sys/time.h>

#include "cci.h"

#define ITERS       (512 * 1024)
#define WARMUP      (1024)
#define MAX_RMA_SIZE    (4 * 1024 * 1024)

/* Globals */
int connect_done = 0, done = 0;
int ready = 0;
int is_server = 0;
int count = 0;
int iters = ITERS;
int warmup = WARMUP;
char *name;
char *server_uri;
char *buffer;
uint32_t current_size = 0;
cci_device_t **devices = NULL;
cci_endpoint_t *endpoint = NULL;
cci_connection_t *connection = NULL;
cci_conn_attribute_t attr = CCI_CONN_ATTR_UU;
uint64_t local_rma_handle = 0ULL;
int remote_completion = 0;
void *rmt_comp_msg = NULL;
uint32_t rmt_comp_len = 0;

typedef struct options {
    uint64_t    server_rma_handle;
    uint32_t    max_rma_size;
#define AM        0
#define RMA_WRITE 1
#define RMA_READ  2
    uint32_t    method;
    int         flags;
    int         pad;
} options_t;

options_t opts = { 0ULL, 0, 0, 0 };

void
print_usage()
{
    fprintf(stderr, "usage: %s -h <server_uri> [-s] [-i <iters>] "
            "[-W <warmup>] [-c <type>] [-n] "
            "[[-w | -r] [-m <max_rma_size> [-C]]]\n", name);
    fprintf(stderr, "where:\n");
    fprintf(stderr, "\t-h\tServer's URI\n");
    fprintf(stderr, "\t-s\tSet to run as the server\n");
    fprintf(stderr, "\t-i\tRun this number of iterations\n");
    fprintf(stderr, "\t-W\tRun this number of warmup iterations\n");
    fprintf(stderr, "\t-c\tConnection type (UU, RU, or RO) set by client only\n");
    fprintf(stderr, "\t-n\tSet CCI_FLAG_NO_COPY ito avoid copying\n");
    fprintf(stderr, "\t-w\tUse RMA WRITE instead of active messages\n");
    fprintf(stderr, "\t-r\tUse RMA READ instead of active messages\n");
    fprintf(stderr, "\t-m\tTest RMA messages up to max_rma_size\n");
    fprintf(stderr, "\t-C\tSend RMA remote completion message\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "server$ %s -h ip://foo -p 2211 -s\n", name);
    fprintf(stderr, "client$ %s -h ip://foo -p 2211\n", name);
    exit(EXIT_FAILURE);
}

void
check_return(char *func, int ret, int need_exit)
{
    if (ret) {
        fprintf(stderr, "%s() returned %s\n", func, cci_strerror(ret));
        if (need_exit)
            exit(EXIT_FAILURE);
    }
    return;
}

static void
poll_events(void)
{
    int ret;
    cci_event_t *event;

    ret = cci_get_event(endpoint, &event);
    if (ret == CCI_SUCCESS) {
        assert(event);
        switch (event->type) {
        case CCI_EVENT_SEND:
            if (opts.method != AM) {
                if (!is_server && event->send.context == (void*)1) {
                    count++;
                    if (count < warmup + iters) {
                        ret = cci_rma(connection, rmt_comp_msg, rmt_comp_len,
                                      local_rma_handle, 0,
                                      opts.server_rma_handle, 0,
                                      current_size, (void*)1, opts.flags);
                        check_return("cci_rma", ret, 1);
                    }
                }
            }
            if (!is_server && event->send.context == (void *)0xdeadbeef)
                done = 1;
            break;
        case CCI_EVENT_RECV:
        {
            if (!is_server && opts.method != AM
                           && event->recv.ptr == (void*)1) {
                count++;
                if (count < warmup + iters) {
                    ret = cci_rma(connection, rmt_comp_msg, rmt_comp_len,
                                      local_rma_handle, 0,
                                      opts.server_rma_handle, 0,
                                      current_size, (void*)1, opts.flags);
                        check_return("cci_rma", ret, 1);
                    }
            }
            if (!ready) {
                ready = 1;
                if (opts.method != AM && !is_server) {
                    /* get server_rma_handle */
                    opts = *((options_t *)event->recv.ptr);
                    fprintf(stderr, "server RMA handle is 0x%"PRIx64"\n",
                                    opts.server_rma_handle);
                }
            } else if (is_server && event->recv.len == 3) {
                done = 1;
                break;
            } else if (opts.method == AM) {
                if (is_server) {
                    if (event->recv.len > current_size)
                        current_size = event->recv.len;
                } else {
                    if (event->recv.len == current_size)
                        count++;
                }
                if (is_server ||
                    count < warmup + iters) {
                    ret = cci_send(connection, buffer, current_size, NULL, opts.flags);
                    if (ret)
                        fprintf(stderr, "%s: %s: send returned %s\n", __func__,
                                is_server ? "server" : "client", cci_strerror(ret));
                }
            }
            break;
        }
        case CCI_EVENT_CONNECT_ACCEPTED:
        case CCI_EVENT_CONNECT_TIMEDOUT:
        case CCI_EVENT_CONNECT_REJECTED:
            if (!is_server) {
                connect_done = 1;
                if (event->type == CCI_EVENT_CONNECT_ACCEPTED)
                    connection = event->accepted.connection;
                else
                    connection = NULL;
            }
            break;
        default:
            fprintf(stderr, "ignoring event type %d\n", event->type);
        }
        cci_return_event(event);
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
    uint32_t min = 0, max;
    struct timeval start, end;
    char *func;
    char *header = "Done";

    /* let server start */
    sleep(3);

    /* initiate connect */
    ret = cci_connect(endpoint, server_uri, &opts, sizeof(opts), attr, NULL, 0, NULL);
    check_return("cci_connect", ret, 1);

    /* poll for connect completion */
    while (!connect_done)
       poll_events();

    if (!connection) {
        fprintf(stderr, "no connection\n");
        return;
    }

    while (!ready)
        poll_events();

    if (opts.method == AM) {
        func = "cci_send";
        max = connection->max_send_size;
    } else {
        func = "cci_rma";
        max = opts.max_rma_size;
    }

    ret = posix_memalign((void **)&buffer, 4096, max);
    check_return("memalign buffer", ret, 1);

    memset(buffer, 'b', max);

    if (opts.method != AM) {
        ret = cci_rma_register(endpoint, connection, buffer,
                               max, &local_rma_handle);
        check_return("cci_rma_register", ret, 1);
        fprintf(stderr, "local_rma_handle is 0x%"PRIx64"\n", local_rma_handle);
        min = 1;
        if (opts.method == RMA_WRITE)
            opts.flags |= CCI_FLAG_WRITE;
        else
            opts.flags |= CCI_FLAG_READ;
    }

    if (remote_completion) {
        rmt_comp_msg = header;
        rmt_comp_len = 4;
    }

    if (opts.method == AM)
        printf("Bytes\tLatency (one-way)\tThroughput\n");
    else
        printf("Bytes\t\tLatency (round-trip)\tThroughput\n");

	/* begin communication with server */
    for (current_size = min; current_size <= max; ) {
        double lat = 0.0;
        double bw = 0.0;

        if (opts.method == AM)
            ret = cci_send(connection, buffer, current_size, NULL, opts.flags);
        else
            ret = cci_rma(connection, rmt_comp_msg, rmt_comp_len,
                          local_rma_handle, 0,
                          opts.server_rma_handle, 0,
                          current_size, (void*)1, opts.flags);
        check_return(func, ret, 1);

        while (count < warmup)
            poll_events();

        gettimeofday(&start, NULL);

        while (count < warmup + iters)
            poll_events();

        gettimeofday(&end, NULL);

        if (opts.method == AM)
            lat = usecs(start, end) / (double) iters / 2.0;
        else
            lat = usecs(start, end) / (double) iters;

        bw = (double) current_size / lat;
        printf("%8d\t%8.2lf us\t\t%8.2lf MB/s\n", current_size, lat, bw);

        count = 0;

        if (current_size == 0)
            current_size++;
        else
            current_size *= 2;

        if (current_size >= 64*1024) {
            iters /= 2;
            if (iters < 16)
                iters = 16;
            warmup /= 2;
            if (warmup < 2)
                warmup = 2;
        }
    }

    ret = cci_send(connection, "bye", 3, (void*) 0xdeadbeef, opts.flags);
    check_return("cci_send", ret, 0);

    while (!done)
        poll_events();

    printf("client done\n");
    sleep(1);

    return;
}

void
do_server()
{
    int ret, accept = 0;

    while (!accept) {
        cci_event_t *event;

        ret = cci_get_event(endpoint, &event);
        if (ret == 0 && event) {
            int len;

            accept = 1;
            ready = 1;
            opts = *((options_t *)event->request.data_ptr);
            ret = cci_accept(event, &connection);
            check_return("cci_accept", ret, 1);

	    ret = cci_return_event(event);
            check_return("cci_return_event", ret, 1);

            if (opts.method == AM)
                len = connection->max_send_size;
            else
                len = opts.max_rma_size;

            ret = posix_memalign((void **)&buffer, 4096, len);
            check_return("memalign buffer", ret, 1);

	    memset(buffer, 'a', len);

            if (opts.method != AM) {
                ret = cci_rma_register(endpoint, connection, buffer,
                                       opts.max_rma_size, &opts.server_rma_handle);
                check_return("cci_rma_register", ret, 1);
                fprintf(stderr, "server_rma_handle is 0x%"PRIx64"\n", opts.server_rma_handle);
            }
            ret = cci_send(connection, &opts, sizeof(opts), NULL, 0);
            check_return("cci_send", ret, 1);
        }
    }

    while (!done)
        poll_events();

    printf("server done\n");
    sleep(1);

    return;
}

int main(int argc, char *argv[])
{
    int ret, c;
    uint32_t caps = 0;
    cci_os_handle_t ep_fd;

    name = argv[0];

    while ((c = getopt(argc, argv, "h:sc:nwrm:Ci:W:")) != -1) {
        switch (c) {
        case 'h':
            server_uri = strdup(optarg);
            break;
        case 's':
            is_server = 1;
            break;
        case 'i':
            iters = strtoul(optarg, NULL, 0);
            break;
        case 'W':
            warmup = strtoul(optarg, NULL, 0);
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
        case 'n':
            opts.flags = CCI_FLAG_NO_COPY;
            break;
        case 'w':
            opts.method = RMA_WRITE;
            break;
        case 'r':
            opts.method = RMA_READ;
            break;
        case 'm':
            opts.max_rma_size = strtoul(optarg, NULL, 0);
            break;
        case 'C':
            remote_completion = 1;
            break;
        default:
            print_usage();
        }
    }

    if (attr == CCI_CONN_ATTR_UU) {
        if (opts.method != AM) {
            fprintf(stderr, "RMA %s not allowed with UU connections\n",
                    opts.method == RMA_WRITE ? "WRITE" : "READ");
            print_usage();
        }
        if (opts.max_rma_size) {
            printf("ignoring max_rma_size (-m) with active messages\n");
            opts.max_rma_size = 0;
        }
    } else {
        /* RO or RU */
        if (opts.flags == CCI_FLAG_NO_COPY) {
            printf("Ignoring CCI_FLAG_NO_COPY (-n) with RMA %s\n",
                   opts.method == RMA_WRITE ? "WRITE" : "READ");
            opts.flags &= ~(CCI_FLAG_NO_COPY);
        }
        if (!opts.max_rma_size)
            opts.max_rma_size = MAX_RMA_SIZE;
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
    printf("Opened %s\n", endpoint->name);

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
