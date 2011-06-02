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

#include "cci.h"

int main(int argc, char *argv[])
{
    int ret;
    uint32_t caps = 0, port = 54321;
    cci_device_t **devices = NULL;
    cci_endpoint_t *endpoint = NULL;
    cci_os_handle_t ep_fd, bind_fd;
    cci_service_t *service = NULL;
    cci_connection_t *connection = NULL;

    /* init */
    ret = cci_init(CCI_ABI_VERSION, 0, &caps);
    if (ret) {
        fprintf(stderr, "cci_init() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* get devices */
    ret = cci_get_devices((cci_device_t const *** const) &devices);
    if (ret) {
        fprintf(stderr, "cci_get_devices() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* create an endpoint */
    ret = cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);
    if (ret) {
        fprintf(stderr, "cci_create_endpoint() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* bind first device to the service at port 54321 */
    ret = cci_bind(devices[0], 10, &port,&service, &bind_fd);
    if (ret) {
        fprintf(stderr, "cci_bind() failed with %s\n", cci_strerror(ret));
        exit(EXIT_FAILURE);
    }

    while (1) {
        int accept = 1;
        char *buffer;
        cci_conn_req_t *conn_req;
        cci_event_t *event;

        ret = cci_get_conn_req(service, &conn_req);
        if (ret == CCI_SUCCESS) {
            /* inspect conn_req_t and decide to accept or reject */

            if (accept) {
                /* associate this connect request with this endpoint */
                ret = cci_accept(conn_req, endpoint, &connection);
                if (ret != CCI_SUCCESS) {
                    fprintf(stderr, "cci_accept() returned %s",
                                    cci_strerror(ret));
                } else if (!buffer) {
                    buffer = calloc(1, connection->max_send_size + 1);
                    /* check for buffer ... */
                }

            } else {
                cci_reject(conn_req);
            }
        }

        /* check for next event...
         * handle communication over existing connections */

again:
        ret = cci_get_event(endpoint, &event, 0);
        if (ret == CCI_SUCCESS) {
            switch (event->type) {
                case CCI_EVENT_RECV:
                {
                    memcpy(buffer, event->info.recv.header_ptr, event->info.recv.header_len);
                    buffer[event->info.recv.header_len] = 0;
                    printf("recv'd:\n");
                    printf("\theader: \"%s\"\n", buffer);
                    memcpy(buffer, event->info.recv.data_ptr, event->info.recv.data_len);
                    buffer[event->info.recv.data_len] = 0;
                    printf("\tdata: \"%s\"\n", buffer);

                    /* echo the message to the client */
                    ret = cci_send(connection,
                                   event->info.recv.header_ptr,
                                   event->info.recv.header_len,
                                   event->info.recv.data_ptr,
                                   event->info.recv.data_len,
                                   NULL, 0);
                    if (ret != CCI_SUCCESS)
                        fprintf(stderr, "send returned %s\n", cci_strerror(ret));
                    break;
                }
                case CCI_EVENT_SEND:
                    printf("completed send\n");
                    break;
                default:
                    fprintf(stderr, "unexpected event %d", event->type);
                    break;
            }
            cci_return_event(endpoint, event);
            goto again;
        }
    }

    /* clean up */
    cci_unbind(service, NULL);
    cci_destroy_endpoint(endpoint);
    cci_free_devices((cci_device_t const **) devices);

    return 0;
}
