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

    ret = cci_init(CCI_ABI_VERSION, 0, &caps);
    if (ret) {
        fprintf(stderr, "cci_init() failed with %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    ret = cci_get_devices((cci_device_t const *** const) &devices);
    if (ret) {
        fprintf(stderr, "cci_get_devices() failed with %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* create an endpoint? */
    ret = cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);
    if (ret) {
        fprintf(stderr, "cci_create_endpoint() failed with %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* we don't associate the endpoint with the service? */
    ret = cci_bind(devices[0], 10, &port,&service, &bind_fd);
    if (ret) {
        fprintf(stderr, "cci_bind() failed with %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    while (1) {
        int accept = 1;
        cci_conn_req_t *conn_req;
        cci_event_t *event;

        ret = cci_get_conn_req(service, &conn_req);
        if (ret == 0 && conn_req) {

            /* inspect conn_req_t and decide to accept or reject */

            if (accept) {
                /* associate this connect request with this endpoint */
                cci_accept(conn_req, endpoint, &connection);

                /* add new connection to connection list, etc. */
            } else {
                cci_reject(conn_req);
            }
        }

        /* check for next event...
         * handle communication over existing connections */

again:
        ret = cci_get_event(endpoint, &event, 0);
        if (ret == 0) {
            if (event->type == CCI_EVENT_RECV) {
                char buf[8192];
                char *hdr = "header:";
                char *data = "data:";
                int len = 0;
                int offset = 0;
                int hlen = event->info.recv.header_len;
                int dlen = event->info.recv.data_len;

                memset(buf, 0, 8192);
                len = strlen(hdr);
                memcpy(buf, hdr, len);
                offset += len;
                memcpy(buf + offset, event->info.recv.header_ptr, hlen);
                offset += hlen;
                len = strlen(data);
                memcpy(buf + offset, data, len);
                offset += len;
                memcpy(buf + offset, event->info.recv.data_ptr, dlen);
                offset += dlen;
                fprintf(stderr, "recv'd \"%s\"\n", buf);
                ret = cci_send(connection, NULL, 0, buf, offset, NULL, 0);
                if (ret)
                    fprintf(stderr, "send returned %d\n", ret);
            } else if (event->type == CCI_EVENT_SEND) {
                fprintf(stderr, "completed send\n");
            } else {
                printf("event type %d\n", event->type);
            }
            cci_return_event(endpoint, event);
            goto again;
        }
        usleep(1000);
    }

    /* clean up */
    cci_unbind(service, NULL);
    cci_destroy_endpoint(endpoint);
    cci_free_devices((cci_device_t const **) devices);

    return 0;
}
