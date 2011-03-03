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

#include "cci.h"

int main(int argc, char *argv[])
{
    int ret;
    uint32_t caps = 0, port = 54321;
    cci_device_t **devices = NULL;
    cci_endpoint_t *endpoint = NULL;
    cci_os_handle_t ep_fd, bind_fd;
    cci_service_t *service = NULL;

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
    ret = cci_bind(devices[0], 10, &port, &service, &bind_fd);
    if (ret) {
        fprintf(stderr, "cci_bind() failed with %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    while (1) {
        int accept = 1;
        cci_conn_req_t *conn_req;
        cci_connection_t *connection = NULL;

        ret = cci_get_conn_req(service, &conn_req);
        if (ret)
            continue;

        /* inspect conn_req_t and decide to accept or reject */

        if (accept) {
            /* associate this connect request with this endpoint */
            cci_accept(conn_req, endpoint, &connection);

            /* add new connection to connection list, etc. */
        } else {
            cci_reject(conn_req);
        }

        /* check for next event...
         * handle communication over existing connections */
    }

    /* clean up */
    cci_unbind(service, NULL);
    cci_destroy_endpoint(endpoint);
    cci_free_devices((cci_device_t const **) devices);

    return 0;
}
