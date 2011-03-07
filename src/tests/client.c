/*
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int done = 0, ret, i = 0;
	uint32_t caps = 0;
    //char *server_uri = "ip://192.168.0.2";
    char *server_uri = "ip://160.91.210.89";
	cci_os_handle_t fd;
	cci_device_t **devices = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_connection_t *connection = NULL;
    cci_opt_handle_t handle;
    uint32_t timeout = 30 * 1000000;
	cci_event_t *event;
    char buffer[8192];

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
    if (ret) {
        fprintf(stderr, "cci_init() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

	ret = cci_get_devices((const cci_device_t *** const)&devices);
    if (ret) {
        fprintf(stderr, "cci_get_devices() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

	/* create an endpoint */
	ret = cci_create_endpoint(NULL, 0, &endpoint, &fd);
    if (ret) {
        fprintf(stderr, "cci_create_endpoint() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    /* set conn tx timeout */
    handle.endpoint = endpoint;
    cci_set_opt(&handle, CCI_OPT_LEVEL_ENDPOINT, CCI_OPT_ENDPT_SEND_TIMEOUT,
                (void *) &timeout, (int) sizeof(timeout));
    if (ret) {
        fprintf(stderr, "cci_set_opt() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

	/* initiate connect */
	ret = cci_connect(endpoint, server_uri, 54321, server_uri, strlen(server_uri), CCI_CONN_ATTR_UU, NULL, 0, NULL);
    if (ret) {
        fprintf(stderr, "cci_connect() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

	/* poll for connect completion */
	while (!done) {
        int ret;

		/* what does this return:
		 *   if there is an event? 0 or 1 or other?
		 *   if there is not an event? is event NULL? */
		ret = cci_get_event(endpoint, &event, 0);

        if (ret == 0) {
		    if (event->type == CCI_EVENT_CONNECT_SUCCESS) {
			    /* shouldn't the event contain the connection? */
			    /* store new connection */
			    done = 1;
                connection = event->info.other.u.connect.connection;
		    } else if (event->type == CCI_EVENT_CONNECT_REJECTED) {
			    done = 1;
		    } else {
                fprintf(stderr, "unknown event type %d\n", event->type);
            }
		    cci_return_event(endpoint, event);
        }
        usleep(1000);
	}

	/* begin communication with server */
    for (i = 0; i < 10; i++) {
        char hdr[32];
        char data[128];

        memset(hdr, 0, sizeof(hdr));
        memset(data, 0, sizeof(data));
        sprintf(hdr, "%4d", i);
        sprintf(data, "Hello World!");
        ret = cci_send(connection, hdr, (uint32_t) strlen(hdr), data, (uint32_t) strlen(data), (void *)(uintptr_t) i, 0);
        if (ret)
            fprintf(stderr, "send returned %d\n", ret);

again:
        ret = cci_get_event(endpoint, &event, 0);
        if (ret == CCI_SUCCESS && event) {
            if (event->type == CCI_EVENT_SEND) {
                fprintf(stderr, "send completed with %d\n", event->info.send.status);
            } else if (event->type == CCI_EVENT_RECV) {
                int len = event->info.recv.header_len + event->info.recv.data_len;

                memcpy(buffer, event->info.recv.header_ptr, len);
                buffer[len] = '\0';
                fprintf(stderr, "received \"%s\"\n", buffer);
            }
            cci_return_event(endpoint, event);
            goto again;
        }
        sleep(1);
    }
    ret = cci_get_event(endpoint, &event, 0);
    if (ret == CCI_SUCCESS && event) {
        if (event->type == CCI_EVENT_SEND) {
            fprintf(stderr, "send completed with %d\n", event->info.send.status);
        } else if (event->type == CCI_EVENT_RECV) {
            int len = event->info.recv.header_len + event->info.recv.data_len;

            memcpy(buffer, event->info.recv.header_ptr, len);
            buffer[len] = '\0';
            fprintf(stderr, "received \"%s\"\n", buffer);
        }
        cci_return_event(endpoint, event);
    }

	/* clean up */
	ret = cci_disconnect(connection);
    if (ret) {
        fprintf(stderr, "cci_disconnect() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
	ret = cci_destroy_endpoint(endpoint);
    if (ret) {
        fprintf(stderr, "cci_destroy_endpoint() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
	ret = cci_free_devices((const cci_device_t ** const)devices);
    if (ret) {
        fprintf(stderr, "cci_free_devices() returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

	return 0;
}
