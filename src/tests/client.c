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
#include <unistd.h>

int main(int argc, char *argv[])
{
	int done = 0;
	uint32_t caps = 0;
    //char *server_uri = "ip://192.168.0.12";
    char *server_uri = "ip://160.91.210.89";
	cci_os_handle_t fd;
	cci_device_t **devices = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_connection_t *connection = NULL;

	cci_init(CCI_ABI_VERSION, 0, &caps);

	cci_get_devices((const cci_device_t *** const)&devices);

	/* create an endpoint */
	cci_create_endpoint(NULL, 0, &endpoint, &fd);

	/* initiate connect */
	cci_connect(endpoint, server_uri, 54321, NULL, 0, CCI_CONN_ATTR_UU, NULL, 0, NULL);

	/* poll for connect completion */
	while (!done) {
        int ret;
		cci_event_t *event;

		/* what does this return:
		 *   if there is an event? 0 or 1 or other?
		 *   if there is not an event? is event NULL? */
		ret = cci_get_event(endpoint, &event, 0);

        if (ret == 0) {
		    if (event->type == CCI_EVENT_CONNECT_SUCCESS) {
			    /* shouldn't the event contain the connection? */
			    /* store new connection */
			    done = 1;
		    } else if (event->type == CCI_EVENT_CONNECT_REJECTED) {
			    done = 1;
		    }
		cci_return_event(endpoint, event);
        }
        usleep(10000);
	}

	/* begin communication with server */
	while (!done) {
		/* do stuff */
	}

	/* clean up */
	cci_disconnect(connection);
	cci_destroy_endpoint(endpoint);
	cci_free_devices((const cci_device_t ** const)devices);

	return 0;
}
