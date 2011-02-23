#include "cci.h"

int main(int argc, char *argv[])
{
	uint32_t caps = 0, port = 5555;
	cci_device_t **devices = NULL;
	cci_endpoint_t *endpoint = NULL;
	cci_os_handle_t ep_fd, bind_fd;
	cci_service_t *service = NULL;

	cci_init(CCI_ABI_VERSION, 0, &caps);

	cci_get_devices((cci_device_t const ***) &devices);

	/* create an endpoint? */
	cci_create_endpoint(NULL, 0, &endpoint, &ep_fd);

	/* we don't associate the endpoint with the service? */
	cci_bind(NULL, 10, &port, &service, &bind_fd);

	while (1) {
		int accept = 0;
		cci_conn_req_t *conn_req;
		cci_connection_t *connection = NULL;

		cci_get_conn_req(service, &conn_req);

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
