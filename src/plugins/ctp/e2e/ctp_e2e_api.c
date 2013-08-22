/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "ctp_e2e.h"

e2e_globals_t *eglobals = NULL;

/*
 * Local functions
 */
static int ctp_e2e_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_e2e_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_e2e_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_e2e_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpoint,
				    cci_os_handle_t * fd);
static int ctp_e2e_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_e2e_accept(cci_event_t *event, const void *context);
static int ctp_e2e_reject(cci_event_t *event);
static int ctp_e2e_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout);
static int ctp_e2e_disconnect(cci_connection_t * connection);
static int ctp_e2e_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val);
static int ctp_e2e_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val);
static int ctp_e2e_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_e2e_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event);
static int ctp_e2e_return_event(cci_event_t * event);
static int ctp_e2e_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags);
static int ctp_e2e_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags);
static int ctp_e2e_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle);
static int ctp_e2e_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle);
static int ctp_e2e_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			cci_rma_handle_t * local_handle, uint64_t local_offset,
			cci_rma_handle_t * remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags);

/*
 * Public plugin structure.
 *
 * The name of this structure must be of the following form:
 *
 *    cci_ctp_<your_plugin_name>_plugin
 *
 * This allows the symbol to be found after the plugin is dynamically
 * opened.
 *
 * Note that your_plugin_name should match the direct name where the
 * plugin resides.
 */
cci_plugin_ctp_t cci_ctp_e2e_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "e2e",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 1, /* priority set to 1 */

	 /* Bootstrap function pointers */
	 cci_ctp_e2e_post_load,
	 cci_ctp_e2e_pre_unload,
	 },

	/* API function pointers */
	ctp_e2e_init,
	ctp_e2e_finalize,
	ctp_e2e_strerror,
	ctp_e2e_create_endpoint,
	ctp_e2e_destroy_endpoint,
	ctp_e2e_accept,
	ctp_e2e_reject,
	ctp_e2e_connect,
	ctp_e2e_disconnect,
	ctp_e2e_set_opt,
	ctp_e2e_get_opt,
	ctp_e2e_arm_os_handle,
	ctp_e2e_get_event,
	ctp_e2e_return_event,
	ctp_e2e_send,
	ctp_e2e_sendv,
	ctp_e2e_rma_register,
	ctp_e2e_rma_deregister,
	ctp_e2e_rma
};

static int ctp_e2e_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret = 0;
	struct cci_device *device;
	cci__dev_t *dev = NULL;
	cci_device_t **devices = NULL;

	CCI_ENTER;

	eglobals = calloc(1, sizeof(*eglobals));
	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	devices = calloc(2, sizeof(*devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* Create one e2e virtual device. It will be generic and can
	 * use any native transport.
	 */

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		ret = CCI_ENOMEM;
		goto out;
	}
	cci__init_dev(dev);
	dev->plugin = plugin;
	dev->priority = plugin->base.priority;
	dev->device.up = 1;
	dev->device.rate = 0;

	device = &dev->device;
	device->conf_argv = calloc(2, sizeof(*device->conf_argv));
	if (!device->conf_argv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	((char **)device->conf_argv)[0] = strdup("transport=e2e");
	if (!device->conf_argv[0]) {
		ret = CCI_ENOMEM;
		goto out;
	}

	cci__add_dev(dev);

	*((cci_device_t ***)&eglobals->devices) = devices;
	eglobals->count = 1;
    out:
	if (ret) {
		if (device) {
			if (device->conf_argv)
				free((char *)device->conf_argv[0]);
		}
		free(dev);
		free(devices);
		free(eglobals);
	}

	CCI_EXIT;
	return CCI_SUCCESS;
}

static int ctp_e2e_finalize(cci_plugin_ctp_t * plugin)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static const char *ctp_e2e_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	CCI_ENTER;

	CCI_EXIT;
	return NULL;
}

static int ctp_e2e_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpoint,
				    cci_os_handle_t * fd)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_destroy_endpoint(cci_endpoint_t * endpoint)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_accept(cci_event_t *event, const void *context)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_reject(cci_event_t *event)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_disconnect(cci_connection_t * connection)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_return_event(cci_event_t * event)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			cci_rma_handle_t * local_handle, uint64_t local_offset,
			cci_rma_handle_t * remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags)
{
	CCI_ENTER

	CCI_EXIT
	return CCI_ERR_NOT_IMPLEMENTED;
}
