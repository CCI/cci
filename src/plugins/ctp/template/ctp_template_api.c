/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "ctp_template.h"

/*
 * Local functions
 */
static int ctp_template_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_template_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_template_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_template_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpoint,
				    cci_os_handle_t * fd);
static int ctp_template_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_template_accept(cci_event_t *event, const void *context);
static int ctp_template_reject(cci_event_t *event);
static int ctp_template_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout);
static int ctp_template_disconnect(cci_connection_t * connection);
static int ctp_template_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val);
static int ctp_template_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val);
static int ctp_template_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_template_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event);
static int ctp_template_return_event(cci_event_t * event);
static int ctp_template_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags);
static int ctp_template_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags);
static int ctp_template_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, uint64_t * rma_handle);
static int ctp_template_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle);
static int ctp_template_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			uint64_t local_handle, uint64_t local_offset,
			uint64_t remote_handle, uint64_t remote_offset,
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
cci_plugin_ctp_t cci_ctp_template_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "template",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 0, /* priority set to 0 because people shouldn't ever use it */

	 /* Bootstrap function pointers */
	 cci_ctp_template_post_load,
	 cci_ctp_template_pre_unload,
	 },

	/* API function pointers */
	ctp_template_init,
	ctp_template_finalize,
	ctp_template_strerror,
	ctp_template_create_endpoint,
	ctp_template_destroy_endpoint,
	ctp_template_accept,
	ctp_template_reject,
	ctp_template_connect,
	ctp_template_disconnect,
	ctp_template_set_opt,
	ctp_template_get_opt,
	ctp_template_arm_os_handle,
	ctp_template_get_event,
	ctp_template_return_event,
	ctp_template_send,
	ctp_template_sendv,
	ctp_template_rma_register,
	ctp_template_rma_deregister,
	ctp_template_rma
};

static int ctp_template_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	debug(CCI_DB_INFO, "In template_init\n");
	return CCI_SUCCESS;
}

static int ctp_template_finalize(cci_plugin_ctp_t * plugin)
{
	debug(CCI_DB_INFO, "In template_free_devices\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static const char *ctp_template_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	debug(CCI_DB_INFO, "In template_sterrror\n");
	return NULL;
}

static int ctp_template_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpoint,
				    cci_os_handle_t * fd)
{
	printf("In template_create_endpoint\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_destroy_endpoint(cci_endpoint_t * endpoint)
{
	printf("In template_destroy_endpoint\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_accept(cci_event_t *event, const void *context)
{
	printf("In template_accept\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_reject(cci_event_t *event)
{
	printf("In template_reject\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout)
{
	printf("In template_connect\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_disconnect(cci_connection_t * connection)
{
	printf("In template_disconnect\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val)
{
	printf("In template_set_opt\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val)
{
	printf("In template_get_opt\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	printf("In template_arm_os_handle\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	printf("In template_get_event\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_return_event(cci_event_t * event)
{
	printf("In template_return_event\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	printf("In template_send\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	printf("In template_sendv\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, uint64_t * rma_handle)
{
	printf("In template_rma_register\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_rma_deregister(cci_endpoint_t * endpoint, uint64_t rma_handle)
{
	printf("In template_rma_deregister\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_template_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			uint64_t local_handle, uint64_t local_offset,
			uint64_t remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags)
{
	printf("In template_rma\n");
	return CCI_ERR_NOT_IMPLEMENTED;
}
