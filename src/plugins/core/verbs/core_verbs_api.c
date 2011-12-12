/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_verbs.h"


/*
 * Local functions
 */
static int verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *verbs_strerror(enum cci_status status);
static int verbs_get_devices(cci_device_t const ***devices);
static int verbs_free_devices(cci_device_t const **devices);
static int verbs_create_endpoint(cci_device_t *device,
                                    int flags,
                                    cci_endpoint_t **endpoint,
                                    cci_os_handle_t *fd);
static int verbs_destroy_endpoint(cci_endpoint_t *endpoint);
static int verbs_accept(union cci_event *event,
                           cci_connection_t **connection);
static int verbs_reject(union cci_event *event);
static int verbs_connect(cci_endpoint_t *endpoint, char *server_uri,
                            void *data_ptr, uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            void *context, int flags,
                            struct timeval *timeout);
static int verbs_disconnect(cci_connection_t *connection);
static int verbs_set_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, const void* val, int len);
static int verbs_get_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, void** val, int *len);
static int verbs_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int verbs_get_event(cci_endpoint_t *endpoint,
                              cci_event_t ** const event);
static int verbs_return_event(cci_event_t *event);
static int verbs_send(cci_connection_t *connection,
                         void *msg_ptr, uint32_t msg_len,
                         void *context, int flags);
static int verbs_sendv(cci_connection_t *connection,
                          struct iovec *data, uint32_t iovcnt,
                          void *context, int flags);
static int verbs_rma_register(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 void *start, uint64_t length,
                                 uint64_t *rma_handle);
static int verbs_rma_deregister(uint64_t rma_handle);
static int verbs_rma(cci_connection_t *connection,
                        void *msg_ptr, uint32_t msg_len,
                        uint64_t local_handle, uint64_t local_offset,
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags);


/*
 * Public plugin structure.
 *
 * The name of this structure must be of the following form:
 *
 *    cci_core_<your_plugin_name>_plugin
 *
 * This allows the symbol to be found after the plugin is dynamically
 * opened.
 *
 * Note that your_plugin_name should match the direct name where the
 * plugin resides.
 */
cci_plugin_core_t cci_core_verbs_plugin = {
    {
        /* Logistics */
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "verbs",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,

        /* Bootstrap function pointers */
        cci_core_verbs_post_load,
        cci_core_verbs_pre_unload,
    },

    /* API function pointers */
    verbs_init,
    verbs_strerror,
    verbs_get_devices,
    verbs_free_devices,
    verbs_create_endpoint,
    verbs_destroy_endpoint,
    verbs_accept,
    verbs_reject,
    verbs_connect,
    verbs_disconnect,
    verbs_set_opt,
    verbs_get_opt,
    verbs_arm_os_handle,
    verbs_get_event,
    verbs_return_event,
    verbs_send,
    verbs_sendv,
    verbs_rma_register,
    verbs_rma_deregister,
    verbs_rma
};


static int verbs_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    printf("In verbs_init\n");
    return CCI_SUCCESS;
}


static const char *verbs_strerror(enum cci_status status)
{
    printf("In verbs_sterrror\n");
    return NULL;
}


static int verbs_get_devices(cci_device_t const ***devices)
{
    printf("In verbs_get_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_free_devices(cci_device_t const **devices)
{
    printf("In verbs_free_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_create_endpoint(cci_device_t *device,
                                    int flags,
                                    cci_endpoint_t **endpoint,
                                    cci_os_handle_t *fd)
{
    printf("In verbs_create_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_destroy_endpoint(cci_endpoint_t *endpoint)
{
    printf("In verbs_destroy_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_accept(union cci_event *event,
                           cci_connection_t **connection)
{
    printf("In verbs_accept\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_reject(union cci_event *event)
{
    printf("In verbs_reject\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_connect(cci_endpoint_t *endpoint, char *server_uri,
                            void *data_ptr, uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            void *context, int flags,
                            struct timeval *timeout)
{
    printf("In verbs_connect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_disconnect(cci_connection_t *connection)
{
    printf("In verbs_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_set_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, const void* val, int len)
{
    printf("In verbs_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_get_opt(cci_opt_handle_t *handle,
                            cci_opt_level_t level,
                            cci_opt_name_t name, void** val, int *len)
{
    printf("In verbs_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    printf("In verbs_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_get_event(cci_endpoint_t *endpoint,
                              cci_event_t ** const event)
{
    printf("In verbs_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_return_event(cci_event_t *event)
{
    printf("In verbs_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_send(cci_connection_t *connection,
                         void *msg_ptr, uint32_t msg_len,
                         void *context, int flags)
{
    printf("In verbs_send\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_sendv(cci_connection_t *connection,
                          struct iovec *data, uint32_t iovcnt,
                          void *context, int flags)
{
    printf("In verbs_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_rma_register(cci_endpoint_t *endpoint,
                                 cci_connection_t *connection,
                                 void *start, uint64_t length,
                                 uint64_t *rma_handle)
{
    printf("In verbs_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_rma_deregister(uint64_t rma_handle)
{
    printf("In verbs_rma_deregister\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int verbs_rma(cci_connection_t *connection,
                        void *msg_ptr, uint32_t msg_len,
                        uint64_t local_handle, uint64_t local_offset,
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
    printf("In verbs_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}
