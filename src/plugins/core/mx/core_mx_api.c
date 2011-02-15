/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_mx.h"


/*
 * Local functions
 */
static int mx_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *mx_strerror(enum cci_status status);
static int mx_get_devices(cci_device_t const ***devices);
static int mx_free_devices(cci_device_t const **devices);
static int mx_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd);
static int mx_destroy_endpoint(cci_endpoint_t *endpoint);
static int mx_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd);
static int mx_unbind(cci_service_t *service, cci_device_t *device);
static int mx_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req);
static int mx_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection);
static int mx_reject(cci_conn_req_t *conn_req);
static int mx_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout);
static int mx_disconnect(cci_connection_t *connection);
static int mx_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len);
static int mx_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len);
static int mx_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int mx_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags);
static int mx_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event);
static int mx_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags);
static int mx_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags);
static int mx_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle);
static int mx_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle);
static int mx_rma_deregister(uint64_t rma_handle);
static int mx_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
                        uint64_t local_handle, uint64_t local_offset, 
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags);


/*
 * Public plugin structure
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
cci_plugin_core_t cci_core_mx_plugin = {
    {
        /* Logistics */
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "mx",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,
        
        /* Bootstrap function pointers */
        cci_core_mx_post_load,
        cci_core_mx_pre_unload,
    },

    /* API function pointers */
    mx_init,
    mx_strerror,
    mx_get_devices,
    mx_free_devices,
    mx_create_endpoint,
    mx_destroy_endpoint,
    mx_bind,
    mx_unbind,
    mx_get_conn_req,
    mx_accept,
    mx_reject,
    mx_connect,
    mx_disconnect,
    mx_set_opt,
    mx_get_opt,
    mx_arm_os_handle,
    mx_get_event,
    mx_return_event,
    mx_send,
    mx_sendv,
    mx_rma_register,
    mx_rma_register_phys,
    mx_rma_deregister,
    mx_rma
};


static int mx_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    printf("In mx_init\n");
    return CCI_SUCCESS;
}


static const char *mx_strerror(enum cci_status status)
{
    printf("In mx_sterrror\n");
    return NULL;
}


static int mx_get_devices(cci_device_t const ***devices)
{
    printf("In mx_get_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_free_devices(cci_device_t const **devices)
{
    printf("In mx_free_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd)
{
    printf("In mx_create_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_destroy_endpoint(cci_endpoint_t *endpoint)
{
    printf("In mx_destroy_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd)
{
    printf("In mx_bind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_unbind(cci_service_t *service, cci_device_t *device)
{
    printf("In mx_unbind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req)
{
    printf("In mx_get_conn_req\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection)
{
    printf("In mx_accept\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_reject(cci_conn_req_t *conn_req)
{
    printf("In mx_reject\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout)
{
    printf("In mx_connect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_disconnect(cci_connection_t *connection)
{
    printf("In mx_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len)
{
    printf("In mx_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len)
{
    printf("In mx_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    printf("In mx_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags)
{
    printf("In mx_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event)
{
    printf("In mx_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags)
{
    printf("In mx_send\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags)
{
    printf("In mx_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle)
{
    printf("In mx_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle)
{
    printf("In mx_rma_register_phys\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma_deregister(uint64_t rma_handle)
{
    printf("In mx_rma_deregister\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
                        uint64_t local_handle, uint64_t local_offset, 
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
    printf("In mx_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}
