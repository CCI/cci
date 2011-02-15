/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_template.h"


/*
 * Local functions
 */
static int template_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *template_strerror(enum cci_status status);
static int template_get_devices(cci_device_t const ***devices);
static int template_free_devices(cci_device_t const **devices);
static int template_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd);
static int template_destroy_endpoint(cci_endpoint_t *endpoint);
static int template_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd);
static int template_unbind(cci_service_t *service, cci_device_t *device);
static int template_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req);
static int template_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection);
static int template_reject(cci_conn_req_t *conn_req);
static int template_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout);
static int template_disconnect(cci_connection_t *connection);
static int template_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len);
static int template_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len);
static int template_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int template_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags);
static int template_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event);
static int template_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags);
static int template_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags);
static int template_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle);
static int template_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle);
static int template_rma_deregister(uint64_t rma_handle);
static int template_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
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
cci_plugin_core_t cci_core_template_plugin = {
    {
        /* Logistics */
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "template",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,
        
        /* Bootstrap function pointers */
        cci_core_template_post_load,
        cci_core_template_pre_unload,
    },

    /* API function pointers */
    template_init,
    template_strerror,
    template_get_devices,
    template_free_devices,
    template_create_endpoint,
    template_destroy_endpoint,
    template_bind,
    template_unbind,
    template_get_conn_req,
    template_accept,
    template_reject,
    template_connect,
    template_disconnect,
    template_set_opt,
    template_get_opt,
    template_arm_os_handle,
    template_get_event,
    template_return_event,
    template_send,
    template_sendv,
    template_rma_register,
    template_rma_register_phys,
    template_rma_deregister,
    template_rma
};


static int template_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    printf("In template_init\n");
    return CCI_SUCCESS;
}


static const char *template_strerror(enum cci_status status)
{
    printf("In template_sterrror\n");
    return NULL;
}


static int template_get_devices(cci_device_t const ***devices)
{
    printf("In template_get_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_free_devices(cci_device_t const **devices)
{
    printf("In template_free_devices\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd)
{
    printf("In template_create_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_destroy_endpoint(cci_endpoint_t *endpoint)
{
    printf("In template_destroy_endpoint\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd)
{
    printf("In template_bind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_unbind(cci_service_t *service, cci_device_t *device)
{
    printf("In template_unbind\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req)
{
    printf("In template_get_conn_req\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection)
{
    printf("In template_accept\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_reject(cci_conn_req_t *conn_req)
{
    printf("In template_reject\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout)
{
    printf("In template_connect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_disconnect(cci_connection_t *connection)
{
    printf("In template_disconnect\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len)
{
    printf("In template_set_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len)
{
    printf("In template_get_opt\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    printf("In template_arm_os_handle\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags)
{
    printf("In template_get_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event)
{
    printf("In template_return_event\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags)
{
    printf("In template_send\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags)
{
    printf("In template_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle)
{
    printf("In template_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle)
{
    printf("In template_rma_register_phys\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_rma_deregister(uint64_t rma_handle)
{
    printf("In template_rma_deregister\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int template_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
                        uint64_t local_handle, uint64_t local_offset, 
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
    printf("In template_rma\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}
