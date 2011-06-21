/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_mx.h"

volatile int mx_shut_down = 0;
mx_globals_t *mglobals = NULL;

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
                          struct iovec *data, uint8_t iovcnt,
                          void *context, int flags);
static int mx_rma_register(cci_endpoint_t *endpoint,
                           cci_connection_t *connection,
                           void *start, uint64_t length,
                           uint64_t *rma_handle);
static int mx_rma_register_phys(cci_endpoint_t *endpoint,
                                cci_connection_t *connection,
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
    int             ret;
    int             init    = 0;
    cci__dev_t      *dev;
    cci_device_t    **devices;

    CCI_ENTER;

    ret = mx_init();
    if (ret != MX_SUCCESS) {
        debug(CCI_DB_WARN, "mx_init() returned %s", mx_strerror(ret));
        ret = CCI_ENODEV;
        goto out;
    }

    init = 1;

    mglobals = calloc(1, sizeof(*mglobals));
    if (!mglobals) {
        ret = CCI_ENOMEM;
        goto out;
    }

    devices = calloc(CCI_MAX_DEVICES, sizeof(*mglobals->devices));
    if (!devices) {
        ret = CCI_ENOMEM;
        goto out;
    }

    /* find devices that we own */

    TAILQ_FOREACH(dev, &globals->devs, entry) {
        if (0 == strcmp("mx", dev->driver)) {
            const char **arg;
            cci_device_t *device;
            mx_dev_t *mdev;

            device = &dev->device;
            device->max_send_size = MX_MSS;

            /* TODO determine link rate */
            device->rate = 10000000000ULL;

            device->pci.domain = -1;    /* per CCI spec */
            device->pci.bus = -1;       /* per CCI spec */
            device->pci.dev = -1;       /* per CCI spec */
            device->pci.func = -1;      /* per CCI spec */

            dev->priv = calloc(1, sizeof(*mdev));
            if (!dev->priv) {
                ret = CCI_ENOMEM;
                goto out;
            }

            mdev->is_progressing = 0;

            /* parse conf_argv */
            for (arg = device->conf_argv;
                 *arg != NULL;
                 arg++) {
                if (0 == strncmp("mtu=", *arg, 4)) {
                    const char *mss_str = *arg + 4;
                    uint32_t mss = strtol(mss_str, NULL, 0);

                    assert(mss == MX_MSS);
                    device->max_send_size = mss;
                }
            }
            devices[mglobals->count] = device;
            mglobals->count++;
            dev->is_up = 1;
        }
    }

    devices = realloc(devices, (mglobals->count + 1) * sizeof(cci_device_t *));
    devices[mglobals->count] = NULL;

    *((cci_device_t ***) &mglobals->devices) = devices;

out:
    if (ret) {
        if (devices) {
            cci_device_t const *device;
            cci__dev_t *dev;

            for (device = devices[0];
                 device != NULL;
                 device++) {
                dev = container_of(device, cci__dev_t, device);
                if (dev->priv)
                    free(dev->priv);
            }
            free(devices);
        }

        if (mglobals) {
            free(mglobals);
            mglobals = NULL;
        }

        if (init)
            mx_finalize();
    }

    CCI_EXIT;
    return ret;
}


static const char *mx_strerror(enum cci_status status)
{
    CCI_ENTER;

    CCI_EXIT;
    return NULL;
}


static int mx_get_devices(cci_device_t const ***devices)
{
    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    *devices = mglobals->devices;

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int mx_free_devices(cci_device_t const **devices)
{
    CCI_ENTER;

    pthread_mutex_lock(&globals->lock);
    mx_shut_down = 1;
    pthread_mutex_unlock(&globals->lock);

    pthread_mutex_lock(&globals->lock);
    TAILQ_FOREACH(dev, &globals->devs, entry)
        free(dev->priv);
    pthread_mutex_unlock(&globals->lock);

    free(mglobals->devices);
    free((void *) mglobals);

    CCI_EXIT;
    return CCI_SUCCESS;
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
                          struct iovec *data, uint8_t iovcnt,
                          void *context, int flags)
{
    printf("In mx_sendv\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma_register(cci_endpoint_t *endpoint,
                           cci_connection_t *connection,
                           void *start, uint64_t length,
                           uint64_t *rma_handle)
{
    printf("In mx_rma_register\n");
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int mx_rma_register_phys(cci_endpoint_t *endpoint,
                                cci_connection_t *connection,
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
