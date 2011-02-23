/*
 * Copyright (c) 2010-2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2010-2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_sock.h"

sock_globals_t *sglobals = NULL;

/*
 * Local functions
 */
static int sock_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *sock_strerror(enum cci_status status);
static int sock_get_devices(cci_device_t const ***devices);
static int sock_free_devices(cci_device_t const **devices);
static int sock_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd);
static int sock_destroy_endpoint(cci_endpoint_t *endpoint);
static int sock_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd);
static int sock_unbind(cci_service_t *service, cci_device_t *device);
static int sock_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req);
static int sock_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection);
static int sock_reject(cci_conn_req_t *conn_req);
static int sock_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout);
static int sock_disconnect(cci_connection_t *connection);
static int sock_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len);
static int sock_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len);
static int sock_arm_os_handle(cci_endpoint_t *endpoint, int flags);
static int sock_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags);
static int sock_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event);
static int sock_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags);
static int sock_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags);
static int sock_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle);
static int sock_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle);
static int sock_rma_deregister(uint64_t rma_handle);
static int sock_rma(cci_connection_t *connection, 
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
cci_plugin_core_t cci_core_sock_plugin = {
    {
        /* Logistics */
        CCI_ABI_VERSION,
        CCI_CORE_API_VERSION,
        "sock",
        CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
        5,
        
        /* Bootstrap function pointers */
        cci_core_sock_post_load,
        cci_core_sock_pre_unload,
    },

    /* API function pointers */
    sock_init,
    sock_strerror,
    sock_get_devices,
    sock_free_devices,
    sock_create_endpoint,
    sock_destroy_endpoint,
    sock_bind,
    sock_unbind,
    sock_get_conn_req,
    sock_accept,
    sock_reject,
    sock_connect,
    sock_disconnect,
    sock_set_opt,
    sock_get_opt,
    sock_arm_os_handle,
    sock_get_event,
    sock_return_event,
    sock_send,
    sock_sendv,
    sock_rma_register,
    sock_rma_register_phys,
    sock_rma_deregister,
    sock_rma
};


static int sock_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    cci__dev_t *dev;

    fprintf(stderr, "In sock_init\n");

    /* init sock globals */
    sglobals = calloc(1, sizeof(*sglobals));
    if (!sglobals)
        return CCI_ENOMEM;

    /* FIXME magic number */
    sglobals->devices = calloc(32, sizeof(*sglobals->devices));

    /* find devices that we own */

    TAILQ_FOREACH(dev, &globals->devs, entry) {
        if (0 == strcmp("sock", dev->driver)) {
            int i;
            const char *arg;
            cci_device_t *device;
            sock_dev_t *sdev;

            device = &dev->device;
            device->max_send_size = SOCK_AM_SIZE;

            /* TODO determine link rate
             *
             * linux->driver->get ethtool settings->speed
             * bsd/darwin->ioctl(SIOCGIFMEDIA)->ifm_active
             * windows ?
             */
            device->rate = 10000000000;

            device->pci.domain = -1;    /* per CCI spec */
            device->pci.bus = -1;       /* per CCI spec */
            device->pci.dev = -1;       /* per CCI spec */
            device->pci.func = -1;      /* per CCI spec */

            dev->priv = calloc(1, sizeof(*dev->priv));
            if (!dev->priv)
                return CCI_ENOMEM;

            sdev = dev->priv;
            TAILQ_INIT(&sdev->queued);
            TAILQ_INIT(&sdev->pending);
            pthread_mutex_init(&sdev->lock, NULL);

            /* parse conf_argv */
            for (i = 0, arg = device->conf_argv[i];
                 arg != NULL; 
                 i++, arg = device->conf_argv[i]) {
                if (0 == strncmp("ip=", arg, 3)) {
                    const char *ip = &arg[3];

                    sdev->ip= inet_addr(ip); /* network order */
                }
            }
            if (sdev->ip!= 0) {
                sglobals->devices[sglobals->count] = device;
                sglobals->count++;
                dev->is_up = 1;
            }

            /* TODO determine if IP is available and up */
        }
    }

    sglobals->devices = realloc(sglobals->devices,
                                (sglobals->count + 1) * sizeof(cci_device_t *));

    return CCI_SUCCESS;
}


static const char *sock_strerror(enum cci_status status)
{
    printf("In sock_sterrror\n");
    return NULL;
}


static int sock_get_devices(cci_device_t const ***devices)
{
    printf("In sock_get_devices\n");

    if (!sglobals)
        return CCI_ENODEV;

    *devices = sglobals->devices;

    return CCI_SUCCESS;
}


static int sock_free_devices(cci_device_t const **devices)
{
    printf("In sock_free_devices\n");

    if (!sglobals)
        return CCI_ENODEV;

    /* tear everything down */

    /* for each device
     *     for each endpoint
     *         for each connection
     *             close conn
     *         for each tx/rx
     *             free it
     *         close socket
     *     for each listening endpoint
     *         remove from service
     *         for each conn_req
     *             free it
     *         close socket
     */

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd)
{
    int i, ret;
    cci__dev_t *dev;
    cci__ep_t *ep;
    sock_ep_t *sep;

    printf("In sock_create_endpoint\n");

    if (!sglobals)
        return CCI_ENODEV;

    dev = container_of(device, cci__dev_t, device);
    if (0 != strcmp("sock", dev->driver)) {
        ret = CCI_EINVAL;
        goto out;
    }

    ep = container_of(*endpoint, cci__ep_t, endpoint);
    ep->priv = calloc(1, sizeof(*sep));
    if (!ep->priv) {
        ret = CCI_ENOMEM;
        goto out;
    }

    (*endpoint)->max_recv_buffer_count = SOCK_EP_RX_CNT;
    ep->max_hdr_size = SOCK_EP_MAX_HDR_SIZE;
    ep->rx_buf_cnt = SOCK_EP_RX_CNT;
    ep->tx_buf_cnt = SOCK_EP_TX_CNT;
    ep->buffer_len = SOCK_EP_BUF_LEN;
    ep->tx_timeout = SOCK_EP_TX_TIMEOUT;

    sep = ep->priv;

    sep->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sep->sock == -1) {
        ret = errno;
        goto out;
    }

    for (i = 0; i < SOCK_EP_HASH_SIZE; i++)
        TAILQ_INIT(&sep->conn_hash[i]);

    TAILQ_INIT(&sep->txs);
    TAILQ_INIT(&sep->idle_txs);
    TAILQ_INIT(&sep->rxs);
    TAILQ_INIT(&sep->idle_rxs);
    pthread_mutex_init(&sep->lock, NULL);

    return CCI_SUCCESS;

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE(&dev->eps, ep, entry);
    pthread_mutex_unlock(&dev->lock);
    if (ep->priv)
        free(ep->priv);
    free(ep);
    *endpoint = NULL;
    return ret;
}


static int sock_destroy_endpoint(cci_endpoint_t *endpoint)
{
    printf("In sock_destroy_endpoint\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}

/*! sock_bind()
 *
 * device, port, service are always set
 */
static int sock_bind(cci_device_t *device, int backlog, uint32_t *port, 
                         cci_service_t **service, cci_os_handle_t *fd)
{
    int ret;
    cci__dev_t *dev;
    cci__svc_t *svc;
    cci__lep_t *lep;
    sock_dev_t *sdev;
    sock_lep_t *slep;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    printf("In sock_bind\n");

    if (!sglobals)
        return CCI_ENODEV;

    dev = container_of(device, cci__dev_t, device);
    if (0 != strcmp("sock", dev->driver)) {
        ret = CCI_EINVAL;
        goto out;
    }

    if (*port > (64 * 1024))
        return CCI_ERANGE;

    svc = container_of(*service, cci__svc_t, service);
    TAILQ_FOREACH(lep, &svc->leps, sentry) {
        if (lep->dev == dev) {
            break;
        }
    }

    /* allocate sock listening endpoint */
    slep = calloc(1, sizeof(*slep));
    if (!slep)
        return CCI_ENOMEM;

    /* open socket */
    slep->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (slep->sock == -1) {
        ret = errno;
        goto out;
    }

    /* bind socket to device and port */
    sdev = dev->priv;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) *port);
    sin.sin_addr.s_addr = sdev->ip;

    ret = bind(slep->sock, (const struct sockaddr *) &sin, len);
    if (ret) {
        ret = errno;
        goto out;
    }

    /* create OS handle */
    /* TODO */

    lep->priv = slep;

    return CCI_SUCCESS;

out:
    if (slep)
        free(slep);
    return ret;
}


static int sock_unbind(cci_service_t *service, cci_device_t *device)
{
    printf("In sock_unbind\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req)
{
    printf("In sock_get_conn_req\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection)
{
    printf("In sock_accept\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_reject(cci_conn_req_t *conn_req)
{
    printf("In sock_reject\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout)
{
    printf("In sock_connect\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_disconnect(cci_connection_t *connection)
{
    printf("In sock_disconnect\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len)
{
    printf("In sock_set_opt\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len)
{
    printf("In sock_get_opt\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    printf("In sock_arm_os_handle\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_get_event(cci_endpoint_t *endpoint, 
                              cci_event_t ** const event,
                              uint32_t flags)
{
    printf("In sock_get_event\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event)
{
    printf("In sock_return_event\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_sendto(cci_os_handle_t sock, void *buf, int len,
                       const struct sockaddr_in *sin)
{
    int ret = 0;
    int left = len;
    const struct sockaddr *s = (const struct sockaddr *)sin;
    socklen_t slen = sizeof(*sin);

    while (left) {
        int offset = len - left;
        ret = sendto(sock, buf + offset, left, 0, s, slen);
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            else {
                ret = errno;
            goto out;
            }
        }
        offset += ret;
        left -= ret;
    }
out:
        return ret;
}

static int sock_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags)
{
    int ret;
    cci_endpoint_t *endpoint = connection->endpoint;
    cci__ep_t *ep;
    cci__conn_t *conn;
    sock_ep_t *sep;
    sock_conn_t *sconn;
    sock_tx_t *tx;
    sock_header_t *hdr;
    void *ptr;

    printf("In sock_send\n");

    if (!sglobals)
        return CCI_ENODEV;

    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    conn = container_of(connection, cci__conn_t, connection);
    sconn = conn->priv;

    /* is conn unreliable? */
    if (!(connection->attribute & CCI_CONN_ATTR_RO ||
          connection->attribute & CCI_CONN_ATTR_RU)) {
        int len;
        char *buffer;

        len = sizeof(sock_header_t) + header_len + data_len;
        buffer = calloc(len, sizeof(char));
        if (!buffer)
            return CCI_ENOMEM;

        /* pack buffer */

        hdr = (sock_header_t *) tx->buffer;
        sock_pack_send(hdr, header_len, data_len, sconn->peer_id);
        ptr = hdr++;
        tx->len = len;

        if (header_len) {
            memcpy(ptr, header_ptr, header_len);
            ptr += header_len;
        }
        if (data_len)
            memcpy(ptr, data_ptr, data_len);

        /* try to send */
        ret = sock_sendto(sep->sock, buffer, len, &sconn->sin);
        free(buffer);
        if (ret == 0)
            return CCI_SUCCESS;

        /* if error, fall through */
    }

    /* get a tx */
    pthread_mutex_lock(&sep->lock);
    if (!TAILQ_EMPTY(&sep->idle_txs)) {
        tx = TAILQ_FIRST(&sep->idle_txs);
        TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&sep->lock);

    if (!tx)
        return CCI_EAGAIN;

    /* pack buffer */

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint segment_cnt, void *context, int flags)
{
    printf("In sock_sendv\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle)
{
    printf("In sock_rma_register\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle)
{
    printf("In sock_rma_register_phys\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma_deregister(uint64_t rma_handle)
{
    printf("In sock_rma_deregister\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
                        uint64_t local_handle, uint64_t local_offset, 
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
    printf("In sock_rma\n");

    if (!sglobals)
        return CCI_ENODEV;

    return CCI_ERR_NOT_IMPLEMENTED;
}
