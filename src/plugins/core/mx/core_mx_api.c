/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <assert.h>

#include "cci.h"
#include "plugins/core/core.h"
#include "core_mx.h"

volatile int mx_shut_down = 0;
mx_globals_t *mglobals = NULL;

/*
 * Local functions
 */
static int mx__init(uint32_t abi_ver, uint32_t flags, uint32_t *caps);
static const char *mx__strerror(enum cci_status status);
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
static int mx__connect(cci_endpoint_t *endpoint, char *server_uri,
                            uint32_t port,
                            void *data_ptr, uint32_t data_len,
                            cci_conn_attribute_t attribute,
                            void *context, int flags,
                            struct timeval *timeout);
static int mx__disconnect(cci_connection_t *connection);
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
    mx__init,
    mx__strerror,
    mx_get_devices,
    mx_free_devices,
    mx_create_endpoint,
    mx_destroy_endpoint,
    mx_bind,
    mx_unbind,
    mx_get_conn_req,
    mx_accept,
    mx_reject,
    mx__connect,
    mx__disconnect,
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


static int
mx__init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
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


static const char *mx__strerror(enum cci_status status)
{
    CCI_ENTER;

    CCI_EXIT;
    return NULL;
}


static int
mx_get_devices(cci_device_t const ***devices)
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


static int
mx_free_devices(cci_device_t const **devices)
{
    cci__dev_t  *dev;

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

/* Caller must be holding ep->lock */
static int
mx_add_tx(cci__ep_t *ep)
{
    int         ret     = 1;
    mx_ep_t     *mep    = ep->priv;
    mx_tx_t     *tx;

    tx = calloc(1, sizeof(*tx));
    if (!tx) {
        ret = 0;
        goto out;
    }
    tx->evt.event.type = CCI_EVENT_SEND;
    tx->evt.ep = ep;

    ret = 1;
    TAILQ_INSERT_TAIL(&mep->txs, tx, tentry);
    TAILQ_INSERT_TAIL(&mep->idle_txs, tx, dentry);

out:
    return ret;
}

/* Caller must be holding ep->lock */
static int
mx_add_rx(cci__ep_t *ep)
{
    int         ret     = 1;
    mx_ep_t     *mep    = ep->priv;
    mx_rx_t     *rx;

    rx = calloc(1, sizeof(*rx));
    if (!rx) {
        ret = 0;
        goto out;
    }

    rx->buffer = calloc(1, MX_MSS);
    if (!rx->buffer) {
        free(rx);
        ret = 0;
        goto out;
    }

    rx->evt.event.type = CCI_EVENT_RECV;
    rx->evt.ep = ep;
    TAILQ_INSERT_TAIL(&mep->rxs, rx, gentry);
    TAILQ_INSERT_TAIL(&mep->idle_rxs, rx, entry);
out:
    return ret;
}

/* Free a tx.
 *
 * \param[in] mep   Portals endpoint
 * \param[in] force If force, selct from all txs
 *                  otherwise, only select from idle txs
 *
 * Only use force if closeing the endpoint and we do not
 * casre if the application is holding an event (tx).
 *
 * Caller must be holding ep->lock.
 */
static int
mx_free_tx(mx_ep_t *mep, int force)
{
    mx_tx_t    *tx;

    if (force)
        tx = TAILQ_FIRST(&mep->txs);
    else
        tx = TAILQ_FIRST(&mep->idle_txs);

    if (!tx)
        return 0;

    TAILQ_REMOVE(&mep->txs, tx, tentry);
    TAILQ_REMOVE(&mep->idle_txs, tx, dentry);
    free(tx);

    return 1;
}

/* Free a rx.
 *
 * \param[in] mep    Portals endpoint
 * \param[in] force If force, selct from all rxs
 *                  otherwise, only select from idle rxs
 *
 * Only use force if closeing the endpoint and we do not
 * casre if the application is holding an event (rx).
 *
 * Caller must be holding ep->lock.
 */
static int
mx_free_rx(mx_ep_t *mep, int force)
{
    mx_rx_t    *rx;

    if (force)
        rx = TAILQ_FIRST(&mep->rxs);
    else
        rx = TAILQ_FIRST(&mep->idle_rxs);

    if (!rx)
        return 0;

    TAILQ_REMOVE(&mep->rxs, rx, gentry);
    TAILQ_REMOVE(&mep->idle_rxs, rx, entry);
    if (rx->buffer)
        free(rx->buffer);
    free(rx);
    return 1;
}


static int
mx_create_endpoint(cci_device_t *device,
                   int flags,
                   cci_endpoint_t **endpoint,
                   cci_os_handle_t *fd)
{
    int i, ret;
    cci__dev_t *dev = NULL;
    cci__ep_t *ep = NULL;
    mx_ep_t *mep = NULL;
    mx_dev_t *mdev;


    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev = container_of(device, cci__dev_t, device);
    if (0 != strcmp("mx", dev->driver)) {
        ret = CCI_EINVAL;
        goto out;
    }
    mdev = dev->priv;

    ep = container_of(*endpoint, cci__ep_t, endpoint);
    ep->priv = calloc(1, sizeof(*mep));
    if (!ep->priv) {
        ret = CCI_ENOMEM;
        goto out;
    }
    mep = ep->priv;

    (*endpoint)->max_recv_buffer_count = MX_EP_RX_CNT;
    ep->max_hdr_size = MX_EP_MAX_HDR_SIZE;
    ep->rx_buf_cnt = MX_EP_RX_CNT;
    ep->tx_buf_cnt = MX_EP_TX_CNT;
    ep->buffer_len = dev->device.max_send_size;
    ep->tx_timeout = MX_EP_TX_TIMEOUT_MS * 1000;

    TAILQ_INIT(&mep->txs);
    TAILQ_INIT(&mep->idle_txs);
    TAILQ_INIT(&mep->rxs);
    TAILQ_INIT(&mep->idle_rxs);
    TAILQ_INIT(&mep->conns);

    ret = mx_open_endpoint(mdev->board, MX_ANY_ENDPOINT, MX_KEY, NULL, 0, &mep->ep);
    if (ret) {
        debug(CCI_DB_DRVR, "open_endpoint() returned %s", mx_strerror(ret));
        ret = CCI_ERROR;
        goto out;
    }

    for (i = 0; i < ep->tx_buf_cnt; i++) {
        ret = mx_add_tx(ep);
        if (ret != 1) {
            ret = CCI_ENOMEM;
            goto out;
        }
    }

    for (i = 0; i < ep->rx_buf_cnt; i++) {
        ret = mx_add_rx(ep);
        if (ret != 1) {
            ret = CCI_ENOMEM;
            goto out;
        }
    }

    CCI_EXIT;
out:
    if (ret) {
        if (mep) {
            if (mep->ep)
                mx_close_endpoint(mep->ep);

            while(!TAILQ_EMPTY(&mep->txs))
                mx_free_tx(mep, 1);

            while(!TAILQ_EMPTY(&mep->rxs))
                mx_free_rx(mep, 1);

            free(mep);
            ep->priv = NULL;
        }
    }
    return ret;
}


static int
mx_destroy_endpoint(cci_endpoint_t *endpoint)
{
    cci__ep_t   *ep     = NULL;
    cci__dev_t  *dev    = NULL;
    mx_ep_t     *mep    = NULL;
    mx_dev_t    *mdev   = NULL;

    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    dev = ep->dev;
    mep = ep->priv;
    mdev = dev->priv;

    pthread_mutex_lock(&dev->lock);
    pthread_mutex_lock(&ep->lock);

    ep->priv = NULL;

    if (mep) {
        if (mep->ep)
            mx_close_endpoint(mep->ep);

        while(!TAILQ_EMPTY(&mep->txs))
            mx_free_tx(mep, 1);

        while(!TAILQ_EMPTY(&mep->rxs))
            mx_free_rx(mep, 1);

        free(mep);
        ep->priv = NULL;
    }

    pthread_mutex_unlock(&ep->lock);
    pthread_mutex_unlock(&dev->lock);

    CCI_EXIT;
    return CCI_SUCCESS;
}


static int
mx_bind(cci_device_t *device, int backlog, uint32_t *port,
        cci_service_t **service, cci_os_handle_t *fd)
{
    int             ret;
    cci__dev_t      *dev;
    cci__svc_t      *svc;
    cci__lep_t      *lep;
    cci__crq_t      *crq;
    mx_dev_t        *mdev;
    mx_lep_t        *mlep;
    mx_crq_t        *mcrq;

    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev = container_of(device, cci__dev_t, device);
    if (strcmp("mx", dev->driver)) {
        ret = CCI_EINVAL;
        goto out;
    }
    mdev = dev->priv;

    svc = container_of(*service, cci__svc_t, service);
    TAILQ_FOREACH(lep, &svc->leps, sentry) {
        if (lep->dev == dev)
            break;
    }

    /* allocate mx listening endpoint */
    if (!(mlep = calloc(1, sizeof(*mlep)))) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    ret = mx_open_endpoint(mdev->board, *port, MX_KEY, NULL, 0, &mlep->ep);
    if (ret) {
        debug(CCI_DB_DRVR, "open_endpoint() returned %s", mx_strerror(ret));
        ret = CCI_ERROR;
        goto out;
    }

    /* alloc portal for each cci__crq_t */
    TAILQ_FOREACH(crq, &lep->crqs, entry) {
        if(!(crq->priv = calloc(1, sizeof(*mcrq)))) {
            ret = CCI_ENOMEM;
            goto out;
        }
        mcrq = crq->priv;
        mcrq->buffer = calloc(1, 1024);
        if (!mcrq->buffer) {
            ret = CCI_ENOMEM;
            goto out;
        }
    }

    lep->priv = mlep;

out:
    CCI_EXIT;
    if (ret) {
        TAILQ_FOREACH(crq, &lep->crqs, entry) {
            if (crq->priv) {
                if (crq->priv) {
                    mcrq = crq->priv;
                    if (mcrq->buffer)
                        free(mcrq->buffer);
                    free(mcrq);
                    crq->priv = NULL;
                }
            }
        }

        if (mlep) {
            if (mlep->ep)
                mx_close_endpoint(mlep->ep);
            free(mlep);
        }
    }
    return CCI_SUCCESS;
}


static int
mx_unbind(cci_service_t *service, cci_device_t *device)
{
    CCI_ENTER;

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


/* currently never called */
static int
mx_get_conn_req(cci_service_t *service,
                cci_conn_req_t **conn_req)
{
    CCI_ENTER;

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_accept(cci_conn_req_t *conn_req,
          cci_endpoint_t *endpoint,
          cci_connection_t **connection)
{
    int             ret;
    cci__ep_t       *ep     = NULL;
    cci__dev_t      *dev    = NULL;
    cci__conn_t     *conn   = NULL;
    cci__crq_t      *crq    = NULL;
    cci__lep_t      *lep    = NULL;
    mx_ep_t         *mep    = NULL;
    mx_dev_t        *mdev   = NULL;
    mx_crq_t        *mcrq   = NULL;
    mx_conn_t       *mconn  = NULL;
    mx_conn_accept_t accept;
    mx_tx_t         *tx     = NULL;
    uint64_t        bits    = 0ULL;
    mx_segment_t    mxseg;
    mx_request_t    mxreq;

    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    mep = ep->priv;
    crq = container_of(conn_req, cci__crq_t, conn_req);
    mcrq = crq->priv;
    dev = ep->dev;
    mdev = dev->priv;
    lep = crq->lep;

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        ret = CCI_ENOMEM;
        goto out_with_crq;
    }

    conn->tx_timeout = ep->tx_timeout;
    conn->priv = calloc(1, sizeof(*mconn));
    if (!conn->priv) {
        ret = CCI_ENOMEM;
        goto out_with_conn;
    }
    mconn = conn->priv;
    mconn->conn = conn;

    /* prepare accept msg */

    accept.max_recv_buffer_count = mcrq->max_recv_buffer_count;
    accept.server_conn_upper = (uint32_t)((uintptr_t)conn >> 32);
    accept.server_conn_lower = (uint32_t)((uintptr_t)conn & 0xFFFFFFFF);

    /* setup connection */

    conn->connection.attribute = crq->conn_req.attribute;
    conn->connection.endpoint = endpoint;
    conn->connection.max_send_size = dev->device.max_send_size;

    mconn->epa = mcrq->epa;
    mconn->peer_conn = mcrq->client_conn;
    mconn->peer_ep_id = mcrq->client_id;
    mconn->max_tx_cnt = mcrq->max_recv_buffer_count;

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&mep->conns, mconn, entry);
    pthread_mutex_unlock(&ep->lock);

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&mep->idle_txs)) {
        tx = TAILQ_FIRST(&mep->idle_txs);
        TAILQ_REMOVE(&mep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        ret = CCI_ENOBUFS;
        goto out_with_conn;
    }

    /* prep the tx */
    tx->msg_type = MX_MSG_OOB;
    tx->oob_type = MX_MSG_OOB_CONN_REPLY;

    tx->evt.ep = ep;
    tx->evt.conn = conn;
    tx->evt.event.type = CCI_EVENT_SEND;

    bits = ((uint64_t) mconn->peer_ep_id) << MX_EP_SHIFT;
    bits |= ((uint64_t) MX_MSG_OOB_CONN_REPLY) << 2;
    bits |= (uint64_t) MX_MSG_OOB;

    mxseg.segment_ptr = &accept;
    mxseg.segment_length = sizeof(accept);

    ret = mx_isend(mep->ep, &mxseg, 1, mconn->epa, bits, tx, &mxreq);
    if (ret) {
        ret = CCI_ERROR;
        goto out_with_conn;
    }

    pthread_mutex_lock(&lep->lock);
    TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
    pthread_mutex_unlock(&lep->lock);

    *connection = &conn->connection;

    CCI_EXIT;
    return CCI_SUCCESS;

out_with_conn:
    free(conn);
out_with_crq:
    pthread_mutex_lock(&lep->lock);
    TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
    pthread_mutex_unlock(&lep->lock);

    return ret;
}


static int
mx_reject(cci_conn_req_t *conn_req)
{
    CCI_ENTER;

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}

/* valid MX uris:
 * mx://hostname
 * mx://hostname:board
 * mx://hostname:board:ep_id
 */
static int
mx_parse_uri(char *uri,
             char **mx_hostname, /* hostname or hostname:board_index */
             uint32_t *board,   /* board index */
             uint32_t *ep_id)
{
    int  ret        = CCI_SUCCESS;
    char *hostname  = NULL;
    char *colon     = NULL;
    char *rcolon    = NULL;

    CCI_ENTER;

    if (!strncmp("mx://", uri, 4)) {
        hostname = strdup(&uri[4]);
        if (!hostname)
            return CCI_ENOMEM;
    } else {
        CCI_EXIT;
        return CCI_EINVAL;
    }

    colon = strchr(hostname, ':');
    rcolon = strrchr(hostname, ':');
    if (colon && rcolon && colon == rcolon) {
        /* mx://hostname:board */
        *ep_id = 0;

        rcolon++;
        if (*rcolon == '\0') {
            /* mx://hostname: */
            ret = CCI_EINVAL;
            goto out;
        }
        *board = strtoul(rcolon, NULL, 0);
    } else if (colon && rcolon && colon != rcolon) {
        /* mx://hostname:board:ep_id */
        *rcolon = '\0';
        rcolon++;
        if (rcolon == NULL) {
            ret = CCI_EINVAL;
            goto out;
        }
        *ep_id = strtoul(rcolon, NULL, 0);
        colon++;
        if (colon == NULL) {
            /* mx://hostname::ep_id */
            ret = CCI_EINVAL;
            goto out;
        }
        *board = strtoul(colon, NULL, 0);
    } else if (colon) {
        /* mx://hostname:board */
        colon++;
        if (*colon == '\0') {
            /* mx://hostname: */
            ret = CCI_EINVAL;
            goto out;
        }
        *board = strtoul(colon, NULL, 0);
        *ep_id = 0;
    } else {
        /* mx:hostname */
        *board = 0;
        *ep_id = 0;
    }

out:
    CCI_EXIT;
    return ret;
}

static int
mx__connect(cci_endpoint_t *endpoint,
            char *server_uri,
            uint32_t port,
            void *data_ptr,
            uint32_t data_len,
            cci_conn_attribute_t attribute,
            void *context,
            int flags,
            struct timeval *timeout)
{
    int                 ret;
    cci__ep_t           *ep     = NULL;
    cci__dev_t          *dev    = NULL;
    cci__conn_t         *conn   = NULL;
    mx_ep_t             *mep    = NULL;
    mx_dev_t            *mdev   = NULL;
    cci_connection_t    *connection = NULL;
    mx_conn_t           *mconn  = NULL;
    mx_tx_t             *tx     = NULL;
    cci__evt_t          *evt    = NULL;
    cci_event_t         *event  = NULL;
    cci_event_other_t   *other  = NULL;
    char                *hostname;
    uint64_t            nic_id  = 0ULL;
    uint32_t            board   = 0;
    uint32_t            ep_id   = 0;
    mx_endpoint_addr_t  epa;
    mx_conn_request_t   conn_request;
    uint64_t            bits    = 0ULL;
    mx_segment_t        mxseg[2];
    int                 count   = 1;
    mx_request_t        mxreq;

    CCI_ENTER;

    if (!mglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    /* allocate a new connection */
    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    conn->priv = calloc(1, sizeof(*mconn));
    if(!conn->priv) {
        ret = CCI_ENOMEM;
        goto out;
    }
    mconn = conn->priv;
    mconn->conn = conn;

    /* conn->tx_timeout=0  by default */
    connection = &conn->connection;
    connection->attribute = attribute;
    connection->endpoint = endpoint;

    /* get our endpoint and device */
    ep = container_of(endpoint, cci__ep_t, endpoint);
    mep = ep->priv;
    dev = ep->dev;
    mdev = dev->priv;

    connection->max_send_size=dev->device.max_send_size;

    /* lookup epa */
    ret = mx_parse_uri(server_uri, &hostname, &board, &ep_id);
    ret = mx_hostname_to_nic_id(server_uri, &nic_id);
    mconn->epa = epa;

    /* get a tx */
    pthread_mutex_lock(&ep->lock);
    if(!TAILQ_EMPTY(&mep->idle_txs)) {
        tx = TAILQ_FIRST(&mep->idle_txs);
        TAILQ_REMOVE(&mep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&ep->lock);

    if(!tx) {
        ret = CCI_ENOBUFS;
        goto out;
    }

    /* prep the tx */
    tx->msg_type=MX_MSG_OOB;
    tx->oob_type=MX_MSG_OOB_CONN_REQUEST;
    mconn->tx = tx; /* we need its event for the accept|reject */

    evt=&tx->evt;
    evt->ep=ep;
    evt->conn=conn;
    event=&evt->event;
    event->type=CCI_EVENT_CONNECT_SUCCESS; /* for now */

    other=&event->info.other;
    other->context=context;
    other->u.connect.connection=connection;

    /* pack the bits */
    bits = ((uint64_t) port) << MX_EP_SHIFT;
    bits |= ((uint64_t) (data_len & 0xFFFF)) << 16;
    bits |= ((uint64_t) attribute) << 8;
    bits |= ((uint64_t) MX_MSG_OOB_CONN_REQUEST) << 2;
    bits |= (uint64_t) MX_MSG_OOB;

    /* pack the payload */
    conn_request.max_recv_buffer_count = endpoint->max_recv_buffer_count;
    conn_request.client_ep_id = mep->id;

    mxseg[0].segment_ptr = &conn_request;
    mxseg[0].segment_length = sizeof(conn_request);
    if (data_len) {
        mxseg[1].segment_ptr = data_ptr;
        mxseg[1].segment_length = data_len;
        count = 2;
    }

    ret = mx_isend(mep->ep, mxseg, count, mconn->epa, bits, tx, &mxreq);
    if (ret)
        ret = CCI_ERROR;

out:
    CCI_EXIT;

    if (ret) {
        if (conn) {
            if (conn->uri)
                free((char *)conn->uri);
            if (conn->priv)
                free(conn->priv);
            free(conn);
        }
    }

    return ret;
}


static int
mx__disconnect(cci_connection_t *connection)
{
    CCI_ENTER;

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_set_opt(cci_opt_handle_t *handle,
           cci_opt_level_t level,
           cci_opt_name_t name, const void* val, int len)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_get_opt(cci_opt_handle_t *handle,
           cci_opt_level_t level,
           cci_opt_name_t name, void** val, int *len)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_get_event(cci_endpoint_t *endpoint,
             cci_event_t ** const event,
             uint32_t flags)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_return_event(cci_endpoint_t *endpoint,
                cci_event_t *event)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_send(cci_connection_t *connection,
        void *header_ptr, uint32_t header_len,
        void *data_ptr, uint32_t data_len,
        void *context, int flags)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_sendv(cci_connection_t *connection,
         void *header_ptr, uint32_t header_len,
         struct iovec *data, uint8_t iovcnt,
         void *context, int flags)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_rma_register(cci_endpoint_t *endpoint,
                cci_connection_t *connection,
                void *start, uint64_t length,
                uint64_t *rma_handle)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_rma_register_phys(cci_endpoint_t *endpoint,
                     cci_connection_t *connection,
                     cci_sg_t *sg_list, uint32_t sg_cnt,
                     uint64_t *rma_handle)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_rma_deregister(uint64_t rma_handle)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int
mx_rma(cci_connection_t *connection,
       void *header_ptr, uint32_t header_len,
       uint64_t local_handle, uint64_t local_offset,
       uint64_t remote_handle, uint64_t remote_offset,
       uint64_t data_len, void *context, int flags)
{
    CCI_ENTER;

	CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}
