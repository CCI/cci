/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>

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
                          uint8_t segment_cnt, void *context, int flags);
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


static void sock_progress_sends(sock_dev_t *sdev);
static void *sock_progress_thread(void *arg);
static inline void sock_progress_dev(cci__dev_t *dev);
static int sock_sendto(cci_os_handle_t sock, void *buf, int len,
                       const struct sockaddr_in sin);

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

static inline void
sock_sin_to_name(struct sockaddr_in sin, char *buffer, int len)
{
    snprintf(buffer, len, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    return;
}

static inline const char *
sock_msg_type(sock_msg_type_t type)
{   
    switch (type) {
    case SOCK_MSG_CONN_REQUEST:
        return "conn_request";
    case SOCK_MSG_CONN_REPLY:
        return "conn_reply";
    case SOCK_MSG_CONN_ACK:
        return "conn_ack";
    case SOCK_MSG_DISCONNECT:
        return "disconnect";
    case SOCK_MSG_SEND:
        return "send";
    case SOCK_MSG_KEEPALIVE:
        return "keepalive";
    case SOCK_MSG_ACK_ONLY:
        return "ack_only";
    case SOCK_MSG_ACK_UP_TO:
        return "ack_up_to";
    case SOCK_MSG_SACK:
        return "selective ack";
    case SOCK_MSG_RMA_WRITE:
        return "RMA write";
    case SOCK_MSG_RMA_WRITE_DONE:
        return "RMA write done";
    case SOCK_MSG_RMA_READ_REQUEST:
        return "RMA read request";
    case SOCK_MSG_RMA_READ_REPLY:
        return "RMA read reply";
    case SOCK_MSG_INVALID:
        assert(0);
        return "invalid";
    case SOCK_MSG_TYPE_MAX:
        assert(0);
        return "type_max";
    }
    return NULL;
}


static int sock_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    int ret;
    cci__dev_t *dev;
    pthread_t pid;
    cci_device_t **devices;

    CCI_ENTER;

    /* init sock globals */
    sglobals = calloc(1, sizeof(*sglobals));
    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    srandomdev();

    devices = calloc(CCI_MAX_DEVICES, sizeof(*sglobals->devices));
    if (!devices) {
        ret = CCI_ENOMEM;
        goto out;
    }

    /* find devices that we own */

    TAILQ_FOREACH(dev, &globals->devs, entry) {
        if (0 == strcmp("sock", dev->driver)) {
            const char **arg;
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

            dev->priv = calloc(1, sizeof(*sdev));
            if (!dev->priv) {
                ret = CCI_ENOMEM;
                goto out;
            }

            sdev = dev->priv;
            TAILQ_INIT(&sdev->queued);
            TAILQ_INIT(&sdev->pending);
            pthread_mutex_init(&sdev->lock, NULL);
            sdev->is_progressing = 0;

            /* parse conf_argv */
            for (arg = device->conf_argv;
                 *arg != NULL; 
                 arg++) {
                if (0 == strncmp("ip=", *arg, 3)) {
                    const char *ip = *arg + 3;

                    sdev->ip= inet_addr(ip); /* network order */
                }
            }
            if (sdev->ip != 0) {
                devices[sglobals->count] = device;
                sglobals->count++;
                dev->is_up = 1;
            }

            /* TODO determine if IP is available and up */
        }
    }

    devices = realloc(devices, (sglobals->count + 1) * sizeof(cci_device_t *));
    devices[sglobals->count] = NULL;

    *((cci_device_t ***) &sglobals->devices) = devices;

    ret = pthread_create(&pid, NULL, sock_progress_thread, NULL);
    if (ret)
        goto out;

    CCI_EXIT;
    return CCI_SUCCESS;

out:
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
    if (sglobals) {
        free(sglobals);
        sglobals = NULL;
    }
    CCI_EXIT;
    return ret;
}


static const char *sock_strerror(enum cci_status status)
{
    CCI_ENTER;

    CCI_EXIT;
    return NULL;
}


static int sock_get_devices(cci_device_t const ***devices)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    *devices = sglobals->devices;

    CCI_EXIT;

    return CCI_SUCCESS;
}


static int sock_free_devices(cci_device_t const **devices)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

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

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}

static inline int
sock_set_nonblocking(cci_os_handle_t sock)
{
    int ret, flags;

    flags = fcntl(sock, F_GETFL, 0);
    if (-1 == flags)
        flags = 0;
    ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (-1 == ret)
        return errno;
    return 0;
}

static int sock_create_endpoint(cci_device_t *device, 
                                    int flags, 
                                    cci_endpoint_t **endpoint, 
                                    cci_os_handle_t *fd)
{
    int i, ret;
    cci__dev_t *dev = NULL;
    cci__ep_t *ep = NULL;
    sock_ep_t *sep = NULL;
    sock_dev_t *sdev;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

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
    ep->tx_timeout = SOCK_EP_TX_TIMEOUT_SEC * 1000000;

    sep = ep->priv;
    sep->ids = calloc(SOCK_NUM_BLOCKS, sizeof(*sep->ids));
    if (!sep->ids) {
        ret = CCI_ENOMEM;
        goto out;
    }

    sep->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sep->sock == -1) {
        ret = errno;
        goto out;
    }
    ret = sock_set_nonblocking(sep->sock);
    if (ret)
        goto out;

    /* bind socket to device */
    sdev = dev->priv;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = sdev->ip;

    ret = bind(sep->sock, (const struct sockaddr *) &sin, len);
    if (ret) {
        ret = errno;
        goto out;
    }

    for (i = 0; i < SOCK_EP_HASH_SIZE; i++) {
        TAILQ_INIT(&sep->conn_hash[i]);
        TAILQ_INIT(&sep->active_hash[i]);
    }

    TAILQ_INIT(&sep->txs);
    TAILQ_INIT(&sep->idle_txs);
    TAILQ_INIT(&sep->rxs);
    TAILQ_INIT(&sep->idle_rxs);
    pthread_mutex_init(&sep->lock, NULL);

    /* alloc txs */
    for (i = 0; i < ep->tx_buf_cnt; i++) {
        sock_tx_t *tx;

        tx = calloc(1, sizeof(*tx));
        if (!tx) {
            ret = CCI_ENOMEM;
            goto out;
        }
        tx->evt.event.type = CCI_EVENT_SEND;
        tx->evt.ep = ep;
        tx->buffer = malloc(ep->buffer_len);
        if (!tx->buffer) {
            ret = CCI_ENOMEM;
            goto out;
        }
        tx->len = 0;
        TAILQ_INSERT_TAIL(&sep->txs, tx, tentry);
        TAILQ_INSERT_TAIL(&sep->idle_txs, tx, dentry);
    }

    /* alloc rxs */
    for (i = 0; i < ep->rx_buf_cnt; i++) {
        sock_rx_t *rx;

        rx = calloc(1, sizeof(*rx));
        if (!rx) {
            ret = CCI_ENOMEM;
            goto out;
        }
        rx->evt.event.type = CCI_EVENT_RECV;
        rx->evt.ep = ep;
        rx->buffer = malloc(ep->buffer_len);
        if (!rx->buffer) {
            ret = CCI_ENOMEM;
            goto out;
        }
        rx->len = 0;
        TAILQ_INSERT_TAIL(&sep->rxs, rx, gentry);
        TAILQ_INSERT_TAIL(&sep->idle_rxs, rx, entry);
    }

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE(&dev->eps, ep, entry);
    pthread_mutex_unlock(&dev->lock);
    if (sep) {
        while (!TAILQ_EMPTY(&sep->txs)) {
            sock_tx_t *tx;

            tx = TAILQ_FIRST(&sep->txs);
            TAILQ_REMOVE(&sep->txs, tx, tentry);
            if (tx->buffer)
                free(tx->buffer);
            free(tx);
        }
        while (!TAILQ_EMPTY(&sep->rxs)) {
            sock_rx_t *rx;

            rx = TAILQ_FIRST(&sep->rxs);
            TAILQ_REMOVE(&sep->rxs, rx, gentry);
            if (rx->buffer)
                free(rx->buffer);
            free(rx);
        }
        if (sep->ids)
            free(sep->ids);
        if (sep->sock)
            close(sep->sock);
        free(sep);
    }
    if (ep)
        free(ep);
    *endpoint = NULL;
    CCI_EXIT;
    return ret;
}


static int sock_destroy_endpoint(cci_endpoint_t *endpoint)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
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
    cci__dev_t  *dev    = NULL;
    cci__svc_t  *svc    = NULL;
    cci__lep_t  *lep    = NULL;
    cci__crq_t  *crq    = NULL;
    sock_dev_t  *sdev   = NULL;
    sock_lep_t  *slep   = NULL;
    sock_crq_t  *scrq   = NULL;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    dev = container_of(device, cci__dev_t, device);
    if (0 != strcmp("sock", dev->driver)) {
        ret = CCI_EINVAL;
        goto out;
    }

    if (*port > (64 * 1024)) {
        CCI_EXIT;
        return CCI_ERANGE;
    }

    svc = container_of(*service, cci__svc_t, service);
    TAILQ_FOREACH(lep, &svc->leps, sentry) {
        if (lep->dev == dev) {
            break;
        }
    }

    /* allocate sock listening endpoint */
    slep = calloc(1, sizeof(*slep));
    if (!slep) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    /* alloc sock_crq_t for each cci__crq_t */
    TAILQ_FOREACH(crq, &lep->crqs, entry) {
        crq->priv = calloc(1, sizeof(*scrq));
        if (!crq->priv) {
            ret = CCI_ENOMEM;
            goto out;
        }
        scrq = crq->priv;
        scrq->buffer = calloc(1, CCI_CONN_REQ_LEN + SOCK_CONN_REQ_HDR_LEN);
        if (!scrq->buffer) {
            ret = CCI_ENOMEM;
            goto out;
        }
    }

    TAILQ_INIT(&lep->passive);

    /* open socket */
    slep->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (slep->sock == -1) {
        ret = errno;
        goto out;
    }

    ret = sock_set_nonblocking(slep->sock);
    if (ret)
        goto out;

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

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if (slep) {
        TAILQ_FOREACH(crq, &lep->crqs, entry) {
            scrq = crq->priv;
            if (scrq) {
                if (scrq->buffer)
                    free(scrq->buffer);
                free(scrq);
                crq->priv = NULL;
            }
        }
        if (slep->sock > 0)
            close(slep->sock);
        free(slep);
        lep->priv = NULL;
    }
    CCI_EXIT;
    return ret;
}


static int sock_unbind(cci_service_t *service, cci_device_t *device)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_get_conn_req(cci_service_t *service, 
                                 cci_conn_req_t **conn_req)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}

static void
sock_get_id(sock_ep_t *ep, uint32_t *id)
{
    uint32_t n, block, offset;
    uint64_t *b;

    while (1) {
        n = random() % SOCK_NUM_BLOCKS;
        block = n / SOCK_BLOCK_SIZE;
        offset = n % SOCK_BLOCK_SIZE;
        b = &ep->ids[block];

        if ((*b & (1ULL << offset)) == 0) {
            *b |= (1ULL << offset);
            *id = (block * SOCK_BLOCK_SIZE) + offset;
            break;
        }
    }
    return;
}

static void
sock_put_id(sock_ep_t *ep, uint32_t id)
{
    uint32_t block, offset;
    uint64_t *b;

    block = id / SOCK_BLOCK_SIZE;
    offset = id % SOCK_BLOCK_SIZE;
    b = &ep->ids[block];

    assert((*b & (1 << offset)) == 1);
    *b &= ~(1 << offset);

    return;
}

static inline uint64_t
sock_get_new_seq(void)
{
    uint64_t seq = 0ULL;

    seq = random() << 16; /* fill bits 16-47 */
    seq |= random() & 0xFFFFULL; /* fill bits 0-15 */

    return seq;
}

/* The endpoint maintains 256 lists. Hash the ip and port and return the index
 * of the list. We use all six bytes and this is endian agnostic. It evenly
 * disperses large blocks of addresses as well as large ranges of ports on the
 * same address.
 */
uint8_t sock_ip_hash(in_addr_t ip, uint16_t port)
{
    port ^= (ip & 0x0000FFFF);
    port ^= (ip & 0xFFFF0000) >> 16;
    return (port & 0x00FF) ^ ((port & 0xFF00) >> 8);
}

static int sock_accept(cci_conn_req_t *conn_req, 
                           cci_endpoint_t *endpoint, 
                           cci_connection_t **connection)
{
    uint8_t         a;
    uint16_t        b;
    uint32_t        peer_id, id;
    uint64_t        peer_seq;
    uint64_t        peer_ack;
    int             i;
    cci__ep_t       *ep     = NULL;
    cci__crq_t      *crq    = NULL;
    cci__conn_t     *conn   = NULL;
    cci__evt_t      *evt    = NULL;
    cci__dev_t      *dev    = NULL;
    sock_ep_t       *sep    = NULL;
    sock_crq_t      *scrq   = NULL;
    sock_conn_t     *sconn  = NULL;
    sock_dev_t      *sdev   = NULL;
    sock_header_r_t *hdr_r  = NULL;
    sock_msg_type_t type;
    sock_tx_t       *tx     = NULL;
    void            *ptr    = NULL;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    crq = container_of(conn_req, cci__crq_t, conn_req);
    scrq = crq->priv;

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    conn->tx_timeout = ep->tx_timeout;
    conn->priv = calloc(1, sizeof(*sconn));
    if (!conn->priv) {
        free(conn);
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    /* get a tx */
    pthread_mutex_lock(&sep->lock);
    if (!TAILQ_EMPTY(&sep->idle_txs)) {
        tx = TAILQ_FIRST(&sep->idle_txs);
        TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&sep->lock);

    if (!tx) {
        free(conn->priv);
        free(conn);
        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    hdr_r = scrq->buffer;
    sock_parse_header(&hdr_r->header, &type, &a, &b, &peer_id);
    sock_parse_seq_ack(&hdr_r->seq_ack, &peer_seq, &peer_ack);

    conn->connection.attribute = a;
    conn->connection.endpoint = endpoint;
    conn->connection.max_send_size = SOCK_AM_SIZE;

    sconn = conn->priv;
    sconn->conn = conn;
    sconn->status = SOCK_CONN_READY; /* set ready since the app thinks it is */
    *((struct sockaddr_in *) &sconn->sin) = scrq->sin;
    sconn->peer_id = peer_id;
    sock_get_id(sep, &sconn->id);
    sconn->seq = sock_get_new_seq(); /* even for UU since this reply is reliable */
    sconn->ack = peer_seq;

    pthread_mutex_init(&sconn->lock, NULL);

    /* insert in sock ep's list of conns */

    i = sock_ip_hash(sconn->sin.sin_addr.s_addr, sconn->sin.sin_port);
    pthread_mutex_lock(&sep->lock);
    TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
    pthread_mutex_unlock(&sep->lock);

    debug(CCI_DB_CONN, "accepting conn with hash %d", i);

    /* prepare conn_reply */

    tx->msg_type = SOCK_MSG_CONN_REPLY;
    tx->last_attempt_us = 0ULL;
    tx->timeout_us = 0ULL;

    evt = &tx->evt;
    evt->ep = ep;
    evt->conn = conn;
    evt->event.type = CCI_EVENT_NONE; /* for now */
    evt->event.info.other.context = NULL; /* FIXME or crq? */
    evt->event.info.other.u.connect.connection = &conn->connection;

    /* pack the msg */

    hdr_r = (sock_header_r_t *) tx->buffer;
    sock_pack_conn_reply(&hdr_r->header, CCI_EVENT_CONNECT_SUCCESS, sconn->peer_id);
    sock_pack_seq_ack(&hdr_r->seq_ack, sconn->seq, sconn->ack);
    id = htonl(sconn->id);
    ptr = tx->buffer + sizeof(*hdr_r);
    memcpy(ptr, &id, sizeof(sconn->id));

    tx->len = sizeof(*hdr_r) + sizeof(sconn->id);
    tx->seq = sconn->seq;

    debug(CCI_DB_CONN, "queuing conn_reply with seq %" PRIx64 " ack %" PRIx64"",
          sconn->seq, sconn->ack);

    /* insert at tail of device's queued list */

    dev = ep->dev;
    sdev = dev->priv;

    tx->state = SOCK_TX_QUEUED;
    pthread_mutex_lock(&sdev->lock);
    TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
    pthread_mutex_unlock(&sdev->lock);

    /* try to progress txs */

    sock_progress_dev(dev);

    *connection = &conn->connection;

    CCI_EXIT;

    return CCI_SUCCESS;
}


static int sock_reject(cci_conn_req_t *conn_req)
{
    int             ret     = CCI_SUCCESS;
    uint8_t         a;
    uint16_t        b;
    uint32_t        peer_id;
    uint64_t        peer_seq;
    uint64_t        peer_ack;
    char            buffer[SOCK_CONN_REQ_HDR_LEN];
    cci__lep_t      *lep     = NULL;
    cci__crq_t      *crq    = NULL;
    sock_crq_t      *scrq   = NULL;
    sock_lep_t      *slep    = NULL;
    sock_header_r_t *hdr_r  = NULL;
    sock_msg_type_t type;
    char name[32];

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    crq = container_of(conn_req, cci__crq_t, conn_req);
    scrq = crq->priv;
    lep = crq->lep;
    slep = lep->priv;

    hdr_r = scrq->buffer;
    sock_parse_header(&hdr_r->header, &type, &a, &b, &peer_id);
    sock_parse_seq_ack(&hdr_r->seq_ack, &peer_seq, &peer_ack);

    /* prepare conn_reply */

    hdr_r = (sock_header_r_t *) buffer;
    sock_pack_conn_reply(&hdr_r->header, CCI_EVENT_CONNECT_REJECTED, peer_id);
    sock_pack_seq_ack(&hdr_r->seq_ack, 0, peer_seq);

    scrq->peer_id = peer_id;
    scrq->last_attempt_us = sock_get_usecs();
    scrq->timeout_us = scrq->last_attempt_us + (10 * 1000000);

    /* queue here until acked */
    pthread_mutex_lock(&lep->lock);
    TAILQ_INSERT_TAIL(&lep->passive, crq, entry);
    pthread_mutex_unlock(&lep->lock);

    memset(name, 0, sizeof(name));
    sock_sin_to_name(scrq->sin, name, sizeof(name));
    debug((CCI_DB_MSG|CCI_DB_CONN), "listening ep %d sending reject to %s",
          slep->sock, name);

    ret = sock_sendto(slep->sock, buffer, sizeof(*hdr_r), scrq->sin);
    if (ret != (int) sizeof(*hdr_r)) {
        debug((CCI_DB_CONN|CCI_DB_MSG), "unable to send reject to %s with"
              "%s", name, cci_strerror(ret));
    }

    /* TODO when progressing, walk passive list and resend as needed */

    CCI_EXIT;
    return ret;
}

static int sock_getaddrinfo(const char *uri, in_addr_t *in)
{
    int ret;
    char *hostname, *colon;
    struct addrinfo *ai, hints;

    if (0 == strncmp("ip://", uri, 5))
        hostname = strdup(&uri[5]);
    else {
        CCI_EXIT;
        return CCI_EINVAL;
    }

    colon = strchr(hostname, ':');
    if (colon)
        colon = '\0';

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    ret = getaddrinfo(hostname, NULL, &hints, &ai);
    free(hostname);

    if (ret) {
        freeaddrinfo(ai);
        CCI_EXIT;
        return ret;
    }

    *in = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(ai);

    CCI_EXIT;
    return CCI_SUCCESS;
}

static sock_conn_t *
sock_find_open_conn(sock_ep_t *sep, in_addr_t ip, uint16_t port, uint32_t id)
{
    uint8_t i;
    struct s_conns *conn_list;
    sock_conn_t *sconn = NULL, *sc;

    CCI_ENTER;

    i = sock_ip_hash(ip, port);
    conn_list = &sep->conn_hash[i];
    TAILQ_FOREACH(sc, conn_list, entry) {
        if (sc->sin.sin_addr.s_addr == ip &&
            sc->sin.sin_port == port &&
            sc->id == id) {
                sconn = sc;
                break;
        }
    }
    CCI_EXIT;
    return sconn;
}

static sock_conn_t *
sock_find_new_conn(sock_ep_t *sep, in_addr_t ip, uint16_t port, uint32_t id)
{
    uint8_t i;
    struct s_conns *conn_list;
    sock_conn_t *sconn = NULL, *sc;

    CCI_ENTER;

    i = sock_ip_hash(ip, port);
    conn_list = &sep->conn_hash[i];
    TAILQ_FOREACH(sc, conn_list, entry) {
        if (sc->sin.sin_addr.s_addr == ip &&
            sc->sin.sin_port == port &&
            sc->peer_id == id) {
                sconn = sc;
                break;
        }
    }
    CCI_EXIT;
    return sconn;
}

static sock_conn_t *
sock_find_active_conn(sock_ep_t *sep, in_addr_t ip, uint32_t id)
{
    uint8_t i;
    struct s_active *active_list;
    sock_conn_t *sconn = NULL, *sc;

    CCI_ENTER;
    i = sock_ip_hash(ip, 0);
    active_list = &sep->active_hash[i];
    TAILQ_FOREACH(sc, active_list, entry) {
        if (sc->sin.sin_addr.s_addr == ip &&
            sc->id == id) {
                sconn = sc;
                break;
        }
    }
    CCI_EXIT;
    return sconn;
}

static sock_conn_t *
sock_find_conn(sock_ep_t *sep, in_addr_t ip, uint16_t port, uint32_t id, sock_msg_type_t type)
{
    switch (type) {
    case SOCK_MSG_CONN_REPLY:
        return sock_find_active_conn(sep, ip, id);
    case SOCK_MSG_CONN_ACK:
        return sock_find_new_conn(sep, ip, port, id);
    default:
        return sock_find_open_conn(sep, ip, port, id);
    }
    return NULL;
}

static int sock_connect(cci_endpoint_t *endpoint, char *server_uri, 
                            uint32_t port,
                            void *data_ptr, uint32_t data_len, 
                            cci_conn_attribute_t attribute,
                            void *context, int flags, 
                            struct timeval *timeout)
{
    int                 ret;
    int                 i;
    cci__ep_t           *ep         = NULL;
    cci__dev_t          *dev        = NULL;
    cci__conn_t         *conn       = NULL;
    sock_ep_t           *sep        = NULL;
    sock_dev_t          *sdev       = NULL;
    sock_conn_t         *sconn      = NULL;
    sock_tx_t           *tx         = NULL;
    sock_header_r_t     *hdr_r      = NULL;
    cci__evt_t          *evt        = NULL;
    cci_event_t         *event      = NULL;
    cci_event_other_t   *other      = NULL;
    cci_connection_t    *connection = NULL;
    struct sockaddr_in  *sin        = NULL;
    void                *ptr        = NULL;
    in_addr_t           ip;
    uint64_t            ack;
    struct s_active     *active_list;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    /* allocate a new connection */
    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        CCI_EXIT;
        return CCI_ENOMEM;
    }

    conn->priv = calloc(1, sizeof(*sconn));
    if (!conn->priv) {
        ret = CCI_ENOMEM;
        goto out;
    }
    sconn = conn->priv;
    sconn->conn = conn;

    /* set up the connection */
    conn->uri = strdup(server_uri);
    if (!conn->uri) {
        ret = CCI_ENOMEM;
        goto out;
    }

    /* conn->tx_timeout = 0  by default */

    connection = &conn->connection;
    connection->attribute = attribute;
    connection->endpoint = endpoint;
    connection->max_send_size = SOCK_AM_SIZE;

    /* set up sock specific info */

    sconn->status = SOCK_CONN_ACTIVE;
    sin = (struct sockaddr_in *) &sconn->sin;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);

    ret = sock_getaddrinfo(server_uri, &ip);
    if (ret)
        goto out;
    sin->sin_addr.s_addr = ip;  /* already in network order */

    /* peer will assign id */

    pthread_mutex_init(&sconn->lock, NULL);

    /* get our endpoint and device */
    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    dev = ep->dev;
    sdev = dev->priv;

    i = sock_ip_hash(ip, 0);
    active_list = &sep->active_hash[i];
    pthread_mutex_lock(&sep->lock);
    TAILQ_INSERT_TAIL(active_list, sconn, entry);
    pthread_mutex_unlock(&sep->lock);

    /* get a tx */
    pthread_mutex_lock(&sep->lock);
    if (!TAILQ_EMPTY(&sep->idle_txs)) {
        tx = TAILQ_FIRST(&sep->idle_txs);
        TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&sep->lock);

    if (!tx) {
        CCI_EXIT;
        return CCI_ENOBUFS;
    }

    /* prep the tx */
    tx->msg_type = SOCK_MSG_CONN_REQUEST;

    evt = &tx->evt;
    evt->ep = ep;
    evt->conn = conn;
    event = &evt->event;
    event->type = CCI_EVENT_CONNECT_SUCCESS; /* for now */

    other = &event->info.other;
    other->context = context;
    other->u.connect.connection = connection;

    /* pack the msg */

    hdr_r = (sock_header_r_t *) tx->buffer;
    sock_get_id(sep, &sconn->id);
    /* FIXME silence -Wall -Werror until it is used */
    if (0) sock_put_id(sep, 0);
    sock_pack_conn_request(&hdr_r->header, attribute, (uint16_t) data_len, sconn->id);
    tx->len = sizeof(*hdr_r);
    ptr = tx->buffer + tx->len;

    /* add seq and ack */

    sconn->seq = sock_get_new_seq();
    tx->seq = sconn->seq;
    ack = 0; /* unneeded */
    sock_pack_seq_ack(&hdr_r->seq_ack, tx->seq, ack);

    debug(CCI_DB_CONN, "queuing conn_request with seq %" PRIx64 " ack %" PRIx64"",
          tx->seq, ack);

    /* zero even if unreliable */

    tx->last_attempt_us = 0ULL;
    tx->timeout_us = 0ULL;

    if (data_len)
            memcpy(ptr, data_ptr, data_len);

    tx->len += data_len;
    assert(tx->len <= ep->buffer_len);

    /* insert at tail of device's queued list */

    dev = ep->dev;
    sdev = dev->priv;

    tx->state = SOCK_TX_QUEUED;
    pthread_mutex_lock(&sdev->lock);
    TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
    pthread_mutex_unlock(&sdev->lock);

    /* try to progress txs */

    sock_progress_dev(dev);

    CCI_EXIT;
    return CCI_SUCCESS;

out:
    if (conn) {
        if (conn->uri)
            free((char *) conn->uri);
        if (conn->priv)
            free(conn->priv);
        free(conn);
    }
    CCI_EXIT;
    return ret;
}


static int sock_disconnect(cci_connection_t *connection)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    /* need to clean up */

    /* remove conn from ep->conn_hash[i] */
    /* if sock conn uri, free it
     * free sock conn
     * free conn
     */

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_set_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, const void* val, int len)
{
    int             ret = CCI_SUCCESS;
    cci__ep_t       *ep;
    cci__conn_t     *conn;
    sock_ep_t       *sep;
    sock_conn_t     *sconn;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    if (CCI_OPT_LEVEL_ENDPOINT == level) {
        ep = container_of(handle->endpoint, cci__ep_t, endpoint);
        sep = ep->priv;
    } else {
        conn = container_of(handle->connection, cci__conn_t, connection);
        sconn = conn->priv;
    }

    switch (name) {
    case CCI_OPT_ENDPT_MAX_HEADER_SIZE:
        ret = CCI_EINVAL;   /* not settable */
        break;
    case CCI_OPT_ENDPT_SEND_TIMEOUT:
        assert(len == sizeof(ep->tx_timeout));
        memcpy(&ep->tx_timeout, val, len);
        break;
    case CCI_OPT_ENDPT_RECV_BUF_COUNT:
        ret = CCI_ERR_NOT_IMPLEMENTED;
        break;
    case CCI_OPT_ENDPT_SEND_BUF_COUNT:
        ret = CCI_ERR_NOT_IMPLEMENTED;
        break;
    case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
        assert(len == sizeof(ep->keepalive_timeout));
        memcpy(&ep->keepalive_timeout, val, len);
        break;
    case CCI_OPT_CONN_SEND_TIMEOUT:
        assert(len == sizeof(conn->tx_timeout));
        memcpy(&conn->tx_timeout, val, len);
        break;
    default:
        debug(CCI_DB_INFO, "unknown option %d", name);
        ret = CCI_EINVAL;
    }

    CCI_EXIT;

    return ret;
}


static int sock_get_opt(cci_opt_handle_t *handle, 
                            cci_opt_level_t level, 
                            cci_opt_name_t name, void** val, int *len)
{
    int             ret = CCI_SUCCESS;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;

    return ret;
}


static int sock_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_get_event(cci_endpoint_t *endpoint, 
                          cci_event_t ** const event,
                          uint32_t flags)
{
    int             ret = CCI_SUCCESS;
    cci__ep_t       *ep;
    cci__evt_t      *ev = NULL, *e;
    cci__dev_t      *dev;
    sock_ep_t       *sep;
    cci_event_t     *tmp;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    dev = ep->dev;

    sock_progress_dev(dev);

    pthread_mutex_lock(&ep->lock);
    if (TAILQ_EMPTY(&ep->evts)) {
        pthread_mutex_unlock(&ep->lock);
        *event = NULL;
        CCI_EXIT;
        return CCI_EAGAIN;
    }

    if (!flags) {
        /* give the user the first event */
        TAILQ_FOREACH(e, &ep->evts, entry) {
            if (e->event.type == CCI_EVENT_SEND) {
                /* NOTE: if it is blocking, skip it since sock_sendv()
                 * is waiting on it
                 */
                sock_tx_t *tx = container_of(e, sock_tx_t, evt);
                if (tx->flags & CCI_FLAG_BLOCKING) {
                    continue;
                } else {
                    ev = e;
                    break;
                }
            } else {
                ev = e;
                break;
            }
        }
    } else {
        TAILQ_FOREACH(e, &ep->evts, entry) {
            tmp = &e->event;

            if (flags & CCI_PE_SEND_EVENT &&
                tmp->type == CCI_EVENT_SEND) {
                sock_tx_t *tx = container_of(e, sock_tx_t, evt);
                if (tx->flags & CCI_FLAG_BLOCKING) {
                    continue;
                } else {
                    ev = e;
                    break;
                }
            } else if (flags & CCI_PE_RECV_EVENT &&
                       tmp->type == CCI_EVENT_RECV) {
                ev = e;
                break;
            } else if (flags & CCI_PE_OTHER_EVENT &&
                       !(tmp->type == CCI_EVENT_SEND ||
                         tmp->type == CCI_EVENT_RECV)) {
                ev = e;
                break;
            }
        }
    }

    if (ev)
        TAILQ_REMOVE(&ep->evts, ev, entry);
    else
        ret = CCI_EAGAIN;

    pthread_mutex_unlock(&ep->lock);

    /* TODO drain fd so that they can block again */

    *event = &ev->event;

    CCI_EXIT;
    return ret;
}


static int sock_return_event(cci_endpoint_t *endpoint, 
                                 cci_event_t *event)
{
    cci__ep_t   *ep;
    sock_ep_t   *sep;
    cci__evt_t  *evt;
    sock_tx_t   *tx;
    sock_rx_t   *rx;

    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;

    evt = container_of(event, cci__evt_t, event);

    if (evt->ep != ep) {
        CCI_EXIT;
        return CCI_EINVAL;
    }

    /* enqueue the event */

    switch (event->type) {
    case CCI_EVENT_SEND:
        tx = container_of(evt, sock_tx_t, evt);
        pthread_mutex_lock(&sep->lock);
        /* insert at head to keep it in cache */
        TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&sep->lock);
        break;
    case CCI_EVENT_RECV:
        rx = container_of(evt, sock_rx_t, evt);
        pthread_mutex_lock(&sep->lock);
        /* insert at head to keep it in cache */
        TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
        pthread_mutex_unlock(&sep->lock);
        break;
    default:
        /* TODO */
        break;
    }

    CCI_EXIT;

    return CCI_SUCCESS;
}


static int sock_sendto(cci_os_handle_t sock, void *buf, int len,
                       const struct sockaddr_in sin)
{
    int ret;
    const struct sockaddr *s = (const struct sockaddr *)&sin;
    socklen_t slen = sizeof(sin);

    ret = sendto(sock, buf, len, 0, s, slen);
    if (ret != -1)
        assert(ret == len);

    return ret;
}

static void
sock_progress_pending(sock_dev_t *sdev)
{
    int ret;
    uint64_t            now;
    sock_tx_t           *tx, *tmp;
    cci__evt_t          *evt;
    cci_event_t         *event;         /* generic CCI event */
    cci_connection_t    *connection;    /* generic CCI connection */
    cci__conn_t         *conn;
    sock_conn_t         *sconn;
    cci__ep_t           *ep;
    sock_ep_t           *sep;

    CCI_ENTER;

    TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs = TAILQ_HEAD_INITIALIZER(idle_txs);
    TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
    TAILQ_INIT(&idle_txs);
    TAILQ_INIT(&evts);

    now = sock_get_usecs();

    /* This is only for reliable messages.
     * Do not dequeue txs, just walk the list.
     */

    pthread_mutex_lock(&sdev->lock);
    TAILQ_FOREACH_SAFE(tx, &sdev->pending, dentry, tmp) {

        evt = &(tx->evt);
        conn = evt->conn;
        connection = &conn->connection;
        sconn = conn->priv;
        event = &evt->event;

        ep = container_of(connection->endpoint, cci__ep_t, endpoint);
        sep = ep->priv;

        assert(tx->last_attempt_us != 0ULL);

        /* has it timed out? */

        if (tx->timeout_us < now) { /* FIXME need to handle rollover */

            /* dequeue */

            TAILQ_REMOVE(&sdev->pending, tx, dentry);

            /* set status and add to completed events */

            switch (tx->msg_type) {
            case SOCK_MSG_SEND:
                event->info.send.status = CCI_ETIMEDOUT;
                break;
            case SOCK_MSG_CONN_REQUEST:
            {
                int i;
                struct s_active *active_list;

                event->type = CCI_EVENT_CONNECT_TIMEOUT;
                if (conn->uri)
                    free((char *) conn->uri);
                sconn->status = SOCK_CONN_CLOSING;
                i = sock_ip_hash(sconn->sin.sin_addr.s_addr, 0);
                active_list = &sep->active_hash[i];
                pthread_mutex_lock(&sep->lock);
                TAILQ_REMOVE(active_list, sconn, entry);
                pthread_mutex_unlock(&sep->lock);
                free(sconn);
                free(conn);
                sconn = NULL;
                conn = NULL;
                tx->evt.ep = ep;
                tx->evt.conn = NULL;
                break;
            }
            case SOCK_MSG_CONN_REPLY:
            case SOCK_MSG_CONN_ACK:
            default:
                /* TODO */
                CCI_EXIT;
                return;
            }
            /* if SILENT, put idle tx */
            if (tx->msg_type == SOCK_MSG_SEND &&
                tx->flags & CCI_FLAG_SILENT) {

                tx->state = SOCK_TX_IDLE;
                /* store locally until we can drop the sdev->lock */
                TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
            } else {
                tx->state = SOCK_TX_COMPLETED;
                /* store locally until we can drop the sdev->lock */
                TAILQ_INSERT_TAIL(&evts, evt, entry);
            }
            continue;
        }

        /* is it time to resend? */

        if ((tx->last_attempt_us + (SOCK_RESEND_TIME_SEC * 1000000)) > now)
            continue;

        /* need to resend it */

        tx->last_attempt_us = now;

        debug(CCI_DB_MSG, "sending %s msg", sock_msg_type(tx->msg_type));
        ret = sock_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
        if (ret != tx->len) {
            debug((CCI_DB_MSG|CCI_DB_INFO), "sendto() failed with %s\n", cci_strerror(errno));
            continue;
        }
#if 0
        /* msg sent, dequeue */

        TAILQ_REMOVE(&sdev->pending, tx, dentry);

        /* set status and add to completed events */

        switch (tx->msg_type) {
        case SOCK_MSG_SEND:
            event->info.send.status = CCI_SUCCESS;
            break;
        case SOCK_MSG_CONN_REQUEST:
            event->type = CCI_EVENT_CONNECT_SUCCESS;
            break;
        case SOCK_MSG_CONN_REPLY:
        case SOCK_MSG_CONN_ACK:
        default:
            /* TODO */
            CCI_EXIT;
            return;
        }
        /* if SILENT, put idle tx */
        if (tx->msg_type == SOCK_MSG_SEND &&
            tx->flags & CCI_FLAG_SILENT) {

            tx->state = SOCK_TX_IDLE;
            /* store locally until we can drop the sdev->lock */
            TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
        } else {
            tx->state = SOCK_TX_COMPLETED;
            /* store locally until we can drop the sdev->lock */
            TAILQ_INSERT_TAIL(&evts, evt, entry);
        }
#endif
    }
    pthread_mutex_unlock(&sdev->lock);

    /* transfer txs to sock ep's list */
    while (!TAILQ_EMPTY(&idle_txs)) {
        tx = TAILQ_FIRST(&idle_txs);
        TAILQ_REMOVE(&idle_txs, tx, dentry);
        ep = tx->evt.ep;
        sep = ep->priv;
        pthread_mutex_lock(&sep->lock);
        TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&sep->lock);
    }

    /* transfer evts to the ep's list */
    while (!TAILQ_EMPTY(&evts)) {
        evt = TAILQ_FIRST(&evts);
        TAILQ_REMOVE(&evts, evt, entry);
        ep = evt->ep;
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
        pthread_mutex_unlock(&ep->lock);
    }

    CCI_EXIT;

    return;
}

static void
sock_progress_queued(sock_dev_t *sdev)
{
    int                 ret;
    uint32_t            timeout;
    uint64_t            now;
    sock_tx_t           *tx, *tmp;
    cci__ep_t           *ep;
    cci__evt_t          *evt;
    cci__conn_t         *conn;
    sock_ep_t           *sep;
    sock_conn_t         *sconn;
    cci_event_t         *event;         /* generic CCI event */
    cci_connection_t    *connection;    /* generic CCI connection */
    cci_endpoint_t      *endpoint;      /* generic CCI endpoint */

    CCI_ENTER;

    TAILQ_HEAD(s_idle_txs, sock_tx) idle_txs = TAILQ_HEAD_INITIALIZER(idle_txs);
    TAILQ_HEAD(s_evts, cci__evt) evts = TAILQ_HEAD_INITIALIZER(evts);
    TAILQ_INIT(&idle_txs);
    TAILQ_INIT(&evts);

    now = sock_get_usecs();

    pthread_mutex_lock(&sdev->lock);
    TAILQ_FOREACH_SAFE(tx, &sdev->queued, dentry, tmp) {
        evt = &(tx->evt);
        event = &(evt->event);
        conn = evt->conn;
        connection = &conn->connection;
        sconn = conn->priv;

        endpoint = connection->endpoint;
        ep = container_of(endpoint, cci__ep_t, endpoint);
        sep = ep->priv;

        /* try to send it */

        if (tx->last_attempt_us == 0ULL) {
            timeout = conn->tx_timeout ? conn->tx_timeout : ep->tx_timeout;
            tx->timeout_us = now + (uint64_t) timeout;
        }

        if (tx->timeout_us < now) { /* FIXME nned to handle rollover */

            /* set status and add to completed events */

            switch (tx->msg_type) {
            case SOCK_MSG_SEND:
                event->info.send.status = CCI_ETIMEDOUT;
                break;
            case SOCK_MSG_CONN_REQUEST:
                /* FIXME only CONN_REQUEST gets an event
                 * the other two need to disconnect the conn */
                event->type = CCI_EVENT_CONNECT_TIMEOUT;
                break;
            case SOCK_MSG_CONN_REPLY:
            case SOCK_MSG_CONN_ACK:
            default:
                /* TODO */
                CCI_EXIT;
                return;
            }
            TAILQ_REMOVE(&sdev->queued, tx, dentry);

            /* if SILENT, put idle tx */
            if (tx->msg_type == SOCK_MSG_SEND &&
                tx->flags & CCI_FLAG_SILENT) {

                tx->state = SOCK_TX_IDLE;
                /* store locally until we can drop the sdev->lock */
                TAILQ_INSERT_HEAD(&idle_txs, tx, dentry);
            } else {
                tx->state = SOCK_TX_COMPLETED;
                /* store locally until we can drop the sdev->lock */
                TAILQ_INSERT_TAIL(&evts, evt, entry);
            }
            continue;
        }

        if ((tx->last_attempt_us + (SOCK_RESEND_TIME_SEC * 1000000)) > now)
            continue;

        tx->last_attempt_us = now;

        /* need to send it */
            
        debug(CCI_DB_MSG, "sending %s msg", sock_msg_type(tx->msg_type));
        ret = sock_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
        if (ret == -1) {
            switch (errno) {
            default:
                debug((CCI_DB_MSG|CCI_DB_INFO), "sendto() failed with %s\n", strerror(errno));
                /* fall through */
            case EINTR:
            case EAGAIN:
            case ENOMEM:
            case ENOBUFS:
                continue;
            }
        }
        /* msg sent, dequeue */
        TAILQ_REMOVE(&sdev->queued, tx, dentry);

        /* if reliable or connection, add to pending
         * else add to idle txs */

        if (connection->attribute & CCI_CONN_ATTR_RO ||
            connection->attribute & CCI_CONN_ATTR_RU ||
            tx->msg_type == SOCK_MSG_CONN_REQUEST ||
            tx->msg_type == SOCK_MSG_CONN_REPLY) {

            tx->state = SOCK_TX_PENDING;
            TAILQ_INSERT_TAIL(&sdev->pending, tx, dentry);
            debug((CCI_DB_CONN|CCI_DB_MSG), "moving queued %s tx to pending",
                  sock_msg_type(tx->msg_type));
        } else {
            tx->state = SOCK_TX_COMPLETED;
            TAILQ_INSERT_TAIL(&idle_txs, tx, dentry);
        }
    }
    pthread_mutex_unlock(&sdev->lock);

    /* transfer txs to sock ep's list */
    while (!TAILQ_EMPTY(&idle_txs)) {
        tx = TAILQ_FIRST(&idle_txs);
        TAILQ_REMOVE(&idle_txs, tx, dentry);
        ep = tx->evt.ep;
        sep = ep->priv;
        pthread_mutex_lock(&sep->lock);
        TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&sep->lock);
    }

    /* transfer evts to the ep's list */
    while (!TAILQ_EMPTY(&evts)) {
        evt = TAILQ_FIRST(&evts);
        TAILQ_REMOVE(&evts, evt, entry);
        ep = evt->ep;
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
        pthread_mutex_unlock(&ep->lock);
    }

    CCI_EXIT;

    return;
}

static void
sock_progress_sends(sock_dev_t *sdev)
{
    sock_progress_pending(sdev);
    sock_progress_queued(sdev);

    return;
}

static int sock_send(cci_connection_t *connection, 
                         void *header_ptr, uint32_t header_len, 
                         void *data_ptr, uint32_t data_len, 
                         void *context, int flags)
{
    uint8_t segment_cnt = 0;

    if (data_ptr && data_len)
        segment_cnt = 1;

    return sock_sendv(connection, header_ptr, header_len,
                      (char **) &data_ptr, (int *) &data_len,
                      segment_cnt, context, flags);
}


static int sock_sendv(cci_connection_t *connection, 
                          void *header_ptr, uint32_t header_len, 
                          char **data_ptrs, int *data_lens,
                          uint8_t segment_cnt, void *context, int flags)
{
    int i, ret, is_reliable = 0, data_len = 0;
    char *func = segment_cnt < 2 ? "send" : "sendv";
    cci_endpoint_t *endpoint = connection->endpoint;
    cci__ep_t *ep;
    cci__dev_t *dev;
    cci__conn_t *conn;
    sock_ep_t *sep;
    sock_conn_t *sconn;
    sock_dev_t *sdev;
    sock_tx_t *tx = NULL;
    sock_header_t *hdr;
    void *ptr;
    cci__evt_t *evt;
    cci_event_t *event;     /* generic CCI event */
    cci_event_send_t *send; /* generic CCI send event */

    debug(CCI_DB_FUNC, "entering %s", func);

    if (!sglobals) {
        debug(CCI_DB_FUNC, "exiting %s", func);
        return CCI_ENODEV;
    }

    for (i = 0; i < segment_cnt; i++) {
        if (!data_ptrs[i] && data_lens[i]) {
            debug(CCI_DB_FUNC, "exiting %s", func);
            return CCI_EINVAL;
        }
        data_len += data_lens[i];
    }

    if (header_len + data_len > connection->max_send_size) {
        debug(CCI_DB_FUNC, "exiting %s", func);
        return CCI_EMSGSIZE;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    conn = container_of(connection, cci__conn_t, connection);
    sconn = conn->priv;
    dev = ep->dev;
    sdev = dev->priv;

    is_reliable = connection->attribute & CCI_CONN_ATTR_RO ||
                  connection->attribute & CCI_CONN_ATTR_RU;

    /* get a tx */
    pthread_mutex_lock(&sep->lock);
    if (!TAILQ_EMPTY(&sep->idle_txs)) {
        tx = TAILQ_FIRST(&sep->idle_txs);
        TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
    }
    pthread_mutex_unlock(&sep->lock);

    if (!tx) {
        debug(CCI_DB_FUNC, "exiting %s", func);
        return CCI_ENOBUFS;
    }

    /* tx bookkeeping */
    tx->msg_type = SOCK_MSG_SEND;
    tx->flags = flags;

    /* zero even if unreliable */

    tx->last_attempt_us = 0ULL;
    tx->timeout_us = 0ULL;

    /* setup generic CCI event */
    evt = &tx->evt;
    evt->ep = ep;
    evt->conn = conn;
    event = &evt->event;
    event->type = CCI_EVENT_SEND;

    send = &(event->info.send);
    send->connection = connection;
    send->context = context;
    send->status = CCI_SUCCESS; /* for now */

    /* pack buffer */
    hdr = (sock_header_t *) tx->buffer;
    sock_pack_send(hdr, header_len, data_len, sconn->peer_id);
    tx->len = sizeof(*hdr);

    /* if reliable, add seq and ack */

    if (is_reliable) {
        sock_header_r_t *hdr_r = tx->buffer;
        uint64_t ack;

        pthread_mutex_lock(&sconn->lock);
        tx->seq = sconn->seq++;
        ack = sconn->ack;
        pthread_mutex_unlock(&sconn->lock);

        sock_pack_seq_ack(&hdr_r->seq_ack, tx->seq, ack);
        tx->len = sizeof(*hdr_r);
    }
    ptr = tx->buffer + tx->len;

    /* copy user header and data to buffer
     * NOTE: ignore CCI_FLAG_NO_COPY because we need to
             send the entire packet in one shot. We could
             use sendmsg() with an iovec. */

    if (header_len) {
        memcpy(ptr, header_ptr, header_len);
        ptr += header_len;
        tx->len += header_len;
    }
    for (i = 0; i < segment_cnt; i++) {
        if (data_lens[i]) {
            memcpy(ptr, data_ptrs[i], data_lens[i]);
            ptr += data_lens[i];
            tx->len += data_lens[i];
        }
    }

    /* if unreliable, try to send */
    if (!is_reliable) {
        ret = sock_sendto(sep->sock, tx->buffer, tx->len, sconn->sin);
        if (ret == tx->len) {
            /* queue event on enpoint's completed queue */
            tx->state = SOCK_TX_COMPLETED;
            pthread_mutex_lock(&ep->lock);
            TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
            pthread_mutex_unlock(&ep->lock);
            debug(CCI_DB_MSG, "sent UU msg");

            sock_progress_dev(dev);

            debug(CCI_DB_FUNC, "exiting %s", func);

            return CCI_SUCCESS;
        }

        /* if error, fall through */
    }

    /* insert at tail of sock device's queued list */

    tx->state = SOCK_TX_QUEUED;
    pthread_mutex_lock(&sdev->lock);
    TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
    pthread_mutex_unlock(&sdev->lock);

    /* try to progress txs */

    sock_progress_dev(dev);

    /* if unreliable, we are done since it is buffered internally */
    if (!is_reliable) {
        debug(CCI_DB_FUNC, "exiting %s", func);
        return CCI_SUCCESS;
    }

    ret = CCI_SUCCESS;

    /* if blocking, wait for completion */

    if (tx->flags & CCI_FLAG_BLOCKING) {
        while (tx->state != SOCK_TX_COMPLETED)
            usleep(SOCK_PROG_TIME_US / 2);

        /* get status and cleanup */
        ret = send->status;

        /* FIXME race with get_event()
         *       get_event() must ignore sends with 
         *       flags & CCI_FLAG_BLOCKING */

        pthread_mutex_lock(&ep->lock);
        TAILQ_REMOVE(&ep->evts, evt, entry);
        pthread_mutex_unlock(&ep->lock);

        pthread_mutex_lock(&sep->lock);
        TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&sep->lock);
    }

    debug(CCI_DB_FUNC, "exiting %s", func);
    return ret;
}


static int sock_rma_register(cci_endpoint_t *endpoint, void *start, 
                                 uint64_t length, uint64_t *rma_handle)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;

    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma_register_phys(cci_endpoint_t *endpoint, 
                                      cci_sg_t *sg_list, uint32_t sg_cnt, 
                                      uint64_t *rma_handle)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma_deregister(uint64_t rma_handle)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}


static int sock_rma(cci_connection_t *connection, 
                        void *header_ptr, uint32_t header_len, 
                        uint64_t local_handle, uint64_t local_offset, 
                        uint64_t remote_handle, uint64_t remote_offset,
                        uint64_t data_len, void *context, int flags)
{
    CCI_ENTER;

    if (!sglobals) {
        CCI_EXIT;
        return CCI_ENODEV;
    }

    CCI_EXIT;
    return CCI_ERR_NOT_IMPLEMENTED;
}

static void
sock_handle_active_message(sock_conn_t *sconn,
                           sock_rx_t *rx,
                           uint8_t header_len,
                           uint16_t data_len,
                           uint32_t id)
{
    cci__evt_t *evt;
    cci__conn_t *conn = sconn->conn;
    sock_header_t *hdr;         /* wire header */
    cci_event_t *event;             /* generic CCI event */
    cci_event_recv_t *recv;         /* generic CCI recv event */
    cci_endpoint_t *endpoint;        /* generic CCI endpoint */
    cci__ep_t *ep;

    CCI_ENTER;

    endpoint = (&conn->connection)->endpoint;
    ep = container_of(endpoint, cci__ep_t, endpoint);

    /* get cci__evt_t to hang on ep->events */

    evt = &rx->evt;

    /* set wire header so we can find user header */

    hdr = (sock_header_t *) rx->buffer;

    /* setup the generic event for the application */

    event = (cci_event_t *) &evt->event;
    event->type = CCI_EVENT_RECV;

    recv = &(event->info.recv);
    *((uint32_t *) &recv->header_len) = header_len;
    *((uint32_t *) &recv->data_len) = data_len;
    *((void **) &recv->header_ptr) = rx->buffer + sizeof(*hdr);
    recv->connection = &conn->connection;

    /* if a reliable connection, handle the ack */

    if (conn->connection.attribute & CCI_CONN_ATTR_RO ||
        conn->connection.attribute & CCI_CONN_ATTR_RU) {

        sock_header_r_t *hdr_r = (sock_header_r_t *) rx->buffer;
        sock_seq_ack_t *sa = &hdr_r->seq_ack;

        /* TODO handle_ack(conn, sa->ack, up_to) */
        if (0)
            sa->ack++;

        *((void **) &recv->header_ptr) = hdr_r + sizeof(*hdr_r);
    }

    *((void **) &recv->data_ptr) = recv->header_ptr + header_len;

    /* queue event on endpoint's completed event queue */

    pthread_mutex_lock(&ep->lock);
    TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
    pthread_mutex_unlock(&ep->lock);

    /* TODO notify via ep->fd */

    CCI_EXIT;

    return;
}

static int
sock_handle_ack(cci__ep_t *ep, uint64_t ack)
{
    int             ret     = 0;

    return ret;
}

/* Possible states and what to do:
 *
 * Recv         send        send        with        complete    switch
 * Success      conn_ack    reliably    seq_ack     event       lists
 * -------------------------------------------------------------------
 * No conn      Error
 * Active conn  Yes         Yes         Yes         Yes         Yes
 * Ready conn   Yes         Yes         Yes         No          No
 * ===================================================================
 * Recv         send        send        with        complete    free
 * Rejected     conn_ack    reliably    seq_ack     event       conn
 * -------------------------------------------------------------------
 * No conn      Yes         No          No          No          No
 * Active conn  Yes         No          No          Yes         Yes
 * Ready conn   Error
 */
static void
sock_handle_conn_reply(sock_conn_t *sconn, /* NULL if rejected */
                           sock_rx_t *rx,
                           uint8_t reply, /* SUCCESS or REJECTED */
                           uint16_t unused,
                           uint32_t id,
                           struct sockaddr_in sin,
                           cci__ep_t *ep)
{
    int             i, ret;
    uint32_t        peer_id = 0;
    cci__evt_t      *evt    = NULL;
    cci__dev_t      *dev    = NULL;
    cci__conn_t     *conn   = NULL;
    sock_ep_t       *sep    = NULL;
    sock_dev_t      *sdev   = NULL;
    sock_tx_t       *tx = NULL, *tmp = NULL, *t = NULL;
    sock_header_r_t *hdr_r;     /* wire header */
    cci_event_t     *event;     /* generic CCI event */
    cci_endpoint_t  *endpoint;  /* generic CCI endpoint */
    void            *ptr;
    uint64_t        seq;        /* peer's seq */
    uint64_t        ack;        /* our original seq */

    CCI_ENTER;

    sep = ep->priv;

    if (!sconn) {
        /* either this is a dup and the conn is now ready or
         * the conn is closed and we simply ack the msg
         */
        /* look for a conn that is ready */
        sconn = sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id, SOCK_MSG_SEND);
        if (!sconn) {
            sock_header_r_t hdr;
            int len = (int) sizeof(hdr);
            char from[32];

            memset(from, 0, sizeof(from));
            sock_sin_to_name(sin, from, sizeof(from));
            debug((CCI_DB_CONN|CCI_DB_MSG), "ep %d recv'd conn_reply (%s) from %s"
                  " with no matching conn", sep->sock,
                  reply == CCI_EVENT_CONNECT_SUCCESS ? "success" : "rejected",
                  from);
            /* simply ack this msg and cleanup */
            memset(&hdr, 0, sizeof(hdr));
            sock_pack_conn_ack(&hdr.header, id);
            ret = sock_sendto(sep->sock, &hdr, len, sin);
            if (ret != len) {
                debug((CCI_DB_CONN|CCI_DB_MSG), "ep %d failed to send conn_ack with %s",
                      sep->sock, cci_strerror(ret));
            }
            pthread_mutex_lock(&sep->lock);
            TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
            pthread_mutex_unlock(&sep->lock);
            CCI_EXIT;
            return;
        }
        /* else we have a connection and we can ack normally */
    }

    conn = sconn->conn;
    endpoint = &ep->endpoint;
    dev = ep->dev;
    sdev = dev->priv;

    /* set wire header so we can find user header */

    hdr_r = (sock_header_r_t *) rx->buffer;
    ptr = rx->buffer + sizeof(*hdr_r);

    /* TODO handle ack */

    sock_parse_seq_ack(&hdr_r->seq_ack, &seq, &ack);

    /* silence compiler for now */
    if (0) sock_handle_ack(ep, ack);

    if (sconn->status == SOCK_CONN_ACTIVE) {
        struct s_active *active_list;

        debug(CCI_DB_CONN, "transition active connection to ready");

        /* get pending conn_req tx, create event, move conn to conn_hash */
        pthread_mutex_lock(&sdev->lock);
        TAILQ_FOREACH_SAFE(t, &sdev->pending, dentry, tmp) {
            if (t->seq == ack) {
                TAILQ_REMOVE(&sdev->pending, t, dentry);
                tx = t;
                break;
            }
        }
        pthread_mutex_unlock(&sdev->lock);

        if (!tx) {
            char from[32];

            memset(from, 0, sizeof(from));
            sock_sin_to_name(sin, from, sizeof(from));

            /* how can we be active without a tx pending? */
            debug(CCI_DB_WARN, "ep %d received conn_reply (%s) from %s "
                  "with an active conn and no matching tx", sep->sock,
                  reply == CCI_EVENT_CONNECT_SUCCESS ? "success" : "rejected",
                  from);
            /* we can't transition to ready since we do not have the 
             * context from the conn_request tx */
            assert(0);
        }

        /* get cci__evt_t to hang on ep->events */

        evt = &rx->evt;

        /* setup the generic event for the application */

        event = (cci_event_t *) &evt->event;
        event->type = reply; /* CCI_EVENT_CONNECT_[SUCCESS|REJECTED] */
        event->info.other.context = tx->evt.event.info.send.context;

        i = sock_ip_hash(sin.sin_addr.s_addr, 0);
        active_list = &sep->active_hash[i];
        pthread_mutex_lock(&sep->lock);
        TAILQ_REMOVE(active_list, sconn, entry);
        pthread_mutex_unlock(&sep->lock);

        if (CCI_EVENT_CONNECT_SUCCESS == reply) {
            event->info.other.u.connect.connection = &conn->connection;
            memcpy(&peer_id, ptr, sizeof(peer_id));
            sconn->peer_id = ntohl(peer_id);
            sconn->status = SOCK_CONN_READY;
            *((struct sockaddr_in *) &sconn->sin) = sin;
            sconn->ack = seq;

            i = sock_ip_hash(sin.sin_addr.s_addr, sin.sin_port);
            pthread_mutex_lock(&sep->lock);
            TAILQ_INSERT_TAIL(&sep->conn_hash[i], sconn, entry);
            pthread_mutex_unlock(&sep->lock);

            debug(CCI_DB_CONN, "conn ready on hash %d", i);

        } else {
            sock_header_r_t hdr;
            int len = (int) sizeof(hdr);
            char name[32];

            free(sconn);
            if (conn->uri)
                free((char *) conn->uri);
            free(conn);

            /* send unreliable conn_ack */
            memset(name, 0, sizeof(name));
            sock_sin_to_name(sin, name, sizeof(name));
            debug((CCI_DB_CONN|CCI_DB_MSG), "ep %d recv'd conn_reply (rejected) from %s"
                  " - closing conn", sep->sock, name);

            /* simply ack this msg and cleanup */
            memset(&hdr, 0, sizeof(hdr));
            sock_pack_conn_ack(&hdr.header, id);
            ret = sock_sendto(sep->sock, &hdr, len, sin);
            if (ret != len) {
                debug((CCI_DB_CONN|CCI_DB_MSG), "ep %d failed to send conn_ack with %s",
                      sep->sock, cci_strerror(ret));
            }
        }
        /* add rx->evt to ep->evts */
        pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
        pthread_mutex_unlock(&ep->lock);

        if (reply != CCI_EVENT_CONNECT_SUCCESS) {
            CCI_EXIT;
            return;
        }
    } else if (sconn->status == SOCK_CONN_READY) {
        pthread_mutex_lock(&sep->lock);
        if (!TAILQ_EMPTY(&sep->idle_txs)) {
            tx = TAILQ_FIRST(&sep->idle_txs);
            TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
        }
        pthread_mutex_unlock(&sep->lock);

        if (!tx) {
            char to[32];

            memset(to, 0, sizeof(to));
            sock_sin_to_name(sin, to, sizeof(to));

            /* we can't ack, cleanup */
            debug((CCI_DB_CONN|CCI_DB_MSG), "ep %d does not have any tx "
                  "buffs to send a conn_ack to %s", sep->sock, to);
            pthread_mutex_lock(&sep->lock);
            TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
            pthread_mutex_unlock(&sep->lock);

            CCI_EXIT;
            return;
        }
    }

    /* we have a tx for the conn_ack */

    tx->seq = ++(sconn->seq);

    tx->msg_type = SOCK_MSG_CONN_ACK;
    tx->evt.event.type = CCI_EVENT_NONE;
    tx->evt.event.info.other.u.connect.connection = &conn->connection;
    tx->evt.ep = ep;
    tx->evt.conn = conn;

    tx->last_attempt_us = 0ULL;
    tx->timeout_us = 0ULL;

    hdr_r = tx->buffer;
    sock_pack_conn_ack(&hdr_r->header, sconn->id);
    sock_pack_seq_ack(&hdr_r->seq_ack, tx->seq, seq);

    debug(CCI_DB_CONN, "queuing conn_ack with seq %" PRIx64 " ack %" PRIx64"",
          tx->seq, seq);

    tx->state = SOCK_TX_QUEUED;
    pthread_mutex_lock(&sdev->lock);
    TAILQ_INSERT_TAIL(&sdev->queued, tx, dentry);
    pthread_mutex_unlock(&sdev->lock);

    /* try to progress txs */

    sock_progress_dev(dev);

    CCI_EXIT;

    return;
}

static void
sock_handle_conn_ack(sock_conn_t *sconn,
                           sock_rx_t *rx,
                           uint8_t unused1,
                           uint16_t unused2,
                           uint32_t peer_id,
                           struct sockaddr_in sin)
{
    cci__ep_t       *ep;
    cci__dev_t      *dev;
    cci__conn_t     *conn = sconn->conn;
    sock_ep_t       *sep;
    sock_dev_t      *sdev;
    sock_tx_t       *tx = NULL, *tmp = NULL, *t = NULL;
    sock_header_r_t *hdr_r;     /* wire header */
    cci_endpoint_t  *endpoint;  /* generic CCI endpoint */
    uint64_t        seq;
    uint64_t        ack;

    CCI_ENTER;

    endpoint = (&conn->connection)->endpoint;
    ep = container_of(endpoint, cci__ep_t, endpoint);
    sep = ep->priv;
    dev = ep->dev;
    sdev = dev->priv;

    assert(peer_id == sconn->peer_id);

    /* TODO handle ack */

    hdr_r = rx->buffer;
    sock_parse_seq_ack(&hdr_r->seq_ack, &seq, &ack);

    debug(CCI_DB_CONN, "%s: seq %"PRIx64" ack %"PRIx64"", __func__, seq, ack);

    /* silence compiler for now */
    if (0) sock_handle_ack(ep, ack);

    pthread_mutex_lock(&sdev->lock);
    TAILQ_FOREACH_SAFE(t, &sdev->pending, dentry, tmp) {
        if (t->seq == ack) {
            TAILQ_REMOVE(&sdev->pending, t, dentry);
            tx = t;
            debug(CCI_DB_CONN, "%s: found conn_reply", __func__);
            break;
        }
    }
    pthread_mutex_unlock(&sdev->lock);

    if (!tx) {
        /* FIXME do what here? */
        /* if no tx, then it timed out or this is a duplicate,
         * but we have a sconn */
        debug((CCI_DB_MSG|CCI_DB_CONN), "received conn_ack and no matching tx "
              "(seq %"PRIx64" ack %"PRIx64")", seq, ack);
    } else {
        pthread_mutex_lock(&sep->lock);
        TAILQ_INSERT_HEAD(&sep->idle_txs, tx, dentry);
        pthread_mutex_unlock(&sep->lock);
    }

    pthread_mutex_lock(&sep->lock);
    TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
    pthread_mutex_unlock(&sep->lock);

    CCI_EXIT;

    return;
}

static inline void
sock_drop_msg(cci_os_handle_t sock)
{
    char buf[4];
    struct sockaddr sa;
    socklen_t slen;

    recvfrom(sock, buf, 4, 0, &sa, &slen);
    return;
}

static void
sock_recvfrom_ep(cci__ep_t *ep)
{
    int ret = 0, drop_msg = 0, reply = 0;
    uint8_t a;
    uint16_t b;
    uint32_t id;
    sock_rx_t *rx = NULL;
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    sock_conn_t *sconn;
    sock_ep_t *sep;
    sock_msg_type_t type;

    CCI_ENTER;

    /* get idle rx */

    sep = ep->priv;
    pthread_mutex_lock(&sep->lock);
    if (!TAILQ_EMPTY(&sep->idle_rxs)) {
        rx = TAILQ_FIRST(&sep->idle_rxs);
        TAILQ_REMOVE(&sep->idle_rxs, rx, entry);
    }
    pthread_mutex_unlock(&sep->lock);

    if (!rx) {
        debug(CCI_DB_WARN, "no rx buffers available on endpoint %d", sep->sock);
        /* FIXME do we drop? */
        CCI_EXIT;
        return;
    }

    /* peek at msg header.
     * handler must call recvfrom for the full msg. */

    ret = recvfrom(sep->sock, rx->buffer, SOCK_PEEK_LEN,
                   MSG_PEEK, (struct sockaddr *)&sin, &sin_len);
    if (ret < (int) sizeof(sock_header_t)) {
        drop_msg = 1;
        goto out;
    }

    /* lookup connection from sin and id */

    sock_parse_header(rx->buffer, &type, &a, &b, &id);
    if (SOCK_MSG_CONN_REPLY == type)
        reply = 1;
    sconn = sock_find_conn(sep, sin.sin_addr.s_addr, sin.sin_port, id, type);

    {
        char name[32];
        memset(name, 0, sizeof(name));
        sock_sin_to_name(sin, name, sizeof(name));
        debug((CCI_DB_MSG), "ep %d recv'd %s msg from %s",
              sep->sock, sock_msg_type(type), name);
    }

    /* if no conn, drop msg, requeue rx */
    if (!sconn && !reply) {
        debug((CCI_DB_CONN|CCI_DB_MSG), "no sconn for incoming %s msg "
               "from %s:%d", sock_msg_type(type),
               inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
        drop_msg = 1;
        goto out;
    }

    /* TODO handle types */

    switch (type) {
    case SOCK_MSG_CONN_REQUEST:
        debug((CCI_DB_MSG|CCI_DB_CONN), "conn request on non-listening "
                "endpoint from %s:%d", inet_ntoa(sin.sin_addr),
                ntohs(sin.sin_port));
        drop_msg = 1;
        break;
    case SOCK_MSG_CONN_REPLY:
        recvfrom(sep->sock, rx->buffer, SOCK_AM_SIZE,
                 0, (struct sockaddr *)&sin, &sin_len);
        sock_handle_conn_reply(sconn, rx, a, b, id, sin, ep);
        break;
    case SOCK_MSG_CONN_ACK:
        recvfrom(sep->sock, rx->buffer, SOCK_AM_SIZE,
                 0, (struct sockaddr *)&sin, &sin_len);
        sock_handle_conn_ack(sconn, rx, a, b, id, sin);
        break;
    case SOCK_MSG_DISCONNECT:
        break;
    case SOCK_MSG_SEND:
        recvfrom(sep->sock, rx->buffer, SOCK_AM_SIZE,
                 0, (struct sockaddr *)&sin, &sin_len);
        sock_handle_active_message(sconn, rx, a, b, id);
        break;
    case SOCK_MSG_KEEPALIVE:
        break;
    case SOCK_MSG_ACK_ONLY:
        break;
    case SOCK_MSG_ACK_UP_TO:
        break;
    case SOCK_MSG_SACK:
        break;
    case SOCK_MSG_RMA_WRITE:
        break;
    case SOCK_MSG_RMA_WRITE_DONE:
        break;
    case SOCK_MSG_RMA_READ_REQUEST:
        break;
    case SOCK_MSG_RMA_READ_REPLY:
        break;
    default:
        debug(CCI_DB_MSG, "unknown active message with type %d\n", type);
    }

out:
    if (drop_msg) {
        pthread_mutex_lock(&sep->lock);
        TAILQ_INSERT_HEAD(&sep->idle_rxs, rx, entry);
        pthread_mutex_unlock(&sep->lock);
        sock_drop_msg(sep->sock);
    }

    CCI_EXIT;

    return;
}

static void
sock_recvfrom_lep(cci__lep_t *lep)
{
    int             ret     = 0;
    uint8_t         a;
    uint16_t        b;
    uint32_t        id;
    uint32_t        len     = SOCK_CONN_REQ_HDR_LEN + CCI_CONN_REQ_LEN;
    char            buffer[len];  /* per CCI spec */
    char            *ptr    = buffer;
    cci__crq_t      *crq    = NULL;
    cci__svc_t      *svc    = NULL;
    sock_crq_t      *scrq;
    struct sockaddr_in sin;
    socklen_t       sin_len = sizeof(sin);
    sock_lep_t      *slep   = NULL;
    sock_msg_type_t type;

    CCI_ENTER;

    /* get idle crq */

    slep = lep->priv;
    pthread_mutex_lock(&lep->lock);
    if (!TAILQ_EMPTY(&lep->crqs)) {
        crq = TAILQ_FIRST(&lep->crqs);
        TAILQ_REMOVE(&lep->crqs, crq, entry);
    }
    pthread_mutex_unlock(&lep->lock);

    /* recv msg */

    if (crq) {
        scrq = crq->priv;
        ptr = scrq->buffer;
    }
        
    ret = recvfrom(slep->sock, ptr, len, 0, (struct sockaddr *)&sin, &sin_len);
    if (ret < SOCK_CONN_REQ_HDR_LEN || !crq) {
        /* nothing available or partial header, return.
         * let the client retry */
        if (crq) {
            pthread_mutex_lock(&lep->lock);
            TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
            pthread_mutex_unlock(&lep->lock);
        }
        CCI_EXIT;
        return;
    }

    /* lookup connection from sin and id */

    sock_parse_header((sock_header_t *)scrq->buffer, &type, &a, &b, &id);

    {
        char name[32];
        memset(name, 0, sizeof(name));
        sock_sin_to_name(sin, name, sizeof(name));
        debug((CCI_DB_MSG), "listening ep %d recv'd %s msg from %s",
              slep->sock, sock_msg_type(type), name);
    }

    /* FIXME need to handle conn_ack after a reject as well */
    /* if !conn_req, drop msg, requeue crq */
    if (!(type == SOCK_MSG_CONN_REQUEST ||
          type == SOCK_MSG_CONN_ACK)) {
        char name[32];

        memset(name, 0, sizeof(name));
        sock_sin_to_name(sin, name, sizeof(name));
        debug(CCI_DB_MSG, "listening ep %d recv'd %s msg from %s - discarding it",
              slep->sock, sock_msg_type(type), name);
        pthread_mutex_lock(&lep->lock);
        TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
        pthread_mutex_unlock(&lep->lock);
        CCI_EXIT;
        return;
    }

    switch (type) {
    case SOCK_MSG_CONN_REQUEST:
    {
        char name[32];

        memset(name, 0, sizeof(name));
        sock_sin_to_name(sin, name, sizeof(name));
        /* FIXME we need to determine on which devices this peer is reachable */
        *((cci_device_t ***) &(crq->conn_req.devices)) = (cci_device_t **) sglobals->devices;
        crq->conn_req.devices_cnt = sglobals->count;
        crq->conn_req.data_ptr = scrq->buffer + SOCK_CONN_REQ_HDR_LEN;
        crq->conn_req.data_len = ret - SOCK_CONN_REQ_HDR_LEN;
        crq->conn_req.attribute = b;
        *((struct sockaddr_in *) &scrq->sin) = sin;
    
        debug(CCI_DB_CONN, "recv'd conn_req from %s (hash %d %d)", name, sock_ip_hash(ntohl(sin.sin_addr.s_addr), ntohs(sin.sin_port)), sock_ip_hash(sin.sin_addr.s_addr, sin.sin_port));
    
        svc = lep->svc;
        pthread_mutex_lock(&svc->lock);
        TAILQ_INSERT_TAIL(&svc->crqs, crq, entry);
        pthread_mutex_unlock(&svc->lock);
    
        break;
    }
    case SOCK_MSG_CONN_ACK:
    {
        char name[32];
        cci__crq_t *c, *ctmp;
        sock_crq_t *sc;

        memset(name, 0, sizeof(name));
        sock_sin_to_name(sin, name, sizeof(name));

        debug((CCI_DB_MSG|CCI_DB_CONN), "listening ep %d recv'd conn_ack "
              "from %s", slep->sock, name);

        /* remove crq from lep and return it to avail list */
        pthread_mutex_lock(&lep->lock);
        TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
        TAILQ_FOREACH_SAFE(c, &lep->passive, entry, ctmp) {
            sc = c->priv;
            if (sc->peer_id == id) {
                TAILQ_REMOVE(&lep->passive, c, entry);
                /* hang on svc after droppping lep->lock */
                TAILQ_INSERT_HEAD(&lep->crqs, c, entry);
                break;
            }
        }
        pthread_mutex_unlock(&lep->lock);
        break;
    }
    default:
        break;
    }

    CCI_EXIT;

    return;
}

static inline void
sock_progress_dev(cci__dev_t *dev)
{
    int have_token = 0;
    sock_dev_t *sdev;
    cci__ep_t *ep;
    cci__lep_t *lep;

    CCI_ENTER;

    sdev = dev->priv;
    pthread_mutex_lock(&sdev->lock);
    if (sdev->is_progressing == 0) {
        sdev->is_progressing = 1;
        have_token = 1;
    }
    pthread_mutex_unlock(&sdev->lock);
    if (!have_token) {
        CCI_EXIT;
        return;
    }

    sock_progress_sends(sdev);

    TAILQ_FOREACH(ep, &dev->eps, entry)
        sock_recvfrom_ep(ep);
    TAILQ_FOREACH(lep, &dev->leps, dentry)
        sock_recvfrom_lep(lep);
    /* TODO progress lep->passive? */

    pthread_mutex_lock(&sdev->lock);
    sdev->is_progressing = 0;
    pthread_mutex_unlock(&sdev->lock);

    CCI_EXIT;
    return;
}

static void *sock_progress_thread(void *arg)
{
    while (!sglobals->shutdown) {
        cci__dev_t *dev;
        cci_device_t const **device;

        /* for each device, try progressing */
        for (device = sglobals->devices;
             *device != NULL;
             device++) {
            dev = container_of(*device, cci__dev_t, device);
            sock_progress_dev(dev);
        }
        usleep(SOCK_PROG_TIME_US);
    }

    pthread_exit(NULL);
}
