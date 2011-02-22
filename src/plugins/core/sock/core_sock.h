/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2010 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2010 Oak Ridge National Labs.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_SOCK_H
#define CCI_CORE_SOCK_H

#include <netinet/in.h>

#include "cci/config.h"
#include "cci.h"
#include "cci_lib_types.h"

#define SOCK_AM_SIZE        (8 * 1024)  /* 8 KB - assume jumbo frames */
#define SOCK_EP_HASH_SIZE   (256)       /* nice round number */

/* A sock device needs the following items in the config file:
 * driver = sock    # must be lowercase
 * ip = 0.0.0.0     # valid IPv4 address of the adapter to use
 */

/* Message types */

typedef enum sock_msg_type {
    SOCK_MSG_INVALID = 0,
    SOCK_MSG_CONN_REQUEST,  /* SYN */
    SOCK_MSG_CONN_REPLY,    /* SYN-ACK */
    SOCK_MSG_CONN_ACK,      /* ACK */
    SOCK_MSG_DISCONNECT,    /* spec says no disconnect is sent */
    SOCK_MSG_SEND,
    SOCK_MSG_KEEPALIVE,

    /* the rest apply to reliable connections only */

    SOCK_MSG_ACK_ONLY,      /* ack only this seqno */
    SOCK_MSG_ACK_UP_TO,     /* ack up to and including this seqno */
    SOCK_MSG_SACK,          /* ack these blocks of sequences */
    SOCK_MSG_RMA_WRITE,
    SOCK_MSG_RMA_WRITE_DONE,
    SOCK_MSG_RMA_READ_REQUEST,
    SOCK_MSG_RMA_READ_REPLY,
    SOCK_MSG_TYPE_MAX
} sock_msg_type_t;

/*! Send active message context.
 *
 * \ingroup messages */
typedef struct sock_tx {
    /*! Associated event (includes public cci_event_t) */
    cci__evt_t evt;

    /*! Message type */
    sock_msg_type_t msg_type;

    /*! Flags (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
    int flags;

    /*! Buffer (wire header, user header, data) */
    void *buffer;

    /*! Buffer length */
    uint16_t len;

    /* Entry for hanging on ep->idle_txs, dev->queued, dev->pending */
    TAILQ_ENTRY(sock_tx) dentry;

    /* Entry for hanging on ep->txs */
    TAILQ_ENTRY(sock_tx) tentry;

    /*! If reliable, use the following: */

    /*! Sequence number */
    uint64_t seq;

    /*! Passes through the progress thread */
    uint64_t cycles;

    /*! Number of resend attempts */
    uint64_t resends;
} sock_tx_t;

/*! Receive active message context.
 *
 * \ingroup messages */
typedef struct sock_rx {
    /*! Associated event (includes public cci_event_t) */
    cci__evt_t evt;

    /*! Buffer (wire header, user header, data) */
    void *buffer;

    /*! Buffer length */
    uint16_t len;

    /* Entry for hanging on ep->idle_rxs, ep->loaned */
    TAILQ_ENTRY(sock_tx) entry;

    /* Entry for hanging on ep->rxs */
    TAILQ_ENTRY(sock_tx) gentry;
} sock_rx_t;

typedef struct sock_ep {
    /*! Socket for sending/recving */
    cci_os_handle_t sock;

    /*! Array of conn lists hased over IP/port */
    TAILQ_HEAD(s_conns, sock_conn) conn_hash[SOCK_EP_HASH_SIZE];

    /*! List of all txs */
    TAILQ_HEAD(s_txs, sock_tx) txs;

    /*! List of idle txs */
    TAILQ_HEAD(s_txsi, sock_tx) idle_txs;

    /*! List of all rxs */
    TAILQ_HEAD(s_rxs, sock_rx) rxs;

    /*! List of idle rxs */
    TAILQ_HEAD(s_rxsi, sock_rx) idle_rxs;

    /*! Lock for lists */
    pthread_mutex_t lock;
} sock_ep_t;

/* Connection info */

typedef enum sock_conn_status {
    SOCK_CONN_CLOSED    = -2,   /* shutdown */
    SOCK_CONN_CLOSING   = -1,   /* disconnect called */
    SOCK_CONN_INIT      =  0,
    SOCK_CONN_ACTIVE,           /* waiting on client ACK */
    SOCK_CONN_PASSIVE,          /* waiting on server ACK */
    SOCK_CONN_READY             /* received peer's ACK */
} sock_conn_status_t;

typedef struct sock_conn {
    /*! Status */
    sock_conn_status_t status;

    /*! Peer's sockaddr_in (IP, port) */
    const struct sockaddr_in sin;

    /*! Send timeout (if 0, use endpoint send timeout) */
    uint32_t tx_timeout;

    /*! ID we assigned to peer */
    uint32_t peer_id;

    /*! ID assigned to us by peer */
    uint32_t our_id;

    /*! Entry to hang on sock_ep->conns[hash] */
    TAILQ_ENTRY(sock_conn) entry;

    /*! Last sequence number sent */
    uint64_t seq;

    /*! Peer's last seqno received */
    uint64_t ack;

    /*! Lock to protect seq, ack */
    pthread_mutex_t lock;
} sock_conn_t;

typedef struct sock_dev {
    /*! Our IP address */
    in_addr_t   ip;

    /*! Queued sends */
    TAILQ_HEAD(s_queued, sock_tx) queued;

    /*! Pending (in-flight) sends */
    TAILQ_HEAD(s_pending, sock_tx) pending;

    /*! Lock to protect queued and pending */
    pthread_mutex_t lock;
} sock_dev_t;

typedef struct sock_globals {
    /*! Number of sock devices */
    int count;

    /*! Array of sock devices */
    cci_device_t const **devices;
} sock_globals_t;

extern sock_globals_t *sglobals;

BEGIN_C_DECLS

int cci_core_sock_post_load(cci_plugin_t *me);
int cci_core_sock_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_SOCK_H */
