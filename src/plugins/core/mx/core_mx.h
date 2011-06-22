/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_MX_H
#define CCI_CORE_MX_H

#include "cci/config.h"
#include "myriexpress.h"
#include "mx_extensions.h"

BEGIN_C_DECLS

#define MX_KEY              (0x636369)  /* "cci" */
#define MX_MSS              (1024)

#define MX_EP_MAX_HDR_SIZE  (32)
#define MX_EP_BUF_LEN       (MX_MSS)
#define MX_EP_RX_CNT        (1024)      /* max rx messages */
#define MX_EP_TX_CNT        (128)       /* max tx messages */
#define MX_EP_TX_TIMEOUT_MS (20 * 1000) /* 20 seconds */
#define MX_EP_SHIFT         (32)

/* Valid URI include:
 *
 * mx://foo.bar.com     # MX hostname
 */

/* Valid URI arguments:
 *
 * :0			# board index
 * :0:4                 # board index followed by endpoint ID
 */

/* A MX device needs the following items in the config file:
 *
 * driver = mx		# must be lowercase
 *
 * A MX device may have these items:
 *
 * listen_ep_id = 9	# endpoint to listen on
 */


/* Limit of 4 message types to ensure that we only use 2 bits for msg type */
typedef enum mx_msg_type {
    MX_MSG_SEND,
    MX_MSG_RMA_WRITE,
    MX_MSG_RMA_READ,
    MX_MSG_OOB
}   mx_msg_type_t;

/* generic match bits:

    <--------------------------- 62 bits ------------------------> 2b
   +--------------------------------------------------------------+--+
   |                               A                              |T |
   +--------------------------------------------------------------+--+

   where each message type decides how to use A and T is msg type

 */

#define MX_TYPE_BITS            (2)
#define MX_TYPE_MASK            ((1ULL << MX_TYPE_BITS) - 1)

#define MX_A_BITS               (62)
#define MX_A_SHIFT              (2)
#define MX_A_MASK               (((1ULL << MX_A_BITS) - 1) << MX_A_SHIFT)
#define MX_A_MAX                (MX_A_MASK)

#define MX_TYPE(x)              ((uint32_t)(((uint64_t)(x)) & MX_TYPE_MASK))
#define MX_A(x)                 (((uint64_t)(x)) & MX_A_MASK)

#define MX_PACK_BITS(type,a)    ((((uint64_t)(a)) & MX_A_MASK) | \
                                 (((uint64_t)(type)) & MX_TYPE_MASK))

static inline void
mx_pack_bits(uint64_t *match_bits, mx_msg_type_t type, uint64_t a)
{
    *match_bits = MX_PACK_BITS(type, a);
}

static inline void
mx_parse_match_bits(uint64_t match_bits, mx_msg_type_t *type, uint64_t *a)
{
    *type = MX_TYPE(match_bits);
    *a = MX_A(match_bits);
}

/* Send

   Matchbits:
    <---------------------------- 64 bits --------------------------->
    <----------- 32b -------------->  5b  <---- 16b ----> <- 8b -> 1 2b
   +--------------------------------+----+---------------+--------+-+--+
   |      receiver endpoint id      |hlen|   data len    | reservd|R|T |
   +--------------------------------+----+---------------+--------+-+--+
   where T is MX_MSG_SEND

   R is 0 for UU and 1 for RO/RU

   hdr_data is the receiver's conn opaque handle

 */

typedef enum mx_msg_oob_type {
    MX_MSG_OOB_CONN_REQUEST = 0x1,
    MX_MSG_OOB_CONN_REPLY = 0x2,
    MX_MSG_KEEPALIVE = 0x3
} mx_msg_oob_type_t;

/* OOB msg payload is a minimum of one uint32_t with the OOB msg type */

/* connection request:

   Matchbits:
    <--------------------------- 62 bits -------------------------> 2b
    <------------ 32b ------------> <---- 16b ----> <- 8b -> <4b> 2b 2b
   +-------------------------------+---------------+--------+----+--+--+
   |      server endpoint id       |      len      |  attr  |rsv |O |T |
   +-------------------------------+---------------+--------+----+--+--+
   where T is MX_MSG_OOB and O is MX_MSG_OOB_CONN_REQUEST

   Payload:
    <------------- 32b ------------>
   +--------------------------------+
   |      max_recv_buffer_count     |
   +--------------------------------+
   |      client's endpoint id      |
   +--------------------------------+
   |     client conn opaque upper   |
   +--------------------------------+
   |     client conn opaque lower   |
   +--------------------------------+

 */

typedef struct mx_conn_request {
    uint32_t max_recv_buffer_count; /* max recvs the client can handle */
    uint32_t client_ep_id;          /* client's endpoint id */
    uint32_t client_conn_upper;     /* upper 32 bits of client conn opaque */
    uint32_t client_conn_lower;     /* lower 32 bits of client conn opaque */
} mx_conn_request_t;

/* connection reply (accept):

   Matchbits:
    <--------------------------- 62 bits ----------------------> 2b 2b
   +-------------------------------+----------------------------+--+--+
   |      client endpoint id       |           reserved         |O |T |
   +-------------------------------+----------------------------+--+--+
   where T is MX_MSG_OOB and O is MX_MSG_OOB_CONN_REPLY

   Payload:
    <------------- 32b ------------>
   +--------------------------------+
   |      max_recv_buffer_count     |
   +--------------------------------+
   |     client conn opaque upper   |
   +--------------------------------+
   |     client conn opaque lower   |
   +--------------------------------+
   |     server conn opaque upper   |
   +--------------------------------+
   |     server conn opaque lower   |
   +--------------------------------+

 */

typedef struct mx_conn_accept {
    uint32_t max_recv_buffer_count; /* max recvs the server can handle */
    uint32_t client_conn_upper;     /* upper 32 bits of client conn opaque */
    uint32_t client_conn_lower;     /* lower 32 bits of client conn opaque */
    uint32_t server_conn_upper;     /* upper 32 bits of server conn opaque */
    uint32_t server_conn_lower;     /* lower 32 bits of server conn opaque */
} mx_conn_accept_t;

/* connection reply (reject):

   Matchbits:
    <--------------------------- 62 bits ----------------------> 2b 2b
   +-------------------------------+------------------------------+--+
   |      client endpoint id       |           reserved         |O |T |
   +-------------------------------+----------------------------+--+--+
   where T is MX_MSG_OOB and O is MX_MSG_OOB_CONN_REPLY

   hdr_data is the client's conn opaque handle

   NO Payload

 */

typedef struct mx_tx {
    cci__evt_t          evt;        /* associated event */
    mx_msg_type_t       msg_type;   /* message type */
    mx_msg_oob_type_t   oob_type;   /* if MX_MSG_OOB above, set oob type here */
    int                 flags;      /* (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
    //void                *buffer;    /* active msg buffer */
    //uint16_t            len;        /* length of buffer */
    TAILQ_ENTRY(mx_tx)  dentry;     /* Hangs on ep->idle_txs  dev->queued */
                                    /*   dev->pending */
    TAILQ_ENTRY(mx_tx)  tentry;     /* Hangs on ep->txs */
} mx_tx_t;

typedef struct mx_rx {
    cci__evt_t          evt;        /* associated event */
    void                *buffer;    /* active msg buffer */
    uint64_t            match;      /* match bits for msg */
    TAILQ_ENTRY(mx_rx)  entry;      /* Hangs on ep->idle_rxs */
    TAILQ_ENTRY(mx_rx)  gentry;     /* Hangs on ep->rxs */
} mx_rx_t;

typedef struct mx_dev {
    uint32_t            board;          /* board index */
    int                 is_progressing; /* Being progressed? */
} mx_dev_t;

typedef struct mx_globals {
    int                 count;      /* mx devices */
    const cci_device_t  **devices;  /* Array of devices */
} mx_globals_t;

extern mx_globals_t *pglobals;

typedef struct mx_ep {
    mx_endpoint_t                   ep;
    uint32_t                        id;         /* id for endpoint multiplexing */
    int                             in_use;     /* token to serialize get_event */
    TAILQ_HEAD(p_txs, mx_tx)        txs;        /* List of all txs */
    TAILQ_HEAD(p_txsi, mx_tx)       idle_txs;   /* List of idle txs */
    TAILQ_HEAD(p_rxs, mx_rx)        rxs;        /* List of all rxs */
    TAILQ_HEAD(p_rxsi, mx_rx)       idle_rxs;   /* List of all rxs */
    TAILQ_HEAD(p_conns, mx_conn)    conns;      /* List of all conns for cleanup */
} mx_ep_t;

typedef struct mx_lep {
    mx_endpoint_t       ep;
    cci_os_handle_t     fd;         /* OS handle for poll */
} mx_lep_t;

typedef struct mx_crq {
    void                   *buffer;     /* Buffer for optional payload */
    mx_endpoint_addr_t     epa;         /* Client's endpoint addr */
    uint32_t               client_id;   /* Client's ep id */
    uint32_t               max_recv_buffer_count;
    uint64_t               client_conn; /* Client's conn addr */
} mx_crq_t;

/* Connection info */
typedef enum mx_conn_status {
    MX_CONN_CLOSED = -2,                /* Shutdown */
    MX_CONN_CLOSING = -1,               /* Disconnect called */
    MX_CONN_INIT = 0,                   /* NULL (initial) state */
    MX_CONN_ACTIVE,                     /* Waiting on server ACK */
    MX_CONN_PASSIVE,                    /* Waiting on client ACK */
    MX_CONN_READY                       /* Open and usable */
} mx_conn_status_t;

typedef struct mx_conn {
    cci__conn_t             *conn;          /* Owning conn */
    mx_conn_status_t        status;         /* Status */
    mx_endpoint_addr_t      epa;            /* Peer's (NID, PID) */
    uint64_t                peer_conn;      /* Peer's conn addr */
    uint32_t                peer_ep_id;     /* Peer's endpoint ID */
    uint32_t                max_tx_cnt;     /* Max sends in flight */
    mx_tx_t                 *tx;            /* for conn request */
    TAILQ_ENTRY(mx_conn) entry;             /* Hangs on pep->conns */
} mx_conn_t;



int cci_core_mx_post_load(cci_plugin_t *me);
int cci_core_mx_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_MX_H */
