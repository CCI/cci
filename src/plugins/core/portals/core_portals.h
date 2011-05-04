/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_PORTALS_H
#define CCI_CORE_PORTALS_H

#include <assert.h>
#include <portals/portals3.h>
#include "cci/config.h"

BEGIN_C_DECLS

#define PORTALS_DEFAULT_MSS       (8192)     /* 8 KB */
#define PORTALS_MIN_MSS           (1024)
#define PORTALS_MAX_MSS           (64 * 1024)

#define PORTALS_BLOCK_SIZE        (64)       /* bytes for id storage */
#define PORTALS_EP_MAX_HDR_SIZE   (32)       /* per spec */
#define PORTALS_EP_BUF_LEN        (8192)     /* 8 kB for now */
#define PORTALS_EP_RX_CNT         (1024)     /* max rx messages */
#define PORTALS_EP_TX_CNT         (128)      /* max tx messages */
#define PORTALS_EQ_RX_CNT         PORTALS_EP_RX_CNT * 3
#define PORTALS_EQ_TX_CNT         PORTALS_EP_TX_CNT * 4
#define PORTALS_BLOCK_SIZE        (64)       /* 64b blocks for id */
#define PORTALS_NUM_BLOCKS        (16384)    /* number of blocks */
#define PORTALS_MAX_EP_ID         (PORTALS_BLOCK_SIZE * PORTALS_NUM_BLOCKS)
#define PORTALS_EP_BITS           (32)
#define PORTALS_EP_SHIFT          (32)
#define PORTALS_PROG_TIME_US      (10000) /* try to progress every N microseconds */

#define PORTALS_WILDCARD          {PTL_NID_ANY, PTL_PID_ANY}
#define PORTALS_EP_MATCH          ((uint64_t)0)
#define PORTALS_EP_IGNORE         (~((uint64_t)0))

static inline uint64_t portals_tv_to_usecs(
    struct timeval         tv ) {

    return (tv.tv_sec*1000000)+tv.tv_usec;
}

#define PORTALS_TV_TO_USECS(tv)    (((tv).tv_sec*1000000)+(tv).tv_usec)

static inline uint64_t portals_get_usecs(void) {

    struct timeval         tv;

    gettimeofday( &tv, NULL );
    return portals_tv_to_usecs(tv);
}

/* Limit of 4 message types to ensure that we only use 2 bits for msg type */
typedef enum portals_msg_type {
    PORTALS_MSG_SEND,
    PORTALS_MSG_RMA_WRITE,
    PORTALS_MSG_RMA_READ,
    PORTALS_MSG_OOB
}   portals_msg_type_t;

/* generic match bits:

    <--------------------------- 62 bits ------------------------> 2b
   +--------------------------------------------------------------+--+
   |                               A                              |T |
   +--------------------------------------------------------------+--+

   where each message type decides how to use A and T is msg type

 */

#define PORTALS_TYPE_BITS           (2)
#define PORTALS_TYPE_MASK           ((1ULL << PORTALS_TYPE_BITS) - 1)

#define PORTALS_A_BITS              (62)
#define PORTALS_A_SHIFT             (2)
#define PORTALS_A_MASK              (((1ULL << PORTALS_A_BITS) - 1) << PORTALS_A_SHIFT)
#define PORTALS_A_MAX               (PORTALS_A_MASK)

#define PORTALS_TYPE(x)             ((uint32_t)(((uint64_t)(x))&PORTALS_TYPE_MASK))
#define PORTALS_A(x)                (((uint64_t)(x))&PORTALS_A_MASK)

#define PORTALS_PACK_BITS(type,a)   ((((uint64_t)(a))&PORTALS_A_MASK) | \
                                    (((uint64_t)(type))&PORTALS_TYPE_MASK))

static inline void portals_pack_bits(
    ptl_match_bits_t       *match_bits,
    portals_msg_type_t     type,
    uint64_t               a ) {

    *match_bits = PORTALS_PACK_BITS(type, a);
}

static inline void portals_parse_match_bits(
    ptl_match_bits_t       match_bits,
    portals_msg_type_t     *type,
    uint64_t               *a ) {

    *type=PORTALS_TYPE(match_bits);
    *a=PORTALS_A(match_bits);
}

/* Send

   Matchbits:
    <---------------------------- 64 bits --------------------------->
    <----------- 32b -------------->  5b  <---- 16b ----> <-- 9b -> 2b
   +--------------------------------+----+---------------+---------+--+
   |      receiver endpoint id      |hlen|   data len    | reservd |T |
   +--------------------------------+----+---------------+---------+--+
   where T is PORTALS_MSG_SEND

   hdr_data is the receiver's conn opaque handle

 */

/* RMA write

   Matchbits:
    <--------------------------- 62 bits ------------------------> 2b
   +--------------------------------------------------------------+--+
   |                       remote RMA handle                      |T |
   +--------------------------------------------------------------+--+
   where T is PORTALS_MSG_RMA_WRITE

   hdr_data is NULL

 */

/* RMA read

   Matchbits:
    <--------------------------- 62 bits ------------------------> 2b
   +--------------------------------------------------------------+--+
   |                       remote RMA handle                      |T |
   +--------------------------------------------------------------+--+
   where T is PORTALS_MSG_RMA_READ

   hdr_data is NULL

 */

/* OOB msg types */

typedef enum portals_msg_oob_type {
    PORTALS_MSG_OOB_CONN_REQUEST = 0x1,
    PORTALS_MSG_OOB_CONN_REPLY = 0x2,
    PORTALS_MSG_KEEPALIVE = 0x3
}   portals_msg_oob_type_t;

/* OOB msg payload is a minimum of one uint32_t with the OOB msg type */

/* connection request:

   Matchbits:
    <--------------------------- 62 bits -------------------------> 2b
    <------------ 32b ------------> <---- 16b ----> <- 8b -> <4b> 2b 2b
   +-------------------------------+---------------+--------+----+--+--+
   |      server endpoint id       |      len      |  attr  |rsv |O |T |
   +-------------------------------+---------------+--------+----+--+--+
   where T is PORTALS_MSG_OOB and O is PORTALS_MSG_OOB_CONN_REQUEST

   hdr_data is the client's conn opaque handle

   Payload:
    <------------- 32b ------------>
   +--------------------------------+
   |          max_send_size         |
   +--------------------------------+
   |      max_recv_buffer_count     |
   +--------------------------------+
   |      client's endpoint id      |
   +--------------------------------+

 */

typedef struct portals_conn_request {
    uint32_t max_send_size;         /* mss that the client supports */
    uint32_t max_recv_buffer_count; /* max recvs the client can handle */
    uint32_t client_ep_id;          /* client's endpoint id */
}   portals_conn_request_t;

/* connection reply (accept):

   Matchbits:
    <--------------------------- 62 bits ----------------------> 2b 2b
   +-------------------------------+----------------------------+--+--+
   |      client endpoint id       |           reserved         |O |T |
   +-------------------------------+----------------------------+--+--+
   where T is PORTALS_MSG_OOB and O is PORTALS_MSG_OOB_CONN_REPLY

   hdr_data is the client's conn opaque handle

   Payload:
    <------------- 32b ------------>
   +--------------------------------+
   |          max_send_size         |
   +--------------------------------+
   |      max_recv_buffer_count     |
   +--------------------------------+
   |     server conn opaque upper   |
   +--------------------------------+
   |     server conn opaque lower   |
   +--------------------------------+

 */

typedef struct portals_conn_accept {
    uint32_t server_ep_id;
    uint32_t max_send_size;         /* the min of the two mss */
    uint32_t max_recv_buffer_count; /* max recvs the server can handle */
    uint32_t server_conn_upper;     /* upper 32 bits of server conn opaque */
    uint32_t server_conn_lower;     /* lower 32 bits of server conn opaque */
}   portals_conn_accept_t;

/* connection reply (reject):

   Matchbits:
    <--------------------------- 62 bits ----------------------> 2b 2b
   +-------------------------------+------------------------------+--+
   |      client endpoint id       |           reserved         |O |T |
   +-------------------------------+----------------------------+--+--+
   where T is PORTALS_MSG_OOB and O is PORTALS_MSG_OOB_CONN_REPLY

   hdr_data is the client's conn opaque handle

   NO Payload

 */

typedef struct portals_tx {
    cci__evt_t              evt;        /* associated event */
    portals_msg_type_t      msg_type;   /* message type */
    portals_msg_oob_type_t  oob_type;   /* if PORTALS_MSG_OOB above, set oob type here */
    int                     flags;      /* (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
    void                    *buffer;    /* active msg buffer */
    uint16_t                len;        /* length of buffer */
    ptl_handle_md_t         mdh;        /* Memory descriptor handle */
    TAILQ_ENTRY(portals_tx) dentry;     /* Hangs on ep->idle_txs  dev->queued */
                                        /*   dev->pending */
    TAILQ_ENTRY(portals_tx) tentry;     /* Hangs on ep->txs */
}   portals_tx_t;

typedef struct portals_am_buffer {
    void                   *buffer;          /* large buffer for incoming msgs */
    uint32_t               length;           /* max_recv_buffer_count * mss / 2 */
    int                    active;           /* whether able to recv or not */
    uint32_t               refcnt;           /* how many fragments held by app */
    struct portals_ep      *pep;             /* owning Portals endpoint */
    ptl_handle_me_t        meh;              /* ME handle */
    ptl_handle_md_t        mdh;              /* MD handle */
} portals_am_buffer_t;

typedef struct portals_rx {
    cci__evt_t              evt;        /* associated event */
    ptl_event_t             pevent;     /* Portals event */
    portals_am_buffer_t     *am;        /* owning buffer */
    TAILQ_ENTRY(portals_rx) entry;      /* Hangs on ep->idle_rxs */
    TAILQ_ENTRY(portals_rx) gentry;     /* Hangs on ep->rxs */
}   portals_rx_t;

typedef struct portals_dev {
    ptl_process_id_t       idp;
    ptl_pt_index_t         table_index;
    ptl_handle_ni_t        niHandle;         /* Seastar handle */
    int                    max_mes;          /* Match Entries */
    int                    max_mds;          /* Memory Descriptors */
    int                    max_eqs;          /* Event Queues */
    int                    max_ac_index;     /* Access Control Table */
    int                    max_pt_index;     /* Portals Table Index */
    int                    max_md_iovecs;    /* Number of IO vectors */
    int                    max_me_list;      /* ME's to Portals Index */
    int                    max_getput_md;    /* Max len atomic swap */
    int                    is_progressing;   /* Being progressed? */
    uint64_t               *ep_ids;          /* Endpoint id blocks */
}   portals_dev_t;

typedef struct portals_globals {
    int                    count;            /* portals devices */
    const cci_device_t     **devices;        /* Array of devices */
}   portals_globals_t;
extern portals_globals_t   *pglobals;

typedef struct portals_ep {
    uint32_t                        id;         /* id for endpoint multiplexing */
    ptl_handle_eq_t                 eqh;        /* eventq handle */
    portals_am_buffer_t             am[2];      /* each holds 1/2 of active msg buffer */
    int                             in_use;     /* token to serialize get_event */
    TAILQ_HEAD(p_txs, portals_tx)   txs;        /* List of all txs */
    TAILQ_HEAD(p_txsi, portals_tx)  idle_txs;   /* List of idle txs */
    TAILQ_HEAD(p_rxs, portals_rx)   rxs;        /* List of all rxs */
    TAILQ_HEAD(p_rxsi, portals_rx)  idle_rxs;   /* List of all rxs */
    TAILQ_HEAD(p_conns, portals_conn) conns;    /* List of all conns for cleanup */
}   portals_ep_t;

typedef struct portals_lep {

    cci_os_handle_t        fd;               /* OS handle for poll */
    ptl_handle_eq_t                 eqh;        /* eventq handle */
}   portals_lep_t;

typedef struct portals_crq {
    void                   *buffer;     /* Buffer for optional payload */
    ptl_handle_md_t         mdh;        /* Memory descriptor handle */
    ptl_handle_me_t         meh;        /* Match list entry handle */
    ptl_process_id_t       idp;         /* Client's nid, pid */
    uint32_t               client_id;   /* Client's ep id */
    uint32_t               mss;         /* Client's MSS */
    uint32_t               max_recv_buffer_count;
    uint64_t               client_conn; /* Client's conn addr */
}   portals_crq_t;

/* Connection info */
typedef enum portals_conn_status {
    PORTALS_CONN_CLOSED=-2,                  /* Shutdown */
    PORTALS_CONN_CLOSING=-1,                 /* Disconnect called */
    PORTALS_CONN_INIT=0,                     /* NULL (initial) state */
    PORTALS_CONN_ACTIVE,                     /* Waiting on server ACK */
    PORTALS_CONN_PASSIVE,                    /* Waiting on client ACK */
    PORTALS_CONN_READY                       /* Open and usable */
}   portals_conn_status_t;

typedef struct portals_conn {
    cci__conn_t             *conn;          /* Owning conn */
    portals_conn_status_t   status;         /* Status */
    ptl_process_id_t        idp;            /* Peer's (NID, PID) */
    uint64_t                peer_conn;      /* Peer's conn addr */
    uint32_t                peer_ep_id;     /* Peer's endpoint ID */
    uint32_t                max_tx_cnt;     /* Max sends in flight */
    uint32_t                mss;            /* max_segment_size for this conn */
    portals_tx_t            *tx;            /* for conn request */
    TAILQ_ENTRY(portals_conn) entry;        /* Hangs on pep->conns */
}   portals_conn_t;

int cci_core_portals_post_load(cci_plugin_t *me);
int cci_core_portals_pre_unload(cci_plugin_t *me);
END_C_DECLS

#endif /* CCI_CORE_PORTALS_H */
