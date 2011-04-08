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

#define PORTALS_EP_MAX_HDR_SIZE   (8)        /* bytes */
#define PORTALS_BLOCK_SIZE        (64)       /* bytes for id storage */
#define PORTALS_EP_BUF_LEN        (8192)     /* 8 kB for now */
#define PORTALS_EP_RX_CNT         (1024)     /* max rx messages */
#define PORTALS_EP_TX_CNT         (128)      /* max tx messages */
#define PORTALS_EQ_RX_CNT         PORTALS_EP_RX_CNT * 3
#define PORTALS_EQ_TX_CNT         PORTALS_EP_TX_CNT * 4
#define PORTALS_EP_TX_TIMEOUT_SEC (60)       /* seconds for now */
#define PORTALS_EP_HASH_SIZE      (256)      /* nice round number */
#define PORTALS_BLOCK_SIZE        (64)       /* 64b blocks for id */
#define PORTALS_NUM_BLOCKS        (16384)    /* number of blocks */
#define PORTALS_CONN_REQ_HDR_LEN  (sizeof(struct portals_header_r))
#define PORTALS_RESEND_TIME_SEC   (1)        /* secs between resends */
#define PORTALS_PROG_TIME_US      (10000)    /* try progress N usecs */
#define PORTALS_RESEND_CYCLES     (PORTALS_RESEND_TIME_SEC*1000000/\
                                   PORTALS_PROG_TIME_US)

#define PORTALS_WILDCARD          {PTL_NID_ANY, PTL_PID_ANY};
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

typedef enum portals_msg_type {

    PORTALS_MSG_INVALID=0,
    PORTALS_MSG_CONN_REQUEST,                /* SYN */
    PORTALS_MSG_CONN_REPLY,                  /* SYN-ACK */
    PORTALS_MSG_CONN_ACK,                    /* ACK */
    PORTALS_MSG_DISCONNECT,                  /* no disconnect is sent */
    PORTALS_MSG_SEND,
    PORTALS_MSG_KEEPALIVE,

    /* the rest apply to reliable connections only */
    PORTALS_MSG_ACK_ONLY,                    /* ack only this seqno */
    PORTALS_MSG_ACK_UP_TO,                   /* ack thru this seqno */
    PORTALS_MSG_SACK,                        /* ack blks of sequences */
    PORTALS_MSG_RMA_WRITE,
    PORTALS_MSG_RMA_WRITE_DONE,
    PORTALS_MSG_RMA_READ_REQUEST,
    PORTALS_MSG_RMA_READ_REPLY,
    PORTALS_MSG_TYPE_MAX
}   portals_msg_type_t;

typedef enum portals_tx_state_t {

    PORTALS_TX_IDLE=0,                       /* available */
    PORTALS_TX_QUEUED,                       /* queued for sending */
    PORTALS_TX_PENDING,                      /* sent, waiting ack */
    PORTALS_TX_COMPLETED                     /* completed, status set */
}   portals_tx_state_t;

typedef struct portals_tx {

    cci__evt_t             evt;              /* associated event */
    portals_msg_type_t     msg_type;         /* message type */
    int                    flags;            /* (CCI_FLAG_
                                           [BLOCKING|SILENT|NO_COPY]) */
    portals_tx_state_t     state;            /* state of send */
    void                   *buffer;          /* Buffer */
    uint16_t               len;              /* Buffer length */
    TAILQ_ENTRY(portals_tx) dentry;          /* Hangs on ep->idle_txs  dev->queued */
                                             /*   dev->pending */
    TAILQ_ENTRY(portals_tx) tentry;          /* Hangs on ep->txs */

    /*! If reliable, use the following: */
    uint32_t               seq;              /* Sequence number */
    uint32_t               send_count;       /* Send attempts */
    uint64_t               last_attempt_us;  /* Last send (usec) */
    uint64_t               timeout_us;       /* Timeout (usec) */
}   portals_tx_t;

typedef struct portals_rx {

    cci__evt_t             evt;              /* associated event */
    void                   *buffer;          /* Buffer */
    uint16_t               len;              /* Buffer length */
    TAILQ_ENTRY(portals_rx) entry;           /* Hangs on ep->idle_rxs, ep->loaned */
    TAILQ_ENTRY(portals_rx) gentry;          /* Hangs on ep->rxs */
}   portals_rx_t;

typedef struct portals_seq_ts {

    uint32_t               seq;
    uint32_t               ts;
}   portals_seq_ts_t;

static inline void portals_pack_seq_ts(
    portals_seq_ts_t       *sa,
    uint32_t               seq,
    uint32_t               ts ) {

    sa->seq=htonl(seq);
    sa->ts=htonl(ts);
}

static inline void portals_parse_seq_ts(
    portals_seq_ts_t       *sa,
    uint32_t               *seq,
    uint32_t               *ts ) {

    *seq=ntohl(sa->seq);
    *ts=ntohl(sa->ts);
}

typedef struct portals_seq_ack {

    uint32_t               seq;
    uint32_t               seq_ack;
    uint32_t               ack;
}   portals_seq_ack_t;

/* generic header:

    <---------- 32 bits ---------->
    <- 8 -> <--8--> <---- 16 ----->
   +-------+-------+---------------+
   | type  |   A   |       B       |
   +-------+-------+---------------+
   |               C               |
   +-------+-------+---------------+

   where each message type decides how to use A, B, and C

 */
typedef struct portals__header {

    uint32_t               type;             /* upper 8b are type,
                                                next 8b are A and
                                                rest are B */
    uint32_t               c;
    char                   data[0];          /* unreliable payload */
}   portals_header_t;

typedef struct portals_header_r {            /* reliable header */

    portals_header_t       header;
    portals_seq_ts_t       seq_ts;
    char                   data[0];          /* reliable payload */
}   portals_header_r_t;

#define PORTALS_T_BITS            (8)
#define PORTALS_T_MASK            (0xFF)
#define PORTALS_T_SHIFT           (24)

#define PORTALS_A_BITS            (8)
#define PORTALS_A_MASK            (0xFF)
#define PORTALS_A_MAX             (PORTALS_A_MASK)
#define PORTALS_A_SHIFT           (16)

#define PORTALS_B_BITS            (16)
#define PORTALS_B_MASK            (0xFFFF)
#define PORTALS_B_MAX             (PORTALS_B_MASK)

#define PORTALS_TYPE(x)           ((uint8_t)((x)>>PORTALS_T_SHIFT))
#define PORTALS_A(x)              ((uint8_t)(((x)>>PORTALS_A_SHIFT)&   \
                                                   PORTALS_A_MASK))
#define PORTALS_B(x)              ((uint16_t)((x)&PORTALS_B_MASK))

#define PORTALS_PACK_TYPE( t, a, b )                                   \
                                  ((((uint32_t)(t))<<PORTALS_T_SHIFT)| \
                                   (((uint32_t)(a))<<PORTALS_A_SHIFT)| \
                                    ((uint32_t)(b)))

static inline void portals_pack_header(
    portals_header_t       *header,
    portals_msg_type_t     type,
    uint8_t                a,
    uint16_t               b,
    uint32_t               c ) {

    assert( type<PORTALS_MSG_TYPE_MAX && type>PORTALS_MSG_INVALID );
    header->type=htonl(PORTALS_PACK_TYPE( type, a, b ));
    header->c=htonl(c);
    fprintf( stderr, "type=%d a=%d b=%d c=%d\n", type, a, b, c );
}

static inline void portals_parse_header(
    portals_header_t       *header,
    portals_msg_type_t     *type,
    uint8_t                *a,
    uint16_t               *b,
    uint32_t               *c ) {

    uint32_t               hl=ntohl(header->type);

    *type=PORTALS_TYPE(hl);
    *a=PORTALS_A(hl);
    *b=PORTALS_B(hl);
    *c=ntohl(header->c);
}

#define PORTALS_SEQ_BITS          (32)
#define PORTALS_SEQ_MASK          (~0)
#define PORTALS_ACK_MASK          (PORTALS_SEQ_MASK)
#define PORTALS_U64_LT(a,b)       ((int64_t)((a)-(b))<0)

/* connection request/reply */
typedef struct portals_handshake {

    uint32_t               id;               /* peer id to send to me */
    uint32_t               ack;              /* to ack request/reply */
    uint32_t               max_recv_buffer_count;
                                             /* max recv's I handle */
    uint32_t               mss;              /* less of each endpoint */
}   portals_handshake_t;

static inline void portals_pack_handshake(
    portals_handshake_t    *hs,
    uint32_t               id,
    uint32_t               ack,
    uint32_t               max_recv_buffer_count,
    uint32_t               mss ) {

/*
    assert(mss < (SOCK_UDP_MAX - SOCK_MAX_HDR_SIZE));
    assert(mss >= SOCK_MIN_MSS);
*/
    hs->id=htonl(id);
    hs->ack=htonl(ack);
    hs->max_recv_buffer_count=htonl(max_recv_buffer_count);
    hs->mss=htonl(mss);
}

static inline void portals_parse_handshake(
    portals_handshake_t    *hs,
    uint32_t               *id,
    uint32_t               *ack,
    uint32_t               *max_recv_buffer_count,
    uint32_t               *mss ) {

    *id=ntohl(hs->id);
    *ack=ntohl(hs->ack);
    *max_recv_buffer_count=ntohl(hs->max_recv_buffer_count);
    *mss=ntohl(hs->mss);
}

/* connection request header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  | attr  |   data len    |
   +-------+-------+---------------+
   |               0               |
   +-------------------------------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

   +-------------------------------+
   |           client id           |
   +-------------------------------+
   |               0               |
   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+

   The peer uses the id when sending to us.
   The user data follows the header.

   attr: CCI_CONN_ATTR_[UU|RU|RO]
   data len: amount of user data following header
   id: peer uses ID when sending to us
   seq: starting sequence number for this connection
   ts: timestamp in usecs
   max_recv_buffer_count: number of msgs we can receive
   mss: max send size

 */
static inline void portals_pack_conn_request(
    portals_header_t       *header,
    cci_conn_attribute_t   attr,
    uint16_t               data_len,
    uint32_t               id ) {

    portals_pack_header( header, PORTALS_MSG_CONN_REQUEST,
                        (uint8_t)attr, data_len, id);
}

/* connection reply header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  | reply |   reserved    |
   +-------+-------+---------------+
   |           client id           |
   +-------------------------------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

   +-------------------------------+
   |           server id           |
   +-------------------------------+
   |          client's seq         |
   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+

   The reply is 0 for success else errno.
   I use this ID when sending to this peer.
   The accepting peer will send his id back in the payload (length 4)

   reply: CCI_EVENT_CONNECT_[SUCCESS|REJECTED]
   mss: max app payload (user header and user data)
 */
static inline void portals_pack_conn_reply(
    portals_header_t       *header,
    uint8_t                reply,
    uint32_t               id ) {

    portals_pack_header( header, PORTALS_MSG_CONN_REPLY, reply, 0, id );
}

typedef struct portals_dev {

    ptl_process_id_t       idp;
    ptl_pt_index_t         table_index;
    ptl_handle_ni_t        niHandle;         /* Seastar handle */
    ptl_handle_eq_t        eqhSend;          /* EQ handle for Send */
    ptl_handle_eq_t        eqhRecv;          /* EQ handle for Recv */
    int                    max_mes;          /* Match Entries */
    int                    max_mds;          /* Memory Descriptors */
    int                    max_eqs;          /* Event Queues */
    int                    max_ac_index;     /* Access Control Table */
    int                    max_pt_index;     /* Portals Table Index */
    int                    max_md_iovecs;    /* Number of IO vectors */
    int                    max_me_list;      /* ME's to Portals Index */
    int                    max_getput_md;    /* Max len atomic swap */
    TAILQ_HEAD( p_queued, portals_tx ) queued;           /* Queued sends */
    TAILQ_HEAD( p_pending, portals_tx ) pending;          /* Pending sends */
    pthread_mutex_t        lock;             /* For queued/pending */
    int                    is_progressing;   /* Being progressed? */
}   portals_dev_t;

typedef struct portals_globals {

    int                    count;            /* portals devices */
    const cci_device_t     **devices;        /* Array of devices */
    int                    shutdown;         /* In shutdown? */
}   portals_globals_t;
extern portals_globals_t   *pglobals;

typedef struct portals_ep {

    TAILQ_HEAD( p_txs, portals_tx ) txs; /* List of all txs */
    TAILQ_HEAD( p_txsi, portals_tx ) idle_txs; /* List of idle txs */
    TAILQ_HEAD( p_rxs, portals_rx ) rxs; /* List of all rxs */
    TAILQ_HEAD( p_rxsi, portals_rx ) idle_rxs; /* List of idle rxs */
    pthread_mutex_t        lock;             /* Lock for lists */
    uint64_t               *ids;             /* Connection id blocks */
    /* List of active connections awaiting replies */
    TAILQ_HEAD( p_active, portals_conn ) active_hash[PORTALS_EP_HASH_SIZE];
}   portals_ep_t;

typedef struct portals_lep {

    cci_os_handle_t        fd;               /* OS handle for poll */
}   portals_lep_t;

typedef struct portals_crq {

    void                   *buffer;          /* Buffer for request */
    ptl_process_id_t       idp;              /* Client's address */
    uint32_t               peer_id;          /* Peer's id reject */
    uint64_t               last_attempt_us;  /* Last send usec reject */
    uint64_t               timeout_us;       /* Timeout usec reject */
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

    cci__conn_t            *conn;            /* Owning conn */
    portals_conn_status_t  status;           /* Status */
    ptl_process_id_t       idp;              /* Peer's (NID, PID) */
    ptl_pt_index_t         table_index;      /* Peer's (NID, PID) */
    uint32_t               peer_id;          /* ID assigned by peer */
    uint32_t               id;               /* ID assigned to peer */
    uint32_t               max_tx_cnt;       /* Max sends in flight */
    TAILQ_ENTRY(portals_conn) entry;         /* Hangs on portals_ep->conns[hash] */
    uint32_t               seq;              /* Last sequence sent */
    uint32_t               seq_pending;      /* Lowest pending seq */
    uint32_t               pending;          /* Pending send count */
    TAILQ_HEAD( p_tx_seqs, portals_tx ) tx_seqs; /* Pending awaiting acks */
    uint32_t               acked;            /* Peer's last */
                                             /*   contiguous seqno */
                                             /*   acked (ACK_UP_TO) */
    uint32_t               ts;               /* Peer's last timestamp */
    uint32_t               last_ack_seq;     /* Seq of last ack tx */
    uint64_t               last_ack_ts;      /* Timestamp last ack tx */
    int                    ack_queued;
    TAILQ_HEAD( p_acks, portals_ack ) acks;  /* List sequence to ack */
    pthread_mutex_t        lock;             /* For protect seq, ack */
}   portals_conn_t;

int cci_core_portals_post_load(cci_plugin_t *me);
int cci_core_portals_pre_unload(cci_plugin_t *me);
END_C_DECLS

#endif /* CCI_CORE_PORTALS_H */
