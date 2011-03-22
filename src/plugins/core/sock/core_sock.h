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

#ifndef CCI_CORE_SOCK_H
#define CCI_CORE_SOCK_H

#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>


#include "cci/config.h"
#include "cci.h"
#include "cci_lib_types.h"

BEGIN_C_DECLS

#define SOCK_UDP_MAX            (65507) /* 64 KB - 8 B UDP - 20 B IP */
#define SOCK_MAX_HDR_SIZE       (64)    /* max sock header size */
#define SOCK_MAX_HDRS           (SOCK_MAX_HDR_SIZE + 20 + 8) /* IP + UDP */
#define SOCK_DEFAULT_MSS        (8192)  /* 8 KB - assume jumbo frames */

#define SOCK_EP_MAX_HDR_SIZE    (32)    /* max user header size */
#define SOCK_EP_TX_TIMEOUT_SEC  (60)    /* seconds for now */
#define SOCK_EP_RX_CNT          (1024)  /* number of rx active messages */
#define SOCK_EP_TX_CNT          (128)   /* number of tx active messages */

#define SOCK_EP_HASH_SIZE       (256)   /* nice round number */

#define SOCK_BLOCK_SIZE         (64)    /* use 64b blocks for id storage */
#define SOCK_NUM_BLOCKS         (16384) /* number of blocks */
#define SOCK_MAX_ID             (SOCK_BLOCK_SIZE * SOCK_NUM_BLOCKS)
                                        /* 1048576 conns per endpoint */
#define SOCK_PROG_TIME_US       (10000) /* try to progress every N microseconds */
#define SOCK_RESEND_TIME_SEC    (1)     /* time between resends in seconds */
#define SOCK_RESEND_CYCLES      (SOCK_RESEND_TIME_SEC * 1000000 / SOCK_PROG_TIME_US)
                                        /* progress attempts every N cycles */
#define SOCK_PEEK_LEN           (32)    /* large enough for RMA header */
#define SOCK_CONN_REQ_HDR_LEN   ((int) (sizeof(struct sock_header_r)))
                                        /* header + seqack */

static inline uint64_t
sock_tv_to_usecs(struct timeval tv)
{
    return (tv.tv_sec * 1000000) + tv.tv_usec;
}

#define SOCK_TV_TO_USECS(tv)    (((tv).tv_sec * 1000000) + (tv).tv_usec)

static inline uint64_t
sock_get_usecs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return sock_tv_to_usecs(tv);
}

/* Valid URI include:
 *
 * ip://1.2.3.4         # IPv4 address
 * ip://foo.bar.com     # Resolvable name
 */

/* Valid URI arguments:
 *
 * :eth0                # Interface name
 */

/* A sock device needs the following items in the config file:
 *
 * driver = sock        # must be lowercase
 * ip = 0.0.0.0         # valid IPv4 address of the adapter to use
 *
 * A sock device may have these items:
 *
 * mss = 9000           # max_send_size - default 8192
 * listen_port = 54321  # port to listen on
 * min_port = 4444      # lowest port to use for endpoints
 * max_port = 5555      # highest port to use for endpoints
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

/* Wire format */

/* Message headers */

/* basic header shared by RO, RU and UU */

/* all headers should be 32-bit aligned */
/* all fields should be in network byte order on the wire */
/* all bit mangling is done while in host order */

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

typedef struct sock_header {
    uint32_t type;  /* upper 8b are type, next 8b are A and rest are B */
    uint32_t c;
} sock_header_t;

/* type, a, and b bit mangling */

#define SOCK_TYPE_BITS      (8)
#define SOCK_TYPE_MASK      (0xFF)
#define SOCK_TYPE_SHIFT     (24)

#define SOCK_A_BITS         (8)
#define SOCK_A_MASK         (0xFF)
#define SOCK_A_MAX          (SOCK_A_MASK)
#define SOCK_A_SHIFT        (16)

#define SOCK_B_BITS         (16)
#define SOCK_B_MASK         (0xFFFF)
#define SOCK_B_MAX          (SOCK_B_MASK)

#define SOCK_TYPE(x)        ((uint8_t)  ((x) >> SOCK_TYPE_SHIFT))
#define SOCK_A(x)           ((uint8_t) (((x) >> SOCK_A_SHIFT) & \
                                                    SOCK_A_MASK))
#define SOCK_B(x)           ((uint16_t) ((x) & SOCK_B_MASK))

#define SOCK_PACK_TYPE(type,a,b)                    \
        ((((uint32_t) (type)) << SOCK_TYPE_SHIFT) | \
         (((uint32_t) (a)) << SOCK_A_SHIFT) |       \
          ((uint32_t) (b)))

static inline void
sock_pack_header(sock_header_t *header,
                 sock_msg_type_t type,
                 uint8_t a,
                 uint16_t b,
                 uint32_t c)
{
    assert(type < SOCK_MSG_TYPE_MAX && type > SOCK_MSG_INVALID);

    header->type = htonl(SOCK_PACK_TYPE(type, a, b));
    header->c = htonl(c);
}

static inline void
sock_parse_header(sock_header_t *header,
                  sock_msg_type_t *type,
                  uint8_t *a,
                  uint16_t *b,
                  uint32_t *c)
{
    uint32_t hl = ntohl(header->type);

    *type = SOCK_TYPE(hl);
    *a = (uint32_t) SOCK_A(hl);
    *b = (uint32_t) SOCK_B(hl);
    *c = ntohl(header->c);
}

/* Reliable message headers (RO and RU) */

#define SOCK_SEQ_BITS       (31)
#define SOCK_SEQ_MASK       ((1 << (SOCK_SEQ_BITS - 1)) - 1)
#define SOCK_SEQ_MAX        (SOCK_SEQ_MASK)

#define SOCK_ACK_MASK       (SOCK_SEQ_MASK)
#define SOCK_ACK_MAX        (SOCK_SEQ_MAX)

/* sequence and timestamp

    <---------- 32 bits ---------->
   +-------------------------------+
   |              seq              |
   +---------------+---------------+
   |           timestamp           |
   +-------------------------------+

*/

typedef struct sock_seq_ts {
    uint32_t seq;
    uint32_t ts;
} sock_seq_ts_t;

static inline void
sock_pack_seq_ts(sock_seq_ts_t *sa, uint32_t seq, uint32_t ts)
{
    assert(seq <= SOCK_SEQ_MAX);

    sa->seq = htonl(seq);
    sa->ts = htonl(ts);
}

static inline void
sock_parse_seq_ts(sock_seq_ts_t *sa, uint32_t *seq, uint32_t *ts)
{
    *seq = ntohl(sa->seq);
    *ts = ntohl(sa->ts);
}

/* reliable header */

typedef struct sock_header_r {
    sock_header_t header;
    sock_seq_ts_t seq_ts;
} sock_header_r_t;

/* Common message headers (RO, RU, and UU) */

/* connection request/reply */
typedef struct sock_handshake {
    uint32_t id;                    /* id that peer uses when sending to me */
    uint32_t ack;                   /* to ack the request and reply */
    uint32_t max_recv_buffer_count; /* max recvs that I can handle */
    uint16_t mss;                   /* lower of each endpoint */
    uint16_t reserved;
} sock_handshake_t;

/* connection request header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  | attr  |   data len    |
   +-------+-------+---------------+
   |               0               |
   +-------------------------------+

   +-------------------------------+
   |           client id           |
   +-------------------------------+
   |              ack              |
   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |      mss      |   reserved    |
   +---------------+---------------+

   The peer uses the id when sending to us.
   The user data follows the header.

   attr: CCI_CONN_ATTR_[UU|RU|RO]
   data len: amount of user data following header
   id: peer uses ID when sending to us
   seq: starting sequence number for this connection
   ts: timestamp in usecs
   mss: max send size

 */

static inline void
sock_pack_conn_request(sock_header_t *header, cci_conn_attribute_t attr,
                       uint16_t data_len, uint32_t id)
{
    sock_pack_header(header, SOCK_MSG_CONN_REQUEST, attr, data_len, id);
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
   |           server id           |
   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+
   |      mss      |     cwnd      |
   +---------------+---------------+

   The reply is 0 for success else errno.
   I use this ID when sending to this peer.
   The accepting peer will send his id back in the payload (length 4)

   reply: CCI_EVENT_CONNECT_[SUCCESS|REJECTED]
   mss: max app payload (user header and user data)
 */

static inline void
sock_pack_conn_reply(sock_header_t *header, uint8_t reply, uint32_t id)
{
    sock_pack_header(header, SOCK_MSG_CONN_REPLY, reply, 0, id);
}

/* connection ack header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-----------------------+
   | type  |       reserved        |
   +-------+-----------------------+
   |           peer_id             |
   +-------------------------------+

   I use this ID when sending to this peer.

 */

static inline void
sock_pack_conn_ack(sock_header_t *header, uint32_t id)
{
    sock_pack_header(header, SOCK_MSG_CONN_ACK, 0, 0, id);
}

/* send header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  | hlen  |   data len    |
   +-------+-------+---------------+
   |              id               |
   +-------------------------------+

   The user header and the data follow the send header.
   The ID is the value assigned to me by the peer.

 */

static inline void
sock_pack_send(sock_header_t *header, uint8_t header_len,
               uint16_t data_len, uint32_t id)
{
    sock_pack_header(header, SOCK_MSG_SEND, header_len, data_len, id);
}

/* keepalive header:

    <---------- 32 bits ---------->
    <- 8 -> <-------- 24 --------->
   +-------+-----------------------+
   | type  |       reserved        |
   +-------+-----------------------+
   |              id               |
   +-------------------------------+

 */

static inline void
sock_pack_keepalive(sock_header_t *header, uint32_t id)
{
    sock_pack_header(header, SOCK_MSG_KEEPALIVE, 0, 0, id);
}

#if 0
typedef struct sock_pkt {
    union {
        sock_header_t u;
        sock_header_r_t r;
    } hdr;
    union {
        sock_handshake_t hs;
        sock_ack_t ack;
        sock_rma_t rma;
    } u;
    char payload[0];
} sock_pkt_t;
#endif

/* RMA headers */


typedef enum sock_tx_state_t {
    /*! available, held by endpoint */
    SOCK_TX_IDLE = 0,

    /*! queued for sending */
    SOCK_TX_QUEUED,

    /*! sent, waiting ack */
    SOCK_TX_PENDING,

    /*! completed with status set */
    SOCK_TX_COMPLETED
} sock_tx_state_t;


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

    /*! State of send - not to be confused with completion status */
    sock_tx_state_t state;

    /*! Buffer (wire header, user header, data) */
    void *buffer;

    /*! Buffer length */
    uint16_t len;

    /*! Entry for hanging on ep->idle_txs, dev->queued, dev->pending */
    TAILQ_ENTRY(sock_tx) dentry;

    /*! Entry for hanging on ep->txs */
    TAILQ_ENTRY(sock_tx) tentry;

    /*! If reliable, use the following: */

    /*! Sequence number */
    uint32_t seq;

    /*! Last send in microseconds */
    uint64_t last_attempt_us;

    /*! Timeout in microseconds */
    uint64_t timeout_us;
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

    /*! Entry for hanging on ep->idle_rxs, ep->loaned */
    TAILQ_ENTRY(sock_rx) entry;

    /*! Entry for hanging on ep->rxs */
    TAILQ_ENTRY(sock_rx) gentry;
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

    /*! Connection id blocks */
    uint64_t *ids;

    /*! List of active connections awaiting replies */
    TAILQ_HEAD(s_active, sock_conn) active_hash[SOCK_EP_HASH_SIZE];
} sock_ep_t;

/* Connection info */

typedef enum sock_conn_status {
    /*! Shutdown */
    SOCK_CONN_CLOSED    = -2,

    /*! Disconnect called */
    SOCK_CONN_CLOSING   = -1,

    /*! NULL (intial) state */
    SOCK_CONN_INIT      =  0,

    /*! Waiting on server ACK */
    SOCK_CONN_ACTIVE,

    /*! Waiting on client ACK */
    SOCK_CONN_PASSIVE,

    /*! Connection open and useable */
    SOCK_CONN_READY
} sock_conn_status_t;

typedef struct sock_conn {
    /*! Owning conn */
    cci__conn_t *conn;

    /*! Status */
    sock_conn_status_t status;

    /*! Peer's sockaddr_in (IP, port) */
    const struct sockaddr_in sin;

    /*! ID we assigned to us by peer - use when sending to peer */
    uint32_t peer_id;

    /*! ID we assigned to peer - peer uses to send to us and we use to look up conn */
    uint32_t id;

    /*! Max sends in flight to this peer */
    uint32_t max_tx_cnt;

    /*! Entry to hang on sock_ep->conns[hash] */
    TAILQ_ENTRY(sock_conn) entry;

    /*! Last sequence number sent */
    uint32_t seq;

    /*! Peer's last seqno received */
    uint32_t ack;

    /*! Peer's last timestamp received */
    uint32_t ts;

    /*! Lock to protect seq, ack */
    pthread_mutex_t lock;
} sock_conn_t;

typedef struct sock_dev {
    /*! Our IP address in network order */
    in_addr_t ip;

    /*! Queued sends */
    TAILQ_HEAD(s_queued, sock_tx) queued;

    /*! Pending (in-flight) sends */
    TAILQ_HEAD(s_pending, sock_tx) pending;

    /*! Lock to protect queued and pending */
    pthread_mutex_t lock;

    /*! Being progressed? */
    int is_progressing;
} sock_dev_t;

typedef struct sock_lep {
    /*! OS handle for poll/select */
    cci_os_handle_t fd;

    /*! Socket for receiving conn requests */
    cci_os_handle_t sock;
} sock_lep_t;

typedef struct sock_crq {
    /*! Buffer for conn request */
    void *buffer;

    /*! Client's sockaddr_in */
    const struct sockaddr_in sin;

    /*! Peer's id if we reject */
    uint32_t peer_id;

    /*! Last send in microseconds if reject */
    uint64_t last_attempt_us;

    /*! Timeout in microseconds if reject */
    uint64_t timeout_us;
} sock_crq_t;

typedef struct sock_globals {
    /*! Number of sock devices */
    int count;

    /*! Array of sock devices */
    cci_device_t const ** const devices;

    /*! In shutdown? */
    int shutdown;
} sock_globals_t;

extern sock_globals_t *sglobals;

int cci_core_sock_post_load(cci_plugin_t *me);
int cci_core_sock_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_SOCK_H */
