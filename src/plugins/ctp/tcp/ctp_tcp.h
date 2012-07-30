/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_CTP_TCP_H
#define CCI_CTP_TCP_H

#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "cci/config.h"
#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"

BEGIN_C_DECLS
#define TCP_MAX_HDR_SIZE       (44) /* max header size (RMA READ) */
#define TCP_DEFAULT_MSS        (4096)	/* 4 KB */
#define TCP_MIN_MSS            (TCP_MAX_HDR_SIZE + 64)
#define TCP_MAX_MSS            (64*1024)
#define TCP_MAX_SACK           (32)		/* pairs of start/end acks */
#define TCP_ACK_DELAY          (1)		/* send an ack after every Nth rx */
#define TCP_EP_TX_TIMEOUT_SEC  (64)		/* seconds for now */
#define TCP_EP_RX_CNT          (4096)	/* number of rx MSGs */
#define TCP_EP_TX_CNT          (1024)	/* number of tx MSGs */
//#define TCP_EP_HASH_SIZE       (256)	/* nice round number */
#define TCP_MAX_EPS            (256)	/* max sock fd value - 1 */
//#define TCP_BLOCK_SIZE         (64)		/* use 64b blocks for id storage */
//#define TCP_NUM_BLOCKS         (16384)	/* number of blocks */
//#define TCP_MAX_ID             (TCP_BLOCK_SIZE * TCP_NUM_BLOCKS)
    /* 1048576 conns per endpoint */
#define TCP_PROG_TIME_US       (100000)	/* try to progress every N microseconds */
#define TCP_RESEND_TIME_SEC    (1)		/* time between resends in seconds */
//#define TCP_PEEK_LEN           (32)	/* large enough for RMA header */
#define TCP_CONN_REQ_HDR_LEN   ((int) (sizeof(struct tcp_header_r)))
					/* header + seqack */
#define TCP_RMA_DEPTH          (16)	/* how many in-flight msgs per RMA */
#define TCP_RMA_FRAG_LEN       (1024*1024)

static inline uint64_t tcp_tv_to_usecs(struct timeval tv)
{
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

#define TCP_TV_TO_USECS(tv)    (((tv).tv_sec * 1000000) + (tv).tv_usec)

static inline uint64_t tcp_get_usecs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tcp_tv_to_usecs(tv);
}

/* Valid URI include:
 *
 * tcp://1.2.3.4:5555		# IPv4 address and port
 * tcp://foo.bar.com:5555	# Resolvable name and port
 */

/* Valid URI arguments:
 *
 * :eth0			# Interface name
 */

/* When using a config file, a sock device needs the following items
 * in the config file:
 *
 * driver = sock		# must be lowercase
 *
 * and at least one of these:
 *
 * ip = 0.0.0.0			# valid IPv4 address of the adapter to use
 * or
 * interface = eth3		# a configured and up interface
 *
 * If both are provided and they do not represent the same device, it will
 * try the IP address before the interface.
 *
 * A sock device may have these items:
 *
 * mtu = 9000             # MTU less headers will become max_send_size
 * min_port = 4444        # lowest port to use for endpoints
 * max_port = 5555        # highest port to use for endpoints
 */

/* Message types */

typedef enum tcp_msg_type {
	TCP_MSG_INVALID = 0,
	TCP_MSG_CONN_REQUEST,	/* SYN */
	TCP_MSG_CONN_REPLY,		/* SYN-ACK */
	TCP_MSG_CONN_ACK,		/* ACK */
	TCP_MSG_DISCONNECT,		/* spec says no disconnect is sent */
	TCP_MSG_SEND,		/* a MSG */
	TCP_MSG_RNR,		/* for both active msg and RMA */
	TCP_MSG_KEEPALIVE,

	/* the rest apply to reliable connections only */

	TCP_MSG_PING,		/* no data, just echo timestamp for RTTM */
	TCP_MSG_ACK_ONLY,		/* ack only this seqno */
	TCP_MSG_ACK_UP_TO,		/* ack up to and including this seqno */
	TCP_MSG_SACK,		/* ack these blocks of sequences */
	TCP_MSG_RMA_WRITE,
	TCP_MSG_RMA_READ_REQUEST,
	TCP_MSG_RMA_READ_REPLY,
	TCP_MSG_RMA_INVALID,	/* invalid handle */
	TCP_MSG_TYPE_MAX
} tcp_msg_type_t;

/* Wire format */

/* Message headers */

/* basic header shared by RO, RU and UU */

/* all headers should be 32-bit aligned */
/* all fields should be in network byte order on the wire */
/* all bit mangling is done while in host order */

/* generic header:

    <---------- 32 bits --------->
    <--------- 24b --------> <- 8b ->
   +------------------------+--------+
   |            A           |  type  |
   +------------------------+--------+

   where each message type decides how to use A

 */

typedef struct tcp_header {
	uint32_t type;		/* upper 8b are type, next 8b are A and rest are B */
	char data[0];		/* start unreliable payload here */
} tcp_header_t;

/* bit mangling */

#define TCP_TYPE_BITS	(8)
#define TCP_TYPE_MASK	(0xFF)
#define TCP_TYPE_SHIFT	(0)

#define TCP_A_BITS		(24)
#define TCP_A_MASK		(TCP_A_BITS - 1)
#define TCP_A_MAX		(TCP_A_MASK)
#define TCP_A_SHIFT		(TCP_TYPE_BITS)

#define TCP_TYPE(x)		((uint8_t)  ((x) & TCP_TYPE_MASK))
#define TCP_A(x)		((uint32_t) (((x) >> TCP_TYPE_SHIFT) & \
                                                    TCP_A_MASK))

#define TCP_PACK_TYPE(type,a)			\
	((((uint32_t) (a)) << TCP_A_SHIFT) | ((uint8_t) (type)))

static inline void
tcp_pack_header(tcp_header_t * header,
		 tcp_msg_type_t type, uint32_t a)
{
	assert(type < TCP_MSG_TYPE_MAX && type > TCP_MSG_INVALID);

	header->type = htonl(TCP_PACK_TYPE(type, a));
}

static inline void
tcp_parse_header(tcp_header_t * header, tcp_msg_type_t * type, uint8_t * a)
{
	uint32_t hl = ntohl(header->type);

	*type = (enum tcp_msg_type)TCP_TYPE(hl);
	*a = TCP_A(hl);
}

/* Reliable message headers (RO and RU) add a seq and timestamp */

#define TCP_SEQ_BITS       (32)
#define TCP_SEQ_MASK       (~0)
#define TCP_ACK_MASK       (TCP_SEQ_MASK)

#define TCP_U32_LT(a,b)    ((int)((a)-(b)) < 0)
#define TCP_U32_LTE(a,b)   ((int)((a)-(b)) <= 0)
#define TCP_U32_GT(a,b)    ((int)((a)-(b)) > 0)
#define TCP_U32_GTE(a,b)   ((int)((a)-(b)) >= 0)
#define TCP_U32_MIN(a,b)   ((TCP_U32_LT(a, b)) ? (a) : (b))
#define TCP_U32_MAX(a,b)   ((TCP_U32_GT(a, b)) ? (a) : (b))

#define TCP_U64_LT(a,b)    ((int64_t)((a)-(b)) < 0)
#define TCP_U64_LTE(a,b)   ((int64_t)((a)-(b)) <= 0)
#define TCP_U64_GT(a,b)    ((int64_t)((a)-(b)) > 0)
#define TCP_U64_GTE(a,b)   ((int64_t)((a)-(b)) >= 0)
#define TCP_U64_MIN(a,b)   ((TCP_U64_LT(a, b)) ? (a) : (b))
#define TCP_U64_MAX(a,b)   ((TCP_U64_GT(a, b)) ? (a) : (b))

#define TCP_SEQ_LT(a,b)    TCP_U32_LT(a,b)
#define TCP_SEQ_LTE(a,b)   TCP_U32_LTE(a,b)
#define TCP_SEQ_GT(a,b)    TCP_U32_GT(a,b)
#define TCP_SEQ_GTE(a,b)   TCP_U32_GTE(a,b)
#define TCP_SEQ_MIN(a,b)   TCP_U32_MIN(a,b)
#define TCP_SEQ_MAX(a,b)   TCP_U32_MAX(a,b)

/* sequence and ack

    <---------- 32 bits ---------->
   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

*/

typedef struct tcp_seq_ack {
	uint32_t seq;
	uint32_t ack;
} tcp_seq_ack_t;

static inline void
tcp_pack_seq_ack(tcp_seq_ack_t * sa, uint32_t seq, uint32_t ack)
{
	sa->seq = htonl(seq);
	sa->ack = htonl(ack);
}

static inline void
tcp_parse_seq_ack(tcp_seq_ack_t * sa, uint32_t * seq, uint32_t * ack)
{
	*seq = ntohl(sa->seq);
	*ack = ntohl(sa->ack);
}

/* reliable header */

typedef struct tcp_header_r {
	tcp_header_t header;
	tcp_seq_ack_t seq_ack;
	char data[0];		/* start reliable payload here */
} tcp_header_r_t;

/* Common message headers (RO, RU, and UU) */

/* connection request/reply */
typedef struct tcp_handshake {
	uint32_t max_recv_buffer_count;	/* max recvs that I can handle */
	uint32_t mss;		/* lower of each endpoint */
	uint32_t keepalive;	/* keepalive timeout (when activated) */
} tcp_handshake_t;

static inline void
tcp_pack_handshake(tcp_handshake_t * hs, uint32_t max_recv_buffer_count,
		uint32_t mss, uint32_t keepalive)
{
	assert(mss <= TCP_MAX_MSS);
	assert(mss >= TCP_MIN_MSS);

	hs->max_recv_buffer_count = htonl(max_recv_buffer_count);
	hs->mss = htonl(mss);
	hs->keepalive = htonl(keepalive);
}

static inline void
tcp_parse_handshake(tcp_handshake_t * hs, uint32_t * max_recv_buffer_count,
		uint32_t * mss, uint32_t * ka)
{
	*max_recv_buffer_count = ntohl(hs->max_recv_buffer_count);
	*mss = ntohl(hs->mss);
	*ka = ntohl(hs->keepalive);
}

/* connection request header:

    <---------- 32 bits ---------->
    <---- 16 -----> <- 8 -> <- 8 ->
   +---------------+-------+-------+
   |   data len    | attr  | type  |
   +---------------+-------+-------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+
   |           keepalive           |
   +-------------------------------+

   The user data follows the header.

   attr: CCI_CONN_ATTR_[UU|RU|RO]
   data len: amount of user data following header
   seq: starting sequence number for this connection
   ack: 0 for request, ack for reply and ack
   max_recv_buffer_count: number of msgs we can receive
   mss: max send size
   keepalive: if keepalive is activated, this specifies the keepalive timeout
 */

static inline void
tcp_pack_conn_request(tcp_header_t * header, cci_conn_attribute_t attr,
		       uint16_t data_len, uint32_t id)
{
	uint32_t a = (data_len << 8) | attr;

	tcp_pack_header(header, TCP_MSG_CONN_REQUEST, a);
}

/* connection reply header:

    <---------- 32 bits ---------->
    <---- 16 -----> <- 8 -> <- 8 ->
   +---------------+-------+-------+
   |   reserved    | reply | type  |
   +---------------+-------+-------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+

   The reply is 0 for success else errno.

   reply: 0 == SUCCESS, !0 is reject reason
   mss: max app payload
 */

static inline void
tcp_pack_conn_reply(tcp_header_t * header, uint8_t reply)
{
	tcp_pack_header(header, TCP_MSG_CONN_REPLY, reply);
}

/* connection ack header:

    <---------- 32 bits ---------->
    <-------- 24b --------> <- 8 ->
   +-----------------------+-------+
   |       reserved        | type  |
   +-----------------------+-------+

 */

static inline void tcp_pack_conn_ack(tcp_header_t * header)
{
	tcp_pack_header(header, TCP_MSG_CONN_ACK, 0);
}

/* send header:

    <---------- 32 bits ---------->
    <- 8 -> <---- 16 -----> <- 8 ->
   +-------+---------------+-------+
   | rsvd  |   data len    | type  |
   +-------+---------------+-------+

   The payload follows the send header.

   If reliable, includes seq and ack

 */

static inline void
tcp_pack_send(tcp_header_t * header, uint16_t len)
{
	tcp_pack_header(header, TCP_MSG_SEND, len);
}

/* keepalive header:

    <---------- 32 bits ---------->
    <-------- 24 ---------> <- 8 ->
   +-----------------------+-------+
   |       reserved        | type  |
   +-----------------------+-------+

 */

static inline void tcp_pack_keepalive(tcp_header_t * header)
{
	tcp_pack_header(header, TCP_MSG_KEEPALIVE, 0);
}

/* nack header and nack(s)

    <---------- 32 bits ---------->
    <-------- 24b --------> <- 8 ->
   +-----------------------+-------+
   |                       | type  |
   +-----------------------+-------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   type: TCP_MSG_RNR

 */
static inline void
tcp_pack_nack(tcp_header_r_t * header_r, uint32_t seq, uint32_t ack)
{
	tcp_pack_header(&header_r->header, TCP_MSG_RNR, 0);
	tcp_pack_seq_ack(&header_r->seq_ack, seq, ack);
}

static inline void
tcp_parse_nack(tcp_header_r_t * header_r)
{
	/* Nothing to do? */
}

/* ack header and ack(s):

    <---------- 32 bits ---------->
    <---- 16 -----> <- 8 -> <- 8 ->
   +---------------+-------+-------+
   |   reserved    |  cnt  | type  |
   +---------------+-------+-------+
   |              ack              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   type: TCP_MSG_[ACK_ONLY|ACK_UP_TO|SACK]
   cnt: number of acks
   ack: ack payload starting at header->data

   Note: this is _not_ a reliable header (no seq_ack)
 */

static inline void
tcp_pack_ack(tcp_header_t * header, tcp_msg_type_t type,
	      uint32_t * ack, int count)
{
	int i;
	uint32_t *p = (uint32_t *) & header->data;

	if (count == 1)
		assert(type == TCP_MSG_ACK_ONLY || type == TCP_MSG_ACK_UP_TO);
	else {
		assert(type == TCP_MSG_SACK);
		assert(count >= 2);
		assert(count % 2 == 0);
		assert(count / 2 <= TCP_MAX_SACK);
	}

	tcp_pack_header(header, type, (uint8_t) count);
	for (i = 0; i < count; i++)
		p[i] = htonl(ack[i]);
}

/* Caller must provide storage for (TCP_MAX_SACK * 2) acks */
/* Count = number of acks. If sack, count each start and end */
static inline void
tcp_parse_ack(tcp_header_r_t * header, tcp_msg_type_t type,
	       uint32_t * ack, int count)
{
	int i;
	uint32_t *p = (uint32_t *) & header->data;

	assert(type);
	assert(ack != NULL);
	for (i = 0; i < count; i++)
		ack[i] = (uint32_t) ntohl(p[i]);
}

/* RMA headers */

/* RMA handle offset

    <---------- 32 bits ---------->
   +-------------------------------+
   |         handle (0 - 31)       |
   +-------------------------------+
   |         handle (32 - 63)      |
   +-------------------------------+
   |         offset (0 - 31)       |
   +-------------------------------+
   |         offset (32 - 63)      |
   +-------------------------------+

 */

typedef struct tcp_rma_handle_offset {
	uint32_t handle_high;
	uint32_t handle_low;
	uint32_t offset_high;
	uint32_t offset_low;
} tcp_rma_handle_offset_t;

static inline void
tcp_pack_rma_handle_offset(tcp_rma_handle_offset_t * ho,
			    uint64_t handle, uint64_t offset)
{
	ho->handle_high = htonl((uint32_t) (handle >> 32));
	ho->handle_low = htonl((uint32_t) (handle & 0xFFFFFFFF));
	ho->offset_high = htonl((uint32_t) (offset >> 32));
	ho->offset_low = htonl((uint32_t) (offset & 0xFFFFFFFF));
}

static inline void
tcp_parse_rma_handle_offset(tcp_rma_handle_offset_t * ho,
			     uint64_t * handle, uint64_t * offset)
{
	*handle = ((uint64_t) ntohl(ho->handle_high)) << 32;
	*handle |= (uint64_t) ntohl(ho->handle_low);
	*offset = ((uint64_t) ntohl(ho->offset_high)) << 32;
	*offset |= (uint64_t) ntohl(ho->offset_low);
}

typedef struct tcp_rma_write_header {
	tcp_header_r_t header_r;
	tcp_rma_handle_offset_t remote;
	char data[0];
} tcp_rma_write_header_t;

/* RMA write

    <---------- 32 bits ---------->
    <-------- 24b --------> <- 8 ->
   +-----------------------+-------+
   |        data_len       | type  |
   +-----------------------+-------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   +-------------------------------+
   |     remote handle (0 - 31)    |
   +-------------------------------+
   |     remote handle (32 - 63)   |
   +-------------------------------+
   |     remote offset (0 - 31)    |
   +-------------------------------+
   |     remote offset (32 - 63)   |
   +-------------------------------+

   +-------------------------------+
   |             data              |

   a = unused
   data_len = number of data bytes in this message
   local handle: cci_rma() caller's handle (stays same for each packet)
   local offset: offset into the local handle (changes for each packet)
   remote handle: passive peer's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
 */

static inline void
tcp_pack_rma_write(tcp_rma_write_header_t * write, uint32_t data_len,
		    uint32_t seq, uint32_t ack,
		    uint64_t remote_handle, uint64_t remote_offset)
{
	assert(data_len < (1 << 24));
	tcp_pack_header(&write->header_r.header, TCP_MSG_RMA_WRITE, data_len);
	tcp_pack_seq_ack(&write->header_r.seq_ack, seq, ack);
	tcp_pack_rma_handle_offset(&write->remote, remote_handle, remote_offset);
}

/* RMA read request

    <---------- 32 bits ---------->
    <-------- 24b --------> <- 8 ->
   +-----------------------+-------+
   |       reserved        | type  |
   +-----------------------+-------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   +-------------------------------+
   |         rma_op (0 - 31)       |
   +-------------------------------+
   |         rma_op (32 - 63)      |
   +-------------------------------+
   |     local offset (0 - 31)     |
   +-------------------------------+
   |     local offset (32 - 63)    |
   +-------------------------------+
   |     remote handle (0 - 31)    |
   +-------------------------------+
   |     remote handle (32 - 63)   |
   +-------------------------------+
   |     remote offset (0 - 31)    |
   +-------------------------------+
   |     remote offset (32 - 63)   |
   +-------------------------------+

   local handle: intitator's rma_op (for lookup on reply)
   local offset: offset into the local handle (changes for each packet)
   remote handle: target's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
 */

typedef struct tcp_rma_read_header {
	tcp_header_r_t header_r;
	tcp_rma_handle_offset_t local;
	tcp_rma_handle_offset_t remote;
	char data[0];
} tcp_rma_read_header_t;

static inline void
tcp_pack_rma_read(tcp_rma_read_header_t * read, uint64_t data_len,
		   uint32_t seq, uint32_t ack,
		   uintptr_t rma_op, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset)
{
	tcp_pack_header(&read->header_r.header, TCP_MSG_RMA_READ_REQUEST,
			 data_len);
	tcp_pack_seq_ack(&read->header_r.seq_ack, seq, ack);
	tcp_pack_rma_handle_offset(&read->local, (uint64_t)rma_op, local_offset);
	tcp_pack_rma_handle_offset(&read->remote, remote_handle,
				    remote_offset);
}

/* RMA read reply

    <---------- 32 bits ---------->
    <-------- 24b --------> <- 8 ->
   +-----------------------+-------+
   |       reserved        | type  |
   +-----------------------+-------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   +-------------------------------+
   |           rma_op (0 - 31)     |
   +-------------------------------+
   |           rma_op (32 - 64)    |
   +-------------------------------+
   |     local offset (0 - 31)     |
   +-------------------------------+
   |     local offset (32 - 63)    |
   +-------------------------------+

   local handle: intitator's local handle (stays same for each packet)
   local offset: offset into the local handle (changes for each packet)
   remote handle: target's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
 */

typedef struct tcp_rma_read_reply_header {
	tcp_header_r_t header_r;
	tcp_rma_handle_offset_t local;
	char data[0];
} tcp_rma_read_reply_header_t;

static inline void
tcp_pack_rma_read_reply(tcp_rma_read_reply_header_t * read_reply, uint64_t data_len,
		   uint32_t seq, uint32_t ack,
		   uintptr_t rma_op, uint64_t local_offset)
{
	tcp_pack_header(&read_reply->header_r.header, TCP_MSG_RMA_READ_REQUEST,
			 data_len);
	tcp_pack_seq_ack(&read_reply->header_r.seq_ack, seq, ack);
	tcp_pack_rma_handle_offset(&read_reply->local, (uint64_t)rma_op, local_offset);
}

/************* TCP private structures ****************/

typedef struct tcp_buffer_pool {
	TAILQ_HEAD(s_e, cci__evt) evts;
	void *buf;		/* memory */
	uint32_t size;		/* 4 GB per endpoint is hopefully enough */
	int repost;		/* 1 for yes, 0 means we are cleaning up */
	uint32_t count;		/* number of items */
	uint32_t avail;		/* items available for use */
	TAILQ_ENTRY(tcp_buffer_pool) entry; /* tep->tx_pools and tep->rx_pools */
} tcp_buffer_pool_t;

typedef enum tcp_tx_state_t {
	/*! available, held by endpoint */
	TCP_TX_IDLE = 0,

	/*! queued for sending */
	TCP_TX_QUEUED,

	/*! sent, waiting ack */
	TCP_TX_PENDING,

	/*! completed with status set */
	TCP_TX_COMPLETED
} tcp_tx_state_t;

/*! Send active message context.
*
* \ingroup messages */
typedef struct tcp_tx {
	/*! Associated event (includes public cci_event_t) */
	cci__evt_t evt;

	/*! Message type */
	tcp_msg_type_t msg_type;

	/*! Flags (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
	int flags;

	/*! State of send - not to be confused with completion status */
	tcp_tx_state_t state;

	/*! Buffer (wire header, data) */
	void *ptr;

	/*! Buffer length */
	uint32_t len;

	/*! Entry for sconn->tx_seqs */
	 TAILQ_ENTRY(tcp_tx) tx_seq;

	/*! If reliable, use the following: */

	/*! Sequence number */
	uint32_t seq;

	/*! Timeout in microseconds */
	uint64_t timeout_us;

	/*! Owning RMA op if not MSG */
	struct tcp_rma_op *rma_op;

	/*! Number of RNR nacks received */
	uint32_t rnr;

	/*! Owning buffer pool */
	tcp_buffer_pool_t *pool;
} tcp_tx_t;

/*! Receive active message context.
 *
 * \ingroup messages */
typedef struct tcp_rx {
	/*! Associated event (includes public cci_event_t) */
	cci__evt_t evt;

	/*! Buffer (wire header, data) */
	void *ptr;

	/*! Buffer length */
	uint32_t len;

	/*! Owning buffer pool */
	tcp_buffer_pool_t *pool;
} tcp_rx_t;

typedef struct tcp_rma_handle {
	/*! Owning endpoint */
	cci__ep_t *ep;

	/*! Registered length */
	uint64_t length;

	/*! Application memory */
	void *start;

	/* Entry for hanging on ep->handles */
	 TAILQ_ENTRY(tcp_rma_handle) entry;

	/*! Reference count */
	uint32_t refcnt;
} tcp_rma_handle_t;

typedef struct tcp_rma_op {
	/*! Entry to hang on sep->rma_ops */
	TAILQ_ENTRY(tcp_rma_op) entry;

	/*! Entry to hang on sconn->rmas */
	TAILQ_ENTRY(tcp_rma_op) rmas;

	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;
	uint64_t remote_offset;

	uint64_t data_len;

	/*! RMA id for ordering in case of fence */
	uint32_t id;

	/*! Number of msgs for data transfer (excluding remote compeltion msg) */
	uint32_t num_msgs;

	/*! Next segment to send */
	uint32_t next;

	/*! Number of messages in-flight */
	uint32_t pending;

	/*! Number of messages completed */
	uint32_t completed;

	/*! Status of the RMA op */
	cci_status_t status;

	/*! Application context */
	void *context;

	/*! Flags */
	int flags;

	/*! Pointer to tx for remote completion if needed */
	tcp_tx_t *tx;

	/*! Optional MSG len */
	uint16_t msg_len;

	/*! Optional MSG ptr if provided */
	char *msg_ptr;
} tcp_rma_op_t;

typedef struct tcp_ep {
	/*! Our IP and port */
	struct sockaddr_in sin;

	/*! Is closing? */
	int closing;

	/*! Socket for connection requests */
	int sock;

	/*! rbtree for connections */
	void *conns;

	/*! List of all tx buffer pools. The head is the current pool. */
	TAILQ_HEAD(s_txp, tcp_buffer_pool) tx_pools;

	/*! List of all rx buffer pools. The head is the current pool. */
	TAILQ_HEAD(s_rxp, tcp_buffer_pool) rx_pools;

	/*! List of active connections awaiting replies */
	TAILQ_HEAD(s_active, tcp_conn) active;

	/*! List of passive connections awaiting replies */
	TAILQ_HEAD(s_passive, tcp_conn) passive;

	/*! List of RMA registrations */
	TAILQ_HEAD(s_handles, tcp_rma_handle) handles;

	/*! List of RMA ops */
	TAILQ_HEAD(s_ops, tcp_rma_op) rma_ops;

	/*! Queued sends */
	TAILQ_HEAD(s_queued, cci__evt) queued;

	/*! Pending (in-flight) sends */
	TAILQ_HEAD(s_pending, cci__evt) pending;

	/*! List of all connections with keepalive enabled */
	TAILQ_HEAD(s_ka, tcp_conn) ka_conns;

	/*! Being progressed? */
	int is_progressing;

	/*! Progress thread */
	pthread_t tid;

	/*! Highest open conn->sock + 1 for select */
	int nfds;

	/*! fd_set for open conn sock fds */
	fd_set fds;
} tcp_ep_t;

/* Connection info */

typedef enum tcp_conn_status {
	/*! Shutdown */
	TCP_CONN_CLOSED = -2,

	/*! Disconnect called */
	TCP_CONN_CLOSING = -1,

	/*! NULL (intial) state */
	TCP_CONN_INIT = 0,

	/*! Waiting on server ACK */
	TCP_CONN_ACTIVE,

	/*! Waiting on client ACK */
	TCP_CONN_PASSIVE,

	/*! Connection open and useable */
	TCP_CONN_READY
} tcp_conn_status_t;

/* ACK_ONLY:    start == end, one item in list
 * ACK_UP_TO:   end > start, one item in list
 * SACK:        multiple items in list
 */
typedef struct tcp_ack {
	/*! Starting seq inclusive */
	uint32_t start;

	/*! Ending seq inclusive */
	uint32_t end;

	/*! Hang on sconn->to_ack */
	 TAILQ_ENTRY(tcp_ack) entry;
} tcp_ack_t;

typedef struct tcp_conn {
	/*! Owning conn */
	cci__conn_t *conn;

	/*! Status */
	tcp_conn_status_t status;

	/*! Peer's sockaddr_in (IP, port) */
	const struct sockaddr_in sin;

	/*! Socket connected to peer */
	int sock;

	/*! Entry on tep->active or tep->passive */
	TAILQ_ENTRY(tcp_conn) entry;

	/*! Max sends in flight to this peer */
	uint32_t max_tx_cnt;

	/*! Last sequence number sent */
	uint32_t seq;

	/* Lowest pending seq */
	uint32_t seq_pending;

	/*! Pending send count (waiting on acks) (i.e. flightsize) */
	uint32_t pending;

	/*! Pending sends waiting on acks */
	 TAILQ_HEAD(s_tx_seqs, tcp_tx) tx_seqs;

	/*! Peer's last contiguous seqno acked (ACK_UP_TO) */
	uint32_t acked;

	/*! Seq of last ack tx */
	uint32_t last_ack_seq;

	/*! Do we have an ack queued to send? */
	int ack_queued;

	/*! List of sequence numbers to ack */
	 TAILQ_HEAD(s_acks, tcp_ack) acks;

	/*! Last RMA started */
	uint32_t rma_id;

	/*! List of RMA ops in process in case of fence */
	 TAILQ_HEAD(s_rmas, tcp_rma_op) rmas;

	/*! Flag to know if the receiver is ready or not */
	uint32_t rnr;

	/*! Array of RMA contextes (used for RMA reads) */
	const void **rma_contexts;

	/*! Current size of the array of RMA contexts */
	uint32_t max_rma_contexts;
} tcp_conn_t;

/* Only call if holding the ep->lock and sconn->acks is not empty
 *
 * If only one item, return 0
 * If more than one item, return 1
 */
static inline int tcp_need_sack(tcp_conn_t * sconn)
{
	return TAILQ_FIRST(&sconn->acks) != TAILQ_LAST(&sconn->acks, s_acks);
}

typedef struct tcp_dev {
	/*! Our ifaddr */
	struct ifaddrs *ifa;
} tcp_dev_t;

typedef struct tcp_globals {
	/*! Mutex */
	pthread_mutex_t lock;

	/*! Number of sock devices */
	int count;

	/*! Array of sock devices */
	cci_device_t const **const devices;

	/*! Array of ifaddrs */
	struct ifaddrs *ifaddrs;

	/*! Count of ifaddrs */
	int ifa_count;
#if 0
	/*! Array of devices indexed by sock fd */
	tcp_fd_idx_t fd_idx[TCP_MAX_EPS];

	/*! Highest open endpoint sock fd + 1 for select */
	int nfds;

	/*! fd_set for open endpoint sock fds */
	fd_set fds;
#endif
} tcp_globals_t;

#ifndef FD_COPY
#define FD_COPY(a,b) memcpy(a,b,sizeof(fd_set))
#endif

#ifdef __GNUC__
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

extern tcp_globals_t *sglobals;

int cci_ctp_tcp_post_load(cci_plugin_t * me);
int cci_ctp_tcp_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_TCP_H */
