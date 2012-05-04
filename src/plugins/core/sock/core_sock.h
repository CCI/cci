/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
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
#include <sys/select.h>

#include "cci/config.h"
#include "cci.h"
#include "cci_lib_types.h"

BEGIN_C_DECLS
#define SOCK_UDP_MAX            (65508)	/* 64 KB - 8 B UDP - 20 B IP */
#define SOCK_MAX_HDR_SIZE       (48)	/* max sock header size (RMA) */
#define SOCK_MAX_HDRS           (SOCK_MAX_HDR_SIZE + 20 + 8)	/* IP + UDP */
/* FIXME */
#define SOCK_DEFAULT_MSS        (64*1024 - 256)	/* assume jumbo frames */
#define SOCK_MIN_MSS            (1500 - SOCK_MAX_HDR_SIZE)
#define SOCK_MAX_SACK           (4)	/* pairs of start/end acks */
#define SOCK_ACK_DELAY          (1)	/* send an ack after every Nth send */
#define SOCK_EP_TX_TIMEOUT_SEC  (64)	/* seconds for now */
#define SOCK_EP_RX_CNT          (16*1024)	/* number of rx active messages */
#define SOCK_EP_TX_CNT          (16*1024)	/* number of tx active messages */
#define SOCK_EP_HASH_SIZE       (256)	/* nice round number */
#define SOCK_MAX_EPS            (256)	/* max sock fd value - 1 */
#define SOCK_BLOCK_SIZE         (64)	/* use 64b blocks for id storage */
#define SOCK_NUM_BLOCKS         (16384)	/* number of blocks */
#define SOCK_MAX_ID             (SOCK_BLOCK_SIZE * SOCK_NUM_BLOCKS)
    /* 1048576 conns per endpoint */
#define SOCK_PROG_TIME_US       (100)	/* try to progress every N microseconds */
#define SOCK_RESEND_TIME_SEC    (1)	/* time between resends in seconds */
#define SOCK_PEEK_LEN           (32)	/* large enough for RMA header */
#define SOCK_CONN_REQ_HDR_LEN   ((int) (sizeof(struct sock_header_r)))
    /* header + seqack */
#define SOCK_RMA_DEPTH          (256)	/* how many in-flight msgs per RMA */
#define ACK_TIMEOUT             (100) /* Timeout associated to ACK blocks */
#define PENDING_ACK_THRESHOLD   (SOCK_RMA_DEPTH/4) /* Maximum size of a ACK block */
static inline uint64_t sock_tv_to_usecs(struct timeval tv)
{
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

#define SOCK_TV_TO_USECS(tv)    (((tv).tv_sec * 1000000) + (tv).tv_usec)

static inline uint64_t sock_get_usecs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return sock_tv_to_usecs(tv);
}

/* Valid URI include:
 *
 * ip://1.2.3.4:5555      # IPv4 address and port
 * ip://foo.bar.com:5555  # Resolvable name and port
 */

/* Valid URI arguments:
 *
 * :eth0                  # Interface name
 */

/* A sock device needs the following items in the config file:
 *
 * driver = sock          # must be lowercase
 * ip = 0.0.0.0           # valid IPv4 address of the adapter to use
 *
 * A sock device may have these items:
 *
 * mtu = 9000             # MTU less headers will become max_send_size
 * min_port = 4444        # lowest port to use for endpoints
 * max_port = 5555        # highest port to use for endpoints
 */

/* Message types */

typedef enum sock_msg_type {
	SOCK_MSG_INVALID = 0,
	SOCK_MSG_CONN_REQUEST,	/* SYN */
	SOCK_MSG_CONN_REPLY,	/* SYN-ACK */
	SOCK_MSG_CONN_ACK,	/* ACK */
	SOCK_MSG_DISCONNECT,	/* spec says no disconnect is sent */
	SOCK_MSG_SEND,
	SOCK_MSG_RNR,		/* for both active msg and RMA */
	SOCK_MSG_KEEPALIVE,

	/* the rest apply to reliable connections only */

	SOCK_MSG_PING,		/* no data, just echo timestamp for RTTM */
	SOCK_MSG_ACK_ONLY,	/* ack only this seqno */
	SOCK_MSG_ACK_UP_TO,	/* ack up to and including this seqno */
	SOCK_MSG_SACK,		/* ack these blocks of sequences */
	SOCK_MSG_RMA_WRITE,
	SOCK_MSG_RMA_WRITE_DONE,
	SOCK_MSG_RMA_READ_REQUEST,
	SOCK_MSG_RMA_READ_REPLY,
	SOCK_MSG_RMA_INVALID,	/* invalid handle */
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
	uint32_t type;		/* upper 8b are type, next 8b are A and rest are B */
	uint32_t c;
	char data[0];		/* start unreliable payload here */
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
sock_pack_header(sock_header_t * header,
		 sock_msg_type_t type, uint8_t a, uint16_t b, uint32_t c)
{
	assert(type < SOCK_MSG_TYPE_MAX && type > SOCK_MSG_INVALID);

	header->type = htonl(SOCK_PACK_TYPE(type, a, b));
	header->c = htonl(c);
}

static inline void
sock_parse_header(sock_header_t * header,
		  sock_msg_type_t * type,
		  uint8_t * a, uint16_t * b, uint32_t * c)
{
	uint32_t hl = ntohl(header->type);

	*type = (enum sock_msg_type)SOCK_TYPE(hl);
	*a = SOCK_A(hl);
	*b = SOCK_B(hl);
	*c = ntohl(header->c);
}

/* Reliable message headers (RO and RU) add a seq and timestamp */

#define SOCK_SEQ_BITS       (32)
#define SOCK_SEQ_MASK       (~0)
#define SOCK_ACK_MASK       (SOCK_SEQ_MASK)

#define SOCK_U32_LT(a,b)    ((int)((a)-(b)) < 0)
#define SOCK_U32_LTE(a,b)   ((int)((a)-(b)) <= 0)
#define SOCK_U32_GT(a,b)    ((int)((a)-(b)) > 0)
#define SOCK_U32_GTE(a,b)   ((int)((a)-(b)) >= 0)
#define SOCK_U32_MIN(a,b)   ((SOCK_U32_LT(a, b)) ? (a) : (b))
#define SOCK_U32_MAX(a,b)   ((SOCK_U32_GT(a, b)) ? (a) : (b))

#define SOCK_U64_LT(a,b)    ((int64_t)((a)-(b)) < 0)
#define SOCK_U64_LTE(a,b)   ((int64_t)((a)-(b)) <= 0)
#define SOCK_U64_GT(a,b)    ((int64_t)((a)-(b)) > 0)
#define SOCK_U64_GTE(a,b)   ((int64_t)((a)-(b)) >= 0)
#define SOCK_U64_MIN(a,b)   ((SOCK_U64_LT(a, b)) ? (a) : (b))
#define SOCK_U64_MAX(a,b)   ((SOCK_U64_GT(a, b)) ? (a) : (b))

#define SOCK_SEQ_LT(a,b)    SOCK_U32_LT(a,b)
#define SOCK_SEQ_LTE(a,b)   SOCK_U32_LTE(a,b)
#define SOCK_SEQ_GT(a,b)    SOCK_U32_GT(a,b)
#define SOCK_SEQ_GTE(a,b)   SOCK_U32_GTE(a,b)
#define SOCK_SEQ_MIN(a,b)   SOCK_U32_MIN(a,b)
#define SOCK_SEQ_MAX(a,b)   SOCK_U32_MAX(a,b)

/* sequence and timestamp

    <---------- 32 bits ---------->
   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

*/

typedef struct sock_seq_ts {
	uint32_t seq;
	uint32_t ts;
} sock_seq_ts_t;

static inline void
sock_pack_seq_ts(sock_seq_ts_t * sa, uint32_t seq, uint32_t ts)
{
	sa->seq = htonl(seq);
	sa->ts = htonl(ts);
}

static inline void
sock_parse_seq_ts(sock_seq_ts_t * sa, uint32_t * seq, uint32_t * ts)
{
	*seq = ntohl(sa->seq);
	*ts = ntohl(sa->ts);
}

/* reliable header */

typedef struct sock_header_r {
	sock_header_t   header;
	sock_seq_ts_t   seq_ts;
	uint32_t        pb_ack; /*piggybacked ACK */
	char            data[0]; /* start reliable payload here */
} sock_header_r_t;

/* Common message headers (RO, RU, and UU) */

/* connection request/reply */
typedef struct sock_handshake {
	uint32_t id;		/* id that peer uses when sending to me */
	uint32_t ack;		/* to ack the request and reply */
	uint32_t max_recv_buffer_count;	/* max recvs that I can handle */
	uint32_t mss;		/* lower of each endpoint */
	uint32_t keepalive;	/* keepalive timeout (when activated) */
} sock_handshake_t;

static inline void
sock_pack_handshake(sock_handshake_t * hs, uint32_t id, uint32_t ack,
		    uint32_t max_recv_buffer_count, uint32_t mss,
		    uint32_t keepalive)
{
	assert(mss <= (SOCK_UDP_MAX - SOCK_MAX_HDR_SIZE));
	assert(mss >= SOCK_MIN_MSS);

	hs->id = htonl(id);
	hs->ack = htonl(ack);
	hs->max_recv_buffer_count = htonl(max_recv_buffer_count);
	hs->mss = htonl(mss);
	hs->keepalive = htonl(keepalive);
}

static inline void
sock_parse_handshake(sock_handshake_t * hs, uint32_t * id, uint32_t * ack,
		     uint32_t * max_recv_buffer_count, uint32_t * mss,
		     uint32_t * ka)
{
	*id = ntohl(hs->id);
	*ack = ntohl(hs->ack);
	*max_recv_buffer_count = ntohl(hs->max_recv_buffer_count);
	*mss = ntohl(hs->mss);
	*ka = ntohl(hs->keepalive);
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
   |            keepalive          |
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
   keepalive: if keepalive is activated, this specifies the keepalive timeout
 */

static inline void
sock_pack_conn_request(sock_header_t * header, cci_conn_attribute_t attr,
		       uint16_t data_len, uint32_t id)
{
	sock_pack_header(header, SOCK_MSG_CONN_REQUEST, (uint8_t) attr,
			 data_len, id);
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

   reply: CCI_EVENT_CONNECT_[ACCEPTED|REJECTED]
   mss: max app payload (user header and user data)
 */

static inline void
sock_pack_conn_reply(sock_header_t * header, uint8_t reply, uint32_t id)
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

static inline void sock_pack_conn_ack(sock_header_t * header, uint32_t id)
{
	sock_pack_header(header, SOCK_MSG_CONN_ACK, 0, 0, id);
}

/* send header:

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  | rsvd  |   data len    |
   +-------+-------+---------------+
   |              id               |
   +-------------------------------+

   The user header and the data follow the send header.
   The ID is the value assigned to me by the peer (peer_id).

   If reliable, includes seq and ts

 */

static inline void
sock_pack_send(sock_header_t * header, uint16_t len, uint32_t id)
{
	sock_pack_header(header, SOCK_MSG_SEND, 0, len, id);
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

static inline void sock_pack_keepalive(sock_header_t * header, uint32_t id)
{
	sock_pack_header(header, SOCK_MSG_KEEPALIVE, 0, 0, id);
}

/* nack header and nack(s)

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  |  cnt  |               |
   +-------+-----------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+
 
   type: SOCK_MSG_RNR

 */
/* FIXME: do we really need "count" */
static inline void
sock_pack_nack(sock_header_r_t * header_r, sock_msg_type_t type,
	       uint32_t peer_id, uint32_t seq, uint32_t ts, int count)
{
	sock_pack_header(&header_r->header, type, (uint8_t) count, 0, peer_id);
	sock_pack_seq_ts(&header_r->seq_ts, seq, ts);
}

static inline void
sock_parse_nack(sock_header_r_t * header_r, sock_msg_type_t type)
{
	/* Nothing to do? */
}

/* ack header and ack(s):

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  |  cnt  |   reserved    |
   +-------+-----------------------+
   |              id               |
   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+
   |              ack              |
   +-------------------------------+

   type: SOCK_MSG_[ACK_ONLY|ACK_UP_TO|SACK]
   cnt: number of acks (1 or 2, 4, 6, 8 if SACK)
   id: ID of the receiver assigned to the sender
   ack: ack payload starting at header_r->data

 */

static inline void
sock_pack_ack(sock_header_r_t * header_r, sock_msg_type_t type,
	      uint32_t peer_id, uint32_t seq, uint32_t ts, uint32_t * ack,
	      int count)
{
	int i;
	uint32_t *p = (uint32_t *) & header_r->data;

	assert(count > 0);
	if (count == 1)
		assert(type == SOCK_MSG_ACK_ONLY || type == SOCK_MSG_ACK_UP_TO);
	else {
		assert(type == SOCK_MSG_SACK);
		assert(count % 2 == 0);
		assert(count / 2 <= SOCK_MAX_SACK);
	}

	sock_pack_header(&header_r->header, type, (uint8_t) count, 0, peer_id);
	sock_pack_seq_ts(&header_r->seq_ts, seq, ts);
	for (i = 0; i < count; i++)
		p[i] = htonl(ack[i]);
}

/* Caller must provide storage for (SOCK_MAX_SACK * 2) acks */
/* Count = number of acks. If sack, count each start and end */
static inline void
sock_parse_ack(sock_header_r_t * header_r, sock_msg_type_t type,
	       uint32_t * ack, int count)
{
	int i;
	uint32_t *p = (uint32_t *) & header_r->data;

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

typedef struct sock_rma_handle_offset {
	uint32_t handle_high;
	uint32_t handle_low;
	uint32_t offset_high;
	uint32_t offset_low;
} sock_rma_handle_offset_t;

static inline void
sock_pack_rma_handle_offset(sock_rma_handle_offset_t * ho,
			    uint64_t handle, uint64_t offset)
{
	ho->handle_high = htonl((uint32_t) (handle >> 32));
	ho->handle_low = htonl((uint32_t) (handle & 0xFFFFFFFF));
	ho->offset_high = htonl((uint32_t) (offset >> 32));
	ho->offset_low = htonl((uint32_t) (offset & 0xFFFFFFFF));
}

static inline void
sock_parse_rma_handle_offset(sock_rma_handle_offset_t * ho,
			     uint64_t * handle, uint64_t * offset)
{
	*handle = ((uint64_t) ntohl(ho->handle_high)) << 32;
	*handle |= (uint64_t) ntohl(ho->handle_low);
	*offset = ((uint64_t) ntohl(ho->offset_high)) << 32;
	*offset |= (uint64_t) ntohl(ho->offset_low);
}

typedef struct sock_rma_header {
	sock_header_r_t header_r;
	sock_rma_handle_offset_t local;
	sock_rma_handle_offset_t remote;
	char data[0];
} sock_rma_header_t;

/* RMA write

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-------+---------------+
   | type  |   a   |    data_len   |
   +-------+-------+---------------+
   |            peer id            |
   +-------------------------------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

   +-------------------------------+
   |        ACK Piggyback          |
   +-------------------------------+

   +-------------------------------+
   |     local handle (0 - 31)     |
   +-------------------------------+
   |     local handle (32 - 63)    |
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
sock_pack_rma_write(sock_rma_header_t * write, uint16_t data_len,
		    uint32_t peer_id, uint32_t seq, uint32_t ts,
		    uint64_t local_handle, uint64_t local_offset,
		    uint64_t remote_handle, uint64_t remote_offset)
{
	sock_pack_header(&write->header_r.header, SOCK_MSG_RMA_WRITE,
			 0, data_len, peer_id);
	sock_pack_seq_ts(&write->header_r.seq_ts, seq, ts);
	sock_pack_rma_handle_offset(&write->local, local_handle, local_offset);
	sock_pack_rma_handle_offset(&write->remote, remote_handle,
				    remote_offset);
}

/* RMA read request

    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-----------------------+
   | type  |   a   |       b       |
   +-------+-----------------------+
   |            peer id            |
   +-------------------------------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

   +-------------------------------+
   |     local handle (0 - 31)     |
   +-------------------------------+
   |     local handle (32 - 63)    |
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

   +-------------------------------+
   |        context (0 - 31)       |
   +-------------------------------+
   |        context (32 - 64)      |
   +-------------------------------+
   a = unused
   local handle: cci_rma() caller's handle (stays same for each packet)
   local offset: offset into the local handle (changes for each packet)
   remote handle: passive peer's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
   context: context of the RMA operation
 */

static inline void
sock_pack_rma_read(sock_rma_header_t * read, uint64_t data_len,
		   uint32_t peer_id, uint32_t seq, uint32_t ts,
		   uint64_t local_handle, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset)
{
	sock_pack_header(&read->header_r.header, SOCK_MSG_RMA_READ_REQUEST,
			 0, data_len, peer_id);
	sock_pack_seq_ts(&read->header_r.seq_ts, seq, ts);
	sock_pack_rma_handle_offset(&read->local, local_handle, local_offset);
	sock_pack_rma_handle_offset(&read->remote, remote_handle,
				    remote_offset);
}

/* RMA WRITE DONE message
    <---------- 32 bits ---------->
    <- 8 -> <- 8 -> <---- 16 ----->
   +-------+-----------------------+
   | type  |   a   |  context_id   |
   +-------+-----------------------+
   |            peer id            |
   +-------------------------------+

   +-------------------------------+
   |              seq              |
   +-------------------------------+
   |           timestamp           |
   +-------------------------------+

   TODO: description
 */

static inline void
sock_pack_rma_write_done(sock_rma_header_t * write, uint16_t data_len,
            uint32_t peer_id, uint32_t seq, uint32_t ts)
{
	sock_pack_header(&write->header_r.header, SOCK_MSG_RMA_WRITE_DONE,
			 0, data_len, peer_id);
	sock_pack_seq_ts(&write->header_r.seq_ts, seq, ts);
}

/************* Windowing and Acking *******************/

/************* SOCK private structures ****************/

typedef struct sock_iov {
	void *addr;
	uint16_t len;
} sock_iov_t;

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

	/*! Buffer (wire header, data) */
	void *buffer;

	/*! Buffer length */
	uint16_t len;

	void *rma_ptr;
	uint16_t rma_len;

	/*! Entry for hanging on ep->idle_txs, dev->queued, dev->pending */
	 TAILQ_ENTRY(sock_tx) dentry;

	/*! Entry for hanging on ep->txs */
	 TAILQ_ENTRY(sock_tx) tentry;

	/*! Entry for sconn->tx_seqs */
	 TAILQ_ENTRY(sock_tx) tx_seq;

	/*! If reliable, use the following: */

	/*! Sequence number */
	uint32_t seq;

	/*! Send attempts */
	uint32_t send_count;

	/*! Last send in microseconds */
	uint64_t last_attempt_us;

	/*! Timeout in microseconds */
	uint64_t timeout_us;

	/*! Owning RMA op if not active message */
	struct sock_rma_op *rma_op;

	/*! Number of RNR nacks received */
	uint32_t rnr;

	/*! Peer address if connect reject message (i.e. no conn) */
	struct sockaddr_in sin;
} sock_tx_t;

/*! Receive active message context.
 *
 * \ingroup messages */
typedef struct sock_rx {
	/*! Associated event (includes public cci_event_t) */
	cci__evt_t evt;

	/*! Buffer (wire header, data) */
	void *buffer;

	/*! Buffer length */
	uint16_t len;

	/*! Entry for hanging on ep->idle_rxs, ep->loaned */
	 TAILQ_ENTRY(sock_rx) entry;

	/*! Entry for hanging on ep->rxs */
	 TAILQ_ENTRY(sock_rx) gentry;

	/*! Peer's sockaddr_in for connection requests */
	struct sockaddr_in sin;
} sock_rx_t;

typedef struct sock_rma_handle {
	/*! Owning endpoint */
	cci__ep_t *ep;

	/*! Owning connection, if any */
	cci__conn_t *conn;

	/*! Registered length */
	uint64_t length;

	/*! Application memory */
	void *start;

	/* Entry for hanging on ep->handles */
	 TAILQ_ENTRY(sock_rma_handle) entry;

	/*! Reference count */
	uint32_t refcnt;
} sock_rma_handle_t;

typedef struct sock_rma_op {
	/*! Entry to hang on sep->rma_ops */
	TAILQ_ENTRY(sock_rma_op) entry;

	/*! Entry to hang on sconn->rmas */
	TAILQ_ENTRY(sock_rma_op) rmas;

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
	sock_tx_t *tx;

	/*! Application AM len */
	uint16_t msg_len;

	/*! Application AM ptr if provided */
	char *msg_ptr;
} sock_rma_op_t;

typedef struct sock_ep {
    /*! ID of the recv thread for the endpoint */
    pthread_t recv_tid;

    /*! ID of the progress thread for the endpoint */
    pthread_t progress_tid;

	/* Our IP and port */
	struct sockaddr_in sin;

	/*! Is closing? */
	int closing;

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

	/*! Connection id blocks */
	uint64_t *ids;

	/*! List of active connections awaiting replies */
	 TAILQ_HEAD(s_active, sock_conn) active_hash[SOCK_EP_HASH_SIZE];

	/*! List of RMA registrations */
	 TAILQ_HEAD(s_handles, sock_rma_handle) handles;

	/*! List of RMA ops */
	 TAILQ_HEAD(s_ops, sock_rma_op) rma_ops;
} sock_ep_t;

/* Connection info */

typedef enum sock_conn_status {
	/*! Shutdown */
	SOCK_CONN_CLOSED = -2,

	/*! Disconnect called */
	SOCK_CONN_CLOSING = -1,

	/*! NULL (intial) state */
	SOCK_CONN_INIT = 0,

	/*! Waiting on server ACK */
	SOCK_CONN_ACTIVE,

	/*! Waiting on client ACK */
	SOCK_CONN_PASSIVE,

	/*! Connection open and useable */
	SOCK_CONN_READY
} sock_conn_status_t;

/* ACK_ONLY:    start == end, one item in list
 * ACK_UP_TO:   end > start, one item in list
 * SACK:        multiple items in list
 */
typedef struct sock_ack {
	/*! Starting seq inclusive */
	uint32_t start;

	/*! Ending seq inclusive */
	uint32_t end;

	/*! Hang on sconn->to_ack */
	 TAILQ_ENTRY(sock_ack) entry;
} sock_ack_t;

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

	/*! Max sends in flight to this peer (i.e. rwnd) */
	uint32_t max_tx_cnt;

	/*! Entry to hang on sock_ep->conns[hash] */
	 TAILQ_ENTRY(sock_conn) entry;

	/*! Last sequence number sent */
	uint32_t seq;

	/* Lowest pending seq */
	uint32_t seq_pending;

	/*! Pending send count (waiting on acks) (i.e. flightsize) */
	uint32_t pending;

#define SOCK_INITIAL_CWND 2
	/*! Congestion window */
	uint32_t cwnd;

	/*! Slow start threshhold */
	uint32_t ssthresh;

	/*! Pending sends waiting on acks */
	 TAILQ_HEAD(s_tx_seqs, sock_tx) tx_seqs;

	/*! Peer's last contiguous seqno acked (ACK_UP_TO) */
	uint32_t acked;

	/*! Peer's last timestamp received */
	uint32_t ts;

	/*! Seq of last ack tx */
	uint32_t last_ack_seq;

	/*! Timestamp of last ack tx */
	uint64_t last_ack_ts;

	/*! Do we have an ack queued to send? */
	int ack_queued;

	/*! List of sequence numbers to ack */
	TAILQ_HEAD(s_acks, sock_ack) acks;

	/*! Last RMA started */
	uint32_t rma_id;

	/*! List of RMA ops in process in case of fence */
	TAILQ_HEAD(s_rmas, sock_rma_op) rmas;

	/*! Flag to know if the receiver is ready or not */
	uint32_t rnr;

	/*! Array of RMA contextes (used for RMA reads) */
	void **rma_contexts;

	/*! Current size of the array of RMA contexts */
	uint32_t max_rma_contexts;
} sock_conn_t;

/* Only call if holding the ep->lock and sconn->acks is not empty
 *
 * If only one item, return 0
 * If more than one item, return 1
 */
static inline int sock_need_sack(sock_conn_t * sconn)
{
	return TAILQ_FIRST(&sconn->acks) != TAILQ_LAST(&sconn->acks, s_acks);
}

typedef struct sock_dev {
	/*! Our IP address in network order */
	in_addr_t ip;

    /*! Our port in network byte order */
    in_port_t port;

	/*! Queued sends */
	 TAILQ_HEAD(s_queued, sock_tx) queued;

	/*! Pending (in-flight) sends */
	 TAILQ_HEAD(s_pending, sock_tx) pending;

	/*! Being progressed? */
	int is_progressing;
} sock_dev_t;

typedef enum sock_fd_type {
	SOCK_FD_UNUSED = 0,
	SOCK_FD_EP,
} sock_fd_type_t;

typedef struct sock_fd_idx {
	sock_fd_type_t type;
	cci__ep_t *ep;
} sock_fd_idx_t;

typedef struct sock_globals {
	/*! Number of sock devices */
	int count;

	/*! Array of sock devices */
	cci_device_t const **const devices;

	/*! Array of devices indexed by sock fd */
	sock_fd_idx_t fd_idx[SOCK_MAX_EPS];

	/*! Highest open endpoint sock fd + 1 for select */
	int nfds;

	/*! fd_set for open endpoint sock fds */
	fd_set fds;

	/*! List of all connections with keepalive enabled */
	 TAILQ_HEAD(ka_conns, sock_conn) ka_conns;
} sock_globals_t;

/* Macro to initialize the structure of a device */
#define INIT_CCI_DEVICE_STRUCT(device) { \
        device->max_send_size = SOCK_DEFAULT_MSS; \
        device->rate = 10000000000ULL; \
        device->pci.domain = -1;    /* per CCI spec */ \
        device->pci.bus = -1;       /* per CCI spec */ \
        device->pci.dev = -1;       /* per CCI spec */ \
        device->pci.func = -1;      /* per CCI spec */ \
        device->up = 0; \
    } while (0)

#define INIT_CCI__DEV_STRUCT(dev,ret) do { \
        cci_device_t *device; \
        sock_dev_t *sdev; \
        ret = CCI_SUCCESS; \
        dev = calloc(1, sizeof(*dev)); \
        if (!dev) \
            ret = CCI_ENOMEM; \
        dev->priv = calloc(1, sizeof(*sdev)); \
        if (!dev->priv) { \
            free(dev); \
            ret = CCI_ENOMEM; \
        } \
        cci__init_dev(dev); \
        device = &dev->device; \
        INIT_CCI_DEVICE_STRUCT(device); \
        sdev = dev->priv; \
        TAILQ_INIT(&sdev->queued); \
        TAILQ_INIT(&sdev->pending); \
        sdev->is_progressing = 0; \
        dev->driver = strdup("sock"); \
    } while(0)

typedef enum device_state {
	IFACE_IS_DOWN = 0,
	IFACE_IS_UP
} core_sock_device_state_t;

#ifndef FD_COPY
#define FD_COPY(a,b) memcpy(a,b,sizeof(fd_set))
#endif

extern sock_globals_t *sglobals;

int cci_core_sock_post_load(cci_plugin_t * me);
int cci_core_sock_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif /* CCI_CORE_SOCK_H */
