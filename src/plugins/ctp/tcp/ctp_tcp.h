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

#include "cci/private_config.h"

#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <poll.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"

BEGIN_C_DECLS
#define TCP_DEFAULT_MSS        (8*1024)	/* assume jumbo frames */
#define TCP_MIN_MSS            (128)
#define TCP_MAX_MSS            (9000)

#define TCP_EP_RX_CNT          (16*1024)	/* number of rx messages */
#define TCP_EP_TX_CNT          (16*1024)	/* number of tx messages */
#define TCP_PROG_TIME_MS       (10)	/* try to progress every N milliseconds */

#define TCP_HDR_LEN            (8)	/* common header size */

#define TCP_RMA_DEPTH          (16)	/* how many in-flight msgs per RMA */
#define TCP_RMA_FRAG_SIZE      (128*1024)
#define TCP_RMA_FRAG_MAX       (1024*1024)

#define TCP_EP_MAX_CONNS       (1024)

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
 * tcp://1.2.3.4:5555      # IPv4 address and port
 * tcp://foo.bar.com:5555  # Resolvable name and port
 */

/* A tcp device needs the following items in the config file:
 *
 * transport = tcp        # must be lowercase
 *
 * ip = 0.0.0.0           # valid IPv4 address of the adapter to use
 *
 * or
 *
 * inerface = ethN        # where ethN is a up interface
 *
 * A tcp device may have these items:
 *
 * mtu = 9000             # MTU less headers will become max_send_size
 * min_port = 4444        # lowest port to use for endpoints
 * max_port = 5555        # highest port to use for endpoints
 */

/* Message types */

typedef enum tcp_msg_type {
	TCP_MSG_INVALID = 0,
	TCP_MSG_CONN_REQUEST,	/* SYN */
	TCP_MSG_CONN_REPLY,	/* SYN-ACK */
	TCP_MSG_CONN_ACK,	/* ACK */
	TCP_MSG_DISCONNECT,	/* spec says no disconnect is sent */
	TCP_MSG_SEND,
	TCP_MSG_RNR,		/* for both msg and RMA */
	TCP_MSG_KEEPALIVE,

	/* the rest apply to reliable connections only */

	TCP_MSG_ACK,		/* acking a MSG */
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

    <----------- 32 bits ---------->
    <---------- 28b ---------->  4b
   +---------------------------+----+
   |             A             |type|
   +---------------------------+----+
   |               B                |
   +--------------------------------+

   where each message type decides how to use A and B

 */

typedef struct tcp_header {
	uint32_t type;		/* lower 4b are type and the rest are A */
	uint32_t b;
	char data[0];		/* start payload here */
} tcp_header_t;

/* type, a, and b bit mangling */

#define TCP_TYPE_BITS      (4)
#define TCP_TYPE_MASK      (0xF)
#define TCP_TYPE_SHIFT     (0)

#define TCP_A_BITS         (28)
#define TCP_A_SHIFT        (TCP_TYPE_BITS)
#define TCP_A_MASK         ((1 << TCP_A_BITS) - 1)
#define TCP_A_MAX          (TCP_A_MASK)

#define TCP_TYPE(x)        ((uint8_t)  ((x) & TCP_TYPE_MASK))
#define TCP_A(x)           ((uint32_t) (((x) >> TCP_A_SHIFT)))

#define TCP_PACK_TYPE(type,a) \
        (((uint32_t) (type)) | (((uint32_t) (a)) << TCP_A_SHIFT))

static inline void
tcp_pack_header(tcp_header_t * header, tcp_msg_type_t type,
	        uint32_t a, uint32_t b)
{
	assert(type < TCP_MSG_TYPE_MAX && type > TCP_MSG_INVALID);

	header->type = htonl(TCP_PACK_TYPE(type, a));
	header->b = htonl(b);
}

static inline void
tcp_parse_header(tcp_header_t * header, tcp_msg_type_t * type,
		 uint32_t * a, uint32_t * b)
{
	uint32_t hl = ntohl(header->type);

	*type = (enum tcp_msg_type)TCP_TYPE(hl);
	assert(*type < TCP_MSG_TYPE_MAX && *type > TCP_MSG_INVALID);
	*a = TCP_A(hl);
	*b = ntohl(header->b);
}

/* Common message headers (RO, RU, and UU) */

/* connection request/reply */
typedef struct tcp_handshake {
	uint32_t max_recv_buffer_count;	/* max recvs that I can handle */
	uint32_t mss;		/* lower of each endpoint */
	uint32_t keepalive;	/* keepalive timeout (when activated) */
	uint32_t server_tx_id;  /* id of server's tx */
} tcp_handshake_t;

static inline void
tcp_pack_handshake(tcp_handshake_t * hs,
		    uint32_t max_recv_buffer_count, uint32_t mss,
		    uint32_t keepalive, uint32_t server_tx_id)
{
	assert(mss <= (TCP_MAX_MSS));
	assert(mss >= TCP_MIN_MSS);

	hs->max_recv_buffer_count = htonl(max_recv_buffer_count);
	hs->mss = htonl(mss);
	hs->keepalive = htonl(keepalive);
	hs->server_tx_id = htonl(server_tx_id);
}

static inline void
tcp_parse_handshake(tcp_handshake_t * hs,
		     uint32_t * max_recv_buffer_count, uint32_t * mss,
		     uint32_t * ka, uint32_t *server_tx_id)
{
	*max_recv_buffer_count = ntohl(hs->max_recv_buffer_count);
	*mss = ntohl(hs->mss);
	*ka = ntohl(hs->keepalive);
	*server_tx_id = ntohl(hs->server_tx_id);
}

/* connection request header:

    <------------ 32 bits ------------>
    <- 8b -> <----- 16b- --->  4b   4b
   +--------+----------------+----+----+
   |  rsvd  |    data len    |attr|type|
   +--------+----------------+----+----+
   |               tx id               |
   +-----------------------------------+

   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+
   |            keepalive          |
   +-------------------------------+
   |          server tx_id         |
   +-------------------------------+

   The peer uses the id when sending to us.
   The user data follows the header.

   attr: CCI_CONN_ATTR_[UU|RU|RO]
   data len: amount of user data following header
   tx id: tx used for message
   max_recv_buffer_count: number of msgs we can receive
   mss: max send size
   keepalive: if keepalive is activated, this specifies the keepalive timeout
   server tx_id: 0 in conn_request and set by server in conn_reply
 */

static inline void
tcp_pack_conn_request(tcp_header_t * header, cci_conn_attribute_t attr,
		       uint16_t data_len, uint32_t client_tx_id)
{
	uint32_t a = attr | (data_len << 4);
	tcp_pack_header(header, TCP_MSG_CONN_REQUEST, a, client_tx_id);
}

/* connection reply header:

    <------------ 32 bits ------------>
    <------- 20b ------> <- 8b ->  4b
   +--------------------+--------+----+
   |        rsvd        |  reply |type|
   +--------------------+--------+----+
   |          client tx id            |
   +----------------------------------+

   +-------------------------------+
   |      max_recv_buffer_count    |
   +-------------------------------+
   |              mss              |
   +-------------------------------+
   |            keepalive          |
   +-------------------------------+
   |          server tx_id         |
   +-------------------------------+

   The reply is 0 for success else errno.
   The tx id is from the active client (to lookup its tx)

   reply: CCI_EVENT_CONNECT_[ACCEPTED|REJECTED]
   mss: max app payload (user header and user data)
   server tx_id: set by server, client will return in conn_ack
 */

static inline void
tcp_pack_conn_reply(tcp_header_t * header, uint8_t reply, uint32_t client_tx_id)
{
	tcp_pack_header(header, TCP_MSG_CONN_REPLY, reply, client_tx_id);
}

/* connection ack header:

    <----------- 32 bits ---------->
    <---------- 28b ---------->  4b
   +----------------------------+----+
   |         reserved           |type|
   +----------------------------+----+
   |          server tx_id           |
   +---------------------------------+

 */

static inline void tcp_pack_conn_ack(tcp_header_t * header, uint32_t server_tx_id)
{
	tcp_pack_header(header, TCP_MSG_CONN_ACK, 0, server_tx_id);
}

/* send header:

    <----------- 32 bits ---------->
    <--- 12b --> <---- 16b ----->  4b
   +------------+----------------+----+
   |    rsvd    |       len      |type|
   +------------+----------------+----+
   |               tx_id              |
   +----------------------------------+

   length of payload
   tx_id for reliable connections

 */

static inline void
tcp_pack_send(tcp_header_t * header, uint16_t len, uint32_t tx_id)
{
	tcp_pack_header(header, TCP_MSG_SEND, len, tx_id);
}

/* keepalive header:

    <----------- 32 bits ---------->
    <---------- 28b ---------->  4b
   +---------------------------+----+
   |         reserved          |type|
   +---------------------------+----+
   |           reserved             |
   +--------------------------------+

 */

static inline void tcp_pack_keepalive(tcp_header_t * header)
{
	tcp_pack_header(header, TCP_MSG_KEEPALIVE, 0, 0);
}

/* ack header:

    <----------- 32 bits ---------->
    <--------- 24b -------->  4b   4b
   +------------------------+----+----+
   |        reserved        |stat|type|
   +------------------------+----+----+
   |              tx_id               |
   +----------------------------------+

   type: TCP_MSG_ACK
   stat: CCI_SUCCESS, CCI_ERR_RNR, CCI_ERR_RMA_HANDLE

 */
static inline void
tcp_pack_ack(tcp_header_t * header, uint32_t tx_id, uint32_t status)
{
	tcp_pack_header(header, TCP_MSG_ACK, status, tx_id);
}

static inline void
tcp_parse_ack(tcp_header_t * header, uint32_t *tx_id)
{
	*tx_id = ntohl(header->b);
	return;
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

typedef struct tcp_rma_header {
	tcp_header_t header;
	tcp_rma_handle_offset_t local;
	tcp_rma_handle_offset_t remote;
	char data[0];
} tcp_rma_header_t;

/* RMA write

    <----------- 32 bits ---------->
    <----------- 28b ---------->  4b
   +----------------------------+----+
   |             len            |type|
   +----------------------------+----+
   |              tx_id              |
   +---------------------------------+

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

   length of payload
   local handle: cci_rma() caller's handle (stays same for each packet)
   local offset: offset into the local handle (changes for each packet)
   remote handle: passive peer's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
 */

static inline void
tcp_pack_rma_write(tcp_rma_header_t * write, uint32_t data_len, uint32_t tx_id,
		   uint64_t local_handle, uint64_t local_offset,
		   uint64_t remote_handle, uint64_t remote_offset)
{
	tcp_pack_header(&write->header, TCP_MSG_RMA_WRITE, data_len, tx_id);
	tcp_pack_rma_handle_offset(&write->local, local_handle, local_offset);
	tcp_pack_rma_handle_offset(&write->remote, remote_handle, remote_offset);
}

/* RMA read request

    <----------- 32 bits ---------->
    <----------- 28b ---------->  4b
   +----------------------------+----+
   |             len            |type|
   +----------------------------+----+
   |              tx_id              |
   +---------------------------------+

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

   type is TCP_MSG_RMA_READ_REQUEST or TCP_MSG_RMA_READ_REPLY
   length of _requested_ payload
   local handle: cci_rma() caller's handle (stays same for each packet)
   local offset: offset into the local handle (changes for each packet)
   remote handle: passive peer's handle (stays same for each packet)
   remote offset: offset into the remote handle (changes for each packet)
 */

static inline void
tcp_pack_rma_read_request(tcp_rma_header_t * read, uint64_t data_len, uint32_t tx_id,
		  uint64_t local_handle, uint64_t local_offset,
		  uint64_t remote_handle, uint64_t remote_offset)
{
	tcp_pack_header(&read->header, TCP_MSG_RMA_READ_REQUEST, data_len, tx_id);
	tcp_pack_rma_handle_offset(&read->local, local_handle, local_offset);
	tcp_pack_rma_handle_offset(&read->remote, remote_handle, remote_offset);
}

static inline void
tcp_pack_rma_read_reply(tcp_rma_header_t * read, uint64_t data_len, uint32_t tx_id,
		  uint64_t local_handle, uint64_t local_offset,
		  uint64_t remote_handle, uint64_t remote_offset)
{
	tcp_pack_header(&read->header, TCP_MSG_RMA_READ_REPLY, data_len, tx_id);
	tcp_pack_rma_handle_offset(&read->local, local_handle, local_offset);
	tcp_pack_rma_handle_offset(&read->remote, remote_handle, remote_offset);
}

/************* TCP private structures ****************/

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

typedef enum tcp_ctx {
	TCP_CTX_TX,
	TCP_CTX_RX
} tcp_ctx_t;

/*! Send message context.
*
* \ingroup messages */
typedef struct tcp_tx {
	/*! Must be TCP_CTX_TX */
	tcp_ctx_t ctx;

	/*! Associated event (includes public cci_event_t) */
	cci__evt_t evt;

	/*! Message type */
	tcp_msg_type_t msg_type;

	/*! Msg ID */
	uint32_t id;

	/*! Flags (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
	int flags;

	/*! State of send - not to be confused with completion status */
	tcp_tx_state_t state;

	/*! Buffer (wire header, data) */
	void *buffer;

	/*! Buffer length */
	uint32_t len;

	/*! Amount of data (len + rma_len) sent */
	uintptr_t offset;

	void *rma_ptr;
	uint32_t rma_len;

	/*! Timeout in microseconds */
	uint64_t timeout_us;

	/*! Owning RMA op if not message */
	struct tcp_rma_op *rma_op;

	/*! RMA fragment ID */
	uint32_t rma_id;

	/*! Number of RNR nacks received */
	uint32_t rnr;

	/*! Peer address if connect reject message (i.e. no conn) */
	struct sockaddr_in sin;
} tcp_tx_t;

/*! Receive message context.
 *
 * \ingroup messages */
typedef struct tcp_rx {
	/*! Must be TCP_CTX_RX */
	tcp_ctx_t ctx;

	/*! Associated event (includes public cci_event_t) */
	cci__evt_t evt;

	/*! Buffer (wire header, data) */
	void *buffer;

	/*! Buffer length */
	uint16_t len;

	/*! rx ID */
	uint32_t id;

	/*! Peer's sockaddr_in for connection requests */
	struct sockaddr_in sin;
} tcp_rx_t;

typedef struct tcp_rma_handle {
	/*! Owning endpoint */
	cci__ep_t *ep;

	/*! Registered length */
	uint64_t length;

	/*! Application memory */
	void *start;

	/*! CCI RMA handle */
	cci_rma_handle_t rma_handle;

	/*! Access flags */
	uint32_t flags;

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

	cci_rma_handle_t * local_handle;
	uint64_t local_offset;
	cci_rma_handle_t * remote_handle;
	uint64_t remote_offset;

	uint64_t data_len;

	/*! RMA id for ordering in case of fence */
	uint32_t id;

	/*! Number of fragments for data transfer (excluding remote completion msg) */
	uint32_t num_msgs;

	/*! Next segment to send */
	uint32_t next;

	/*! Last fragment acked */
	int32_t acked;

	/*! Number of fragments pending */
	uint32_t pending;

	/*! Status of the RMA op */
	cci_status_t status;

	/*! Application context */
	void *context;

	/*! Flags */
	int flags;

	/*! Pointer to tx for remote completion if needed */
	tcp_tx_t *tx;

	/*! Application completion msg len */
	uint16_t msg_len;

	/*! Application completion msg ptr if provided */
	char *msg_ptr;
} tcp_rma_op_t;

typedef struct tcp_ep {
	/*! Socket for listen */
	cci_os_handle_t sock;

	/*! List of open connections */
	TAILQ_HEAD(s_conns, tcp_conn) conns;

	/*! Set when polling - only one poll at a time.
	 *  The poller will need to access fds, nfds, c and they cannot change
	 *  while is_polling is set. We need to queue any changes and the
	 *  poller can perform them after processing the poll results. */
	uint32_t is_polling;

	/*! For polling connection sockets */
	struct pollfd *fds;

	/*! Number of pollfds */
	nfds_t nfds;

	/*! Array of conns indexed by fds */
	cci__conn_t **c;

	/*! Base pointer for the buffers, tcp_rx and tcp_tx allocated */
	char *tcp_xx_base, *buf_base;

	/*! All txs */
	tcp_tx_t *txs;

	/*! List of idle txs */
	TAILQ_HEAD(s_itxs, cci__evt) idle_txs;

	/*! All rxs */
	tcp_rx_t *rxs;

	/*! List of idle rxs */
	TAILQ_HEAD(s_rxsi, cci__evt) idle_rxs;

	/*! Pipe for OS handle */
	int pipe[2];

	/*! Connection id blocks */
	uint64_t *ids;

	/* Our IP and port */
	struct sockaddr_in sin;

#if 0
	/*! Queued sends */
	TAILQ_HEAD(s_queued, cci__evt) queued;

	/*! Pending (in-flight) sends */
	TAILQ_HEAD(s_pending, cci__evt) pending;
#endif

	/*! List of all connections with keepalive enabled */
	/* FIXME: revisit the code to use this
	TAILQ_HEAD(s_ka, tcp_conn) ka_conns;
	*/

	/*! List of active connections awaiting replies */
	TAILQ_HEAD(s_active, tcp_conn) active;

	/*! List of passive connections awaiting requests and acks */
	TAILQ_HEAD(s_passive, tcp_conn) passive;

	/*! List of closing connections */
	TAILQ_HEAD(ss_conns, tcp_conn) closing;

	/*! List of RMA registrations */
	TAILQ_HEAD(s_handles, tcp_rma_handle) handles;

	/*! List of RMA ops */
	TAILQ_HEAD(s_ops, tcp_rma_op) rma_ops;

	/*! ID of the recv thread for the endpoint */
	pthread_t tid;
} tcp_ep_t;

/* Connection info */

typedef enum tcp_conn_status {
	/*! Shutdown */
	TCP_CONN_CLOSED = -2,

	/*! Disconnect called */
	TCP_CONN_CLOSING = -1,

	/*! NULL (intial) state */
	TCP_CONN_INIT = 0,

	/*! Waiting on connect */
	TCP_CONN_ACTIVE1,

	/*! Waiting on conn reply */
	TCP_CONN_ACTIVE2,

	/*! Waiting on client request */
	TCP_CONN_PASSIVE1,

	/*! Waiting on conn ack */
	TCP_CONN_PASSIVE2,

	/*! Connection open and useable */
	TCP_CONN_READY
} tcp_conn_status_t;

static inline char *
tcp_conn_status_str(tcp_conn_status_t status)
{
	switch (status) {
	case TCP_CONN_CLOSED:
		return "TCP_CONN_CLOSED";
	case TCP_CONN_CLOSING:
		return "TCP_CONN_CLOSING";
	case TCP_CONN_INIT:
		return "TCP_CONN_INIT";
	case TCP_CONN_ACTIVE1:
		return "TCP_CONN_ACTIVE1";
	case TCP_CONN_ACTIVE2:
		return "TCP_CONN_ACTIVE2";
	case TCP_CONN_PASSIVE1:
		return "TCP_CONN_PASSIVE1";
	case TCP_CONN_PASSIVE2:
		return "TCP_CONN_PASSIVE2";
	case TCP_CONN_READY:
		return "TCP_CONN_READY";
	}

	/* Never reached */
	return NULL;
}

typedef struct tcp_conn {
	/*! Owning conn */
	cci__conn_t *conn;

	/*! Status */
	tcp_conn_status_t status;

	/*! Peer's sockaddr_in (IP, port) */
	struct sockaddr_in sin;

	/*! socket for this connection */
	uint32_t fd;

	/*! Lock for receiving */
	pthread_mutex_t rlock;

	/*! Lock for sending */
	pthread_mutex_t slock;

	/*! Index in tep->fds */
	uint32_t index;

	/*! Max sends in flight to this peer (i.e. rwnd) */
	uint32_t max_tx_cnt;

	/*! Entry to hang on tcp_ep->conns[hash] */
	 TAILQ_ENTRY(tcp_conn) entry;

	/*! Queued sends */
	TAILQ_HEAD(s_queued, cci__evt) queued;

	/*! Pending (in-flight) sends */
	TAILQ_HEAD(s_pending, cci__evt) pending;

	/*! List of RMA ops in process in case of fence */
	TAILQ_HEAD(s_rmas, tcp_rma_op) rmas;

	/*! Flag to know if the receiver is ready or not */
	uint32_t rnr;
} tcp_conn_t;

typedef struct tcp_dev {
	/*! Our IP address in network order */
	in_addr_t ip;

	/*! Our port in network byte order */
	in_port_t port;

	/*! Set socket buffers sizes */
	uint32_t bufsize;
} tcp_dev_t;

typedef enum tcp_fd_type {
	TCP_FD_UNUSED = 0,
	TCP_FD_EP
} tcp_fd_type_t;

typedef struct tcp_fd_idx {
	tcp_fd_type_t type;
	cci__ep_t *ep;
} tcp_fd_idx_t;

typedef struct tcp_globals {
	/*! Mutex */
	pthread_mutex_t lock;

	/*! Number of sock devices */
	int count;

	/*! Array of sock devices */
	cci_device_t **devices;
} tcp_globals_t;

/* Macro to initialize the structure of a device */
#define INIT_CCI_DEVICE_STRUCT(device) { \
        device->max_send_size = TCP_DEFAULT_MSS; \
        device->rate = 10000000000ULL; \
        device->pci.domain = -1;    /* per CCI spec */ \
        device->pci.bus = -1;       /* per CCI spec */ \
        device->pci.dev = -1;       /* per CCI spec */ \
        device->pci.func = -1;      /* per CCI spec */ \
        device->up = 0; \
    } while (0)

#define INIT_CCI__DEV_STRUCT(dev,ret) do { \
        struct cci_device *device; \
        tcp_dev_t *sdev; \
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
        device->transport = strdup("tcp"); \
    } while(0)

typedef enum device_state {
	IFACE_IS_DOWN = 0,
	IFACE_IS_UP
} core_tcp_device_state_t;

#ifndef FD_COPY
#define FD_COPY(a,b) memcpy(a,b,sizeof(fd_set))
#endif

extern tcp_globals_t *tglobals;

int cci_ctp_tcp_post_load(cci_plugin_t * me);
int cci_ctp_tcp_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_TCP_H */
