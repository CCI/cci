/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011-2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011-2012 Oak Ridge National Labs.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CTP_VERBS_H
#define CCI_CTP_VERBS_H

#include "cci/config.h"
#include <sys/epoll.h>

#include <assert.h>
#include <rdma/rdma_cma.h>

BEGIN_C_DECLS
/* Valid URI include:
 *
 * verbs://hostname:port	# Hostname or IPv4 address and port
 */
/* A verbs device needs the following items in the config file:

   transport = verbs		# must be lowercase

   A verbs device may have these items:

   ip = 1.2.3.4			# IPv4 address of device
				  the default is the first RDMA device found

   interface = ib0		# Ethernet interface name
				  the default is the first RDMA device found

   port = 12345			# base listening port
				  the default is a random, ephemeral port

   Note: if both ip and name are set and if they do not agree (i.e. name's ip
         does not match the given ip), then we rely on the given ip.
 */
#define VERBS_URI		"verbs://"
/* Wire Header Specification */
    typedef enum verbs_msg_type {
	VERBS_MSG_INVALID = 0,
	VERBS_MSG_CONN_REQUEST,
	VERBS_MSG_CONN_PAYLOAD,
	VERBS_MSG_CONN_REPLY,
	VERBS_MSG_DISCONNECT,
	VERBS_MSG_SEND,
	VERBS_MSG_RMA_REMOTE_REQUEST,
	VERBS_MSG_RMA_REMOTE_REPLY,
	VERBS_MSG_KEEPALIVE,
	VERBS_MSG_RMA,
	VERBS_MSG_TYPE_MAX,
} verbs_msg_type_t;

#define VERBS_INLINE_BYTES	(128)

#define VERBS_ACK_CNT		(512)
#define VERBS_PROGRESS_TIMEOUT	(10000) /* microseconds */

/* MSG header */

/* Generic header passed via IMMEDIATE in _host_ order (need to flip before accessing):

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is the msg type and each message type decides how to use B

 */

#define VERBS_TYPE_BITS		(4)
#define VERBS_TYPE_MASK		((1 << VERBS_TYPE_BITS) - 1)
#define VERBS_TYPE(x)		((x) & VERBS_TYPE_MASK)

/* Send via SendRecv

    <------------ 32 bits ----------->
    <--- 12b --> <----- 16b ---->  4b
   +------------+----------------+----+
   |      C     |        B       |  A |
   +------------+----------------+----+

   where:
      A is VERBS_MSG_SEND
      B is seqno for SEND
      C is reserved
 */

#define VERBS_SEQNO_BITS	(16)
#define VERBS_SEQNO_MAX		((1 << VERBS_SEQNO_BITS) - 1)
#define VERBS_SEQNO_SHIFT	(VERBS_TYPE_BITS)
#define VERBS_SEQNO(x)		(((x) >> VERBS_SEQNO_SHIFT) & VERBS_SEQNO_MAX)

/* Conn Request

    <----------- 32 bits ----------->
    <----------- 28b ---------->  4b
   +----------------------------+----+
   |              B             |  A |
   +----------------------------+----+

   where:
      A is VERBS_MSG_CONN_REQUEST
      B is reserved
 */

/* Conn Payload

    <------------- 32 bits ------------>
    <-- 11b --> <--- 12b --> 1  4b   4b
   +-----------+------------+-+----+----+
   |     E     |      D     |C|  B |  A |
   +-----------+------------+-+----+----+

   where:
      A is VERBS_MSG_CONN_PAYLOAD
      B is the connection attribute (UU, RU, RO)
      C is reserved
      D is the payload length
      E is reserved
 */

/* Conn Reply

    <------------ 32 bits ------------>
    <-------- 23b --------> 1  4b   4b
   +-----------------------+-+----+----+
   |           D           |C|  B |  A |
   +-----------------------+-+----+----+

   where:
      A is VERBS_MSG_CONN_REPLY
      B is CCI_EVENT_CONNECT_ACCEPTED or CCI_EVENT_CONNECT_REJECTED
      C is reserved
      D is reserved
 */

/* RMA Remote Handle Request

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is VERBS_MSG_RMA_REMOTE_REQUEST and B is unused.

   The payload is the uint64_t remote handle.
 */

typedef struct verbs_rma_addr_rkey {
	uint64_t remote_handle;	/* the CCI remote handle */
	uint64_t remote_addr;	/* the Verbs remote address */
	uint32_t rkey;		/* the Verbs rkey */
} verbs_rma_addr_rkey_t;

/* RMA Remote Handle Reply

    <----------- 32 bits ----------->
    <---------- 27b ----------> 1  4b
   +---------------------------+-+----+
   |             C             |B|  A |
   +---------------------------+-+----+

   where A is VERBS_MSG_RMA_REMOTE_REPLY
   B is 0 for ERR_NOT_FOUND and 1 for SUCCESS
   C is unused

   The payload is:

       uint64_t remote_handle
       uint64_t remote_addr
       uint32_t rkey
 */

/* Keepalive

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is VERBS_MSG_KEEPALIVE and B is unused.
 */

/* Set some transport defaults */
#define VERBS_EP_RX_CNT		(4096)	/* default SRQ size */
#define VERBS_EP_TX_CNT		(4096)	/* default send count */
				/* default CQ count */
#define VERBS_EP_CQ_CNT		(2 * (VERBS_EP_RX_CNT + VERBS_EP_TX_CNT))
#define VERBS_PROG_TIME_US	(50000)	/* try to progress every N microseconds */

/* RMA Remote Cache
 *
 * Verbs needs 96 bits of info to post an RDMA (remote_addr and rkey). Since the
 * CCI remote handle is a uint64_t, we need to use a rendezvous to obtain the
 * remote_addr and rkey for a given handle. We can cache the most recently used
 * remote handle information on a LRU list attached to the local RMA handle. Each
 * RMA remote uses 36 bytes on a 64-bit machine. There is a scaling trade-off
 * in order to avoid additional rendezvous round-trips since the memory usage
 * will be up to (number of connections * size of LRU list * 36 bytes).
 */
#define VERBS_RMA_REMOTE_SIZE	(4)	/* size of LRU list of RMA remote handles */

/* Data structures */

typedef struct verbs_tx {
	cci__evt_t evt;		/* associated event (connection) */
	verbs_msg_type_t msg_type;	/* message type */
	int flags;		/* (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
	void *buffer;		/* registered send buffer */
	uint16_t len;		/* length of buffer */
	 TAILQ_ENTRY(verbs_tx) entry;	/* hang on vep->idle_txs, vdev->queued,
					   vdev->pending */
	struct verbs_rma_op *rma_op;	/* owning RMA if remote completion msg */
	struct verbs_tx_pool *tx_pool;	/* owning tx pool */
} verbs_tx_t;

typedef struct verbs_rx {
	cci__evt_t evt;		/* associated event */
	uint32_t offset;	/* offset in vep->buffer */
	 TAILQ_ENTRY(verbs_rx) entry;	/* hangs on rx_pool->rxs */
	 uint32_t seqno;	/* seqno for RO SendRecv MSGs */
	struct verbs_rx_pool *rx_pool;	/* owning rx pool */
} verbs_rx_t;

typedef struct verbs_dev {
	struct ibv_context *context;	/* device info and ops */
	struct ifaddrs *ifa;	/* device's interface addr */
	int count;		/* number of ifaddrs */
} verbs_dev_t;

typedef struct verbs_globals {
	int count;		/* number of devices */
	struct cci_device **devices;	/* array of devices */
	struct ibv_context **contexts;	/* open devices */
	struct ifaddrs *ifaddrs;	/* array indexed to contexts */
} verbs_globals_t;

extern volatile verbs_globals_t *vglobals;

typedef struct verbs_rma_handle {
	struct ibv_mr *mr;	/* memory registration */
	cci__ep_t *ep;		/* owning endpoint */
	 TAILQ_ENTRY(verbs_rma_handle) entry;	/* hang on vep->handles */
	uint32_t refcnt;	/* reference count */
	 TAILQ_HEAD(s_rma_ops, verbs_rma_op) rma_ops;	/* list of all rma_ops */
} verbs_rma_handle_t;

typedef struct verbs_rma_remote {
	TAILQ_ENTRY(verbs_rma_remote) entry;	/* hang on local RMA handle */
	verbs_rma_addr_rkey_t info;	/* handle, addr, and rkey */
} verbs_rma_remote_t;

typedef struct verbs_rma_op {
	cci__evt_t evt;		/* completion event */
	verbs_msg_type_t msg_type;	/* to be compatible with tx */
	 TAILQ_ENTRY(verbs_rma_op) entry;	/* vep->rmas */
	 TAILQ_ENTRY(verbs_rma_op) gentry;	/* handle->rma_ops */
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;
	uint64_t remote_offset;

	uint64_t remote_addr;
	uint32_t rkey;

	uint64_t len;
	cci_status_t status;
	void *context;
	int flags;
	verbs_tx_t *tx;
	uint32_t msg_len;
	char *msg_ptr;
} verbs_rma_op_t;

typedef struct verbs_rx_pool {
	TAILQ_ENTRY(verbs_rx_pool) entry;	/* hang on ep->rx_pools */
	void *buf;		/* recv buffer */
	struct ibv_mr *mr;	/* memory registration */
	 TAILQ_HEAD(v_rxs, verbs_rx) rxs;	/* all rxs */
	int repost;		/* repost rxs? */
	uint32_t size;		/* current size */
	uint32_t posted;	/* # of posted rxs */
} verbs_rx_pool_t;

typedef struct verbs_tx_pool {
	TAILQ_HEAD(v_txsi, verbs_tx) idle_txs;	/* idle txs */
	void *buf;		/* active tx buffer */
	struct ibv_mr *mr;	/* active mr */
	uint32_t size;		/* current size */
	uint32_t posted;	/* # of posted txs */
	int repost;		/* repost txs? */
	pthread_mutex_t lock;	/* lock, for buf changes */
} verbs_tx_pool_t;

typedef struct verbs_ep {
	struct ibv_comp_channel *ib_channel;
	struct rdma_event_channel *rdma_channel;	/* for connection requests */
	struct rdma_cm_id *id_rc;	/* reliable ID */
	struct rdma_cm_id *id_ud;	/* unreliable ID */
	struct ibv_pd *pd;	/* protection domain */
	struct ibv_cq *cq;	/* completion queue */
	uint32_t cq_size;	/* number of cqe */
	struct sockaddr_in sin;	/* host address and port */

	void *conn_tree;	/* rbtree of conns sorted by qp_num */
	pthread_rwlock_t conn_tree_lock;

	struct ibv_srq *srq;	/* shared recv queue */

	verbs_tx_pool_t *tx_pool;
	verbs_tx_pool_t *tx_pool_old;
	int tx_resize_in_progress;

	 TAILQ_HEAD(v_rx_pools, verbs_rx_pool) rx_pools;	/* list of rx pools - usually one */

	int fd;			/* epoll() fd */
	int acks;		/* accumulated acks from ibv_get_cq_event() */
	pthread_t tid;		/* progress thread */
	int is_progressing;	/* being progressed? */

	 TAILQ_HEAD(v_conns, verbs_conn) conns;	/* all conns */
	 TAILQ_HEAD(v_active, verbs_conn) active;	/* active conns */
	 TAILQ_HEAD(v_passive, verbs_conn) passive;	/* passive conns */
	 TAILQ_HEAD(v_hdls, verbs_rma_handle) handles;	/* all rma registrations */
	 TAILQ_HEAD(v_ops, verbs_rma_op) rma_ops;	/* all rma ops */
} verbs_ep_t;

typedef enum verbs_conn_state {
	VERBS_CONN_CLOSED = -2,
	VERBS_CONN_CLOSING = -1,
	VERBS_CONN_INIT = 0,
	VERBS_CONN_ACTIVE,
	VERBS_CONN_PASSIVE,
	VERBS_CONN_ESTABLISHED,
} verbs_conn_state_t;

typedef struct verbs_conn_request {
	void *context;		/* application context */
	void *ptr;		/* application payload */
	uint32_t len;		/* payload length */
	cci_conn_attribute_t attr;	/* connection type */
} verbs_conn_request_t;

typedef struct verbs_conn {
	cci__conn_t *conn;	/* owning conn */
	uint32_t qp_num;	/* id->qp->qp_num for vep->conn_tree */
	struct rdma_cm_id *id;	/* peer info */
	verbs_conn_state_t state;	/* current state */
	uint32_t mss;		/* max send size */
	uint32_t max_tx_cnt;	/* max sends in flight */
	uint32_t num_remotes;	/* number of cached remotes */
	uint32_t inline_size;	/* largest inline msg */

	 TAILQ_HEAD(s_rems, verbs_rma_remote) remotes;	/* LRU list of remote handles */
	 TAILQ_HEAD(w_ops, verbs_rma_op) rma_ops;	/* rma ops waiting on remotes */
	 TAILQ_ENTRY(verbs_conn) entry;	/* hangs on vep->conns */
	 TAILQ_ENTRY(verbs_conn) temp;	/* hangs on vep->active|passive */
	verbs_conn_request_t *conn_req;	/* application conn req info */
} verbs_conn_t;

int cci_ctp_verbs_post_load(cci_plugin_t * me);
int cci_ctp_verbs_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif /* CCI_CTP_VERBS_H */
