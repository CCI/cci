/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_GNI_H
#define CCI_CORE_GNI_H

#include "cci/config.h"

#include <netinet/in.h>	/* struck sockaddr_in */
#include <assert.h>
#include <gni_pub.h>

BEGIN_C_DECLS
/* Valid URI include:
 *
 * gni://hostname:port	# Hostname or IPv4 address and port
 */
/* A gni device needs the following items in the config file:

   driver = gni		# must be lowercase

   A gni device may have these items:

   ip = 1.2.3.4			# IPv4 address of device

   interface = ipogif0		# Ethernet interface name

   port = 12345			# base listening port
				  the default is a random, ephemeral port
 */
#define GNI_URI		"gni://"
/* Wire Header Specification */
    typedef enum gni_msg_type {
	GNI_MSG_INVALID = 0,
	GNI_MSG_CONN_REQUEST,		/* client -> server */
	GNI_MSG_CONN_PAYLOAD,
	GNI_MSG_CONN_REPLY,		/* client <- server */
	GNI_MSG_CONN_ACK,		/* client -> server */
	GNI_MSG_DISCONNECT,
	GNI_MSG_SEND,
	GNI_MSG_RMA_REMOTE_REQUEST,
	GNI_MSG_RMA_REMOTE_REPLY,
	GNI_MSG_KEEPALIVE,
	GNI_MSG_RMA,
	GNI_MSG_TYPE_MAX,
} gni_msg_type_t;

/* MSG header */

/* Generic header

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where:
      A is the msg type
      B is set by each message type
 */

#define GNI_MSG_TYPE_BITS	(4)
#define GNI_MSG_TYPE_MASK	((1 << GNI_MSG_TYPE_BITS) - 1)
#define GNI_MSG_TYPE(x)		((x) & GNI_MSG_TYPE_MASK)

/* Send

    <------------ 32 bits ----------->
    <----- 28b ----> <--- 12b -->  4b
   +----------------+------------+----+
   |        C       |      B     |  A |
   +----------------+------------+----+

   where:
      A is GNI_MSG_SEND
      B is msg length
      C is reserved
 */

/* A packed structure to hold gni_smsg_attr_t info */
typedef struct gni_smsg_info {
	gni_mem_handle_t mem_hndl;	/* two uint64_t */
	uint64_t msg_buffer;		/* (uint64_t)(uintptr_t)void * */
	uint32_t nic_id;		/* physical NIC address */
	uint32_t msg_type;		/* typedef enum gni_smsg_type */
	uint32_t buff_size;
	uint32_t mbox_offset;
	uint32_t mbox_maxcredit;
	uint32_t msg_maxsize;
	uint32_t id;			/* conn id */
	uint32_t pad;
} gni_smsg_info_t;

/* Conn Request (sent over the socket)

    <----------- 32 bits ----------->
    <--- 12b --> <--- 12b -->  4b   4b
   +------------+------------+----+----+
   |      D     |      C     |  B |  A |
   +------------+------------+----+----+
   |                                   |
   |             smsg info             |
   |                                   |
   |                                   |
   +-----------------------------------+
   |             payload               |

   where:
      A is GNI_MSG_CONN_REQUEST
      B is the connection attribute (UU, RU, RO)
      C is the payload length
      D is reserved
 */

/* Conn Reply

    <------------ 32 bits ----------->
    <--------- 27b ---------> 1  4b
   +--------------------------+-+----+
   |            C             |B|  A |
   +--------------------------+-+----+
   |                                  |
   |             smsg info            |
   |                                  |
   |                                  |
   +----------------------------------+

   where:
      A is GNI_MSG_CONN_REPLY
      B is CCI_SUCCESS or CCI_ECONNREFUSED
      C is reserved
      If success, return server's smsg info
 */

/* RMA Remote Handle Request

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is GNI_MSG_RMA_REMOTE_REQUEST and B is unused.

   The payload is the uint64_t remote handle.
 */

typedef struct gni_rma_addr_rkey {
	uint64_t remote_handle;		/* the CCI remote handle */
	uint64_t remote_addr;		/* the gni remote address */
	gni_mem_handle_t remote_mem_hndl;	/* two uint64_t */
} gni_rma_addr_rkey_t;

/* RMA Remote Handle Reply

    <----------- 32 bits ----------->
    <---------- 27b ----------> 1  4b
   +---------------------------+-+----+
   |             C             |B|  A |
   +---------------------------+-+----+

   where A is GNI_MSG_RMA_REMOTE_REPLY
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

   where A is GNI_MSG_KEEPALIVE and B is unused.
 */

/* Set some driver defaults */
#define GNI_EP_MSS		(128)		/* default MSS */
#define GNI_EP_MSS_MAX		((1 << 12) -1)	/* largest MSS allowed */
#define GNI_EP_RX_CNT		(32 * 1024)	/* default recv buffer count */
#define GNI_EP_TX_CNT		(16 * 1024)	/* default send buffer count */
#define GNI_EP_CQ_CNT		(GNI_EP_RX_CNT + GNI_EP_TX_CNT)	/* default CQ count */
#define GNI_PROG_TIME_US	(100000)	/* try to progress every N microseconds */
#define GNI_CONN_CREDIT		(8)		/* mbox max msgs */

/* RMA Remote Cache
 *
 * gni needs 96 bits of info to post an RDMA (remote_addr and rkey). Since the
 * CCI remote handle is a uint64_t, we need to use a rendezvous to obtain the
 * remote_addr and rkey for a given handle. We can cache the most recently used
 * remote handle information on a LRU list attached to the local RMA handle. Each
 * RMA remote uses 36 bytes on a 64-bit machine. There is a scaling trade-off
 * in order to avoid additional rendezvous round-trips since the memory usage
 * will be up to (number of connections * size of LRU list * 36 bytes).
 */
#define GNI_RMA_REMOTE_SIZE	(4)	/* size of LRU list of RMA remote handles */

/* Data structures */

typedef struct gni_tx {
	cci__evt_t evt;			/* associated event (connection) */
	gni_msg_type_t msg_type;	/* message type */
	int flags;			/* (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
	void *buffer;			/* registered send buffer */
	uint16_t len;			/* length of buffer */
	TAILQ_ENTRY(gni_tx) entry;	/* hang on gep->idle_txs, gdev->queued,
					   gdev->pending */
	TAILQ_ENTRY(gni_tx) gentry;	/* hangs on gep->txs */
	struct gni_rma_op *rma_op;	/* owning RMA if remote completion msg */
} gni_tx_t;

typedef struct gni_rx {
	cci__evt_t evt;			/* associated event */
	uint32_t offset;		/* offset in gep->buffer */
	TAILQ_ENTRY(gni_rx) entry;	/* hangs on rx_pool->rxs */
	struct gni_rx_pool *rx_pool;	/* owning rx pool */
} gni_rx_t;

typedef struct gni_dev {
	int device_id;			/* GNI device id */
	uint32_t ptag;
	uint32_t cookie;
	struct ifaddrs *ifa;		/* device's interface addr */
	int is_progressing;		/* being progressed? */
} gni_dev_t;

typedef struct gni_globals {
	uint32_t phys_addr;		/* physical Gemini address */
	int count;			/* number of devices */
	int *device_ids;		/* local device ids */
	struct ifaddrs *ifaddrs;
	cci_device_t const **const devices;	/* array of devices */
} gni_globals_t;

extern gni_globals_t *gglobals;

typedef struct gni_rma_handle {
	gni_mem_handle_t mh;		/* memory handle */
	cci__ep_t *ep;			/* owning endpoint */
	TAILQ_ENTRY(gni_rma_handle) entry;	/* hang on gep->handles */
	uint32_t refcnt;		/* reference count */
	TAILQ_HEAD(s_rma_ops, gni_rma_op) rma_ops;	/* list of all rma_ops */
} gni_rma_handle_t;

typedef struct gni_rma_remote {
	TAILQ_ENTRY(gni_rma_remote) entry;	/* hang on local RMA handle */
	gni_rma_addr_rkey_t info;	/* handle, addr, and rkey */
} gni_rma_remote_t;

typedef struct gni_rma_op {
	cci__evt_t evt;			/* completion event */
	gni_msg_type_t msg_type;	/* to be compatible with tx */
	TAILQ_ENTRY(gni_rma_op) entry;	/* gep->rmas */
	TAILQ_ENTRY(gni_rma_op) gentry;	/* handle->rma_ops */
	uint64_t local_handle;
	uint64_t local_offset;
	uint64_t remote_handle;
	uint64_t remote_offset;

	uint64_t remote_addr;
	gni_mem_handle_t remote_mem_hndl; /* memory handle */

	uint64_t len;
	cci_status_t status;
	void *context;
	int flags;
	gni_tx_t *tx;
	uint32_t msg_len;
	char *msg_ptr;
} gni_rma_op_t;

/* This is the endpoint recv buffer container. It does not need to be
 * registered. Unfortunately, each connection with have a SMSG mailbox
 * (which is registered) but can only support one message outstanding.
 * To support multiple events outstanding, we will copy from the mbox
 * to here.
 */
typedef struct gni_rx_pool {
	TAILQ_ENTRY(gni_rx_pool) entry;	/* hang on ep->rx_pools */
	void *buf;			/* recv buffer */
	TAILQ_HEAD(g_rxs, gni_rx) rxs;	/* all rxs */
	uint32_t size;			/* current size */
} gni_rx_pool_t;

typedef struct gni_ep {
	gni_cdm_handle_t cdm;		/* communication domain handle */
	gni_nic_handle_t nic;		/* NIC handle */
	gni_cq_handle_t tx_cq;		/* source CQ for SMSG sends and RDMAs */
	gni_cq_handle_t rx_cq;		/* destination CQ for SMSG recvs */

	int sock;			/* listening socket for connection setup */
	struct sockaddr_in sin;		/* host address and port */
	TAILQ_HEAD(g_crs, gni_rx) crs;	/* all conn requests */
	TAILQ_HEAD(g_crsi, gni_rx) idle_crs;	/* idle conn requests */

	void *tx_buf;			/* send buffer */
	TAILQ_HEAD(g_txs, gni_tx) txs;	/* all txs */
	TAILQ_HEAD(g_txsi, gni_tx) idle_txs;	/* idle txs */

	TAILQ_HEAD(g_rx_pools, gni_rx_pool) rx_pools;	/* list of rx pools - usually one */

	void *conn_tree;		/* tree of peer conn ids */
	pthread_rwlock_t conn_tree_lock;	/* rw lock */
	TAILQ_HEAD(g_conns, gni_conn) conns;	/* all conns */
	TAILQ_HEAD(g_active, gni_conn) active;	/* active conns waiting on connect */
	TAILQ_HEAD(g_active2, gni_conn) active2;	/* active conns waiting on reply */
	TAILQ_HEAD(g_passive, gni_conn) passive;	/* passive conns on request */
	TAILQ_HEAD(g_passive2, gni_conn) passive2;	/* passive conns waitin on ack */
	TAILQ_HEAD(g_hdls, gni_rma_handle) handles;	/* all rma registrations */
	TAILQ_HEAD(g_ops, gni_rma_op) rma_ops;	/* all rma ops */
} gni_ep_t;

typedef enum gni_conn_state {
	GNI_CONN_CLOSED = -2,
	GNI_CONN_CLOSING = -1,
	GNI_CONN_INIT = 0,
	GNI_CONN_ACTIVE,
	GNI_CONN_PASSIVE,
	GNI_CONN_PASSIVE2,
	GNI_CONN_ESTABLISHED,
} gni_conn_state_t;

typedef struct gni_conn_request {
	int sock;			/* socket for connection handshake */
	uint32_t nic_id;		/* peer's physical nic id */
	void *ptr;			/* application payload */
	uint32_t len;			/* payload length */
	gni_smsg_info_t info;		/* sender's smsg info */
} gni_conn_request_t;

typedef struct gni_conn {
	cci__conn_t *conn;		/* owning conn */
	gni_ep_handle_t peer;		/* peer ep handle */
	uint32_t id;			/* peer sets remote_event to this */
	gni_conn_state_t state;		/* current state */
	struct sockaddr_in sin;		/* peer address and port */
	uint32_t mss;			/* max send size */
	uint32_t max_tx_cnt;		/* max sends in flight */

	void *msg_buffer;		/* mbox buffer */
	uint32_t buff_size;		/* length */
	gni_mem_handle_t mem_hndl;	/* memory handle */

	TAILQ_HEAD(s_rems, gni_rma_remote) remotes;	/* LRU list of remote handles */
	TAILQ_HEAD(w_ops, gni_rma_op) rma_ops;	/* rma ops waiting on remotes */
	TAILQ_ENTRY(gni_conn) entry;	/* hangs on gep->conns */
	TAILQ_ENTRY(gni_conn) temp;	/* hangs on gep->active|passive */
	gni_conn_request_t *conn_req;	/* application conn req info */
} gni_conn_t;

int cci_core_gni_post_load(cci_plugin_t * me);
int cci_core_gni_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CORE_GNI_H */
