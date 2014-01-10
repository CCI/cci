/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2011-2012 UT-Battelle, LLC.
 * $COPYRIGHT$
 */

#ifndef CCI_CTP_GNI_H
#define CCI_CTP_GNI_H

#include "cci/private_config.h"
#include "cci.h"

#include <netinet/in.h>	/* struck sockaddr_in */
#include <assert.h>
#include <gni_pub.h>

BEGIN_C_DECLS
/* Valid URI include:
 *
 * gni://hostname:port	# Hostname or IPv4 address and port
 */
/* A gni device needs the following items in the config file:

   transport = gni		# must be lowercase

   A gni device may have these items:

   ip = 1.2.3.4			# IPv4 address of device

   interface = ipogif0		# Ethernet interface name

   port = 12345			# base listening port
				  the default is a random, ephemeral port

   ptag = 208			# CCI system-wide PTAG

   cookie = 0x73e70000		# CCI system-wide cookie

 */
#define GNI_URI			"gni://"

#ifndef GNI_PTAG
#define GNI_DEFAULT_PTAG	(208)
#else
#define GNI_DEFAULT_PTAG	GNI_PTAG
#endif
#ifndef GNI_COOKIE
#define GNI_DEFAULT_COOKIE	(0x73e70000)
#else
#define GNI_DEFAULT_COOKIE	GNI_COOKIE
#endif

/* Wire Header Specification */
    typedef enum gni_msg_type {
	GNI_MSG_INVALID = 0,
	GNI_MSG_CONN_REQUEST,		/* client -> server */
	GNI_MSG_CONN_PAYLOAD,
	GNI_MSG_CONN_REPLY,		/* client <- server */
	GNI_MSG_CONN_ACK,		/* client -> server */
	GNI_MSG_DISCONNECT,
	GNI_MSG_SEND,
	GNI_MSG_KEEPALIVE,
	GNI_MSG_RMA,
	GNI_MSG_TYPE_MAX
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

typedef struct gni_conn_request {
	uint32_t type;
	uint32_t addr;
	uint32_t port;
	uint32_t id;
	gni_smsg_attr_t attr;
} gni_conn_request_t;

/* Conn Request (sent over the socket)

    <----------- 32 bits ----------->
    <--- 12b --> <--- 12b -->  4b   4b
   +------------+------------+----+----+
   |      D     |      C     |  B |  A |
   +------------+------------+----+----+
   |               addr                |
   +-----------------------------------+
   |               port                |
   +-----------------------------------+
   |                id                 |
   +-----------------------------------+
   |                                   |
   |             smsg attr             |
   |                                   |
   |                                   |
   +-----------------------------------+
   |             payload               |

   where:
      A is GNI_MSG_CONN_REQUEST
      B is the connection attribute (UU, RU, RO)
      C is the payload length
      D is reserved
      addr is the sender's physical Gemini address
      port is the sender's instance id
      id is the sender's gconn->id
      smsg attr is the sender's gni_smsg_attr_t
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

/* Keepalive

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is GNI_MSG_KEEPALIVE and B is unused.
 */

/* Set some transport defaults */
#define GNI_EP_MSS		(128)		/* default MSS */
#define GNI_EP_MSS_MAX		((1 << 12) -1)	/* largest MSS allowed */
#define GNI_EP_RX_CNT		(32 * 1024)	/* default recv buffer count */
#define GNI_EP_TX_CNT		(16 * 1024)	/* default send buffer count */
#define GNI_PROG_TIME_US	(100000)	/* try to progress every N microseconds */
#define GNI_CONN_CREDIT		(8)		/* mbox max msgs */

/* Data structures */

typedef struct gni_tx {
	cci__evt_t evt;			/* associated event (connection) */
	gni_msg_type_t msg_type;	/* message type */
	int flags;			/* (CCI_FLAG_[BLOCKING|SILENT|NO_COPY]) */
	uint32_t header;
	void *buffer;			/* registered send buffer */
	uint16_t len;			/* length of buffer */
	uint32_t id;			/* use for SMSG msg_id */
	TAILQ_ENTRY(gni_tx) entry;	/* hang on gep->idle_txs, gdev->queued,
					   gdev->pending */
	TAILQ_ENTRY(gni_tx) gentry;	/* hangs on gep->txs */
	struct gni_rma_op *rma_op;	/* owning RMA if remote completion msg */
} gni_tx_t;

typedef struct gni_rx {
	cci__evt_t evt;			/* associated event */
	void *ptr;			/* start of buffer */
	uint32_t offset;		/* offset in gep->buffer */
	TAILQ_ENTRY(gni_rx) entry;	/* hangs on rx_pool->rxs */
	TAILQ_ENTRY(gni_rx) idle;	/* hangs on rx_pool->idle_rxs */
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
	uint64_t addr;
	gni_mem_handle_t mh;		/* memory handle */
	cci__ep_t *ep;			/* owning endpoint */
	TAILQ_ENTRY(gni_rma_handle) entry;	/* hang on gep->handles */

	/* CCI RMA handle
	   rma_handle->stuff[0] holds the base address
	   rma_handle->stuff[1-2] holds the GNI memory handle
	 */
	cci_rma_handle_t rma_handle;	/* CCI RMA handle */

	uint32_t refcnt;		/* reference count */
	TAILQ_HEAD(s_rma_ops, gni_rma_op) rma_ops;	/* list of all rma_ops */
} gni_rma_handle_t;

typedef enum gni_rma_queue {
	GNI_RMA_QUEUE_NONE,
	GNI_RMA_QUEUE_EP,		/* gep->rma_ops */
	GNI_RMA_QUEUE_CONN,		/* gconn->rma_ops */
	GNI_RMA_QUEUE_CONN_FENCED	/* gconn->fenced */
} gni_rma_queue_t;

typedef struct gni_rma_op {
	cci__evt_t evt;			/* completion event */
	gni_post_descriptor_t pd;	/* GNI post descriptor */
	gni_msg_type_t msg_type;	/* to be compatible with tx */
	TAILQ_ENTRY(gni_rma_op) entry;	/* gep->rmas */
	TAILQ_ENTRY(gni_rma_op) gentry;	/* handle->rma_ops */
	cci_rma_handle_t *local_handle;
	uint64_t local_offset;
	cci_rma_handle_t *remote_handle;
	uint64_t remote_offset;
	uint64_t data_len;

	void *buf;			/* bounce buffer for unaligned GETs */

	cci_status_t status;
	void *context;
	int flags;
	gni_tx_t *tx;
	uint32_t msg_len;
	char *msg_ptr;
	gni_rma_queue_t queue;		/* hanging on which queue */
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
	TAILQ_HEAD(g_irxs, gni_rx) idle_rxs;	/* available rxs */
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
	gni_tx_t *txs;			/* array of txs */
	TAILQ_HEAD(g_txsi, gni_tx) idle_txs;	/* idle txs */
	uint32_t rma_op_cnt;		/* number of active RMAs */

	TAILQ_HEAD(g_rx_pools, gni_rx_pool) rx_pools;	/* list of rx pools - usually one */

	void *conn_tree;		/* tree of peer conn ids */
	pthread_rwlock_t conn_tree_lock;	/* rw lock */

	int fd;				/* for event fd when blocking */
	uint32_t fd_used;		/* if fd has data (non-zero) */
	pthread_t tid;			/* progress thread id */
	int ready;			/* let app thread know that progress thread
					   is ready */
	uint32_t port;			/* cache for progress thread */

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
	GNI_CONN_ESTABLISHED
} gni_conn_state_t;

typedef struct gni_new_conn {
	int sock;			/* socket for connection handshake */
	void *ptr;			/* application payload */
	uint32_t len;			/* payload length */
	gni_conn_request_t cr;		/* conn request */
} gni_new_conn_t;

typedef struct gni_conn {
	cci__conn_t *conn;		/* owning conn */
	gni_ep_handle_t peer;		/* peer ep handle */
	uint32_t id;			/* peer sets remote_event to this */
	gni_conn_state_t state;		/* current state */
	struct sockaddr_in sin;		/* peer address and port */
	uint32_t mss;			/* max send size */
	uint32_t max_tx_cnt;		/* max sends in flight */
	TAILQ_HEAD(c_txs, gni_tx) pending;

	void *msg_buffer;		/* mbox buffer */
	uint32_t buff_size;		/* length */
	gni_mem_handle_t mem_hndl;	/* memory handle */

	uint32_t rma_op_cnt;		/* track posted RMAs in case we need to fence */

	TAILQ_HEAD(w_ops, gni_rma_op) rma_ops;	/* rma ops waiting on remotes */
	TAILQ_HEAD(v_ops, gni_rma_op) fenced;	/* fenced rma ops */
	TAILQ_ENTRY(gni_conn) entry;	/* hangs on gep->conns */
	TAILQ_ENTRY(gni_conn) temp;	/* hangs on gep->active|passive */
	gni_new_conn_t *new;		/* application conn req info */
} gni_conn_t;

int cci_ctp_gni_post_load(cci_plugin_t * me);
int cci_ctp_gni_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_GNI_H */
