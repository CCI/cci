/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_CTP_E2E_H
#define CCI_CTP_E2E_H

#include "cci/private_config.h"

#include <assert.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "cci/cci_e2e_wire.h"
#include "cci-api.h"

BEGIN_C_DECLS

/* Valid URI include:
 *
 * e2e://as.subnet.base_uri      # where:
 *
 * as is the organization's AS id
 *
 * subnet is the subnet ID that the host is directly connected to
 *
 * base_uri is the underlying endpoint's URI less the prefix
 * (i.e. the URI after <transport>://)
 */

/* During cci_init(), the e2e transport will create a e2e virtual device
 * for each real device that has the following items in the config file:
 *
 * as = 1234			# The organization's AS ID in decimal or hex.
 *				# The device must have only one AS ID.
 *
 * subnet = 0x20		# The connected subnet's ID in decimal or hex.
 *				# The device must have only one subnet ID.
 *
 * router = <native URI>	# The native CCI URI for a router connected
 *				# this subnet. The device must list one or more
 *				# routers connected to this subnet.
 */

/* NOTE: see cci_e2e_wire.h for headers and msg types */

#define E2E_TX_CNT	(1024)
#define E2E_RX_CNT	(1024)
#define E2E_RMA_CNT	(E2E_TX_CNT)
#define E2E_RMA_MTU	(1024 * 1024)

typedef struct e2e_globals e2e_globals_t;	/* globals state */
typedef struct e2e_ep e2e_ep_t;			/* endpoint */
typedef struct e2e_conn e2e_conn_t;		/* connection */
typedef struct e2e_rma e2e_rma_t;		/* Pipelined RMA state */
typedef struct e2e_tx e2e_tx_t;			/* Send context */
typedef struct e2e_rx e2e_rx_t;			/* Receive context */
typedef struct e2e_rma_frag e2e_rma_frag_t;	/* RMA fragment context */
typedef union e2e_ctx e2e_ctx_t;		/* MSG/RMA context */

struct e2e_globals {
	int count;		/* Number of e2e devices */
	cci_device_t **devices;	/* Array of e2e devices */
};

/* struct e2e_dev no needed */

struct e2e_ep {
	cci_endpoint_t *real;	/* The underlying transport's real endpoint */
	TAILQ_HEAD(e_txs, cci__evt) idle_txs; /* Idle txs */
	TAILQ_HEAD(e_rxs, cci__evt) idle_rxs; /* Idle rxs */
	TAILQ_HEAD(e_rmas, cci__evt) idle_rma_frags; /* Idle rmas */
	TAILQ_HEAD(e_conns, e2e_conn) conns; /* List of open connections */
	TAILQ_HEAD(e_active, e2e_conn) active; /* List of conns waiting on CONNECT */
	TAILQ_HEAD(e_passive, e2e_conn) passive; /* List of conns waiting on ACCEPT */
	TAILQ_HEAD(e_closing, e2e_conn) closing; /* List of conns closing */
	const char * const *routers;	/* NULL-terminated array of router URIs */
	uint32_t as;		/* Our organization's AS ID */
	uint32_t subnet;	/* Subnet ID for this endpoint */
	e2e_tx_t *txs;		/* Array of txs */
	e2e_rx_t *rxs;		/* Array of rxs */
	e2e_rma_frag_t *rma_frags; /* Array of rma fragments */
	uint32_t tx_cnt;	/* Number of txs */
	uint32_t rx_cnt;	/* Number of rxs */
	uint32_t rma_frag_cnt;	/* Number of rma fragments */
};

typedef enum e2e_conn_state {
	E2E_CONN_INIT		= 0,
	E2E_CONN_ACTIVE1	= (1 << 0),	/* waiting on native CCI_EVENT_CONNECT */
	E2E_CONN_ACTIVE2	= (1 << 1),	/* waiting on e2e CCI_EVENT_CONNECT */
	E2E_CONN_PASSIVE1	= (1 << 2),	/* waiting on native CCI_EVENT_ACCEPT */
	E2E_CONN_PASSIVE2	= (1 << 3),	/* waiting on e2e CCI_EVENT_ACCEPT */
	E2E_CONN_CONNECTED	= (1 << 4),
	E2E_CONN_CLOSED		= (1 << 5),
	E2E_CONN_CLOSING	= (1 << 6)
} e2e_conn_state_t;

static inline char *
e2e_conn_state_str(e2e_conn_state_t state)
{
	switch (state) {
	case E2E_CONN_CONNECTED:
		return "E2E_CONN_CONNECTED";
	case E2E_CONN_CLOSED:
		return "E2E_CONN_CLOSED";
	case E2E_CONN_CLOSING:
		return "E2E_CONN_CLOSING";
	case E2E_CONN_INIT:
		return "E2E_CONN_INIT";
	case E2E_CONN_ACTIVE1:
		return "E2E_CONN_ACTIVE1";
	case E2E_CONN_ACTIVE2:
		return "E2E_CONN_ACTIVE2";
	case E2E_CONN_PASSIVE1:
		return "E2E_CONN_PASSIVE1";
	case E2E_CONN_PASSIVE2:
		return "E2E_CONN_PASSIVE2";
	}
	/* silence picky compiler */
	return NULL;
}

struct e2e_conn {
	cci__conn_t *conn;		/* Owning conn */
	e2e_conn_state_t state;		/* State */
	cci_connection_t *real;		/* Underlying transport's real connection */
	TAILQ_ENTRY(e2e_conn) entry;	/* To hang on eep->conns */
	TAILQ_HEAD(c_txs, cci__evt) pending; /* pending reliable sends */
	uint32_t rma_mtu;		/* RMA fragment for this connection */
	uint16_t seq;
};

typedef enum e2e_ctx_type {
	E2E_CTX_INVALID = 0,
	E2E_CTX_RX,
	E2E_CTX_TX,
	E2E_CTX_RMA
} e2e_ctx_type_t;

static inline char *
e2e_ctx_type_str(e2e_ctx_type_t type) {
	switch (type) {
	case E2E_CTX_INVALID:
		return "E2E_CTX_INVALID";
	case E2E_CTX_RX:
		return "E2E_CTX_RX";
	case E2E_CTX_TX:
		return "E2E_CTX_TX";
	case E2E_CTX_RMA:
		return "E2E_CTX_RMA";
	}
	/* silence picky compiler */
	return NULL;
}

struct e2e_rx {
	e2e_ctx_type_t type;	/* E2E_CTX_RX */
	cci__evt_t evt;		/* Associated event (including public event) */
	cci_e2e_msg_type_t msg_type; /* E2E msg type */
	uint16_t seq;		/* Sequence number for ack */
	cci_event_t *native;	/* Stored native recv event */
};

typedef enum e2e_tx_state {
	E2E_TX_IDLE = 0,	/* available, held by endpoint */
	E2E_TX_QUEUED,		/* queued for sending */
	E2E_TX_PENDING,		/* sent, waiting e2e ack */
	E2E_TX_COMPLETED	/* completed with status set */
} e2e_tx_state_t;

struct e2e_tx {
	e2e_ctx_type_t type;	/* E2E_CTX_TX */
	cci__evt_t evt;		/* Associated event (including public event) */
	cci_e2e_msg_type_t msg_type; /* E2E msg type */
	e2e_tx_state_t state;	/* Send state */
	int flags;		/* Send flags */
	uint16_t seq;		/* Sequence number for ack */
	e2e_rma_t *rma;		/* Owning RMA if completion msg */
};

struct e2e_rma_frag {
	e2e_ctx_type_t type;	/* E2E_CTX_RMA */
	cci__evt_t evt;		/* Associated event (including public event) */
	uint64_t loffset;	/* Local offset of this fragment */
	uint64_t roffset;	/* Remote offset of this fragment  */
	uint64_t len;		/* Length of this fragment */
	e2e_rma_t *rma;		/* Owning RMA operation */
	uint32_t id;		/* Fragment ID */
};

union e2e_ctx {
	e2e_ctx_type_t type;		/* ctx type - must be first in each struct */
	e2e_rx_t rx;
	e2e_tx_t tx;
	e2e_rma_frag_t rma_frag;
};

struct e2e_rma {
	cci__evt_t evt;			/* Associated event (including public event) */
	cci_rma_handle_t *lh;		/* Local RMA handle pointer */
	uint64_t loffset;		/* Local offset for RMA */
	cci_rma_handle_t *rh;		/* Remote RMA handle pointer */
	uint64_t roffset;		/* Remote offset for RMA */
	uint64_t length;		/* Length of RMA */
	void *context;			/* User's context */
	void *msg_ptr;			/* Completion MSG pointer */
	uint32_t msg_len;		/* Completion MSG length */
	int flags;			/* User's RMA flags */
	uint32_t num_frags;		/* Number of frags needed */
	uint32_t next;			/* Next fragment ID */
	int32_t acked;			/* Last fragment acked (starts at -1) */
	uint32_t pending;		/* Number of fragments in-flight */
};

extern e2e_globals_t *eglobals;

int cci_ctp_e2e_post_load(cci_plugin_t * me);
int cci_ctp_e2e_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_E2E_H */
