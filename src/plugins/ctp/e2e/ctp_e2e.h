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

typedef struct e2e_globals e2e_globals_t;	/* globals state */
typedef struct e2e_ep e2e_ep_t;			/* endpoint */
typedef struct e2e_conn e2e_conn_t;		/* connection */
typedef struct e2e_rma e2e_rma_t;		/* Pipelined RMA state */
typedef union e2e_ctx e2e_ctx_t;		/* MSG/RMA context */

struct e2e_globals {
	int count;		/* Number of e2e devices */
	cci_device_t **devices;	/* Array of e2e devices */
};

/* struct e2e_dev no needed */

struct e2e_ep {
	cci_endpoint_t *real;	/* The underlying transport's real endpoint */
	TAILQ_HEAD(e_conns, e2e_conn) conns; /* List of open connections */
	TAILQ_HEAD(e_active, e2e_conn) active; /* List of conns waiting on CONNECT */
	TAILQ_HEAD(e_passive, e2e_conn) passive; /* List of conns waiting on ACCEPT */
	TAILQ_HEAD(e_closing, e2e_conn) closing; /* List of conns closing */
};

typedef enum e2e_conn_state {
	E2E_CONN_CLOSED = -2,
	E2E_CONN_CLOSING = -1,
	E2E_CONN_INIT = 0,
	E2E_CONN_ACTIVE,	/* waiting on CCI_EVENT_CONNECT */
	E2E_CONN_PASSIVE,	/* waiting on CCI_EVENT_ACCEPT */
	E2E_CONN_CONNECTED
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
	case E2E_CONN_ACTIVE:
		return "E2E_CONN_ACTIVE";
	case E2E_CONN_PASSIVE:
		return "E2E_CONN_PASSIVE";
	}
	/* silence picky compiler */
	return NULL;
}

struct e2e_conn {
	cci__conn_t *conn;		/* Owning conn */
	e2e_conn_state_t state;		/* State */
	cci_connection_t *real;		/* Underlying transport's real connection */
	TAILQ_ENTRY(e2e_conn) entry;	/* To hang on eep->conns */
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

union e2e_ctx {
	e2e_ctx_type_t type;		/* ctx type - must be first in each struct */

	struct e2e_rx {
		e2e_ctx_type_t type;	/* E2E_CTX_RX */
		cci__evt_t evt;		/* Associated event (including public event) */
		cci_e2e_msg_type_t msg_type; /* E2E msg type */
		uint16_t seq;		/* Sequence number for ack */
	} rx;

	struct e2e_tx {
		e2e_ctx_type_t type;	/* E2E_CTX_TX */
		cci__evt_t evt;		/* Associated event (including public event) */
		cci_e2e_msg_type_t msg_type; /* E2E msg type */
		uint16_t seq;		/* Sequence number for ack */
		e2e_rma_t *rma;		/* Owning RMA if completion msg */
	} tx;

	struct e2e_rma_frag {
		e2e_ctx_type_t type;	/* E2E_CTX_RMA */
		cci__evt_t evt;		/* Associated event (including public event) */
		uint64_t loffset;	/* Local offset of this fragment */
		uint64_t roffset;	/* Remote offset of this fragment  */
		uint64_t len;		/* Length of this fragment */
		e2e_rma_t *rma;		/* Owning RMA operation */
		uint32_t id;		/* Fragment ID */
	} rma;
};

struct e2e_rma {
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

int cci_ctp_e2e_post_load(cci_plugin_t * me);
int cci_ctp_e2e_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_E2E_H */
