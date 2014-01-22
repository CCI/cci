/*
 * Copyright (c) 2013 UT-Battelle, LLC. All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CTP_SM_H
#define CCI_CTP_SM_H

#include "cci/private_config.h"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/poll.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"

BEGIN_C_DECLS
#define SM_BLOCK_SIZE		(64)		/* uint64_t sized ep id blocks */
#define SM_NUM_BLOCKS		(1)		/* start with one block for 64 ep ids */

#define SM_EP_RX_CNT		(1024)		/* number of rx messages */
#define SM_EP_TX_CNT		(1024)		/* number of tx messages */

#define SM_DEFAULT_MTU		(1024)
#define SM_MIN_MTU		(128)		/* cache line size */
#define SM_MAX_MTU		(4096)		/* page size */

#define SM_HDR_LEN		(4)		/* common header size */

#define SM_MSS(mtu)		((mtu) - SM_HDR_LEN)
						/* max send size */

#define SM_RMA_DEPTH		(16)		/* how many in-flight msgs per RMA */
#define SM_RMA_FRAG_SIZE	(16*1024)	/* optimal for POSIX shmem */
#define SM_RMA_FRAG_MAX		(128*1024)	/* optimal for knem and CMA */

#define SM_EP_MAX_CONNS		(1024)		/* Number of cores? */

#define SM_DEFAULT_PATH		"/tmp/cci/sm"

/* Valid URI include:
 *
 * sm://path/pid/id	# Directory path, process id and endpoint id
 *
 *                        The path may be relative from the process' working
 *                        directory or absolute. The process must have read,
 *                        write, and execute permissions for the directory to
 *                        create an endpoint and read and execute to connect
 *                        to an endpoint.
 *
 *                        On init(), a device will create a subdirectory with
 *                        their pid.
 *
 *                        When creating a new endpoint, the device will create
 *                        a file with the new endpoint's id.
 */

/* A sm device needs the following items in the config file:
 *
 * transport = sm	# must be lowercase
 *
 * A sm device may have these items:
 *
 * mtu = 128		# MTU less headers will become max_send_size.
 *                        The default it 1 KB.
 *
 * id = 32		# Base ep_id for this process. The default is 0.
 *
 * path = /tmp/cci	# Path to the base directory holding the UNIX Domain
			  Socket names. The endpoint URI will be stored as
			  pid/ep_id where pid is the process id and the ep_id
			  is the endpoint's id.

			  If the path does not exist, the SM transport will
			  try to create it. If not succesful, the transport
			  will not load.

			  For example, sm:///tmp/cci/sm/1234/1 would be bound to:

			  /tmp/cci/sm/1234/1

			  The default path is /tmp/cci/sm.
 */

typedef enum sm_msg_type {
	SM_MSG_INVALID	= 0,
	SM_MSG_CONNECT,
	SM_MSG_CONN_REPLY,
	SM_MSG_CONN_ACK,	/* do we need this? */
	SM_MSG_SEND,
	SM_MSG_ACK,
	SM_MSG_RNR,
	SM_MSG_KEEPALIVE,
	SM_MSG_RMA_WRITE,
	SM_MSG_RMA_READ_REQUEST,
	SM_MSG_RMA_READ_REPLY,
	SM_MSG_MAX
} sm_msg_type_t;

typedef union sm_hdr {
	/* Generic header used by all messages */
	struct sm_hdr_generic {
		unsigned int type	: 4;	/* header type */
		unsigned int pad	: 28;	/* fill to 32 bits */
		/* 32b */
	} generic;

	/* Generic connect request (without data ptr) */
	struct sm_hdr_connect_generic {
		unsigned int type	: 4;	/* SM_MSG_CONNECT */
		unsigned int pad	: 4;	/* reserved */
		unsigned int version	: 8;	/* version */
		unsigned int len	: 16;	/* payload length */
		/* 32b */
	} _connect;

	/* Connect request */
	struct sm_hdr_connect {
		unsigned int type	: 4;	/* SM_MSG_CONNECT */
		unsigned int pad	: 4;	/* reserved */
		unsigned int version	: 8;	/* version */
		unsigned int len	: 16;	/* payload length */
		/* 32b */
		char data[1];
	} connect;

	/* Connect reply */
	struct sm_hdr_reply {
		unsigned int type	: 4;	/* SM_MSG_CONN_REPLY */
		unsigned int accept	: 8;	/* ACCEPT=0 or errno */
		unsigned int pad26	: 20;	/* reserved */
		/* 32b */
	} reply;

	/* Generic send (without data ptr) */
	struct sm_hdr_send_generic {
		unsigned int type	: 4;	/* SM_MSG_SEND */
		unsigned int len	: 14;	/* payload length */
		unsigned int id		: 14;	/* tx id */
		/* 32b */
	} _send;

	/* Send */
	struct sm_hdr_send {
		unsigned int type	: 4;	/* SM_MSG_SEND */
		unsigned int id		: 14;	/* tx id */
		unsigned int len	: 14;	/* payload length */
		/* 32b */
		char data[1];
	} send;

	/* Ack */
	struct sm_hdr_ack {
		unsigned int type	: 4;	/* SM_MSG_ACK */
		unsigned int id		: 14;	/* tx id */
		unsigned int pad	: 14;	/* reserved */
		/* 32b */
	} ack;

	/* RNR */
	struct sm_hdr_rnr {
		unsigned int type	: 4;	/* SM_MSG_RNR */
		unsigned int id		: 14;	/* tx id */
		unsigned int pad	: 14;	/* reserved */
		/* 32b */
	} rnr;

	/* Keepalive */
	struct sm_hdr_keepalive {
		unsigned int type	: 4;	/* SM_MSG_KEEPALIVE */
		unsigned int id		: 14;	/* tx id */
		unsigned int pad	: 14;	/* reserved */
		/* 32b */
	} keepalive;

	/* Generic RMA write (without data ptr) */
	struct _sm_hdr_rma_write {
		unsigned int type	: 4;	/* SM_MSG_RMA_WRITE */
		unsigned int slot	: 8;	/* RMA mmap slot */
		unsigned int msg_len	: 14;	/* Completion msg payload length */
		unsigned int pad	: 6;	/* reserved */
		/* 32b */
		uint32_t handle;		/* ID of target's RMA handle */
		/* 64b */
		uint32_t offset_hi;		/* Offset into target's RMA handle */
		/* 96b */
		uint32_t offset_lo;		/* Upper 32 and lower 32 bits */
		/* 128b */
	} _write;

	/* RMA write */
	struct sm_hdr_rma_write {
		unsigned int type	: 4;	/* SM_MSG_RMA_WRITE */
		unsigned int slot	: 8;	/* RMA mmap slot */
		unsigned int msg_len	: 14;	/* Completion msg payload length */
		unsigned int pad	: 6;	/* reserved */
		/* 32b */
		uint32_t len;			/* RMA payload len */
		/* 32b */
		uint32_t handle;		/* ID of target's RMA handle */
		/* 64b */
		uint32_t offset_hi;		/* Offset into target's RMA handle */
		/* 96b */
		uint32_t offset_lo;		/* Upper 32 and lower 32 bits */
		/* 128b */
		char data[1];			/* For completion msg, if needed */
	} write;
} sm_hdr_t;

static inline char *
sm_msg_str(sm_msg_type_t type)
{
	switch (type) {
	case SM_MSG_INVALID:
		return "SM_MSG_INVALID";
	case SM_MSG_CONNECT:
		return "SM_MSG_CONNECT";
	case SM_MSG_CONN_REPLY:
		return "SM_MSG_CONN_REPLY";
	case SM_MSG_CONN_ACK:
		return "SM_MSG_CONN_ACK";
	case SM_MSG_SEND:
		return "SM_MSG_SEND";
	case SM_MSG_ACK:
		return "SM_MSG_ACK";
	case SM_MSG_RNR:
		return "SM_MSG_RNR";
	case SM_MSG_KEEPALIVE:
		return "SM_MSG_KEEPALIVE";
	case SM_MSG_RMA_WRITE:
		return "SM_MSG_RMA_WRITE";
	case SM_MSG_RMA_READ_REQUEST:
		return "SM_MSG_RMA_READ_REQUEST";
	case SM_MSG_RMA_READ_REPLY:
		return "SM_MSG_RMA_READ_REPLY";
	case SM_MSG_MAX:
		return "SM_MSG_MAX";
	}
	/* never reached */
	return NULL;
}

typedef enum sm_ctx {
	SM_TX,
	SM_RX
} sm_ctx_t;

typedef enum sm_tx_state {
	SM_TX_INIT = 0,				/* available, held by endpoint */
	SM_TX_QUEUED,				/* queued on conn for sending */
	SM_TX_PENDING,				/* sent, waiting ack */
	SM_TX_COMPLETED				/* completed, queued on ep->evts */
} sm_tx_state_t;

static inline char *
sm_tx_state_str(sm_tx_state_t state)
{
	switch (state) {
	case SM_TX_INIT:
		return "SM_TX_INIT";
	case SM_TX_QUEUED:
		return "SM_TX_QUEUED";
	case SM_TX_PENDING:
		return "SM_TX_PENDING";
	case SM_TX_COMPLETED:
		return "SM_TX_COMPLETED";
	}
	/* never reached */
	return NULL;
}

typedef struct sm_tx {
	sm_ctx_t		ctx;		/* SM_TX */
	cci__evt_t		evt;		/* CCI event - private and public) */
	sm_tx_state_t		state;
	sm_msg_type_t		type;
	uint32_t		id;		/* TX id */
	int			flags;		/* CCI_FLAG_* */
	void			*buf;		/* Pointer into sep->tx_buf */
	uint32_t		len;		/* Msg len */
	struct sm_rma_op	*rma_op;	/* Owning RMA if completion msg */
	uint32_t		rma_id;		/* RMA fragment ID */
} sm_tx_t;

typedef struct sm_rx {
	sm_ctx_t		ctx;		/* SM_TX */
	cci__evt_t		evt;		/* CCI event - private and public) */
	void			*buf;		/* Pointer into sep->rx_buf */
} sm_rx_t;

typedef struct sm_ep {
	cci_os_handle_t		sock;		/* For listen socket */
	uint32_t		is_polling;	/* Serialize accept to sockets
						   and polling strctures */
	uint32_t		id;		/* Endpoint id */
	nfds_t			nfds;		/* Numbder of pollfds */
	struct pollfd		*fds;		/* For UNIX sockets */
	cci__conn_t		**c;		/* Array of conns indexed by fds */

	void			*tx_buf;	/* TX common buffer */
	sm_tx_t			*txs;		/* All txs */
	TAILQ_HEAD(itx, sm_tx)	idle_txs;	/* List of idle txs */
	void			*rx_buf;	/* RX common buffer */
	sm_rx_t			*rxs;		/* All rxs */
	TAILQ_HEAD(irx, sm_rx)	idle_rxs;	/* List of idle rxs */

	TAILQ_HEAD(cns, sm_conn) conns;		/* Connected conns */
	TAILQ_HEAD(act, sm_conn) active;	/* Active conns */
	TAILQ_HEAD(psv, sm_conn) passive;	/* Passive conns */
	TAILQ_HEAD(cls, sm_conn) closing;	/* Closing conns */
} sm_ep_t;

typedef enum sm_conn_state {
	SM_CONN_CLOSED = -2,
	SM_CONN_CLOSING = -1,
	SM_CONN_INIT = 0,
	SM_CONN_ACTIVE1,
	SM_CONN_ACTIVE2,
	SM_CONN_PASSIVE1,
	SM_CONN_PASSIVE2,
	SM_CONN_READY
} sm_conn_state_t;

static inline char *
sm_conn_state_str(sm_conn_state_t state)
{
	switch (state) {
	case SM_CONN_READY:
		return "SM_CONN_READY";
	case SM_CONN_INIT:
		return "SM_CONN_INIT";
	case SM_CONN_ACTIVE1:
		return "SM_CONN_ACTIVE1";
	case SM_CONN_ACTIVE2:
		return "SM_CONN_ACTIVE2";
	case SM_CONN_PASSIVE1:
		return "SM_CONN_PASSIVE1";
	case SM_CONN_PASSIVE2:
		return "SM_CONN_PASSIVE2";
	case SM_CONN_CLOSING:
		return "SM_CONN_CLOSING";
	case SM_CONN_CLOSED:
		return "SM_CONN_CLOSED";
	}
	/* never reached */
	return NULL;
}

typedef struct sm_conn {
	cci__conn_t		*conn;		/* Owning conn */
	sm_conn_state_t		state;		/* State */
	cci_os_handle_t		fd;		/* Socket for this conn */
	pthread_mutex_t		lock;		/* Sending lock */
	uint32_t		index;		/* Index in sep->fds */
	TAILQ_ENTRY(sm_conn)	entry;		/* Entry in sep->conns|active|passive */
	TAILQ_HEAD(qd, sm_tx)	queued;		/* Queued sends */
	TAILQ_HEAD(pd, sm_tx)	pending;	/* Pending (in-flight) sends */
	struct sockaddr_un	sun;		/* UNIX name */
} sm_conn_t;

typedef struct sm_dev {
	char			*path;		/* Path to URI base */
	uint64_t		*ids;		/* Bit mask of ids starting at sdev->id */
	uint32_t		id;		/* Starting endpoint id */
	uint32_t		num_blocks;	/* Number of ids blocks */
} sm_dev_t;

typedef struct sm_globals {
	int			count;		/* Number of sm devices = 1 */
	cci_device_t		**devices;	/* Array of sm devices */
} sm_globals_t;

extern sm_globals_t		*sglobals;

int cci_ctp_sm_post_load(cci_plugin_t * me);
int cci_ctp_sm_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_SM_H */
