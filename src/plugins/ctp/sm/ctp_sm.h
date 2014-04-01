/*
 * Copyright (c) 2013 UT-Battelle, LLC. All rights Reserved.
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

/* Define minimal cache line sizes.
 * The cache line must be larger than the size of sm_tx_t.
 */
#define SM_SHIFT		(7)		/* 7 = 128B, 8 = 256B */
#define SM_LINE			(1 << SM_SHIFT)	/* Cache line size */
#define SM_MASK			(SM_LINE - 1)	/* Mask bits for line size */

#define SM_DEFAULT_MSS		(SM_LINE)	/* Default max send size */
#define SM_MIN_MSS		(64)		/* Minimum cache line size */
#define SM_MAX_MSS		(4096)		/* page size */

#define SM_HDR_LEN		(8)		/* MSG and RMA header size */

#define SM_RMA_DEPTH		(4)		/* how many in-flight msgs per RMA */
#define SM_RMA_FRAG_SIZE	(8*1024)	/* optimal for POSIX shmem */
#define SM_RMA_FRAG_MAX		(64*1024)	/* optimal for knem and CMA */

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
 * mss = 128		# Set max_send_size.
 *                        The default is 128 bytes. The min is 64 and max is 4096.
 *
 * id = 32		# Base ep_id for this process. The default is 0.
 *
 * path = /tmp/cci	# Path to the base directory holding the UNIX Domain
			  Socket names. The endpoint URI will be stored as
			  pid/ep_id where pid is the process id and the ep_id
			  is the endpoint's id.

			  If the path does not exist, the SM transport will
			  try to create it. If not successful, the transport
			  will not load.

			  For example, sm:///tmp/cci/sm/1234/1 would be bound to:

			  /tmp/cci/sm/1234/1

			  The default path is /tmp/cci/sm.
 */

typedef enum sm_conn_msg_type {
	SM_CMSG_CONNECT,
	SM_CMSG_CONN_REPLY,
	SM_CMSG_CONN_ACK
} sm_conn_msg_type_t;

/* The connection messages are sent via the UDS only */
/* This is a 8-byte structure aligned on 4 bytes */
typedef union sm_conn_hdr {
	/* Generic header used by all messages */
	struct sm_conn_hdr_generic {
		uint32_t type		:  2;	/* header type */
		uint32_t pad1		: 30;	/* fill to 32 bits */
		/* 32b */
		uint32_t pad2		: 32;	/* fill to 64 bits */
		/* 64b */
	} generic;

	/* Connect request */
	struct sm_conn_hdr_connect {
		uint32_t type		:  2;	/* SM_CMSG_CONNECT */
		uint32_t version	:  8;	/* version */
		uint32_t len		: 12;	/* payload length */
		uint32_t pad1		: 10;	/* Reserved */
		/* 32b */
		uint32_t server_id	: 16;	/* Client-assigned ID for server */
		uint32_t pad		: 16;	/* Reserved */
		/* 64b */
	} connect;

	/* Connect reply */
	struct sm_conn_hdr_connect_reply {
		uint32_t type		:  2;	/* SM_CMSG_CONN_REPLY */
		uint32_t accept		:  8;	/* ACCEPT=0 or errno */
		uint32_t pad1		: 22;	/* Reserved */
		/* 32b */
		uint32_t server_id	: 16;	/* Client-assigned ID for server */
		uint32_t client_id	: 16;	/* Server-assigned ID for client */
		/* 64b */
	} reply;

	/* Connect ack */
	struct sm_conn_hdr_connect_ack {
		uint32_t type		:  2;	/* SM_CMSG_CONN_REPLY */
		uint32_t pad		: 30;	/* Reserved */
		/* 32b */
		uint32_t server_id	: 16;	/* Client-assigned ID for server */
		uint32_t client_id	: 16;	/* Server-assigned ID for client */
		/* 64b */
	} ack;
} sm_conn_hdr_t;

typedef enum sm_msg_type {
	SM_MSG_INVALID	= 0,
	SM_MSG_SEND,
	SM_MSG_SEND_ACK,
	SM_MSG_KEEPALIVE,
	SM_MSG_KEEPALIVE_ACK,
	SM_MSG_RMA_WRITE,
	SM_MSG_RMA_READ,
	SM_MSG_RMA_ACK,
	SM_MSG_MAX
} sm_msg_type_t;

/* The message headers are sent via the FIFO only and act as a doorbell */
/* This is a 8-byte aligned structure */
typedef union sm_hdr {
	/* Generic header used by all messages */
	struct sm_hdr_generic {
		uint32_t type		:  4;	/* header type */
		uint32_t id		: 16;	/* Connection ID */
		uint32_t pad1		: 12;	/* fill to 32 bits */
		/* 32b */
		uint32_t pad2;			/* fill to 64 bits */
		/* 64b */
	} generic;

	/* Send (header only, payload in sender's MMAP MSG buffer) */
	struct sm_hdr_send {
		uint32_t type		:  4;	/* SM_MSG_SEND[_ACK] */
		uint32_t id		: 16;	/* Connection ID */
		uint32_t offset		: 12;	/* MMAP cacheline index */
		/* 32b */
		uint32_t seq		: 14;	/* Sequence or msg ID */
		uint32_t len		: 12;	/* payload length */
		uint32_t pad		: 6;	/* Reserved */
		/* 64b */
	} send;

	/* Keepalive */
	struct sm_hdr_keepalive {
		uint32_t type		:  4;	/* SM_MSG_KEEPALIVE[_ACK] */
		uint32_t id		: 16;	/* Connection ID */
		uint32_t pad1		: 12;	/* Reserved */
		/* 32b */
		uint32_t seq		: 14;	/* Sequence or msg ID */
		uint32_t pad2		: 18;	/* Reserved */
		/* 64b */
	} keepalive;

	/* RMA request (used by MMAP RMA only) */
	struct sm_hdr_rma {
		uint32_t type		:  4;	/* SM_MSG_RMA_[WRITE|_READ] */
		uint32_t id		: 16;	/* Connection ID */
		uint32_t offset		: 12;	/* MMAP cacheline offset */
		/* 32b */
		uint32_t len		: 16;	/* Length of payload */
		uint32_t pad		: 16;	/* Reserved */
		/* 64b */
	} rma;

	/* RMA ack (used by MMAP RMA only) */
	struct sm_hdr_rma_ack {
		uint32_t type		:  4;	/* SM_MSG_RMA_ACK */
		uint32_t id		: 16;	/* Connection ID */
		uint32_t offset		: 12;	/* MMAP cacheline offset */
		/* 32b */
		uint32_t len		: 16;	/* Length of payload */
		uint32_t status		:  8;	/* Status (0 for success, else errno) */
		uint32_t pad		:  8;	/* Reserved */
		/* 64b */
	} rma_ack;

	/* Force alignment for all members */
	uint64_t align;
} sm_hdr_t;

/* This is an 8-byte aligned structure */
typedef struct sm_rma_hdr {
	uint64_t local_handle;			/* Initiator's sm_rma_handle_t * */
	/*  8 B */
	uint64_t local_offset;			/* Initiator's offset */
	/* 16 B */
	uint64_t remote_handle;			/* Target's sm_rma_handle_t * */
	/* 24 B */
	uint64_t remote_offset;			/* Target's offset */
	/* 32 B */
	uint64_t len;				/* Total RMA length */
	/* 40 B */
	uint64_t rma;				/* Initiator's sm_rma_t * */
	/* 48 B */
} sm_rma_hdr_t;

static inline char *
sm_conn_msg_str(sm_conn_msg_type_t type)
{
	switch (type) {
	case SM_CMSG_CONNECT:
		return "SM_CMSG_CONNECT";
	case SM_CMSG_CONN_REPLY:
		return "SM_CMSG_CONN_REPLY";
	case SM_CMSG_CONN_ACK:
		return "SM_CMSG_CONN_ACK";
	}
	/* never reached */
	return NULL;
}

static inline char *
sm_msg_str(sm_msg_type_t type)
{
	switch (type) {
	case SM_MSG_INVALID:
		return "SM_MSG_INVALID";
	case SM_MSG_SEND:
		return "SM_MSG_SEND";
	case SM_MSG_SEND_ACK:
		return "SM_MSG_SEND_ACK";
	case SM_MSG_KEEPALIVE:
		return "SM_MSG_KEEPALIVE";
	case SM_MSG_KEEPALIVE_ACK:
		return "SM_MSG_KEEPALIVE_ACK";
	case SM_MSG_RMA_WRITE:
		return "SM_MSG_RMA_WRITE";
	case SM_MSG_RMA_READ:
		return "SM_MSG_RMA_READ";
	case SM_MSG_RMA_ACK:
		return "SM_MSG_RMA_ACK";
	case SM_MSG_MAX:
		return "SM_MSG_MAX";
	}
	/* never reached */
	return NULL;
}

typedef struct sm_globals	sm_globals_t;
typedef struct sm_dev		sm_dev_t;
typedef struct sm_ep		sm_ep_t;
typedef struct sm_conn		sm_conn_t;
typedef struct sm_tx		sm_tx_t;
typedef struct sm_rx		sm_rx_t;
typedef struct sm_rma		sm_rma_t;
typedef struct sm_rma_op	sm_rma_op_t;
typedef struct sm_rma_handle	sm_rma_handle_t;
typedef struct sm_buffer	sm_buffer_t;

typedef enum sm_ctx {
	SM_TX,
	SM_RX,
	SM_RMA
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

struct sm_tx {
	sm_ctx_t		ctx;		/* SM_TX */
	cci__evt_t		evt;		/* CCI event - private and public) */
	sm_tx_state_t		state;
	sm_msg_type_t		type;
	uint32_t		id;		/* TX id */
	int			flags;		/* CCI_FLAG_* */
	uint32_t		offset;		/* MMAP cacheline index */
	uint32_t		len;		/* Msg len */
	sm_rma_op_t		*rma_op;	/* Owning RMA if completion msg */
	uint32_t		rma_id;		/* RMA fragment ID */
};

struct sm_rx {
	sm_ctx_t		ctx;		/* SM_RX */
	cci__evt_t		evt;		/* CCI event - private and public) */
};

struct sm_rma_handle {
	void *addr;
	uint64_t len;
	int flags;
};

struct sm_rma {
	cci__evt_t evt;
	sm_rma_hdr_t hdr;
	sm_tx_t *tx;
	uint32_t num_frags;
	uint32_t next_frag;
	uint32_t completed;
};

struct sm_ep {
	cci_os_handle_t		sock;		/* For listen socket */
	uint32_t		is_polling;	/* Serialize accept to sockets
						   and polling strctures */
	uint32_t		id;		/* Endpoint id */
	cci_os_handle_t		fifo;		/* FIFO fd for receiving headers */
	cci_os_handle_t		msgs;		/* File descriptor for send buffer */

	nfds_t			nfds;		/* Numbder of pollfds */
	struct pollfd		*fds;		/* For UNIX sockets */
	cci__conn_t		**c;		/* Array of conns indexed by fds */

	sm_buffer_t		*tx_buf;	/* TX common buffer */
	sm_tx_t			*txs;		/* All txs */
	TAILQ_HEAD(itx, cci__evt) idle_txs;	/* List of idle txs */

	sm_buffer_t		*rx_buf;	/* RX common buffer */
	sm_rx_t			*rxs;		/* All rxs */
	TAILQ_HEAD(irx, cci__evt) idle_rxs;	/* List of idle rxs */

	TAILQ_HEAD(cns, sm_conn) conns;		/* Connected conns */
	TAILQ_HEAD(act, sm_conn) active;	/* Active conns */
	TAILQ_HEAD(psv, sm_conn) passive;	/* Passive conns */
	TAILQ_HEAD(cls, sm_conn) closing;	/* Closing conns */
};

struct sm_buffer {
	void *addr;		/* base address of buffer */
	uint64_t *blocks;	/* bit mask of available cache lines */
	pthread_mutex_t lock;	/* lock */
	uint64_t len;		/* length of buffer in bytes */
	int last_block;		/* last offset's block */
	int block_offset;	/* last offset's block offset */
	int num_blocks;		/* number of blocks in bit mask */
	int min_len;		/* length of minimal allocation - must be power of two */
	int mask;		/* len - 1 */
	int shift;		/* 1 << shift == min_len */
};

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

struct sm_conn {
	cci__conn_t		*conn;		/* Owning conn */
	sm_conn_state_t		state;		/* State */
	cci_os_handle_t		fd;		/* Socket for this conn */
	pthread_mutex_t		lock;		/* Sending lock */
	uint32_t		index;		/* Index in sep->fds */
	TAILQ_ENTRY(sm_conn)	entry;		/* Entry in sep->conns|active|passive */
	TAILQ_HEAD(qd, sm_tx)	queued;		/* Queued sends */
	TAILQ_HEAD(pd, sm_tx)	pending;	/* Pending (in-flight) sends */
	struct sockaddr_un	sun;		/* UNIX name */
};

struct sm_dev {
	char			*path;		/* Path to URI base */
	uint64_t		*ids;		/* Bit mask of ids starting at sdev->id */
	uint32_t		id;		/* Starting endpoint id */
	uint32_t		num_blocks;	/* Number of ids blocks */
};

struct sm_globals {
	int			count;		/* Number of sm devices = 1 */
	cci_device_t		**devices;	/* Array of sm devices */
};

extern sm_globals_t		*smglobals;

int cci_ctp_sm_post_load(cci_plugin_t * me);
int cci_ctp_sm_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_SM_H */
