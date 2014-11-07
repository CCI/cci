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
#include "ring.h"

BEGIN_C_DECLS
#define SM_BLOCK_SIZE		(64)		/* uint64_t sized ep id blocks */
#define SM_NUM_BLOCKS		(1)		/* start with one block for 64 ep ids */

/* These are ignored. We use per-connection counts. */
#define SM_EP_RX_CNT		(1024)		/* number of rx messages */
#define SM_EP_TX_CNT		(1024)		/* number of tx messages */

/* Define minimal cache line sizes. */
#define SM_SHIFT		(6)		/* 6 = 64B, 7 = 128B, 8 = 256B */
#define SM_LINE			(1 << SM_SHIFT)	/* Cache line size */
#define SM_MASK			(SM_LINE - 1)	/* Mask bits for line size */

#define SM_DEFAULT_MSS		(SM_LINE * 4)	/* Default max send size */
#define SM_MIN_MSS		(SM_LINE)	/* Minimum cache line size */
#define SM_MAX_MSS		(4096)		/* page size */

#define SM_RMA_MTU		(4096)		/* Common page size */
#define SM_RMA_SHIFT		(12)
#define SM_RMA_MASK		(SM_RMA_MTU - 1)
#define SM_RMA_DEPTH		(32)		/* how many in-flight msgs per RMA */
#define SM_RMA_FRAG_SIZE	(2*SM_RMA_MTU)	/* optimal for POSIX shmem */
#define SM_RMA_FRAG_MAX		(16*SM_RMA_MTU)	/* optimal for knem and CMA */

#define SM_EP_MAX_CONNS		(1024)		/* Number of cores? */
#define SM_EP_MAX_ID		((1 << 14) - 1)	/* Largest supported endpoint ID -
						   base + index */

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
		uint32_t attribute	:  2;	/* CCI_CONN_ATTR_* */
		uint32_t pad1		:  8;	/* Reserved */
		/* 32b */
		uint32_t server_id	: 16;	/* Client-assigned ID for server */
		uint32_t pad2		: 16;	/* Reserved */
		/* 64b */
	} connect;

	/* Connect reply */
	struct sm_conn_hdr_connect_reply {
		uint32_t type		:  2;	/* SM_CMSG_CONN_REPLY */
		uint32_t status		:  8;	/* ACCEPT=0 or errno */
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
	SM_MSG_KEEPALIVE,
	SM_MSG_RMA_WRITE,
	SM_MSG_RMA_READ,
	SM_MSG_RMA_ACK,
	SM_MSG_MAX
} sm_msg_type_t;

/* The message headers are sent via the hdr ring */
/* This is a 4-byte aligned structure */
typedef union sm_hdr {
	/* Generic header used by all messages */
	struct sm_hdr_generic {
		uint32_t type		:  4;	/* header type */
		uint32_t pad		: 28;	/* fill to 32 bits */
		/* 32b */
	} generic;

	/* Send (header only, payload in sender's MMAP MSG buffer) */
	struct sm_hdr_send {
		uint32_t type		:  4;	/* SM_MSG_SEND[_ACK|_NACK] */
		uint32_t offset		:  8;	/* MMAP cacheline index */
		uint32_t len		: 12;	/* payload length */
		uint32_t pad		:  8;	/* Reserve */
		/* 32b */
	} send;

	/* Keepalive */
	struct sm_hdr_keepalive {
		uint32_t type		:  4;	/* SM_MSG_KEEPALIVE[_ACK] */
		uint32_t pad1		: 20;	/* Reserved */
		uint32_t seq		:  8;	/* Sequence or msg ID */
		/* 32b */
	} keepalive;

	/* RMA request (used by MMAP RMA only) */
	struct sm_hdr_rma {
		uint32_t type		:  4;	/* SM_MSG_RMA_[WRITE|_READ] */
		uint32_t offset		: 16;	/* MMAP cache line index */
		uint32_t pad		:  4;	/* Reserved */
		uint32_t seq		:  8;	/* Sequence or msg ID */
		/* 32b */
	} rma;

	/* RMA ack (used by MMAP RMA only) */
	struct sm_hdr_rma_ack {
		uint32_t type		:  4;	/* SM_MSG_RMA_ACK */
		uint32_t offset		: 16;	/* MMAP cache line index */
		uint32_t pad		:  4;	/* Reserved */
		uint32_t status		:  8;	/* Status (0 for success, else errno) */
		/* 32b */
	} rma_ack;

	uint32_t	u32;			/* for alignment and ring insert */
} sm_hdr_t;

/* This is an 8-byte aligned structure */
typedef struct sm_rma_hdr {
	uint64_t local_handle;			/* Initiator's sm_rma_handle_t * */
	/*  8 B */
	uint64_t local_offset;			/* Initiator's offset for this fragment */
	/* 16 B */
	uint64_t remote_handle;			/* Target's sm_rma_handle_t * */
	/* 24 B */
	uint64_t remote_offset;			/* Target's offset for this fragment */
	/* 32 B */
	uint64_t len;				/* Length for this fragment */
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
	case SM_MSG_KEEPALIVE:
		return "SM_MSG_KEEPALIVE";
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
typedef struct sm_conn_buffer	sm_conn_buffer_t;
typedef struct sm_rma_buffer	sm_rma_buffer_t;
typedef struct sm_rx		sm_rx_t;
typedef struct sm_rma		sm_rma_t;
typedef struct sm_rma_op	sm_rma_op_t;
typedef struct sm_rma_handle	sm_rma_handle_t;

typedef enum sm_ctx {
	SM_TX = 0,
	SM_RX,
	SM_RMA
} sm_ctx_t;

struct sm_rma_handle {
	cci__ep_t		*ep;		/* Owning endpoint */
	void			*addr;		/* Starting address */
	uint64_t		len;		/* Length */
	struct cci_rma_handle	handle;		/* CCI RMA handle */
	int			flags;		/* Access flags */
};

/* Store RMA pointer in rma->evt.priv to distringuish this from a MSG */
struct sm_rma {
	cci__evt_t		evt;		/* CCI internal event */
	sm_rma_hdr_t		hdr;		/* RMA parameters */
	uint64_t		offset;		/* Bytes transferred */
	void			*msg_ptr;	/* Completion MSG */
	uint32_t		seq;		/* RMA frag seqno */
	uint32_t		next_frag;	/* Next frag index to send */
	uint32_t		pending;	/* In-flight fragments */
	uint32_t		completed;	/* Number of completed frags */
	uint32_t		msg_len;	/* Completion msg length */
	int			flags;		/* CCI flags */
};

struct sm_ep {
	cci_os_handle_t		sock;		/* For listen socket */
	uint32_t		sock_busy :  1;	/* Serialize access to sock */
	uint32_t		fifo_busy :  1;	/* Serialize access to fifo */
	uint32_t		id        : 14;	/* Large enough to handle SM_EP_MAX_ID */
	uint32_t		pad       : 16;	/* Reserved */

	cci_os_handle_t		fifo;		/* FIFO fd for receiving headers */

	void			*conns;		/* Tree of conns sorted by IDs */
	pthread_rwlock_t	conns_lock;	/* Lock for conns tree */
	uint64_t		*conn_ids;	/* Bitmask of conn IDs */
	uint32_t		last_id;	/* Last ID assigned */
	int			pipe[2];	/* Pipe to notify app */

	TAILQ_HEAD(act, sm_conn) active;	/* Active conns */
	TAILQ_HEAD(psv, sm_conn) passive;	/* Passive conns */
	TAILQ_HEAD(cls, sm_conn) closing;	/* Closing conns */

	pthread_t		conn_tid;	/* Connection thread */
};

typedef enum sm_conn_state {
	SM_CONN_CLOSED = -2,
	SM_CONN_CLOSING = -1,
	SM_CONN_INIT = 0,
	SM_CONN_ACTIVE,
	SM_CONN_PASSIVE,
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
	case SM_CONN_ACTIVE:
		return "SM_CONN_ACTIVE";
	case SM_CONN_PASSIVE:
		return "SM_CONN_PASSIVE";
	case SM_CONN_CLOSING:
		return "SM_CONN_CLOSING";
	case SM_CONN_CLOSED:
		return "SM_CONN_CLOSED";
	}
	/* never reached */
	return NULL;
}

typedef struct sm_conn_params {
	void			*data_ptr;	/* Buffered payload */
	uint32_t		data_len;	/* Payload length */
	int			flags;		/* Flags */
} sm_conn_params_t;

struct sm_conn_buffer {
	uint64_t		avail;		/* Bitmask for available cache lines */
	char			pad[SM_LINE - sizeof(uint64_t)];
	char			buf[SM_LINE * 64]; /* Cache lines */
	ring_t			ring;		/* For headers */
};

struct sm_rma_buffer {
	uint64_t		avail;		/* Bitmask for available pages */
	ring_t			ring;		/* For MSG headers */
	char			pad[SM_RMA_MTU - sizeof(uint64_t) - sizeof(ring_t)];
	char			hdr[SM_LINE * 64]; /* Cache lines for RMA frag headers */
	char			buf[SM_RMA_MTU * 64]; /* Pages */
};

struct sm_conn {
	cci__conn_t		*conn;		/* Owning conn */
	sm_conn_state_t		state;		/* SM_CONN_* */
	cci_os_handle_t		fifo;		/* for sending keepalives and wakeups */

	int			id;		/* ID we assigned to peer */
	int			peer_id;	/* ID peer assigned to us */

	void			*mmap;		/* Mmapped buffer */
	sm_conn_buffer_t	*tx;		/* Pointer to mmap */
	void			*peer_mmap;	/* Peer's mmap */
	sm_conn_buffer_t	*rx;		/* Pointer to peer's mmap */

	void			*rma_mmap;	/* Mmapped RMA buffer */
	sm_rma_buffer_t		*rma;		/* Pointer to RMA mmap */
	void			*peer_rma_mmap;	/* Peer's RMA mmap */
	sm_rma_buffer_t		*peer_rma;	/* Pointer to peer's RMA mmap */

	cci__evt_t		*rxs;		/* RECV events */
	cci__evt_t		*txs;		/* SEND events */
	uint64_t		txs_avail;	/* Bitmap of available txs */

	TAILQ_ENTRY(sm_conn)	entry;		/* Entry in sep->conns|active|passive */
	char			*name;		/* sockaddr_un.sun_path */
	/* The following are only used by the client during setup */
	sm_conn_params_t	*params;	/* Params */
};

struct sm_dev {
	char			*path;		/* Path to URI base */
	uint64_t		*ids;		/* Bit mask of ids starting at sdev->id */
	uint32_t		pid;		/* Process id */
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
