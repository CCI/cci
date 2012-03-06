/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCIETH_IO_H
#define CCIETH_IO_H 1

#include <linux/types.h>
#include <linux/ioctl.h>

#define CCIETH_IOCTL_MAGIC 'C'

/* reserved by user-space, driver should never assign it to a connection */
#define CCIETH_CONNECTION_INVALID_ID (~0U)

struct ccieth_ioctl_get_info {
	__u8 addr[6];
	__u8 pad1[2];
	/* 8 */
	__u16 max_send_size;
	__u16 pci_domain;
	__u8 pci_bus;
	__u8 pci_dev;
	__u8 pci_func;
	__u8 pad2;
	/* 16 */
	__u64 rate;
	/* 24 */
};
#define CCIETH_IOCTL_GET_INFO _IOW(CCIETH_IOCTL_MAGIC, 0x1, struct ccieth_ioctl_get_info)

struct ccieth_ioctl_create_endpoint {
	__u8 addr[6];
	__u8 pad1[2];
	/* 8 */
	__u32 id;
	__u32 pad2;
	/* 16 */
};
#define CCIETH_IOCTL_CREATE_ENDPOINT _IOWR(CCIETH_IOCTL_MAGIC, 0x2, struct ccieth_ioctl_create_endpoint)

struct ccieth_ioctl_get_event {
	__u8 type;
	__u8 pad1;
	__u16 data_length;
	__u32 pad2;
	/* 8 */
	union {
		struct {
			__u64 user_conn_id;
			/* 16 */
			__u64 context;
			/* 24 */
			__u32 status;
			__u32 pad1;
			/* 32 */
		} send;
		struct {
			__u64 user_conn_id;
			/* 16 */
		} recv;
		struct {
			__u64 user_conn_id;
			/* 16 */
			__u32 status;
			__u32 conn_id;
			/* 24 */
			__u32 max_send_size;
		} connect;
		struct {
			__u32 conn_id;
			__u32 attribute;
			/* 16 */
			__u32 max_send_size;
		} connect_request;
		struct {
			__u64 user_conn_id;
			/* 16 */
			__u32 status;
		} accept;
		struct {
			__u64 user_conn_id;
			/* 16 */
		} connection_closed;
	};
};
#define CCIETH_IOCTL_GET_EVENT _IOW(CCIETH_IOCTL_MAGIC, 0x3, struct ccieth_ioctl_get_event)

struct ccieth_ioctl_return_event {
	__u32 event_offset;
};
#define CCIETH_IOCTL_RETURN_EVENT _IOR(CCIETH_IOCTL_MAGIC, 0x4, struct ccieth_ioctl_return_event)

struct ccieth_ioctl_connect_request {
	__u8 dest_addr[6];
	__u8 pad1[2];
	/* 8 */
	__u32 dest_eid;
	__u32 data_len;
	/* 16 */
	__u64 data_ptr;
	/* 24 */
	__u8 attribute;
	__u8 pad2[3];
	__u32 flags;
	/* 32 */
	__u64 user_conn_id;	/* give it back in incoming events on this connection */
	/* 40 */
	__u64 timeout_sec;
	/* 48 */
	__u32 timeout_usec;
	__u32 conn_id;		/* output */
	/* 56 */
};
#define CCIETH_IOCTL_CONNECT_REQUEST _IOWR(CCIETH_IOCTL_MAGIC, 0x5, struct ccieth_ioctl_connect_request)

/* FIXME: enforce matching with enum cci_conn_attribute */
#define CCIETH_CONNECT_ATTR_RO 0
#define CCIETH_CONNECT_ATTR_RU 1
#define CCIETH_CONNECT_ATTR_UU 2

struct ccieth_ioctl_connect_accept {
	__u32 conn_id;
	__u32 pad1;
	/* 8 */
	__u64 user_conn_id;	/* give it back in incoming events on this connection */
	/* 16 */
};
#define CCIETH_IOCTL_CONNECT_ACCEPT _IOR(CCIETH_IOCTL_MAGIC, 0x6, struct ccieth_ioctl_connect_accept)

struct ccieth_ioctl_connect_reject {
	__u32 conn_id;
};
#define CCIETH_IOCTL_CONNECT_REJECT _IOR(CCIETH_IOCTL_MAGIC, 0x7, struct ccieth_ioctl_connect_reject)

struct ccieth_ioctl_msg {
	__u32 conn_id;
	__u32 msg_len;
	/* 8 */
	__u64 msg_ptr;
	/* 16 */
	__u64 context;
	/* 24 */
	__u32 flags; /* OR'ed CCIETH_FLAG_{BLOCKING,SILENT,RELIABLE} */
};
#define CCIETH_IOCTL_MSG _IOR(CCIETH_IOCTL_MAGIC, 0x8, struct ccieth_ioctl_msg)

struct ccieth_ioctl_disconnect {
	__u32 conn_id;
};
#define CCIETH_IOCTL_DISCONNECT _IOR(CCIETH_IOCTL_MAGIC, 0x9, struct ccieth_ioctl_disconnect)

struct ccieth_ioctl_rma_register {
	__u32 protection;
	__u32 buffer_len;
	/* 8 */
	__u64 buffer_ptr;
	/* 16 */
	__u64 handle;
	/* 24 */
};
#define CCIETH_IOCTL_RMA_REGISTER _IOWR(CCIETH_IOCTL_MAGIC, 0xa, struct ccieth_ioctl_rma_register)

struct ccieth_ioctl_rma_deregister {
	__u64 handle;
	/* 8 */
};
#define CCIETH_IOCTL_RMA_DEREGISTER _IOR(CCIETH_IOCTL_MAGIC, 0xb, struct ccieth_ioctl_rma_deregister)

#define CCIETH_FLAG_BLOCKING	(1 << 0)
/* NO_COPY unused in ccieth, 1<<2 unused in cci */
#define CCIETH_FLAG_SILENT	(1 << 3)
#define CCIETH_FLAG_READ	(1 << 4)
#define CCIETH_FLAG_WRITE	(1 << 5)
#define CCIETH_FLAG_FENCE	(1 << 6)
#define CCIETH_FLAG_RELIABLE	(1 << 31)

/* FIXME: enforce matching with enum cci_event_type and simplify user-space switch? */
#define CCIETH_IOCTL_EVENT_SEND 1
#define CCIETH_IOCTL_EVENT_RECV 2
#define CCIETH_IOCTL_EVENT_CONNECT 3
#define CCIETH_IOCTL_EVENT_CONNECT_REQUEST 4
#define CCIETH_IOCTL_EVENT_ACCEPT 5
#define CCIETH_IOCTL_EVENT_DEVICE_FAILED 8

#define CCIETH_IOCTL_EVENT_CONNECTION_CLOSED 20

static inline __u32
ccieth_max_send_size(__u32 mtu)
{
	return mtu >= 9000 ? 8192 : 1024;
}

#endif /* CCIETH_IO_H */
