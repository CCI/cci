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
			__u32 conn_id;
			__u32 status;
			/* 16 */
			__u64 context;
			/* 24 */
		} send;
		struct {
			__u32 conn_id;
		} recv;
		struct {
			__u32 conn_id;
			__u32 attribute;
			/* 16 */
			__u32 max_send_size;
		} connect_request;
		struct {
			__u32 conn_id;
			__u32 attribute;
			/* 16 */
			__u64 context;
			/* 24 */
			__u32 max_send_size;
		} connect_accepted;
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
	__u64 context;
	/* 40 */
	__u64 timeout_sec;
	/* 48 */
	__u32 timeout_usec;
	__u32 conn_id; /* output */
	/* 56 */
};
#define CCIETH_IOCTL_CONNECT_REQUEST _IOWR(CCIETH_IOCTL_MAGIC, 0x5, struct ccieth_ioctl_connect_request)

struct ccieth_ioctl_connect_accept {
	__u32 conn_id;
	__u32 max_send_size;
};
#define CCIETH_IOCTL_CONNECT_ACCEPT _IOR(CCIETH_IOCTL_MAGIC, 0x6, struct ccieth_ioctl_connect_accept)

struct ccieth_ioctl_msg {
	__u32 conn_id;
	__u32 msg_len;
	/* 8 */
	__u64 msg_ptr;
	/* 16 */
	__u64 context;
	/* 24 */
	__u32 flags;
};
#define CCIETH_IOCTL_MSG _IOR(CCIETH_IOCTL_MAGIC, 0x7, struct ccieth_ioctl_msg)

/* FIXME: enforce matching with enum cci_event_type */
#define CCIETH_IOCTL_EVENT_SEND 1
#define CCIETH_IOCTL_EVENT_RECV 2
#define CCIETH_IOCTL_EVENT_CONNECT_ACCEPTED 3
#define CCIETH_IOCTL_EVENT_CONNECT_REQUEST 6

#endif /* CCIETH_IO_H */
