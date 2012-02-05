/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCIETH_WIRE_H
#define CCIETH_WIRE_H 1

#define ETH_P_CCI 0x86df

union ccieth_pkt_header {
	struct ccieth_pkt_header_generic {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
	} generic;
	struct _ccieth_pkt_header_connect_generic {
		/* generic connect packet type for (n)acking request/accept/reject:
		 * - not larger than any actual connect header
		 * - all (non-padding) fields here appear the same in actual connect headers
		 * - dst_conn_id must be replaced with -1 manually if type is a request
		 */
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id; /* except in request */
		/* 24 */
		__be32 src_ep_id;
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} _connect_generic;
	struct ccieth_pkt_header_connect_request {
		struct ethhdr eth;
		__u8 type;
		__u8 attribute;
		/* 16 */
		__be32 dst_ep_id;
		__be32 max_send_size;
		/* 24 */
		__be32 src_ep_id;
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 data_len;
		/* 40 */
		__u8 data[0];
	} connect_request;
	struct ccieth_pkt_header_connect_accept {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id; /* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 max_send_size;
		/* 40 */
	} connect_accept;
	struct ccieth_pkt_header_connect_reject {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id; /* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} connect_reject;
	struct ccieth_pkt_header_connect_ack {
		struct ethhdr eth;
		__u8 type;
		__u8 status;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id; /* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} connect_ack;
	struct ccieth_pkt_header_msg {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 conn_seqnum;
		__be32 msg_seqnum;
		/* 32 */
		__be32 msg_len;
		__u8 msg[0];
	} msg;
	struct ccieth_pkt_header_msg_ack {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 conn_seqnum;
		__be32 acked_seqnum;
		/* 32 */
	} msg_ack;
};

enum ccieth_pkt_type {
	CCIETH_PKT_CONNECT_REQUEST,
	CCIETH_PKT_CONNECT_ACCEPT,
	CCIETH_PKT_CONNECT_REJECT,
	CCIETH_PKT_CONNECT_ACK,
	CCIETH_PKT_MSG,
	CCIETH_PKT_MSG_ACK,
};

enum ccieth_pkt_ack_status {
	CCIETH_PKT_ACK_SUCCESS,
	CCIETH_PKT_ACK_INVALID,
	CCIETH_PKT_ACK_NO_ENDPOINT,
	CCIETH_PKT_ACK_NO_CONNECTION,
};

#endif /* CCIETH_WIRE_H */
