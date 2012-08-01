/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCIETH_WIRE_H
#define CCIETH_WIRE_H 1

#include <linux/if_ether.h>

#define ETH_P_CCI 0x86df

union ccieth_pkt_header {
	/* Generic header, common to all packet types */
	struct ccieth_pkt_header_generic {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
	} generic;

	/* Common part of connect request/accept/reject headers, useful for implementing (n)acking in a generic way:
	 * - not larger than any actual connect header
	 * - all (non-padding) fields here appear the same in actual connect headers
	 * - dst_conn_id must be replaced with -1 manually if type is a request
	 * This is a ccieth-specific implementation detail. Could move to ccieth specific files later.
	 */
	struct _ccieth_pkt_header_connect_generic {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;	/* except in request */
		/* 24 */
		__be32 src_ep_id;
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} _connect_generic;

	/* Connect Request.
	 * May be resent as long as it has not been acked, accepted or rejected.
	 */
	struct ccieth_pkt_header_connect_request {
		struct ethhdr eth;
		__u8 type;
		__u8 attribute;
		/* 16 */
		__be32 dst_ep_id;
		__be32 pad2_no_dst_conn_id;	/* dst_conn_id N/A at request time */
		/* 24 */
		__be32 src_ep_id;
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 data_len;
		/* 40 */
		__be32 first_seqnum;
		__be32 max_send_size;
		/* 48 */
		__u8 data[0];
	} connect_request;

	/* Connect Accept.
	 * May be resent as long as it has not been (n)acked.
	 */
	struct ccieth_pkt_header_connect_accept {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id;	/* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
		__be32 first_seqnum;
		__be32 max_send_size;
		/* 48 */
	} connect_accept;

	/* Connect Reject.
	 * May be resent as long as it has not been (n)acked.
	 */
	struct ccieth_pkt_header_connect_reject {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id;	/* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} connect_reject;

	/* Acks (and nacks) for connect request/accept/reject.
	 * Every connect/accept/reject must be acked,
	 * either with an explicit ack packet, or with a accept/reject for connect request.
	 *
	 * Ack guarantees that the packet has been passed to the application,
	 * even if the application ignored the event, or did not call accept/reject yet.
	 *
	 * Acking rejects also helps the target keep track of already rejected
	 * connection request that could be resent.
	 */
	struct ccieth_pkt_header_connect_ack {
		struct ethhdr eth;
		__u8 type;
		__u8 status;	/* one of enum ccieth_pkt_ack_status values */
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 src_ep_id;	/* not really required? */
		__be32 src_conn_id;
		/* 32 */
		__be32 req_seqnum;
		__be32 pad2;
		/* 40 */
	} connect_ack;

	/* MSG.
	 * May be resent as long as not acked.
	 */
	struct ccieth_pkt_header_msg {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 conn_seqnum;	/* The original connect request seqnum */
		__be32 msg_seqnum;
		/* 32 */
		__be32 acked_seqnum;	/* All MSG before this have been received */
		__be32 msg_len;
		/* 40 */
		__u8 msg[0];
	} msg;

	/* Explicit MSG ack.
	 */
	struct ccieth_pkt_header_msg_ack {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 conn_seqnum;	/* The original connect request seqnum */
		__be32 acked_seqnum;	/* All MSG before this have been received */
		/* 32 */
		__be32 acked_bitmap;	/* All MSG seqnum is "acked_seqnum + 1 + a bit set here" have been received */
		__be32 pad2;
		/* 40 */
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
