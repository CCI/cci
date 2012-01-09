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
	struct ccieth_pkt_header_connect_request {
		struct ethhdr eth;
		__u8 type;
		__u8 attribute;
		/* 16 */
		__be32 dst_ep_id;
		__be32 src_ep_id;
		/* 24 */
		__be32 src_conn_id;
		__be32 max_send_size;
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
		__be32 max_send_size;
		__be32 req_seqnum;
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
	struct ccieth_pkt_header_msg {
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 dst_conn_id;
		/* 24 */
		__be32 msg_len;
		__u8 msg[0];
	} msg;
};

enum ccieth_pkt_type {
	CCIETH_PKT_CONNECT_REQUEST,
	CCIETH_PKT_CONNECT_ACCEPT,
	CCIETH_PKT_CONNECT_REJECT,
	CCIETH_PKT_MSG,
};

#endif /* CCIETH_WIRE_H */
