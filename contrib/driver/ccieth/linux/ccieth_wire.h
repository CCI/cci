/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
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
	struct ccieth_pkt_header_connect {
		/* FIXME: mss? */
		struct ethhdr eth;
		__u8 type;
		__u8 attribute;
		/* 16 */
		__be32 dst_ep_id;
		__be32 src_ep_id;
		/* 24 */
		__be32 src_conn_id;
		__be32 data_len;
		/* 32 */
		__u8 data[0];
	} connect;
	struct ccieth_pkt_header_accept {
		/* FIXME: mss? */
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
	} accept;
};

enum ccieth_pkt_type {
	CCIETH_PKT_CONNECT,
	CCIETH_PKT_ACCEPT,
};

#endif /* CCIETH_WIRE_H */
