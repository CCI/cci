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
		struct ethhdr eth;
		__u8 type;
		__u8 pad1;
		/* 16 */
		__be32 dst_ep_id;
		__be32 attributes;
		/* 24 */
		__be32 src_ep_id;
		__be32 src_conn_id;
		/* 32 */
		__be32 data_len;
		__u8 data[0];
	} connect;
};

enum ccieth_pkt_type {
	CCIETH_PKT_CONNECT,
};

#endif /* CCIETH_WIRE_H */
