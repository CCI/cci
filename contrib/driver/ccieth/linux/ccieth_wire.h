/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#ifndef CCIETH_WIRE_H
#define CCIETH_WIRE_H 1

#define ETH_P_CCI 0x86df

struct ccieth_pkt_header {
	struct ethhdr eth;
	u8 type;
	u8 pad1;
	/* 16 */
	u32 endpoint_id;
	u32 pad2;
	/* 24 */
};

enum ccieth_pkt_type {
	CCIETH_PKT_CONNECT,
};

#endif /* CCIETH_WIRE_H */
