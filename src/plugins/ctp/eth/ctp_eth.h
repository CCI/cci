/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CTP_ETH_H
#define CCI_CTP_ETH_H

#include "cci/config.h"
#include "ccieth_io.h"

#include "bsd/queue.h"

#include <netpacket/packet.h>
#include <stdint.h>

BEGIN_C_DECLS

typedef struct eth__dev {
	/*! Mac address of the interface */
	struct sockaddr_ll addr;
} eth__dev_t;

typedef struct eth__ep {
	int fd;

	/*! List of connection (for bookkeeping) */
	TAILQ_HEAD(eep_conns, eth__conn) connections;
} eth__ep_t;

typedef struct eth__conn {
	uint32_t id;
	cci__conn_t _conn;

	/*! Entry for the endpoint connection list */
	TAILQ_ENTRY(eth__conn) entry;
} eth__conn_t;

typedef struct eth__evt {
	cci__evt_t _ev;
	union {
		struct {
			int need_reply;	/* for connect request */
		} connect_request;
	} type_params;
	struct ccieth_ioctl_get_event ioctl_event;
	char data[0];
} eth__evt_t;

extern struct eth__globals {
	int fd;
} * eglobals;

int cci_ctp_eth_post_load(cci_plugin_t * me);
int cci_ctp_eth_pre_unload(cci_plugin_t * me);

END_C_DECLS

#endif /* CCI_CTP_ETH_H */
