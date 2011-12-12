/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_VERBS_H
#define CCI_CORE_VERBS_H

#include "cci/config.h"

#include <assert.h>
#include <rdma/rdma_cma.h>

BEGIN_C_DECLS

/* Valid URI include:
 *
 * verbs://hostname:port	# Hostname or IPv4 address and port
 */

/* A verbs device needs the following items in the config file:
 *
 * driver = verbs		# must be lowercase
 *
 * A verbs device may have these items:
 *
 * mss = 1024			# max_send_size for MSGs
 */

#define VERBS_URI		"verbs://"


/* Wire Header Specification */

typedef enum verbs_msg_type {
	VERBS_MSG_INVALID = 0,
	VERBS_MSG_CONN_REQUEST,
	VERBS_MSG_CONN_REPLY,
	VERBS_MSG_DISCONNECT,
	VERBS_MSG_SEND,
	VERBS_MSG_KEEPALIVE,
	VERBS_MSG_TYPE_MAX,
} verbs_msg_type_t;

/* MSG header */

/* Generic header passed via IMMEDIATE in _host_ order (need to flip before accessing):

    <----------- 32 bits ----------->
    <---------- 28b ----------->  4b
   +----------------------------+----+
   |             B              |  A |
   +----------------------------+----+

   where A is the msg type and each message type decides how to use B

 */

#define VERBS_TYPE_BITS		(4)
#define VERBS_TYPE_MASK		((1 << VERBS_TYPE_BITS) - 1)
#define VERBS_TYPE(x)		((x) & VERBS_TYPE_MASK)

#define VERBS_DEFAULT_MSS	(IBV_MTU_2048)

int cci_core_verbs_post_load(cci_plugin_t *me);
int cci_core_verbs_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_VERBS_H */
