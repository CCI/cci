/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 INRIA.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_ETH_H
#define CCI_CORE_ETH_H

#include "cci/config.h"

#include <netpacket/packet.h>

BEGIN_C_DECLS

typedef struct eth_dev {
  /*! Mac address of the interface */
  struct sockaddr_ll addr;
} eth_dev_t;

typedef struct eth_ep {
  int fd;
} eth_ep_t;

int cci_core_eth_post_load(cci_plugin_t *me);
int cci_core_eth_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_ETH_H */
