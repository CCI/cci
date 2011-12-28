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

typedef struct eth__dev {
  /*! Mac address of the interface */
  struct sockaddr_ll addr;
} eth__dev_t;

typedef struct eth__ep {
  int fd;
} eth__ep_t;

int cci_core_eth_post_load(cci_plugin_t *me);
int cci_core_eth_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_ETH_H */
