/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2010 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2010 Oak Ridge National Labs.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_CORE_H
#define CCI_CORE_CORE_H

#include "cci/config.h"
#include "cci.h"
#include "cci_lib_types.h"

#define CCI_SOCK_AM_SIZE    (8 * 1024)  /* 8 KB - assume jumbo frames */

/* A sock device needs the following items in the config file:
 * driver = sock    # must be lowercase
 * ip = 0.0.0.0     # valid IPv4 address of the adapter to use
 */

BEGIN_C_DECLS

int cci_core_sock_post_load(cci_plugin_t *me);
int cci_core_sock_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_CORE_H */
