/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_PORTALS_H
#define CCI_CORE_PORTALS_H

#include "cci/config.h"

BEGIN_C_DECLS

int cci_core_portals_post_load(cci_plugin_t *me);
int cci_core_portals_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_PORTALS_H */
