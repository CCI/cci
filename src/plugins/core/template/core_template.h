/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_TEMPLATE_H
#define CCI_CORE_TEMPLATE_H

#include "cci/config.h"

BEGIN_C_DECLS int cci_core_template_post_load(cci_plugin_t * me);
int cci_core_template_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CORE_TEMPLATE_H */
