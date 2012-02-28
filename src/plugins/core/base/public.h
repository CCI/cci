/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef PLUGINS_CORE_BASE_PUBLIC_H
#define PLUGINS_CORE_BASE_PUBLIC_H

#include "cci.h"

BEGIN_C_DECLS int cci_plugins_core_open(void);
int cci_plugins_core_verify(cci_plugin_t * plugin);
int cci_plugins_core_close(void);

END_C_DECLS
#endif				/* PLUGINS_CORE_BASE_PUBLIC_H */
