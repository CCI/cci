/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2012 Oak Ridge National Labs.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef PLUGINS_CTP_BASE_PUBLIC_H
#define PLUGINS_CTP_BASE_PUBLIC_H

#include "cci.h"

BEGIN_C_DECLS
int cci_plugins_ctp_open(void);
int cci_plugins_ctp_verify(cci_plugin_t * plugin);
int cci_plugins_ctp_close(void);

END_C_DECLS
#endif				/* PLUGINS_CTP_BASE_PUBLIC_H */
