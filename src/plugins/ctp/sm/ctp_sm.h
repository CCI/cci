/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CTP_SM_H
#define CCI_CTP_SM_H

#include "cci/private_config.h"

BEGIN_C_DECLS int cci_ctp_sm_post_load(cci_plugin_t * me);
int cci_ctp_sm_pre_unload(cci_plugin_t * me);

END_C_DECLS
#endif				/* CCI_CTP_SM_H */
