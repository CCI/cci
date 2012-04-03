/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"

/*
 * Public variables
 */
struct cci_plugin_handle *cci_all_plugins = NULL;

int cci_plugins_core_open(void)
{
	int rc;

	/* This framework only needs 1 plugin */
	rc = cci_plugins_open_all("core", cci_plugins_core_verify,
				  &cci_all_plugins);
	if (CCI_SUCCESS != rc) {
		return rc;
	}

	return CCI_SUCCESS;
}
