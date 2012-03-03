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
cci_plugin_core_t *cci_core = NULL;

int cci_plugins_core_open(void)
{
	int rc;

	/* This framework only needs 1 plugin */
	rc = cci_plugins_open_all("core", cci_plugins_core_verify,
				  &cci_all_plugins);
	if (CCI_SUCCESS != rc) {
		return rc;
	}

	/* FIXME */
	cci_core = (cci_plugin_core_t*) cci_all_plugins[0].plugin;

	return CCI_SUCCESS;
}
