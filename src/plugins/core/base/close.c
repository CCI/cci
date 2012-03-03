/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include "ltdl.h"
#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"
#include "plugins/core/base/private.h"

int cci_plugins_core_close(void)
{
	int i;

	for(i = 0; cci_all_plugins[i].plugin != NULL; i++)
		lt_dlclose(cci_all_plugins[i].handle);
	free(cci_all_plugins);

	return CCI_SUCCESS;
}
