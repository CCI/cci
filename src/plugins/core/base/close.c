/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
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
	if (NULL != cci_core) {
		lt_dlclose(cci_plugins_core_handle);
		cci_core = NULL;
	}

	return CCI_SUCCESS;
}
