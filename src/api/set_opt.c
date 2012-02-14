/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

int cci_set_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, const void *val, int len)
{
	int ret;

	CCI_ENTER;

	if (NULL == handle || NULL == val || len == 0) {
		return CCI_EINVAL;
	}

	if (CCI_OPT_LEVEL_ENDPOINT == level) {
		if (handle->endpoint == NULL
		    || name == CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
	} else {
		if (handle->connection == NULL
		    || name != CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
	}

	ret = cci_core->set_opt(handle, level, name, val, len);

	CCI_EXIT;

	return ret;
}
