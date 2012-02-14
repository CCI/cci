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

#include "cci.h"
#include "plugins/core/core.h"

int cci_rma_deregister(uint64_t rma_handle)
{
	return cci_core->rma_deregister(rma_handle);
}
