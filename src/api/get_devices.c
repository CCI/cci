/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/base/public.h"
#include "plugins/core/core.h"

int cci_get_devices(cci_device_t * const ** devicesp)
{
	/* FIXME: if we have to update the device array at runtime,
	 * add a update_devices plugin callback and call of them here
	 * (with globals->lock held),
	 * to update the TAILQ. then update the devices array.
	 */

	*devicesp = (cci_device_t * const *) globals->devices;
	return CCI_SUCCESS;
}
