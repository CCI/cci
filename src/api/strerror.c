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

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

const char *cci_strerror(cci_endpoint_t *endpoint, enum cci_status status)
{
	cci__ep_t *ep = NULL;

	if (endpoint)
		ep = container_of(endpoint, cci__ep_t, endpoint);

	switch (status) {
	case CCI_SUCCESS:
		return "CCI_SUCCESS";

	case CCI_ERROR:
		return "CCI_ERROR";

	case CCI_ERR_DISCONNECTED:
		return "CCI_ERR_DISCONNECTED";

	case CCI_ERR_RNR:
		return "CCI_ERR_RNR";

	case CCI_ERR_DEVICE_DEAD:
		return "CCI_ERR_DEVICE_DEAD";

	case CCI_ERR_RMA_HANDLE:
		return "CCI_ERR_RMA_HANDLE";

	case CCI_ERR_RMA_OP:
		return "CCI_ERR_RMA_OP";

	case CCI_ERR_NOT_IMPLEMENTED:
		return "CCI_ERR_NOT_IMPLEMENTED";

	case CCI_ERR_NOT_FOUND:
		return "CCI_ERR_NOT_FOUND";

	case CCI_EINVAL:
		return "CCI_EINVAL";

	case CCI_ETIMEDOUT:
		return "CCI_ETIMEDOUT";

	case CCI_ENOMEM:
		return "CCI_ENOMEM";

	case CCI_ENODEV:
		return "CCI_ENODEV";

	case CCI_ENETDOWN:
		return "CCI_ENETDOWN";

	case CCI_EBUSY:
		return "CCI_EBUSY";

	case CCI_ERANGE:
		return "CCI_ERANGE";

	case CCI_EAGAIN:
		return "CCI_EAGAIN";

	case CCI_ENOBUFS:
		return "CCI_ENOBUFS";

	case CCI_EMSGSIZE:
		return "CCI_EMSGSIZE";

	case CCI_ENOMSG:
		return "CCI_ENOMSG";

	case CCI_EADDRNOTAVAIL:
		return "CCI_EADDRNOTAVAIL";

	default:
		if (ep)
			return ep->plugin->strerror(endpoint, status);
		else
			return "unknown error";
	}
}
