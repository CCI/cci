/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include <stdio.h>

#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"

int cci_plugins_core_verify(cci_plugin_t * plugin)
{
	cci_plugin_core_t *p = (cci_plugin_core_t *) plugin;

	if (NULL == p->init ||
	    NULL == p->strerror ||
	    NULL == p->get_devices ||
	    NULL == p->free_devices ||
	    NULL == p->create_endpoint ||
	    NULL == p->destroy_endpoint ||
	    NULL == p->accept ||
	    NULL == p->reject ||
	    NULL == p->connect ||
	    NULL == p->disconnect ||
	    NULL == p->set_opt ||
	    NULL == p->get_opt ||
	    NULL == p->arm_os_handle ||
	    NULL == p->get_event ||
	    NULL == p->return_event ||
	    NULL == p->send ||
	    NULL == p->sendv ||
	    NULL == p->rma_register ||
	    NULL == p->rma_deregister || NULL == p->rma) {
		debug(CCI_DB_WARN,
		      "Core plugin \"%s\" lacks one or more required functions -- ignored",
		      p->base.plugin_name);
		return CCI_ERROR;
	}

	/* Check to ensure it's a supported API version.  For simplicity,
	   we only support 1 version right now. */
	if (p->base.plugin_type_version_major != CCI_CORE_API_VERSION_MAJOR ||
	    p->base.plugin_type_version_minor != CCI_CORE_API_VERSION_MINOR ||
	    p->base.plugin_type_version_release !=
	    CCI_CORE_API_VERSION_RELEASE) {
		return CCI_ERROR;
	}

	return CCI_SUCCESS;
}
