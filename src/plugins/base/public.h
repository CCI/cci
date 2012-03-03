/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 *
 * Types for CCI.
 */

#ifndef CCI_PLUGINS_BASE_PUBLIC_H
#define CCI_PLUGINS_BASE_PUBLIC_H

#include "cci/config.h"

#include "cci.h"
#include "ltdl.h"
#include "plugins/plugins.h"

BEGIN_C_DECLS

struct cci_plugin_handle {
	cci_plugin_t *plugin;
	lt_dlhandle handle;
};

/* Startup the CCI plugins system */
int cci_plugins_init(void);

/* Typedef to allow frameworks to "verify" plugins before they are
   selected */
typedef int (*cci_plugins_framework_verify_fn_t) (cci_plugin_t * plugin);

/* Open all modules of a given framework and return arrays of LT
   handles and pointers to its plugin struct. */
int cci_plugins_open_all(const char *framework,
			 cci_plugins_framework_verify_fn_t verify,
			 struct cci_plugin_handle ** plugins);

/* Normally we only read in the DSO filenames once.  But this function
   can be used to refresh that filename list cache. */
int cci_plugins_recache_files(const char *dir, int flush_cache);

/* This is currently never called, but might as well have it to track
   what things would need to be released if we ever do want to shut
   down. */
int cci_plugins_finalize(void);

END_C_DECLS
#endif				/* CCI_PLUGINS_BASE_PUBLIC_H */
