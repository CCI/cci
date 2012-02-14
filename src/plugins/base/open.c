/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include <stdio.h>
#include <string.h>

#include "ltdl.h"
#include "util/argv.h"
#include "plugins/base/public.h"
#include "plugins/base/private.h"
#include "plugins/core/core.h"

/* Global variables */
char **cci_plugins_filename_cache = NULL;

/* Private variables */
static const char plugin_prefix[] = "cci_";

/* Private functions */
static int save_filename(const char *filename, lt_ptr data);
static int open_plugin(const char *filename, lt_dlhandle * handle,
		       cci_plugin_t ** plugin,
		       cci_plugins_framework_verify_fn_t verify);

/*
 * Cache all the filenames found in a specific directory.  If
 * flush_cache==1, then empty the cache first.
 */
int cci_plugins_recache_files(const char *dir, int flush_cache)
{
	if (flush_cache) {
		cci_argv_free(cci_plugins_filename_cache);
		cci_plugins_filename_cache = NULL;
	}

	if (0 != lt_dlforeachfile(dir, save_filename, NULL)) {
		fprintf(stderr, "lt_dlforeachfile failed: %s\n", lt_dlerror());
		return CCI_ERROR;
	}

	return CCI_SUCCESS;
}

/*
 * Blindly save all filenames into an argv-style list (but make sure
 * the list is unique).  This function is the callback from
 * lt_dlforeachfile().
 */
static int save_filename(const char *filename, lt_ptr data)
{
	int i;

	if (data)		/* Intel disallows dummy */
		debug(CCI_DB_WARN, "%s: Warning: data=%p is not used", __func__,
		      data);
	/* If the filename is already in the list, just return */
	for (i = 0; NULL != cci_plugins_filename_cache &&
	     NULL != cci_plugins_filename_cache[i]; ++i) {
		if (0 == strcmp(filename, cci_plugins_filename_cache[i])) {
			return 0;
		}
	}

	/* We didn't find it in the list, so append this filename to the
	   list */
	cci_argv_append_nosize(&cci_plugins_filename_cache, filename);

	return 0;
}

/*
 * Open plugins for a given framework
 */
int cci_plugins_open_one(const char *framework,
			 cci_plugins_framework_verify_fn_t verify,
			 cci_plugin_t ** plugin_best, lt_dlhandle * handle_best)
{
	int i;
	size_t prefix_len;
	char *ptr;
	cci_plugin_t *plugin;
	lt_dlhandle handle;
	char prefix[BUFSIZ];

	if (CCI_SUCCESS != (i = cci_plugins_init())) {
		return i;
	}

	snprintf(prefix, BUFSIZ - 1, "%s%s_", plugin_prefix, framework);
	prefix[BUFSIZ - 1] = '\0';
	prefix_len = strlen(prefix);

	*plugin_best = NULL;
	for (i = 0; NULL != cci_plugins_filename_cache &&
	     NULL != cci_plugins_filename_cache[i]; ++i) {
		/* Find the basename */
		if ((ptr = strrchr(cci_plugins_filename_cache[i], '/')) == NULL) {
			ptr = cci_plugins_filename_cache[i];
		} else {
			++ptr;
		}

		/* Is this a possible plugin? */
		if (strncasecmp(ptr, prefix, prefix_len) == 0) {
			if (open_plugin
			    (cci_plugins_filename_cache[i], &handle, &plugin,
			     verify) == CCI_SUCCESS) {
				/* First possibillity of a plugin */
				if (NULL == *plugin_best) {
					if (NULL != plugin->post_load &&
					    CCI_SUCCESS !=
					    plugin->post_load(plugin)) {
						fprintf(stderr,
							"Post load hook for %s failed -- ignored\n",
							ptr);
						lt_dlclose(handle);
						continue;
					}

					/* Post load was happy; this is a keeper */
					*plugin_best = plugin;
					*handle_best = handle;
				}

				/* This new plugin is better than the old one */
				else if (plugin->priority >
					 (*plugin_best)->priority) {
					if (NULL != plugin->post_load
					    && CCI_SUCCESS !=
					    plugin->post_load(plugin)) {
						fprintf(stderr,
							"Post load hook for %s failed -- ignored\n",
							ptr);
						lt_dlclose(handle);
						continue;
					}

					/* Close the previous plugin */
					if (NULL != (*plugin_best)->pre_unload) {
						(*plugin_best)->
						    pre_unload(*plugin_best);
					}
					lt_dlclose(*handle_best);

					/* Keep the new plugin */
					*plugin_best = plugin;
					*handle_best = handle;
				}

				/* This new plugin is worse than the old one */
				else {
					if (NULL != plugin->pre_unload) {
						plugin->pre_unload(plugin);
					}
					lt_dlclose(handle);
				}
			}
		}
	}

	if (NULL == *plugin_best) {
		fprintf(stderr, "Unable to find suitable CCI plugin\n");
		return CCI_ERROR;
	}

	return CCI_SUCCESS;
}

static int open_plugin(const char *filename,
		       lt_dlhandle * handle, cci_plugin_t ** plugin,
		       cci_plugins_framework_verify_fn_t verify)
{
	char *p1, *p2, struct_name[BUFSIZ];
	char *local = strdup(filename);

	if (NULL == local) {
		return CCI_ENOMEM;
	}

	/* Open the DSO */
	*handle = lt_dlopenadvise(local, cci_plugins_dladvise);
	if (NULL == *handle) {
		fprintf(stderr, "Failed to open plugin %s: %s\n",
			filename, lt_dlerror());
		free(local);
		return CCI_ERROR;
	}

	/* Make the struct symbol name */
	p1 = strrchr(local, '/');
	if (NULL == p1) {
		p1 = local;
	} else {
		++p1;
	}
	p2 = strchr(p1, '.');
	if (NULL != p2) {
		*p2 = '\0';
	}

	/* Find the symbol name */
	snprintf(struct_name, BUFSIZ - 1, "%s_plugin", p1);
	free(local);
	struct_name[BUFSIZ - 1] = '\0';
	*plugin = lt_dlsym(*handle, struct_name);
	if (NULL == *plugin) {
		fprintf(stderr,
			"Unable to find \"%s\" symbol in %s -- ignored\n",
			struct_name, filename);
		goto bad;
	}

	/* Version check */
	if ((*plugin)->cci_abi_version != CCI_ABI_VERSION) {
		fprintf(stderr,
			"Plugin \"%s\" in %s supports ABI version %d; only version %d is supported -- ignored\n",
			(*plugin)->plugin_name, filename,
			(*plugin)->cci_abi_version, CCI_ABI_VERSION);
		goto bad;
	}

	/* See if the framework likes it */
	if (NULL != verify && CCI_SUCCESS != verify(*plugin)) {
		goto bad;
	}

	/* Alles gut */
	return CCI_SUCCESS;

bad:
	lt_dlclose(*handle);
	return CCI_ERROR;
}
