/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 *
 * Plugin types for CCI.
 */

#ifndef CCI_PLUGINS_H
#define CCI_PLUGINS_H

#include "cci/config.h"
#include "cci.h"

BEGIN_C_DECLS

/* Forward declaration */
struct cci_plugin_t;

/*
 * Typedefs for all CCI plugins.
 */
typedef int (*cci_plugin_post_load_fn_t)(struct cci_plugin_t *me);
typedef int (*cci_plugin_pre_unload_fn_t)(struct cci_plugin_t *me);

/* Plugin struct */

typedef struct cci_plugin_t {
    /* What CCI ABI version number this plugin supports */
    int cci_abi_version;

    /* Name of this plugin type */
    const char plugin_type[128];

    /* Major, minor, and release version number of the plugin type
       that this plugin supports. */
    int plugin_type_version_major, plugin_type_version_minor,
        plugin_type_version_release;

    /* A human-readable name for this plugin */
    const char plugin_name[128];

    /* Major, minor, and release version numbers for this plugin */
    int plugin_version_major, plugin_version_minor, plugin_version_release;

    /* Priority of this plugin (compared to other plugins) */
    int priority;

    /* Plugin bootstrap / shutdown function pointers */
    cci_plugin_post_load_fn_t post_load;
    cci_plugin_pre_unload_fn_t pre_unload;
} cci_plugin_t;

END_C_DECLS

#endif /* CCI_PLUGINS_H */
