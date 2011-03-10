/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCI_CORE_PORTALS_H
#define CCI_CORE_PORTALS_H

#include <portals/portals3.h>
#include "cci/config.h"

BEGIN_C_DECLS

typedef struct portals_dev {

    ptl_process_id_t idp;
} portals_dev_t;

typedef struct portals_globals {

    int count;                      /* Number of portals devices */
    const cci_device_t **devices;   /* Array of portals devices */
    int                shutdown;    /* In shutdown? */
} portals_globals_t;
extern portals_globals_t *pglobals;

int cci_core_portals_post_load(cci_plugin_t *me);
int cci_core_portals_pre_unload(cci_plugin_t *me);

END_C_DECLS

#endif /* CCI_CORE_PORTALS_H */
