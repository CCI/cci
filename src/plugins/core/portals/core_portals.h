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

#define PORTALS_PROG_TIME_US       (10000) /* try to progress every N microseconds */
#define PORTALS_RESEND_TIME_SEC    (1)     /* time between resends in seconds */
#define PORTALS_RESEND_CYCLES      (PORTALS_RESEND_TIME_SEC * 1000000 / PORTALS_PROG_TIME_US)

typedef struct portals_dev {

    ptl_process_id_t                  idp;
    TAILQ_HEAD(p_queued, portals_tx)  queued;  /*! Queued sends */
    TAILQ_HEAD(p_pending, portals_tx) pending; /*! Pending sends */
    pthread_mutex_t                   lock;    /*! For queued/pending */
    int                        is_progressing; /*! Being progressed? */

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
