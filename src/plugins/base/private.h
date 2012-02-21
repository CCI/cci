/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 *
 * Types for CCI.
 */

#ifndef CCI_PLUGINS_BASE_PRIVATE_H
#define CCI_PLUGINS_BASE_PRIVATE_H

#include "cci/config.h"

#include "cci.h"
#include "ltdl.h"

BEGIN_C_DECLS
/* From init.c */
extern int cci_plugins_initialized;
extern lt_dladvise cci_plugins_dladvise;

/* From open.c */
extern char **cci_plugins_filename_cache;

END_C_DECLS
#endif /* CCI_PLUGINS_BASE_PRIVATE_H */
