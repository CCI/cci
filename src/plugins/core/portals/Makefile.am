#
# Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
# Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_core_portals.la

cci_core_portals_la_LDFLAGS = -module -avoid-version
cci_core_portals_la_SOURCES = \
        core_portals.h \
        core_portals_module.c \
        core_portals_api.c

AM_CPPFLAGS = $(core_portals_CPPFLAGS) $(pmi_CPPFLAGS)
LIBS       += $(core_portals_LDFLAGS)  $(pmi_LDFLAGS) $(alps_LDFLAGS)
LIBS       += $(core_portals_LIBS)     $(pmi_LIBS)    $(alps_LIBS)
