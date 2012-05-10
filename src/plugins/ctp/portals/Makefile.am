#
# Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
# Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_ctp_portals.la

cci_ctp_portals_la_LDFLAGS = -module -avoid-version
cci_ctp_portals_la_SOURCES = \
        ctp_portals.h \
        ctp_portals_module.c \
        ctp_portals_api.c

AM_CPPFLAGS = $(ctp_portals_CPPFLAGS) $(pmi_CPPFLAGS)
LIBS       += $(ctp_portals_LDFLAGS)  $(pmi_LDFLAGS) $(alps_LDFLAGS)
LIBS       += $(ctp_portals_LIBS)     $(pmi_LIBS)    $(alps_LIBS)
