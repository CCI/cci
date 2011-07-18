#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES =      cci_core_gni.la

cci_core_gni_la_LDFLAGS = -module -avoid-version
cci_core_gni_la_SOURCES = core_gni.h        \
                          core_gni_module.c \
                          core_gni_api.c

AM_CPPFLAGS = $(core_gni_CPPFLAGS) $(pmi_CPPFLAGS)
LIBS       += $(core_gni_LDFLAGS)  $(pmi_LDFLAGS) $(alps_LDFLAGS)
LIBS       += $(core_gni_LIBS)     $(pmi_LIBS)    $(alps_LIBS)
