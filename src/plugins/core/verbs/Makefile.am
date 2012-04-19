#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_core_verbs.la

cci_core_verbs_la_LDFLAGS = -module -avoid-version $(core_verbs_LDFLAGS)
cci_core_verbs_la_SOURCES = \
        core_verbs.h \
        core_verbs_module.c \
        core_verbs_api.c
cci_core_verbs_la_LIBADD = $(core_verbs_LIBS)
