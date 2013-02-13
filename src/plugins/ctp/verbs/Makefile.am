#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_ctp_verbs.la

AM_CPPFLAGS = $(ctp_verbs_CPPFLAGS)
cci_ctp_verbs_la_LDFLAGS = -module -avoid-version $(ctp_verbs_LDFLAGS)
cci_ctp_verbs_la_SOURCES = \
        ctp_verbs.h \
        ctp_verbs_module.c \
        ctp_verbs_api.c
cci_ctp_verbs_la_LIBADD = $(ctp_verbs_LIBS)
