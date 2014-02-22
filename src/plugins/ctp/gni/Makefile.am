#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES =      cci_ctp_gni.la

cci_ctp_gni_la_LDFLAGS = -module -avoid-version $(ctp_gni_LDFLAGS) -pthread
cci_ctp_gni_la_SOURCES = ctp_gni.h        \
                          ctp_gni_module.c \
                          ctp_gni_api.c

cci_ctp_gni_la_LIBADD = $(ctp_gni_LIBS) $(top_builddir)/src/libcci.la
