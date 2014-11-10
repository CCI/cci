#
# Copyright (c) 2013 UT-Battellee, LLC.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_ctp_sm.la

cci_ctp_sm_la_CFLAGS = $(ctp_sm_CFLAGS)
cci_ctp_sm_la_LDFLAGS = -module -avoid-version $(ctp_sm_LDFLAGS) $(ctp_sm_LIBS)
cci_ctp_sm_la_SOURCES = \
        ctp_sm.h \
        ctp_sm_module.c \
        ctp_sm_api.c \
	ring.h \
	ring.c \
	sm_atomics.h
