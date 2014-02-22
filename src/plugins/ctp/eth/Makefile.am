#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# Copyright © 2011 Inria.  All rights reserved.
# $COPYRIGHT$
#

pkglib_LTLIBRARIES = cci_ctp_eth.la

cci_ctp_eth_la_LDFLAGS = -module -avoid-version
cci_ctp_eth_la_SOURCES = \
        ctp_eth.h \
        ctp_eth_module.c \
        ctp_eth_api.c
cci_ctp_eth_la_LIBADD = $(top_builddir)/src/libcci.la

AM_CPPFLAGS = -I@abs_top_srcdir@/contrib/driver/ccieth/linux
