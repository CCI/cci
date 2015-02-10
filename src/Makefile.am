#
# Copyright © 2010-2011 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

SUBDIRS = \
        libltdl \
	openpa \
        api \
        plugins/base \
        util \
        $(PLUGINS_cci_FRAMEWORKS_SUBDIRS) \
        $(PLUGINS_cci_FRAMEWORK_PLUGIN_STATIC_SUBDIRS) \
        . \
        $(PLUGINS_cci_FRAMEWORK_PLUGIN_DSO_SUBDIRS) \
        tests

DIST_SUBDIRS = \
        libltdl \
	openpa \
        api \
        plugins/base \
        util \
        $(PLUGINS_cci_FRAMEWORKS_SUBDIRS) \
        $(PLUGINS_cci_FRAMEWORK_PLUGIN_ALL_SUBDIRS) \
        tests

noinst_HEADERS = plugins/plugins.h

lib_LTLIBRARIES = libcci.la
libcci_la_SOURCES =
libcci_la_LIBADD = \
	openpa/src/libopa.la \
        api/libcci_api.la \
        plugins/base/libcci_plugins_base.la \
        util/libcci_util.la \
        libltdl/libltdlc.la \
        $(PLUGINS_cci_FRAMEWORK_LIBS)
libcci_la_DEPENDENCIES = $(libcci_la_LIBADD)
libcci_la_LDFLAGS = -version-info $(libcci_so_version)
