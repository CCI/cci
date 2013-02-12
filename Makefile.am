#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

# Note that the -I directory must *exactly* match what was specified
# via AC_CONFIG_MACRO_DIR in configure.ac.
ACLOCAL_AMFLAGS = -I ./config

SUBDIRS = include src examples

#
# "make distcheck" requires that tarballs are able to be able to "make
# dist", so we have to include config/distscript.csh.
#
EXTRA_DIST = 				\
	VERSION				\
	COPYING				\
	INSTALL				\
	README				\
	README.ctp.eth			\
	README.ctp.gni			\
	README.ctp.sock			\
	README.ctp.verbs		\
	config/cci_get_version.sh 	\
	config/distscript.csh

dist-hook:
	csh "$(top_srcdir)/config/distscript.csh" "$(top_srcdir)" "$(distdir)" "$(HWLOC_VERSION)" "$(HWLOC_SVN_R)"

