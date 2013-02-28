#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cci.pc

CCIETH_DRIVER_DIR = contrib/driver/ccieth/linux

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
	config/distscript.csh		\
	$(CCIETH_DRIVER_DIR)/configure.ac		\
	$(CCIETH_DRIVER_DIR)/configure			\
	$(CCIETH_DRIVER_DIR)/check_kernel_headers.sh	\
	$(CCIETH_DRIVER_DIR)/Kbuild.in			\
	$(CCIETH_DRIVER_DIR)/Makefile.in		\
	$(CCIETH_DRIVER_DIR)/ccieth_common.h		\
	$(CCIETH_DRIVER_DIR)/ccieth_hal.h		\
	$(CCIETH_DRIVER_DIR)/ccieth_io.h		\
	$(CCIETH_DRIVER_DIR)/ccieth_main.c		\
	$(CCIETH_DRIVER_DIR)/ccieth_connect.c		\
	$(CCIETH_DRIVER_DIR)/ccieth_msg.c		\
	$(CCIETH_DRIVER_DIR)/ccieth_wire.h

$(CCIETH_DRIVER_DIR)/configure: $(CCIETH_DRIVER_DIR)/configure.ac
	(cd $(top_srcdir)/$(CCIETH_DRIVER_DIR) && autoreconf -ifv)

dist-hook:
	csh "$(top_srcdir)/config/distscript.csh" "$(top_srcdir)" "$(distdir)" "$(HWLOC_VERSION)" "$(HWLOC_SVN_R)"

