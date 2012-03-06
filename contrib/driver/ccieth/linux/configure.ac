#
# Copyright © 2011-2012 Inria.  All rights reserved.
# $COPYRIGHT$
#

AC_INIT(ccieth,
	0.0.1,
	[http://www.cci-forum.org],
	ccieth)
AC_CONFIG_SRCDIR(ccieth_main.c)
AC_CONFIG_LINKS(ccieth_main.c:ccieth_main.c)
AC_CONFIG_LINKS(ccieth_msg.c:ccieth_msg.c)
AC_CONFIG_LINKS(ccieth_rma.c:ccieth_rma.c)
AC_CONFIG_LINKS(ccieth_connect.c:ccieth_connect.c)
AC_CONFIG_LINKS(ccieth_common.h:ccieth_common.h)
AC_CONFIG_LINKS(ccieth_hal.h:ccieth_hal.h)
AC_CONFIG_LINKS(ccieth_wire.h:ccieth_wire.h)
AC_CONFIG_LINKS(ccieth_io.h:ccieth_io.h)

AC_ARG_WITH(linux-release,
	    AC_HELP_STRING(--with-linux-release=<version>, release number of the target kernel),
	    linux_uts_release=$withval,
	    linux_uts_release=`uname -r`)
AC_ARG_WITH(linux,
	    AC_HELP_STRING(--with-linux=<path>, path to the target kernel source tree),
	    [linux_path=$withval;
	     linux_build_path=$withval],
	    [linux_path="/lib/modules/${linux_uts_release}/source";
	     linux_build_path="/lib/modules/${linux_uts_release}/build"])
AC_ARG_WITH(linux-build,
	    AC_HELP_STRING(--with-linux-build=<path>, path to the target kernel build tree),
	    linux_build_path=$withval)
AC_SUBST(CCIETH_LINUX_BUILD_PATH, $linux_build_path)

AC_MSG_NOTICE([checking kernel headers ...])
${srcdir}/check_kernel_headers.sh --force ./ccieth_checks.h "$linux_path" "$linux_build_path"

AC_OUTPUT(Makefile Kbuild)
