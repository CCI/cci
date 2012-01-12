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
AC_CONFIG_LINKS(ccieth_recv.c:ccieth_recv.c)
AC_CONFIG_LINKS(ccieth_connect.c:ccieth_connect.c)
AC_CONFIG_LINKS(ccieth_common.h:ccieth_common.h)
AC_CONFIG_LINKS(ccieth_wire.h:ccieth_wire.h)
AC_CONFIG_LINKS(ccieth_io.h:ccieth_io.h)

AC_ARG_WITH(linux-release,
	    AC_HELP_STRING(--with-linux-release=<version>, release number of the target kernel),
	    linux_uts_release=$withval,
	    linux_uts_release=`uname -r`)
AC_ARG_WITH(linux-build,
	    AC_HELP_STRING(--with-linux-build=<path>, path to the target kernel build tree),
	    linux_build_path=$withval,
	    linux_build_path="/lib/modules/${linux_uts_release}/build")
AC_SUBST(CCIETH_LINUX_BUILD_PATH, $linux_build_path)

AC_OUTPUT(Makefile Kbuild)
