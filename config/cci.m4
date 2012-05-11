dnl -*- Autoconf -*-
dnl
dnl Copyright © 2010 Cisco Systems, Inc.  All rights reserved.
dnl Copyright © 2012 UT-Battelle, LLC.  All rights reserved.
dnl Copyright © 2012 Oak Ridge National Labs.  All rights reserved.
dnl

# Define CCI configure command line arguments
AC_DEFUN([CCI_DEFINE_ARGS],[
    AC_ARG_ENABLE([picky],
        [AC_HELP_STRING([--enable-picky],
                        [Turn on maintainer-level compiler pickyness])])
    AS_IF([test -d $srcdir/.hg -o -d $srcdir/.svn],
          [CCI_DEVEL_BUILD=yes
           AS_IF([test "$enable_picky" = ""],
                 [AC_MSG_WARN([Developer build: enabling pickyness by default])
                  enable_picky=yes])])
])

# Main CCI m4 macro
#
# Expects two or three paramters:
# 1. Configuration prefix
# 2. What to do upon success
# 3. What to do upon failure
# 4. If non-empty, print the announcement banner
#
AC_DEFUN([CCI_SETUP_CTP],[
    AC_REQUIRE([AC_PROG_CC])
    AC_REQUIRE([AM_PROG_CC_C_O])

    AS_IF([test "x$4" != "x"],
          [cci_show_title "Configuring CCI ctp"])

    # If no prefix was defined, set a good value
    m4_ifval([$1], 
             [m4_define([cci_config_prefix],[$1/])],
             [m4_define([cci_config_prefix], [])])

    # Get cci's absolute top builddir (which may not be the same as
    # the real $top_builddir, because we may be building in embedded
    # mode).
    CCI_startdir=`pwd`
    if test x"cci_config_prefix" != "x" -a ! -d "cci_config_prefix"; then
        mkdir -p "cci_config_prefix"
    fi
    if test x"cci_config_prefix" != "x"; then
        cd "cci_config_prefix"
    fi
    CCI_top_builddir=`pwd`
    AC_SUBST(CCI_top_builddir)

    # Get cci's absolute top srcdir (which may not be the same as
    # the real $top_srcdir, because we may be building in embedded
    # mode).  First, go back to the startdir incase the $srcdir is
    # relative.
    cd "$CCI_startdir"
    cd "$srcdir"/cci_config_prefix
    CCI_top_srcdir="`pwd`"
    AC_SUBST(CCI_top_srcdir)

    # Go back to where we started
    cd "$CCI_startdir"

    AC_MSG_NOTICE([cci builddir: $CCI_top_builddir])
    AC_MSG_NOTICE([cci srcdir: $CCI_top_srcdir])
    if test "$CCI_top_builddir" != "$CCI_top_srcdir"; then
        AC_MSG_NOTICE([Detected VPATH build])
    fi

    # Add relevant -I's for our internal header files
    CPPFLAGS="$CPPFLAGS -I$CCI_top_srcdir/include"
    if test "$CCI_top_builddir" != "$CCI_top_srcdir"; then
        CPPFLAGS="$CPPFLAGS -I$CCI_top_builddir/include"
    fi
    CPPFLAGS="$CPPFLAGS -I$CCI_top_srcdir/src -I$CCI_top_srcdir/src/libltdl"
    CPPFLAGS="$CPPFLAGS -I$CCI_top_srcdir/src/api"

    # Look for some header files
    AC_CHECK_HEADERS(errno.h stdint.h sys/types.h sys/time.h sys/uio.h)

    # We need to set a path for header, etc files depending on whether
    # we're standalone or embedded. this is taken care of by CCI_EMBEDDED.
    AC_MSG_CHECKING([for cci directory prefix])
    AC_MSG_RESULT(m4_ifval([$1], cci_config_prefix, [(none)]))

    # If we want picky, be picky.
    CCI_C_COMPILER_VENDOR([cci_cc_vendor])
    AS_IF([test "$enable_picky" = yes -a "$cci_cc_vendor" = "gnu"],
          [cci_add="-Wall -Wundef -Wsign-compare"
           cci_add="$cci_add -Wmissing-prototypes -Wstrict-prototypes"
           cci_add="$cci_add -Wcomment -pedantic"
           cci_add="$cci_add -Werror-implicit-function-declaration "
           cci_add="$cci_add -Wstrict-prototypes"
           CFLAGS="$CFLAGS $cci_add"
	   CCI_UNIQ(CFLAGS)
           AC_MSG_WARN([$cci_add has been added to CFLAGS (--enable-picky)])
           unset cci_add])
    AS_IF([test "$CCI_DEVEL_BUILD" = "yes"],
          [AC_MSG_WARN([-g has been added to CFLAGS (developer build)])
           CFLAGS="$CFLAGS -g"])

    #
    # Basic sanity checking; we can't install to a relative path
    #
    cci_prefix=$prefix
    case "$cci_prefix" in
      /*/bin)
        cci_prefix="`dirname $cci_prefix`"
        echo installing to directory \"$cci_prefix\" 
        ;;
      /*) 
        echo installing to directory \"$cci_prefix\" 
        ;;
      NONE)
        echo installing to directory \"$ac_default_prefix\" 
        cci_prefix=$ac_default_prefix
        ;;
      @<:@a-zA-Z@:>@:*)
        echo installing to directory \"$cci_prefix\" 
        ;;
      *) 
        AC_MSG_ERROR(prefix "$cci_prefix" must be an absolute directory path) 
        ;;
    esac

    # Save sysconfdir
    cci_prefix_save="${prefix}"
    prefix=$cci_prefix
    cci_exec_prefix_save="${exec_prefix}"
    test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
    cci_pkglibdir=`eval echo $libdir/cci`
    AC_DEFINE_UNQUOTED([CCI_PKGLIBDIR], ["$cci_pkglibdir"], 
                       [pkglibdir from configure])
    exec_prefix="${cci_exec_prefix_save}"
    prefix="${cci_prefix_save}"

    # Run some tests
    _CCI_CHECK_ATTRIBUTES
    _CCI_CHECK_VISIBILITY

    # Setup output files
    AM_CONFIG_HEADER(cci_config_prefix[include/cci/configure_output.h])

    AC_CONFIG_FILES(cci_config_prefix[Makefile])
    AC_CONFIG_FILES(cci_config_prefix[include/Makefile])

    AC_CONFIG_FILES(cci_config_prefix[src/Makefile])
    AC_CONFIG_FILES(cci_config_prefix[src/api/Makefile])
    AC_CONFIG_FILES(cci_config_prefix[src/plugins/base/Makefile])
    AC_CONFIG_FILES(cci_config_prefix[src/util/Makefile])
    AC_CONFIG_FILES(cci_config_prefix[src/tests/Makefile])

    # Setup the plugins
    m4_include([config/autogen_found_items.m4])
    CCI_PLUGINS

    # Party on
    $2
])
