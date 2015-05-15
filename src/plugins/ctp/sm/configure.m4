# -*- shell-script -*-
#
# Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
#
# $COPYRIGHT$
# 
# Additional copyrights may follow
# 
# $HEADER$
#

# The name of the macro here must be of the form:
#
#     PLUGINS_cci_<type>_<your_plugin_name>_CONFIG
#
# PLUGINS_cci_ctp_sm_CONFIG([action-if-can-compile], 
#                                  [action-if-cant-compile])
# ------------------------------------------------
AC_DEFUN([PLUGINS_cci_ctp_sm_CONFIG],[

    # Sadly, m4 does not allow comments in between each parameter, so
    # they can'tbe documented inline.  :-( See a lengthy comment at
    # the top of config/cci_setup_plugin_package.m4 for a description
    # of what this macro does and what each of the parameters are.
    CCI_SETUP_PLUGIN_PACKAGE([ctp],
                             [sm],
                             [sm],
                             [include/sys/mman.h],
                             [libc*],
                             [sys/mman.h],
                             [c],
                             [fts_open],
                             [],
                             [$1],
                             [$2])
    cflags_save=$CFLAGS
    ldflags_save=$LDFLAGS
    libs_save=$LIBS
    xpmem_dir=no
    AC_ARG_WITH([sm-xpmem],
        [AS_HELP_STRING([--with-sm-xpmem=DIR], [Build xpmem support in sm])],
        [AS_IF([test "x$withval" != xyes], xpmem_dir=$withval)])
    AS_IF([test "x$xpmem_dir" != xyes -a "x$xpmem_dir" != xno],
        [echo xxpmem_dir is "x$xpmem_dir"
         sm_ldadd="-L$xpmem_dir/lib -L$xpmem_dir/lib64"
         sm_libadd="-lxpmem"
         sm_incadd="-I$xpmem_dir/include"
         CFLAGS="$CFLAGS $sm_incadd"
         LDFLAGS="$LDFLAGS $sm_ldadd $sm_libadd"],
        [echo xpmem not specified])
    AC_CHECK_HEADER(xpmem.h,
        [AC_DEFINE([HAVE_XPMEM_H], [1])
	    CFLAGS="$cflags_save"
	    LDFLAGS="$ldflags_save"
	    LIBS="$libs_save"
	    ctp_sm_CFLAGS="$ctp_sm_CFLAGS $sm_incadd"
	    ctp_sm_LDFLAGS="$ctp_sm_LDFLAGS $sm_ldadd"
	    ctp_sm_LIBS="$ctp_sm_LIBS $sm_libadd"],
        [AC_DEFINE([HAVE_XPMEM_H], [0], [Define if xpmem.h detected])
	    CFLAGS="$cflags_save"
	    LDFLAGS="$ldflags_save"
	    LIBS="$libs_save"
	])
    unset cflags_save
    unset ldflags_save
    unset libs_save
    unset sm_ldadd
    unset sm_libadd
    unset sm_incadd

    use_cma=no
    AC_ARG_WITH([sm-cma],
        [AS_HELP_STRING([--with-sm-cma], [Build cma support in sm])])
    AC_CHECK_FUNC(process_vm_writev,
        [AC_DEFINE([HAVE_CMA_H], [1])],
        [AC_DEFINE([HAVE_CMA_H], [0], [Define if cma.h detected])])
])dnl
