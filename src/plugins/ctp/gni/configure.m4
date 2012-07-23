# -*- shell-script -*-
#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
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
# PLUGINS_cci_ctp_gni_CONFIG([action-if-can-compile], 
#                             [action-if-cant-compile])
# ------------------------------------------------
AC_DEFUN([PLUGINS_cci_ctp_gni_CONFIG],[

    # Sadly, m4 does not allow comments in between each parameter, so
    # they can't be documented inline. See a lengthy comment at
    # the top of config/cci_setup_plugin_package.m4 for a description
    # of what this macro does and what each of the parameters are.
    CCI_SETUP_PLUGIN_PACKAGE([ctp],
                             [gni],
                             [gni],
                             [include/gni_pub.h],
                             [libugni*],
                             [gni_pub.h],
                             [ugni],
                             [GNI_CdmCreate],
                             [],
                             [$1],
                             [$2])
    AC_ARG_WITH([gni-ptag],
                [AS_HELP_STRING([--with-gni-ptag=NUM], [set CCI system PTAG])],
                [AC_DEFINE_UNQUOTED([GNI_PTAG], [$withval], [CCI system PTAG])],
                [AC_DEFINE_UNQUOTED([GNI_PTAG], [208])])
    AC_ARG_WITH([gni-cookie],
                [AS_HELP_STRING([--with-gni-cookie=NUM], [set CCI system COOKIE])],
                [AC_DEFINE_UNQUOTED([GNI_COOKIE], [$withval], [CCI system COOKIE])],
                [AC_DEFINE_UNQUOTED([GNI_COOKIE], [0x73e70000])])
])dnl
