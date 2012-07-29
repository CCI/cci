# -*- shell-script -*-
#
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# Copyright © 2012 Inria.  All rights reserved.
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
# PLUGINS_cci_ctp_eth_CONFIG([action-if-can-compile], 
#                            [action-if-cant-compile])
# ------------------------------------------------
AC_DEFUN([PLUGINS_cci_ctp_eth_CONFIG],[
    AC_REQUIRE([AC_CANONICAL_TARGET])
    case ${target} in
	*-*-linux*) $1;;
	*) $2;;
    esac
])dnl
