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
# PLUGINS_cci_core_verbs_CONFIG([action-if-can-compile], 
#                                  [action-if-cant-compile])
# ------------------------------------------------
AC_DEFUN([PLUGINS_cci_core_verbs_CONFIG],[

    # Sadly, m4 does not allow comments in between each parameter, so
    # they can'tbe documented inline.  :-( See a lengthy comment at
    # the top of config/cci_setup_plugin_package.m4 for a description
    # of what this macro does and what each of the parameters are.
    CCI_SETUP_PLUGIN_PACKAGE([core],
                             [verbs],
                             [verbs],
                             [include/rdma/rdma_cma.h],
                             [librdmacm*],
                             [rdma/rdma_cma.h],
                             [rdmacm],
                             [rdma_create_id],
                             [],
                             [$1],
                             [$2])
])dnl
# This verbs is designed to evade compile.
