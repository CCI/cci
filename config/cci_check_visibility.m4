# This macro set originally copied from Open MPI:
# Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
#                         University Research and Technology
#                         Corporation.  All rights reserved.
# Copyright (c) 2004-2005 The University of Tennessee and The University
#                         of Tennessee Research Foundation.  All rights
#                         reserved.
# Copyright (c) 2004-2007 High Performance Computing Center Stuttgart, 
#                         University of Stuttgart.  All rights reserved.
# Copyright (c) 2004-2005 The Regents of the University of California.
#                         All rights reserved.
# Copyright (c) 2006-2007 Cisco Systems, Inc.  All rights reserved.
# and renamed for cci:
# Copyright (c) 2009 INRIA, Université Bordeaux 1
# Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
# - Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer listed
#   in this license in the documentation and/or other materials
#   provided with the distribution.
# 
# - Neither the name of the copyright holders nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# The copyright holders provide no reassurances that the source code
# provided does not infringe any patent, copyright, or any other
# intellectual property rights of third parties.  The copyright holders
# disclaim any liability to any recipient for claims brought against
# recipient by any third party for infringement of that parties
# intellectual property rights.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


# _CCI_CHECK_VISIBILITY
# --------------------------------------------------------
AC_DEFUN([_CCI_CHECK_VISIBILITY],[
    AC_REQUIRE([AC_PROG_GREP])

    # Check if the compiler has support for visibility, like some versions of gcc, icc.
    AC_ARG_ENABLE(visibility, 
        AC_HELP_STRING([--enable-visibility],
            [enable visibility feature of certain compilers/linkers (default: enabled)]))
    if test "$enable_visibility" = "no"; then
        AC_MSG_CHECKING([enable symbol visibility])
        AC_MSG_RESULT([no]) 
        have_visibility=0
    else
        CFLAGS_orig="$CFLAGS"
        CFLAGS="$CFLAGS_orig -fvisibility=hidden"
        cci_add=
        AC_CACHE_CHECK([if $CC supports -fvisibility],
            [cci_cv_cc_fvisibility],
            [AC_TRY_LINK([
                    #include <stdio.h>
                    __attribute__((visibility("default"))) int foo;
                    void bar(void) { fprintf(stderr, "bar\n"); };
                    ],[],
                    [if test -s conftest.err ; then
                        $GREP -iq "visibility" conftest.err
                        if test "$?" = "0" ; then
                            cci_cv_cc_fvisibility="no"
                        else
                            cci_cv_cc_fvisibility="yes"
                        fi
                     else
                        cci_cv_cc_fvisibility="yes"
                     fi],
                    [cci_cv_cc_fvisibility="no"])
                ])

        if test "$cci_cv_cc_fvisibility" = "yes" ; then
            cci_add=" -fvisibility=hidden"
            have_visibility=1
            AC_MSG_CHECKING([enable symbol visibility])
            AC_MSG_RESULT([yes]) 
        elif test "$enable_visibility" = "yes"; then
            AC_MSG_ERROR([Symbol visibility support requested but compiler does not seem to support it.  Aborting])
        else 
            AC_MSG_CHECKING([enable symbol visibility])
            AC_MSG_RESULT([no]) 
            have_visibility=0
        fi
        CFLAGS=$CFLAGS_orig
        CCI_VISIBILITY_CFLAGS=$cci_add
        unset cci_add 
    fi
    AC_DEFINE_UNQUOTED([CCI_HAVE_VISIBILITY], [$have_visibility],
            [Whether C compiler supports -fvisibility])
])dnl
