dnl -*- shell-script -*-
dnl
dnl Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
dnl                         University Research and Technology
dnl                         Corporation.  All rights reserved.
dnl Copyright (c) 2004-2005 The University of Tennessee and The University
dnl                         of Tennessee Research Foundation.  All rights
dnl                         reserved.
dnl Copyright (c) 2004-2005 High Performance Computing Center Stuttgart, 
dnl                         University of Stuttgart.  All rights reserved.
dnl Copyright (c) 2004-2005 The Regents of the University of California.
dnl                         All rights reserved.
dnl Copyright (c) 2007      Sun Microsystems, Inc.  All rights reserved.
dnl Copyright (c) 2009      Oak Ridge National Labs.  All rights reserved.
dnl Copyright (c) 2009-2010 Cisco Systems, Inc.  All rights reserved.
dnl
dnl $COPYRIGHT$
dnl 
dnl Additional copyrights may follow
dnl 
dnl $HEADER$
dnl

AC_DEFUN([CCI_CONFIGURE_SETUP],[

# Some helper script functions.  Unfortunately, we cannot use $1 kinds
# of arugments here because of the m4 substitution.  So we have to set
# special variable names before invoking the function.  :-\

cci_show_title() {
  cat <<EOF

###
### ${1}
###
EOF
}


cci_show_subtitle() {
  cat <<EOF

*** ${1}
EOF
}


cci_show_subsubtitle() {
  cat <<EOF

+++ ${1}
EOF
}

cci_show_subsubsubtitle() {
  cat <<EOF

--- ${1}
EOF
}

#
# Save some stats about this build
#

CCI_CONFIGURE_USER="`whoami`"
CCI_CONFIGURE_HOST="`hostname | head -n 1`"
CCI_CONFIGURE_DATE="`date`"

#
# Save these details so that they can be used in cci_info later
#
AC_SUBST(CCI_CONFIGURE_USER)
AC_SUBST(CCI_CONFIGURE_HOST)
AC_SUBST(CCI_CONFIGURE_DATE)])dnl

dnl #######################################################################
dnl #######################################################################
dnl #######################################################################

AC_DEFUN([CCI_UNIQ],[
# 1 is the variable name to be uniq-ized
cci_name=$1

# Go through each item in the variable and only keep the unique ones

cci_count=0
for val in ${$1}; do
    cci_done=0
    cci_i=1
    cci_found=0

    # Loop over every token we've seen so far

    cci_done="`expr $cci_i \> $cci_count`"
    while test "$cci_found" = "0" -a "$cci_done" = "0"; do

	# Have we seen this token already?  Prefix the comparison with
	# "x" so that "-Lfoo" values won't be cause an error.

	cci_eval="expr x$val = x\$cci_array_$cci_i"
	cci_found=`eval $cci_eval`

	# Check the ending condition

	cci_done="`expr $cci_i \>= $cci_count`"

	# Increment the counter

	cci_i="`expr $cci_i + 1`"
    done

    # If we didn't find the token, add it to the "array"

    if test "$cci_found" = "0"; then
	cci_eval="cci_array_$cci_i=$val"
	eval $cci_eval
	cci_count="`expr $cci_count + 1`"
    else
	cci_i="`expr $cci_i - 1`"
    fi
done

# Take all the items in the "array" and assemble them back into a
# single variable

cci_i=1
cci_done="`expr $cci_i \> $cci_count`"
cci_newval=
while test "$cci_done" = "0"; do
    cci_eval="cci_newval=\"$cci_newval \$cci_array_$cci_i\""
    eval $cci_eval

    cci_eval="unset cci_array_$cci_i"
    eval $cci_eval

    cci_done="`expr $cci_i \>= $cci_count`"
    cci_i="`expr $cci_i + 1`"
done

# Done; do the assignment

cci_newval="`echo $cci_newval`"
cci_eval="$cci_name=\"$cci_newval\""
eval $cci_eval

# Clean up

unset cci_name cci_i cci_done cci_newval cci_eval cci_count])dnl

dnl #######################################################################
dnl #######################################################################
dnl #######################################################################

# Macro that serves as an alternative to using `which <prog>`. It is
# preferable to simply using `which <prog>` because backticks (`) (aka
# backquotes) invoke a sub-shell which may source a "noisy"
# ~/.whatever file (and we do not want the error messages to be part
# of the assignment in foo=`which <prog>`). This macro ensures that we
# get a sane executable value.
AC_DEFUN([CCI_WHICH],[
# 1 is the variable name to do "which" on
# 2 is the variable name to assign the return value to

CCI_VAR_SCOPE_PUSH([cci_prog cci_file cci_dir cci_sentinel])

cci_prog=$1

IFS_SAVE=$IFS
IFS="$PATH_SEPARATOR"
for cci_dir in $PATH; do
    if test -x "$cci_dir/$cci_prog"; then
        $2="$cci_dir/$cci_prog"
        break
    fi
done
IFS=$IFS_SAVE

CCI_VAR_SCOPE_POP
])dnl
