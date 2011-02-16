#!/bin/sh
#
# Copyright (c) 2004-2006 The Trustees of Indiana University and Indiana
#                         University Research and Technology
#                         Corporation.  All rights reserved.
# Copyright (c) 2004-2005 The University of Tennessee and The University
#                         of Tennessee Research Foundation.  All rights
#                         reserved.
# Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
#                         University of Stuttgart.  All rights reserved.
# Copyright (c) 2004-2005 The Regents of the University of California.
#                         All rights reserved.
# Copyright © 2008-2011 Cisco Systems, Inc.  All rights reserved.
# $COPYRIGHT$
#
# Additional copyrights may follow
#
# $HEADER$
#

# 16 Feb 2010: amended to be a bit more general with respect to
# repository technologies; use "repo_rev" instead of "svn_r".

# 19 May 2010: this file was copied from r2105 from the hwloc SVN
# trunk.  The only changes were s/hwloc/cci/ig.

# 11 September 2009: this file was copied from PLPA's SVN trunk as of
# r251 on 11 September 2009.  The only change made to it was
# s/PLPA/hwloc/ig.


# CCI_GET_VERSION(version_file, variable_prefix)
# -----------------------------------------------
# parse version_file for version information, setting
# the following shell variables:
#
#  prefix_VERSION
#  prefix_BASE_VERSION
#  prefix_MAJOR_VERSION
#  prefix_MINOR_VERSION
#  prefix_RELEASE_VERSION
#  prefix_GREEK_VERSION
#  prefix_WANT_REPO_REV
#  prefix_REPO_REV
#  prefix_RELEASE_DATE

srcfile="$1"
option="$2"

case "$option" in
    # svnversion can take a while to run.  If we don't need it, don't run it.
    --major|--minor|--release|--greek|--base|--help)
        ompi_ver_need_repo_rev=0
        ;;
    *)
        ompi_ver_need_repo_rev=1
esac


if test -z "$srcfile"; then
    option="--help"
else

    : ${ompi_ver_need_repo_rev=1}
    : ${srcdir=.}
    # Some people like to override svnversion because it takes a long
    # time on networked filesystems with a big checkout.
    : ${svnversion_result=-1}

        if test -f "$srcfile"; then
        ompi_vers=`sed -n "
	t clear
	: clear
	s/^major/CCI_MAJOR_VERSION/
	s/^minor/CCI_MINOR_VERSION/
	s/^release/CCI_RELEASE_VERSION/
	s/^greek/CCI_GREEK_VERSION/
	s/^want_repo_rev/CCI_WANT_REPO_REV/
	s/^repo_rev/CCI_REPO_REV/
	s/^date/CCI_RELEASE_DATE/
	t print
	b
	: print
	p" < "$srcfile"`
	eval "$ompi_vers"

        # Only print release version if it isn't 0
        if test $CCI_RELEASE_VERSION -ne 0 ; then
            CCI_VERSION="$CCI_MAJOR_VERSION.$CCI_MINOR_VERSION.$CCI_RELEASE_VERSION"
        else
            CCI_VERSION="$CCI_MAJOR_VERSION.$CCI_MINOR_VERSION"
        fi
        CCI_VERSION="${CCI_VERSION}${CCI_GREEK_VERSION}"
        CCI_BASE_VERSION=$CCI_VERSION

        if test $CCI_WANT_REPO_REV -eq 1 && test $ompi_ver_need_repo_rev -eq 1 ; then
            if test "$svnversion_result" != "-1" ; then
                CCI_REPO_REV=$svnversion_result
            fi
            if test "$CCI_REPO_REV" = "-1" ; then

                if test -d "$srcdir/.svn" ; then
                    CCI_REPO_REV=r`svnversion "$srcdir"`
                elif test -d "$srcdir/.hg" ; then
                    CCI_REPO_REV=hg`hg -v -R "$srcdir" tip | grep changeset | cut -d: -f3`
                elif test -d "$srcdir/.git" ; then
                    CCI_REPO_REV=git`git log -1 "$srcdir" | grep commit | awk '{ print $2 }'`
                fi
                if test "CCI_REPO_REV" = ""; then
                    CCI_REPO_REV=date`date '+%m%d%Y'`
                fi

            fi
            CCI_VERSION="${CCI_VERSION}${CCI_REPO_REV}"
        fi
    fi


    if test "$option" = ""; then
	option="--full"
    fi
fi

case "$option" in
    --full|-v|--version)
	echo $CCI_VERSION
	;;
    --major)
	echo $CCI_MAJOR_VERSION
	;;
    --minor)
	echo $CCI_MINOR_VERSION
	;;
    --release)
	echo $CCI_RELEASE_VERSION
	;;
    --greek)
	echo $CCI_GREEK_VERSION
	;;
    --repo-rev)
	echo $CCI_REPO_REV
	;;
    --base)
        echo $CCI_BASE_VERSION
        ;;
    --release-date)
        echo $CCI_RELEASE_DATE
        ;;
    --all)
        echo ${CCI_VERSION} ${CCI_MAJOR_VERSION} ${CCI_MINOR_VERSION} ${CCI_RELEASE_VERSION} ${CCI_GREEK_VERSION} ${CCI_REPO_REV}
        ;;
    -h|--help)
	cat <<EOF
$0 <srcfile> <option>

<srcfile> - Text version file
<option>  - One of:
    --full         - Full version number
    --major        - Major version number
    --minor        - Minor version number
    --release      - Release version number
    --greek        - Greek (alpha, beta, etc) version number
    --svn          - Subversion repository number
    --all          - Show all version numbers, separated by :
    --base         - Show base version number (no svn number)
    --release-date - Show the release date
    --help         - This message
EOF
        ;;
    *)
        echo "Unrecognized option $option.  Run $0 --help for options"
        ;;
esac

# All done

exit 0
