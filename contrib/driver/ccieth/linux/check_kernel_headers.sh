#!/bin/sh

#
# Copyright © 2007-2012 Inria.  All rights reserved.
# $COPYRIGHT$
#

FORCE=0

if test $# -ge 1 && test "$1" = "--force" ; then
  FORCE=1
  shift
fi

if test $# -lt 3 ; then
  echo "Options:"
  echo "  --force	Check again even if the arguments did not change"
  echo "Need 3 command line arguments:"
  echo "  - header checks output file"
  echo "  - kernel source tree path"
  echo "  - kernel build tree path"
  exit -1
fi

CHECKS_NAME="$1"
LINUX_SRC="$2"
LINUX_BUILD="$3"

CONFIG_LINE="Ran with BUILD=\"$LINUX_BUILD\" SRC=\"$LINUX_SRC\""
if test "$FORCE" != 1 && grep "$CONFIG_LINE" "$CHECKS_NAME" >/dev/null 2>&1; then
  # no need to rerun
  exit 0
fi

# create destination directory if needed
mkdir -p `dirname ${CHECKS_NAME}`

# create the output file
CHECKS_DATE_PREFIX="This file has been first generated on "
TMP_CHECKS_NAME=${CHECKS_NAME}.tmp
rm -f ${TMP_CHECKS_NAME}

# add the header
echo "#ifndef CCIETH_CHECKS_H" >> ${TMP_CHECKS_NAME}
echo "#define CCIETH_CHECKS_H 1" >> ${TMP_CHECKS_NAME}
echo "" >> ${TMP_CHECKS_NAME}

# what command line was used to generate with file
echo "/*" >> ${TMP_CHECKS_NAME}
echo " * ${CHECKS_DATE_PREFIX}"`date` >> ${TMP_CHECKS_NAME}
echo " * ${CONFIG_LINE}" >> ${TMP_CHECKS_NAME}
echo " */" >> ${TMP_CHECKS_NAME}
echo "" >> ${TMP_CHECKS_NAME}

# dev_getbyhwaddr_rcu added in 2.6.38
echo -n "  checking (in kernel headers) dev_getbyhwaddr_rcu availability ... "
if grep "dev_getbyhwaddr_rcu(" ${LINUX_SRC}/include/linux/netdevice.h > /dev/null ; then
  echo "#define CCIETH_HAVE_DEV_GETBYHWADDR_RCU 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# kfree_rcu added in 3.0
echo -n "  checking (in kernel headers) kfree_rcu availability ... "
if grep kfree_rcu ${LINUX_SRC}/include/linux/rcupdate.h > /dev/null ; then
  echo "#define CCIETH_HAVE_KFREE_RCU 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# add the footer
echo "" >> ${TMP_CHECKS_NAME}
echo "#endif /* CCIETH_CHECKS_H */" >> ${TMP_CHECKS_NAME}

# install final file
if diff -q ${CHECKS_NAME} ${TMP_CHECKS_NAME} --ignore-matching-lines="${CHECKS_DATE_PREFIX}" >/dev/null 2>&1; then
  echo "  ${CHECKS_NAME} is unchanged"
  rm -f ${TMP_CHECKS_NAME}
else
  echo "  creating ${CHECKS_NAME}"
  mv -f ${TMP_CHECKS_NAME} ${CHECKS_NAME}
fi
