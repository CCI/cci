AC_DEFUN([PLUGINS_cci_ctp_eth_CONFIG],[
	AC_ARG_ENABLE(valgrind,
		AC_HELP_STRING(--enable-valgrind, enable Valgrind hooks in the eth plugin),
		enable_valgrind=yes)
	if test x$enable_valgrind = xyes ; then
		AC_PREPROC_IFELSE([
			AC_LANG_SOURCE([
#include <valgrind/memcheck.h>
#ifndef VALGRIND_MAKE_MEM_NOACCESS
#error  VALGRIND_MAKE_MEM_NOACCESS not defined
#endif
			])], valgrind_available=yes)
		if test x$valgrind_available = xyes ; then
			AC_DEFINE(CCIETH_VALGRIND_HOOKS, 1, Enable memory allocation debugging with Valgrind in the eth plugin)
			AC_MSG_NOTICE(activating Valgrind hooks in the eth plugin)
		fi
	fi
])dnl
