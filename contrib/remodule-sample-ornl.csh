#!/bin/csh
# This script can either be executed or source'd.

  if ( $# == 0  )  then
	echo "The purpose of this script is to reduce the loaded modules to"
	echo "the minimum necessary to build and run CCI and optionally,"
	echo "NetPIPE with either CCI or MPI driver.  Please specify the"
	echo "Programming Environment to be used for the builds:  gnu, pgi,"
	echo "intel, pathscale (deferred), or cray (deferred) as argument"
	echo "to this script."
	echo ""
  else if  ( "$1" != "gnu" && "$1" != "pgi" && "$1" != "cray" && \
	     "$1" != "pathscale" && "$1" != "intel" )  then
	echo "The "\"$1\"" Programming Environment is not supported."
  else

#	Discover if Gemini network is loaded into the kernel.
	setenv gemini `/bin/lsmod   | /usr/bin/grep -c kgni_gem`
	module         purge
	if ( $gemini > 0   )  then
		module use -a       /ccs/sw/gni/modulefiles
	else
		module use -a       /opt/cray/ss/modulefiles
	endif

	module         load         modules
	module         load         torque
	module         load         moab
	if ( $gemini > 0   )  then
		module load         gni-headers
		module load         ugni
		module load         lustre-cray_gem_s
	else
		module load         portals
		module load         lustre-cray_ss_s/1.8.6
		module load         lustre-cray_ss_s
	endif
	module         load         lustre-utils
	module         load         PrgEnv-$1
	module         unload       xt-libsci
	module         unload       atp

#	Get access to more current releases of autotools.
	module       load         autoconf automake libtool git
  endif
