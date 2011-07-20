#!/bin/sh
# This script can either be executed or expanded in place [. {this script}].

  if [ $# -eq 0 ]; then
	echo "The purpose of this script is to reduce the loaded modules to"
	echo "the minimum necessary to build and run CCI and optionally,"
	echo "NetPIPE with either CCI or MPI driver.  Please specify the"
	echo "Programming Environment to be used for the builds:  gnu, pgi,"
	echo "intel, pathscale (deferred), or cray (deferred) as argument"
	echo "to this script."
	echo ""
  elif     [ "$1" != "gnu" -a "$1" != "pgi" -a "$1" != "cray" -a \
	     "$1" != "pathscale" -a "$1" != "intel" ]; then
	echo "The "\"$1\"" Programming Environment is not supported."
  else

#	Discover if Gemini network is loaded into the kernel.
	gemini=`/bin/lsmod   | /usr/bin/grep -c kgni_gem`
	module         purge
	if [ $gemini -gt 0 ]; then
		module use -a       /ccs/sw/gni/modulefiles
	else
		module use -a       /opt/cray/ss/modulefiles
	fi

	module         load         modules
	module         load         torque
	module         load         moab
	if [ $gemini -gt 0 ]; then
		module load         gni-headers
		module load         ugni
		module load         lustre-cray_gem_s
	else
		module load         portals
		module load         lustre-cray_ss_s/1.8.6
		module load         lustre-cray_ss_s
	fi
	module         load         lustre-utils
	module         load         PrgEnv-$1
	module         unload       xt-libsci
	module         unload       atp

#	Get access to more current releases of autotools.
	module       load         autoconf automake libtool git
  fi
