# Discover if Gemini network is loaded into the kernel.
  gemini=`/bin/lsmod   | /usr/bin/grep -c kgni_gem`
  module       purge
  if [ $gemini -gt 0 ]; then
	module use -a       /ccs/sw/gni/modulefiles
  else
	module use -a       /opt/cray/ss/modulefiles
  fi

  module       load         modules
  module       load         torque
  module       load         moab
  if [ $gemini -gt 0 ]; then
	module load         gni-headers
	module load         ugni
	module load         lustre-cray_gem_s
  else
	module load         portals
	module load         lustre-cray_ss_s/1.8.6
	module load         lustre-cray_ss_s
  fi
  module       load         lustre-utils
  module       load         PrgEnv-$1
  module       unload       xt-libsci
  module       unload       atp

# Get access to more current releases of autotools.
  module       load         autoconf automake libtool git
