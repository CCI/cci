  module       purge        2>/dev/null
  if [ -f /etc/xthostname ]; then
	module use -a       /opt/cray/ss/modulefiles
  else
	module use -a       /ccs/sw/gni/modulefiles
  fi

# Start with GNU.
  module       load         modules
  module       load         torque
  module       load         moab
  if [ -f /etc/xthostname ]; then
	module load         portals
	module load         lustre-cray_ss_s/1.8.6
	module load         lustre-cray_ss_s
  else
	module load         gni-headers
	module load         ugni
	module load         lustre-cray_gem_s
  fi
  module       load         lustre-utils
  module       load         PrgEnv-gnu
  module       unload       xt-libsci
  module       unload       atp

# Get access to more current releases of autotools.
  module       load         autoconf automake libtool git

# At least for now, we will avoid Cray Programming Environment
# interfaces, so we need to set CPPFLAGS and LDFLAGS.
  export       PKG="/usr/bin/pkg-config --silence-errors"
  export       CCI_CONFIG="../../contrib/ornl.ini"
  export       CPP_PMI=` $PKG --cflags cray-pmi`
  export       CPP_PTL=` $PKG --cflags cray-portals`
  export       CPP_UGNI=`$PKG --cflags cray-ugni`
  export       LD_ALPS="-L/usr/lib/alps -lalpslli -lalpsutil"
  export       LD_PMI=`  $PKG --libs   cray-pmi`
  export       LD_PTL=`  $PKG --libs   cray-portals`
  export       LD_UGNI=` $PKG --libs   cray-ugni`
  if [ -f /etc/xthostname ]; then
	export CFLAGS="-g -O3 -pthread -DPORTALS_8B_OOB"
	export CPPFLAGS="${CPP_PMI} ${CPP_PTL}"
	export LDFLAGS="${LD_PMI}  ${LD_PTL} ${LD_ALPS}"
  else
	export CFLAGS="-g -O3 -pthread"
	export CPPFLAGS="${CPP_PMI} ${CPP_UGNI}"
	export LDFLAGS="${LD_PMI}  ${LD_UGNI}"
  fi
