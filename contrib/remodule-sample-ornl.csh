  module       purge
  if ( -f /etc/xthostname ) then
	module use -a       /opt/cray/ss/modulefiles
  else
	module use -a       /ccs/sw/gni/modulefiles
  endif

# Start with GNU.
  module       load         modules
  module       load         torque
  module       load         moab
  if ( -f /etc/xthostname ) then
	module load         portals
	module load         lustre-cray_ss_s/1.8.6
	module load         lustre-cray_ss_s
  else
	module load         gni-headers
	module load         ugni
	module load         lustre-cray_gem_s
  endif
  module       load         lustre-utils
  module       load         PrgEnv-gnu
  module       unload       xt-libsci
  module       unload       atp

# Get access to more current releases of autotools.
  module       load         autoconf automake libtool git

# At least for now, we will avoid Cray Programming Environment
# interfaces, so we need to set CPPFLAGS and LDFLAGS.
  setenv       PKG          "/usr/bin/pkg-config --silence-errors"
  setenv       CCI_CONFIG   "../../contrib/ornl.ini"
  setenv       CPP_PMI      `$PKG --cflags cray-pmi`
  setenv       CPP_PTL      `$PKG --cflags cray-portals`
  setenv       CPP_UGNI     `$PKG --cflags cray-ugni`
  setenv       LD_ALPS      "-L/usr/lib/alps -lalpslli -lalpsutil"
  setenv       LD_PMI       `$PKG --libs   cray-pmi`
  setenv       LD_PTL       `$PKG --libs   cray-portals`
  setenv       LD_UGNI      `$PKG --libs   cray-ugni`
  if ( -f /etc/xthostname ) then
	setenv CPPFLAGS     "${CPP_PMI} ${CPP_PTL}"
	setenv CFLAGS       "-g -O3 -pthread -DPORTALS_8B_OOB"
	setenv LDFLAGS      "${LD_PMI}  ${LD_PTL} ${LD_ALPS}"
  else
	setenv CPPFLAGS     "${CPP_PMI} ${CPP_UGNI}"
	setenv CFLAGS       "-g -O3 -pthread"
	setenv LDFLAGS      "${LD_PMI}  ${LD_UGNI}"
  endif
