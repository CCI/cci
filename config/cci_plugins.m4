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
dnl Copyright (c) 2010      Cisco Systems, Inc.  All rights reserved.
dnl $COPYRIGHT$
dnl 
dnl Additional copyrights may follow
dnl 
dnl $HEADER$
dnl

# CCI_EVAL_ARG(arg)
# ------------------
# evaluates and returns argument
AC_DEFUN([CCI_EVAL_ARG], [$1])

######################################################################
#
# CCI_PLUGINS
#
# configure the plugins.  Works hand in hand with autogen.pl,
# requiring its specially formatted lists of frameworks, plugins,
# etc.
#
# USAGE:
#   CCI_PLUGINS()
#
######################################################################
AC_DEFUN([CCI_PLUGINS],[
    dnl for CCI_CONFIGURE_USER env variable
    AC_REQUIRE([CCI_CONFIGURE_SETUP])

    # Find which plugins should be built as run-time loadable plugins
    # Acceptable combinations:
    #
    # [default -- no option given]
    # --enable-plugins-dso
    # --enable-plugins-dso=[.+,]*PLUGIN_FRAMEWORK[.+,]*
    # --enable-plugins-dso=[.+,]*PLUGIN_FRAMEWORK-PLUGIN_NAME[.+,]*
    # --disable-plugins-dso
    #
    AC_ARG_ENABLE([plugins-no-build],
        [AC_HELP_STRING([--enable-plugins-no-build=LIST],
                        [Comma-separated list of <framework>-<plugin> pairs 
                         that will not be built.  Example: "--enable-plugins-no-build=ctp-sock,ctp-gni" will disable building the "sock" and "gni" ctp plugins.])])

    AC_MSG_CHECKING([which plugins should be disabled])
    if test "$enable_plugins_no_build" = "yes"; then
        AC_MSG_RESULT([yes])
        AC_MSG_ERROR([*** The enable-plugins-no-build flag requires an explicit list
*** of framework-plugin pairs.  For example, --enable-plugins-no-build=pml-ob1])
    else
        ifs_save="$IFS"
        IFS="${IFS}$PATH_SEPARATOR,"
        msg=
        for item in $enable_plugins_no_build; do
            framework="`echo $item | cut -s -f1 -d-`"
            comp="`echo $item | cut -s -f2- -d-`"
            if test -z $framework ; then
                framework=$item
            fi
            if test -z $comp ; then
                str="`echo DISABLE_${framework}=1 | sed s/-/_/g`"
                eval $str
                msg="$item $msg"
            else
                str="`echo DISABLE_${framework}_${comp}=1 | sed s/-/_/g`"
                eval $str
                msg="$item $msg"
            fi
        done
        IFS="$ifs_save"
    fi
    AC_MSG_RESULT([$msg])
    unset msg

    AC_MSG_CHECKING([for projects containing plugin frameworks])
    AC_MSG_RESULT([plugins_project_list])

    # if there isn't a project list, abort
    m4_ifdef([plugins_project_list], [],
             [m4_fatal([Could not find project list - did autogen.pl complete successfully?])])

    # now configre all the projects, frameworks, and plugins.  Most
    # of the hard stuff is in here
    PLUGINS_PROJECT_SUBDIRS=
    m4_map_args_pair([PLUGINS_CONFIGURE_PROJECT], [], plugins_project_list)
    AC_SUBST(PLUGINS_PROJECT_SUBDIRS)
])


######################################################################
#
# PLUGINS_CONFIGURE_PROJECT
#
# Configure all frameworks inside the given project name.  Assumes that
# the frameworks are located in [project_root]/plugins/[frameworks] and that
# there is an m4_defined list named plugins_[project]_framework_list with
# the list of frameworks.
#
# USAGE:
#   PLUGINS_CONFIGURE_PROJECT(project_name, project_root)
#
######################################################################
AC_DEFUN([PLUGINS_CONFIGURE_PROJECT],[
    # can't use a variable rename here because these need to be evaled
    # at auto* time.
    m4_define([mcp_name], $1)
    m4_define([mcp_root], $2)

    cci_show_subtitle "Configuring project mcp_name plugin (dir: mcp_root)"

    PLUGINS_PROJECT_SUBDIRS="$PLUGINS_PROJECT_SUBDIRS mcp_root"

    AC_MSG_CHECKING([for frameworks for mcp_name])
    AC_MSG_RESULT([plugins_]mcp_name[_framework_list])

    # iterate through the list of frameworks.  There is something
    # funky with m4 foreach if the list is defined, but empty.  It
    # will call the 3rd argument once with an empty value for the
    # first argument.  Protect against calling PLUGINS_CONFIGURE_FRAMEWORK
    # with an empty second argument.  Grrr....
    # if there isn't a project list, abort
    #
    # Also setup two variables for Makefiles:
    #  PLUGINS_project_FRAMEWORKS     - list of frameworks in that project
    #  PLUGINS_project_FRAMEWORK_LIBS - list of libraries (or variables pointing
    #                               to more libraries) that must be included
    #                               in the project's main library
    m4_ifdef([plugins_]mcp_name[_framework_list], [], 
             [m4_fatal([Could not find project list - did autogen.pl complete successfully?])])

    PLUGINS_[]mcp_name[]_FRAMEWORKS=
    PLUGINS_[]mcp_name[]_FRAMEWORKS_SUBDIRS=
    PLUGINS_[]mcp_name[]_FRAMEWORK_PLUGIN_ALL_SUBDIRS=
    PLUGINS_[]mcp_name[]_FRAMEWORK_PLUGIN_DSO_SUBDIRS=
    PLUGINS_[]mcp_name[]_FRAMEWORK_LIBS=
    
    m4_foreach(plugins_framework, [plugins_]mcp_name[_framework_list],
               [m4_ifval(plugins_framework, 
                         [# common has to go up front
                          if test "plugins_framework" = "common" ; then
                              PLUGINS_]mcp_name[_FRAMEWORKS="plugins_framework $PLUGINS_]mcp_name[_FRAMEWORKS"
                              PLUGINS_]mcp_name[_FRAMEWORKS_SUBDIRS="[plugins/]plugins_framework $PLUGINS_]mcp_name[_FRAMEWORKS_SUBDIRS"
                              PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_ALL_SUBDIRS="[\$(PLUGINS_]mcp_name[_]plugins_framework[_ALL_SUBDIRS)] $PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_ALL_SUBDIRS"
                              PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_DSO_SUBDIRS="[\$(PLUGINS_]mcp_name[_]plugins_framework[_DSO_SUBDIRS)] $PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_DSO_SUBDIRS"
                          else
                              PLUGINS_]mcp_name[_FRAMEWORKS="$PLUGINS_]mcp_name[_FRAMEWORKS plugins_framework"
                              PLUGINS_]mcp_name[_FRAMEWORKS_SUBDIRS="$PLUGINS_]mcp_name[_FRAMEWORKS_SUBDIRS [plugins/]plugins_framework"
                              PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_ALL_SUBDIRS="$PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_ALL_SUBDIRS [\$(PLUGINS_]mcp_name[_]plugins_framework[_ALL_SUBDIRS)]"
                              PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_DSO_SUBDIRS="$PLUGINS_]mcp_name[_FRAMEWORK_PLUGIN_DSO_SUBDIRS [\$(PLUGINS_]mcp_name[_]plugins_framework[_DSO_SUBDIRS)]"
                          fi
                          if test "plugins_framework" != "common" ; then
                              PLUGINS_]mcp_name[_FRAMEWORK_LIBS="$PLUGINS_]mcp_name[_FRAMEWORK_LIBS [plugins/]plugins_framework[/libcci_plugins_framework_]plugins_framework[.la]"
                          fi
                          m4_ifdef([PLUGINS_]plugins_framework[_CONFIG],
                                   [PLUGINS_]plugins_framework[_CONFIG](mcp_name, 
                                                                plugins_framework),
                                   [PLUGINS_CONFIGURE_FRAMEWORK(mcp_name, 
                                                            mcp_root, 
                                                            plugins_framework, 1)])])])

    AC_SUBST(PLUGINS_[]mcp_name[]_FRAMEWORKS)
    AC_SUBST(PLUGINS_[]mcp_name[]_FRAMEWORKS_SUBDIRS)
    AC_SUBST(PLUGINS_[]mcp_name[]_FRAMEWORK_PLUGIN_ALL_SUBDIRS)
    AC_SUBST(PLUGINS_[]mcp_name[]_FRAMEWORK_PLUGIN_DSO_SUBDIRS)
    AC_SUBST(PLUGINS_[]mcp_name[]_FRAMEWORK_LIBS)
])

######################################################################
#
# PLUGINS_CONFIGURE_FRAMEWORK
#
# Configure the given framework and all plugins inside the
# framework.  Assumes that the framework is located in
# [project_root]/plugins/[framework], and that all plugins are
# available under the framework directory.  Will configure all
# no-configure and builtin plugins, then search for plugins with
# configure scripts.  Assumes that no plugin is marked as builtin
# AND has a configure script.
#
# USAGE:
#   PLUGINS_CONFIGURE_FRAMEWORK(project_name, project_root, framework_name, 
#                           allow_succeed)
#
######################################################################
AC_DEFUN([PLUGINS_CONFIGURE_FRAMEWORK],[
    m4_define([mcf_name], $1)
    m4_define([mcf_root], $2)
    m4_define([mcf_fw], $3)
    m4_define([mcf_allow_succeed], $4)

    cci_show_subsubtitle "Configuring mcf_name plugin framework mcf_fw (dir: mcf_root)"

    # setup for framework
    all_plugins=
    dso_plugins=

    # Ensure that the directory where the #include file is to live
    # exists.  Need to do this for VPATH builds, because the directory
    # may not exist yet.  For the "common" framework, it's not really a
    # plugin, so it doesn't have a base.
    if test "mcf_fw" = "common" ; then
        outdir=mcf_root/plugins/common
    else
        outdir=mcf_root/plugins/mcf_fw/base
    fi
    AS_MKDIR_P([$outdir])

    # print some nice messages about what we're about to do...
    AC_MSG_CHECKING([for no configure plugins in framework mcf_fw])
    AC_MSG_RESULT([plugins_]mcf_name[_]mcf_fw[_no_config_plugin_list])
    AC_MSG_CHECKING([for m4 configure plugins in framework mcf_fw])
    AC_MSG_RESULT([plugins_]mcf_name[_]mcf_fw[_m4_config_plugin_list])

    # configure plugins that don't have any plugin-specific
    # configuration.  See comment in CONFIGURE_PROJECT about the
    # m4_ifval in the m4_foreach.  If there isn't a plugin list,
    # abort with a reasonable message.  If there are plugins in the
    # list, but we're doing one of the "special" selection logics,
    # abort with a reasonable message.
    m4_ifdef([plugins_]mcf_name[_]mcf_fw[_no_config_plugin_list], [], 
             [m4_fatal([Could not find project list - did autogen.pl complete successfully?])])
    # make sure priority stuff set right
    m4_if(CCI_EVAL_ARG([PLUGINS_]plugins_framework[_CONFIGURE_MODE]), [STOP_AT_FIRST],
          [m4_ifval(plugins_]mcf_name[_]mcf_fw[_no_config_plugin_list,
                   [m4_fatal([Framework mcf_fw using STOP_AT_FIRST but at least one plugin has no configure.m4])])])
    m4_if(CCI_EVAL_ARG([PLUGINS_]plugins_framework[_CONFIGURE_MODE]), [STOP_AT_FIRST_PRIORITY],
          [m4_ifval(plugins_]mcf_name[_]mcf_fw[_no_config_plugin_list,
                   [m4_fatal([Framework mcf_fw using STOP_AT_FIRST_PRIORITY but at least one plugin has no configure.m4])])])
    m4_foreach(plugins_plugin, [plugins_]mcf_name[_]mcf_fw[_no_config_plugin_list],
               [m4_ifval(plugins_plugin,
                  [PLUGINS_CONFIGURE_NO_CONFIG_PLUGIN(mcf_name, 
                                                     mcf_root,
                                                     mcf_fw,
                                                     plugins_plugin,
                                                     [all_plugins],
                                                     [dso_plugins],
                                                     [mcf_allow_succeed])])])

    # configure plugins that use built-in configuration scripts see
    # comment in CONFIGURE_PROJECT about the m4_ifval in the
    # m4_foreach.  if there isn't a plugin list, abort
    m4_ifdef([plugins_]mcf_name[_]mcf_fw[_m4_config_plugin_list], [], 
             [m4_fatal([Could not find project list - did autogen.pl complete successfully?])])
    best_plugins_plugin_priority=0
    plugins_looking_for_succeed=mcf_allow_succeed
    plugins_last_result=0
    m4_foreach(plugins_plugin, [plugins_]mcf_name[_]mcf_fw[_m4_config_plugin_list],
               [m4_ifval(plugins_plugin,
                  [m4_if(CCI_EVAL_ARG([PLUGINS_]plugins_framework[_CONFIGURE_MODE]), [STOP_AT_FIRST_PRIORITY],
                         [ # get the plugin's priority...
                          infile="mcf_root/plugins/mcf_fw/plugins_plugin/configure.params"
                          plugins_plugin_priority="`$GREP PARAM_CONFIG_PRIORITY= $infile | cut -d= -f2-`"
                          AS_IF([test -z "$plugins_plugin_priority"], [plugins_plugin_priority=0])
                          AS_IF([test $best_plugins_plugin_priority -gt $plugins_plugin_priority], [plugins_looking_for_succeed=0])])
                   PLUGINS_CONFIGURE_M4_CONFIG_PLUGIN(mcf_name,
                                                     mcf_root,
                                                     mcf_fw,
                                                     plugins_plugin, 
                                                     [all_plugins],
                                                     [dso_plugins],
                                                     [$plugins_looking_for_succeed],
                                                     [plugins_last_result=1],
                                                     [plugins_last_result=0])
                   m4_if(CCI_EVAL_ARG([PLUGINS_]plugins_framework[_CONFIGURE_MODE]), [STOP_AT_FIRST],
                         [AS_IF([test $plugins_last_result -eq 1], [plugins_looking_for_succeed=0])])
                   m4_if(CCI_EVAL_ARG([PLUGINS_]plugins_framework[_CONFIGURE_MODE]), [STOP_AT_FIRST_PRIORITY],
                         [AS_IF([test $plugins_last_result -eq 1], [best_plugins_plugin_priority=$plugins_plugin_priority])])])])

    PLUGINS_[]mcf_name[_]mcf_fw[]_ALL_PLUGINS="$all_plugins"
    PLUGINS_[]mcf_name[_]mcf_fw[]_DSO_PLUGINS="$dso_plugins"

    AC_SUBST(PLUGINS_[]mcf_name[_]mcf_fw[]_ALL_PLUGINS)
    AC_SUBST(PLUGINS_[]mcf_name[_]mcf_fw[]_DSO_PLUGINS)

    CCI_PLUGINS_MAKE_DIR_LIST(PLUGINS_[]mcf_name[_]mcf_fw[]_ALL_SUBDIRS, mcf_fw, [$all_plugins])
    CCI_PLUGINS_MAKE_DIR_LIST(PLUGINS_[]mcf_name[_]mcf_fw[]_DSO_SUBDIRS, mcf_fw, [$dso_plugins])

    unset all_plugins dso_plugins outfile outfile_real
])


######################################################################
#
# PLUGINS_CONFIGURE_NO_CONFIG_PLUGIN
#
# Configure the given framework and all plugins inside the framework.
# Assumes that the framework is located in [project_name]/plugins/[framework],
# and that all plugins are available under the framework directory.
# Will configure all builtin plugins, then search for plugins with
# configure scripts.  Assumes that no plugin is marked as builtin
# AND has a configure script.
#
# USAGE:
#   PLUGINS_CONFIGURE_PROJECT(project_name, project_root,
#                         framework_name, plugin_name
#                         all_plugins_variable, 
#                         dso_plugins_variable,
#                         allowed_to_succeed)
#
######################################################################
AC_DEFUN([PLUGINS_CONFIGURE_NO_CONFIG_PLUGIN],[
    m4_define([mcncc_name], $1)
    m4_define([mcncc_root], $2)
    m4_define([mcncc_fw], $3)
    m4_define([mcncc_comp], $4)
    m4_define([mcncc_all_comps], $5)
    m4_define([mcncc_dso_comps], $6)
    m4_define([mcncc_allow_succeed], $7)

    cci_show_subsubsubtitle "mcncc_name plugin mcncc_fw:mcncc_comp (no configuration)"

    PLUGINS_PLUGIN_BUILD_CHECK(mcncc_root, mcncc_fw, mcncc_comp, 
                              [should_build=mcncc_allow_succeed], [should_build=0])
    PLUGINS_PLUGIN_COMPILE_MODE(mcncc_name, mcncc_fw, mcncc_comp, compile_mode)

    if test "$should_build" = "1" ; then
        PLUGINS_PROCESS_PLUGIN(mcncc_name, mcncc_root, mcncc_fw, mcncc_comp, mcncc_all_comps, mcncc_dso_comps, $compile_mode)
    else
        PLUGINS_PROCESS_DEAD_PLUGIN(mcncc_name, mcncc_fw, mcncc_comp)
        # add plugin to all plugin list
        mcncc_all_comps="$[]mcncc_all_comps[] mcncc_comp"
    fi

    # set the AM_CONDITIONAL on how we should build
    if test "$compile_mode" = "dso" ; then
        BUILD_[]mcncc_name[_]mcncc_fw[_]mcncc_comp[]_DSO=1
    else
        BUILD_[]mcncc_name[_]mcncc_fw[_]mcncc_comp[]_DSO=0
    fi
    AM_CONDITIONAL(CCI_BUILD_[]mcncc_name[_]mcncc_fw[_]mcncc_comp[]_DSO, test "$BUILD_[]mcncc_name[_]mcncc_fw[_]mcncc_comp[]_DSO" = "1")

    unset compile_mode
])


######################################################################
#
# PLUGINS_CONFIGURE_M4_CONFIG_PLUGIN
#
#
# USAGE:
#   PLUGINS_CONFIGURE_PROJECT(project_name, project_root, 
#                         framework_name, plugin_name
#                         all_plugins_variable, 
#                         dso_plugins_variable,
#                         allowed_to_succeed,
#                         [eval if should build], 
#                         [eval if should not build])
#
######################################################################
AC_DEFUN([PLUGINS_CONFIGURE_M4_CONFIG_PLUGIN],[
    m4_define([mcmcc_name], $1)
    m4_define([mcmcc_root], $2)
    m4_define([mcmcc_fw], $3)
    m4_define([mcmcc_comp], $4)
    m4_define([mcmcc_all_comps], $5)
    m4_define([mcmcc_dso_comps], $6)
    m4_define([mcmcc_allow_succeed], $7)
    m4_define([mcmcc_happy], $8)
    m4_define([mcmcc_sad], $9)

    cci_show_subsubsubtitle "mcmcc_name plugin mcmcc_fw:mcmcc_comp (m4 configuration macro)"

    PLUGINS_PLUGIN_BUILD_CHECK(mcmcc_root, mcmcc_fw, mcmcc_comp, [should_build=mcmcc_allow_succeed], [should_build=0])
    # Allow the plugin to override the build mode if it really wants to.
    # It is, of course, free to end up calling PLUGINS_PLUGIN_COMPILE_MODE
    m4_ifdef([PLUGINS_[]mcmcc_fw[_]mcmcc_comp[]_COMPILE_MODE],
             [PLUGINS_[]mcmcc_fw[_]mcmcc_comp[]_COMPILE_MODE(mcmcc_name, mcmcc_fw, mcmcc_comp, compile_mode)],
             [PLUGINS_PLUGIN_COMPILE_MODE(mcmcc_name, mcmcc_fw, mcmcc_comp, compile_mode)])

    # try to configure the plugin.  pay no attention to
    # --enable-dist, since we'll always have makefiles.
    AS_IF([test "$should_build" = "1"],
          [m4_ifdef([PLUGINS_]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[_CONFIG],
                    [PLUGINS_]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[_CONFIG([should_build=1], 
                                         [should_build=0])],
                    # If they forgot to define an 
                    # PLUGINS_<project_<fw>_<comp>_CONFIG 
                    # macro, print a friendly warning and abort.
                    [AC_MSG_WARN([*** The mcmcc_name:mcmcc_fw:mcmcc_comp did not define an])
                     AC_MSG_WARN([*** PLUGINS_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_CONFIG macro in the])
                     AC_MSG_WARN([*** mcmcc_root/plugins/mcmcc_fw/mcmcc_comp/configure.m4 file])
                     AC_MSG_ERROR([Cannot continue])])
          ])

    AS_IF([test "$should_build" = "1"],
          [PLUGINS_PROCESS_PLUGIN(mcmcc_name, mcmcc_root, mcmcc_fw, mcmcc_comp, mcmcc_all_comps, mcmcc_dso_comps, $compile_mode)],
          [PLUGINS_PROCESS_DEAD_PLUGIN(mcmcc_name, mcmcc_fw, mcmcc_comp)
           # add plugin to all plugin list
           mcmcc_all_comps="$[]mcmcc_all_comps mcmcc_comp"])

    m4_ifdef([PLUGINS_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_POST_CONFIG],
             [PLUGINS_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_POST_CONFIG($should_build)])

    # set the AM_CONDITIONAL on how we should build
    AS_IF([test "$compile_mode" = "dso"], 
          [BUILD_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_DSO=1],
          [BUILD_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_DSO=0])
    AM_CONDITIONAL(CCI_BUILD_[]mcmcc_name[_]mcmcc_fw[_]mcmcc_comp[]_DSO, test "$BUILD_[]$1[_]mcmcc_fw[_]mcmcc_comp[]_DSO" = "1")

    AS_IF([test "$should_build" = "1"], mcmcc_happy, mcmcc_sad)

    unset compile_mode
])


######################################################################
#
# PLUGINS_PLUGIN_COMPILE_MODE
#
# set compile_mode_variable to the compile mode for the given plugin
#
# USAGE:
#   PLUGINS_PLUGIN_COMPILE_MODE(project_name, 
#                              framework_name, plugin_name
#                              compile_mode_variable)
#
#   NOTE: plugin_name may not be determined until runtime....
#
######################################################################
AC_DEFUN([PLUGINS_PLUGIN_COMPILE_MODE],[
    m4_define([mccm_name], $1)
    m4_define([mccm_fw], $2)
    m4_define([mccm_comp], $3)
    m4_define([mccm_cmv], $4)

    project=mccm_name
    framework=mccm_fw
    plugin=mccm_comp

    # Is this plugin going to built staic or shared?  $plugin
    # might not be known until configure time, so have to use eval
    # tricks - can't set variable names at autogen time.
    str="SHARED_FRAMEWORK=\$DSO_$framework"
    eval $str
    str="SHARED_PLUGIN=\$DSO_${framework}_$plugin"
    eval $str

    # Static is not supported right now; so the only option is DSO
    mccm_cmv=dso

    AC_MSG_CHECKING([for $project plugin $framework:$plugin compile mode])
    AC_MSG_RESULT([$mccm_cmv])
])


######################################################################
#
# PLUGINS_PROCESS_PLUGIN
#
# does all setup work for given plugin.  It should be known before
# calling that this plugin can build properly (and exists)
#
# USAGE:
#   PLUGINS_PROCESS_PLUGIN(project_name, 
#                         project_root,
#                         framework_name, plugin_name
#                         all_plugins_variable,
#                         dso_plugins_variable,
#                         compile_mode_variable
#
#   NOTE: plugin_name may not be determined until runtime....
#
######################################################################
AC_DEFUN([PLUGINS_PROCESS_PLUGIN],[
    m4_define([mpc_name], $1)
    m4_define([mpc_root], $2)
    m4_define([mpc_fw], $3)
    m4_define([mpc_comp], $4)
    m4_define([mpc_all_comps], $5)
    m4_define([mpc_dso_comps], $6)
    m4_define([mpc_cmv], $7)

    AC_REQUIRE([AC_PROG_GREP])

    project=mpc_name
    framework=mpc_fw
    plugin=mpc_comp

    # See if it dropped an output file for us to pick up some
    # shell variables in.  
    infile="$srcdir/mpc_root/plugins/$framework/$plugin/post_configure.sh"

    # Add this subdir to the mast list of all plugin subdirs
    mpc_all_comps="$[]mpc_all_comps $plugin"

    if test "mpc_cmv" = "dso" ; then
        mpc_dso_comps="$[]mpc_dso_comps $plugin"
    else
        AC_MSG_WARN([Unknown plugin build mode])
        AC_MSG_ERROR([Cannot continue])
    fi

    # Output pretty results
    AC_MSG_CHECKING([if $project plugin $framework:$plugin can compile])
    AC_MSG_RESULT([yes])
    
    # If there's an output file, add the values to
    # scope_EXTRA_flags.
    if test -f $infile; then

        # First check for the ABORT tag
        line="`$GREP ABORT= $infile | cut -d= -f2-`"
        if test -n "$line" -a "$line" != "no"; then
            AC_MSG_WARN([mpc_name plugin configure script told me to abort])
            AC_MSG_ERROR([cannot continue])
        fi
    fi
])


######################################################################
#
# PLUGINS_PLUGIN_BUILD_CHECK
#
# checks the standard rules of plugin building to see if the 
# given plugin should be built.
#
# USAGE:
#    PLUGINS_PLUGIN_BUILD_CHECK(project_root, framework, plugin, 
#                              action-if-build, action-if-not-build)
#
######################################################################
AC_DEFUN([PLUGINS_PLUGIN_BUILD_CHECK],[
    AC_REQUIRE([AC_PROG_GREP])

    m4_define([mcbc_root], $1)
    m4_define([mcbc_fw], $2)
    m4_define([mcbc_comp], $3)
    m4_define([mcbc_happy], $4)
    m4_define([mcbc_sad], $5)

    project_root=mcbc_root
    framework=mcbc_fw
    plugin=mcbc_comp
    plugin_path="$srcdir/$project_root/plugins/$framework/$plugin"
    want_plugin=1

    # if we were explicitly disabled, don't build :)
    str="DISABLED_PLUGIN_CHECK=\$DISABLE_${framework}"
    eval $str
    if test "$DISABLED_PLUGIN_CHECK" = "1" ; then
        want_plugin=0
    fi
    str="DISABLED_PLUGIN_CHECK=\$DISABLE_${framework}_$plugin"
    eval $str
    if test "$DISABLED_PLUGIN_CHECK" = "1" ; then
        want_plugin=0
    fi

    AS_IF([test "$want_plugin" = "1"], [mcbc_happy], [mcbc_sad])
])


######################################################################
#
# PLUGINS_PROCESS_DEAD_PLUGIN
#
# process a plugin that can not be built.  Do the last minute checks
# to make sure the user isn't doing something stupid.
#
# USAGE:
#   PLUGINS_PROCESS_DEAD_PLUGIN(project_name, 
#                         framework_name, plugin_name)
#
#   NOTE: plugin_name may not be determined until runtime....
#
######################################################################
AC_DEFUN([PLUGINS_PROCESS_DEAD_PLUGIN],[
    m4_define([mpdc_name], $1)
    m4_define([mpdc_fw], $2)
    m4_define([mpdc_comp], $3)

    AC_MSG_CHECKING([if ]mpdc_name[ plugin mpdc_fw:mpdc_comp can compile])
    AC_MSG_RESULT([no])

    # If this plugin was requested as the default for this
    # framework, then abort.
    if test "$with_]mpdc_fw[" = "mpdc_comp" ; then
        AC_MSG_WARN([$1 plugin "mpdc_comp" failed to configure properly])
        AC_MSG_WARN([This plugin was selected as the default])
        AC_MSG_ERROR([Cannot continue])
        exit 1
    fi
])

# CCI_PLUGINS_MAKE_DIR_LIST(subst'ed variable, framework, shell list)
# -------------------------------------------------------------------------
AC_DEFUN([CCI_PLUGINS_MAKE_DIR_LIST],[
    # Making DSO compnent list: $1
    $1=
    for item in $3 ; do
       $1="$$1 plugins/$2/$item"
    done
    AC_SUBST($1)
])
