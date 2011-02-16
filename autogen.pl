#!/usr/bin/env perl
#
# Copyright (c) 2009-2010 Cisco Systems, Inc.  All rights reserved. 
#
# $COPYRIGHT$
# 
# Additional copyrights may follow
# 
# $HEADER$
#

use strict;

use Cwd;
use File::Basename;
use File::Find;
use Data::Dumper;

#
# Global variables
#

# The m4 file we'll write at the end
my $m4_output_file = "config/autogen_found_items.m4";
# Sanity check file
my $topdir_file = "include/cci/config.h";

# Data structure to fill up with all the stuff we find
my $found_items;

##############################################################################

my @output_files;
sub process_plugin {
    my ($topdir, $project, $framework, $plugin) = @_;

    my $pname = $project->{name};
    my $pdir = $project->{dir};
    my $cdir = "$topdir/$pdir/plugins/$framework/$plugin";

    return
        if (! -d $cdir);
    $found_items->{$pname}->{$framework}->{$plugin}->{"found"} = 1;

    # Does this plugin have a configure.m4 file?
    if (-f "$cdir/configure.m4") {
        $found_items->{$pname}->{$framework}->{$plugin}->{"configure.m4"} = 1;
        print "    Found plugin configure.m4 file\n";
    }

    # If this plugin has a configure.params, read it in.
    @output_files = ();
    if (-f "$cdir/configure.params") {
        open(FILE, "$cdir/configure.params") ||
            die "Can't open $cdir/configure.params";
        my $file;
        $file .= $_
            while(<FILE>);
        close(FILE);

        if ($file =~ m/\s*PARAM_CONFIG_FILES\s*=\s*(.+)\s*$/) {
            # Strip off any leading and trailing "'s
            my $files = $1;
            $files =~ m/^\"(.+)\"$/;
            $files = $1
                if ($1);
            foreach my $f (split(/\s+/, $files)) {
                push(@output_files, "$pdir/plugins/$framework/$plugin/$f");
            }
        }
    }

    # If there was no configure.params, find all Makefile.am's in this
    # plugin and add them to the AC_OUTPUT list.
    else {
        find(\&_find_makefile_am, $cdir);
        # Normalize the file list; File::Find will have put in
        # absolute pathnames.
        my @dirs;
        foreach my $f (@output_files) {
            $f =~ s@$cdir@$pdir/plugins/$framework/$plugin@;
            push(@dirs, $f);
            @output_files = @dirs;
        }
    }
    # Deep copy the list of files because @output_files is a global.
    @{$found_items->{$pname}->{$framework}->{$plugin}->{"output_files"}} = 
        @output_files;
}

sub _find_makefile_am {
    # Note that $_ / $file will be "." when we're searching a
    # directory, so use basename($File::Find::name) to get the actual
    # directory basename.
    my $file = $_;
    my $basename = basename($File::Find::name);
    my $dirname = dirname($File::Find::name);

    # Don't process special directories or links, and don't recurse
    # down "special" directories.
    return
        if (-l $file);
    if (-d $basename && substr($basename, 0, 1) eq ".") {
        $File::Find::prune = 1;
        return;
    }

    # $File::Find::name is the path relative to the starting point.
    # $_ contains the file's basename.  The code automatically changes
    # to the processed directory, so we want to open / close $_.
    push(@output_files, "$dirname/Makefile")
        if ($file eq "Makefile.am");
}

##############################################################################

sub process_framework {
    my ($topdir, $project, $framework) = @_;

    my $pname = $project->{name};
    my $pdir = $project->{dir};

    # Does this framework have a configure.m4 file?
    $found_items->{$pname}->{$framework}->{"configure.m4"} = 1
        if (-f "$topdir/$pdir/$framework/configure.m4");

    # Look for plugin directories in this framework
    my $dir = "$topdir/$pdir/plugins/$framework";
    if (-d $dir) {
        opendir(DIR, $dir) || 
            die "Can't open $dir directory";
        foreach my $d (readdir(DIR)) {
            # Skip any non-directory, "base", or any dir that begins with "."
            next
                if (! -d "$dir/$d" || $d eq "base" || substr($d, 0, 1) eq ".");

            # If this director does not have .cci_ignore, or if it
            # has a .cci_unignore that has my username in it, then
            # add it to the list of plugins.
            my $want = 1;
            if (-f "$dir/$d/.cci_ignore") {
                $want = 0;
            }
            if (-f "$dir/$d/.cci_unignore") {
                open(UNIGNORE, "$dir/$d/.cci_unignore") ||
                    die "Can't open $pname / $framework / $d .cci_unignore file";
                my $username = getpwuid($>);
                my $found = grep { /$username/ } <UNIGNORE>;
                close(UNIGNORE);
                $want = 1
                    if ($found);
            }

            print "--- Found $pname / $framework / $d plugin";
            if ($want) {
                print "\n";
                process_plugin($topdir, $project, $framework, $d);
            } else {
                print " (ignored)\n";
            }
        }
        closedir(DIR);
    }
}

##############################################################################

sub process_project {
    my ($topdir, $project) = @_;

    my $pname = $project->{name};
    my $pdir = $project->{dir};

    # Does this project have a configure.m4 file?
    if (-f "$topdir/$pdir/configure.m4") {
        $found_items->{$pname}->{"configure.m4"} = 1;
        print "    Found $topdir/$pdir/configure.m4 file\n";
    }

    # Look for framework directories in this project
    my $dir = "$topdir/$pdir/plugins";
    if (-d $dir) {
        opendir(DIR, $dir) || 
            die "Can't open $dir directory";
        foreach my $d (readdir(DIR)) {
            # Skip any non-directory, "base", or any dir that begins with "."
            next
                if (! -d "$dir/$d" || $d eq "base" || substr($d, 0, 1) eq ".");

            # If this directory has a $dir.h file and a base/
            # subdirectory, or its name is "common", then it's a
            # framework.
            if ("common" eq $b || !$project->{need_base} ||
                (-f "$dir/$d/$d.h" && -d "$dir/$d/base")) {
                    print "\n=== Found $pname / $d framework\n";
                    process_framework($topdir, $project, $d);
            }
        }
        closedir(DIR);
    }
}

##############################################################################

sub run_global {
    my ($projects) = @_;

    # Remove out output file
    unlink($m4_output_file);

    # Create header for the M4 include file
    open(M4, ">$m4_output_file") || 
        die "Can't open $m4_output_file";
    print M4 "dnl
dnl \$HEADER
dnl
dnl -----------------------------------------------------------------
dnl This file is automatically created by autogen.pl; it should not
dnl be edited by hand!!
dnl -----------------------------------------------------------------

";

    # For each project, go find a list of frameworks, and for each of
    # those, go find a list of plugins.
    my $topdir = Cwd::cwd();
    foreach my $p (@$projects) {
        if (-d "$topdir/$p->{dir}") {
            print "\n*** Found $p->{name} project\n";
            process_project($topdir, $p);
        }
    }

    ############################################
    # Debugging output
    if (0) {
        my $d = new Data::Dumper([$found_items]);
        $d->Purity(1)->Indent(1);
        print $d->Dump;
    }
    ############################################

    # Write the output m4 file
    # First, write the list of projects
    my $str;
    foreach my $p (@$projects) {
        $str .= "[$p->{name}], [$p->{dir}], ";
    }
    $str =~ s/, $//;
    print M4 "dnl List of projects found my autogen.pl
m4_define([plugins_project_list], [$str])\n\n";

    # Array for all the m4_includes that we'll need to pick up the
    # configure.m4's.
    my @includes;
    # Array for all the AC_OUTPUT files that we'll need to generate
    # for the configure.m4's.
    my @ac_output_files;

    # Next, for each project, write the list of frameworks
    foreach my $p (@$projects) {

        my $pname = $p->{name};
        my $pdir = $p->{dir};

        if (exists($found_items->{$pname})) {
            my $frameworks;
            my $frameworks_comma;
            my $subdirs;
            my $static_subdirs;
            my $dso_subdirs;
            my $all_subdirs;

            # Does this project have a configure.m4 file?
            push(@includes, "$pdir/configure.m4")
                if (exists($found_items->{$p}->{"configure.m4"}));
                           
            # Print out project-level info
            foreach my $f (keys(%{$found_items->{$pname}})) {
                $frameworks .= "$f ";
                $frameworks_comma .= ", $f";
                $subdirs .= "plugins/$f ";
                $static_subdirs .= "\$(PLUGINS_${pname}_${f}_STATIC_SUBDIRS) ";
                $dso_subdirs .= "\$(PLUGINS_${pname}_${f}_DSO_SUBDIRS) ";
                $all_subdirs .= "\$(PLUGINS_${pname}_${f}_ALL_SUBDIRS) ";

                # Does this framework have a configure.m4 file?
                push(@includes, "$pdir/plugins/$f/configure.m4")
                    if (exists($found_items->{$pname}->{$f}->{"configure.m4"}));

                # This framework does have a Makefile.am (or at least,
                # it should!)
                die "Missing $pdir/plugins/$f/Makefile.am"
                    if (! -f "$pdir/plugins/$f/Makefile.am");
                push(@ac_output_files, "$pdir/plugins/$f/Makefile");
            }
            $frameworks_comma =~ s/^, //;

            print M4 "dnl ---------------------------------------------------------------------------

dnl Frameworks in the $pname project and their corresponding directories
m4_define([plugins_${pname}_framework_list], [$frameworks_comma])
PLUGINS_${pname}_FRAMEWORKS=\"$frameworks\"
AC_SUBST([PLUGINS_${pname}_FRAMEWORKS])
PLUGINS_${pname}_FRAMEWORKS_SUBDIRS=\"$subdirs\"
AC_SUBST([PLUGINS_${pname}_FRAMEWORKS_SUBDIRS])

";

            # Print out framework-level info
            foreach my $f (keys(%{$found_items->{$pname}})) {
                my $plugins;
                my $subdirs;
                my $dso_plugins;
                my $dso_subdirs;
                my $static_plugins;
                my $static_ltlibs;
                my $static_subdirs;
                my $m4_config_plugin_list;
                my $no_config_plugin_list;

                foreach my $c (keys(%{$found_items->{$pname}->{$f}})) {
                    $plugins .= "$c ";
                    $subdirs .= "plugins/$f/$c ";

                    # Does this framework have a configure.m4 file?
                    if (exists($found_items->{$pname}->{$f}->{$c}->{"configure.m4"})) {
                        push(@includes, "$pdir/plugins/$f/$c/configure.m4");
                        $m4_config_plugin_list .= ", $c";
                    } else {
                        $no_config_plugin_list .= ", $c";
                    }

                    # Find any output files and add them to the list
                    foreach my $f (@{$found_items->{$pname}->{$f}->{$c}->{"output_files"}}) {
                        push(@ac_output_files, $f);
                    }
                }
                $m4_config_plugin_list =~ s/^, //;
                $no_config_plugin_list =~ s/^, //;
                
                print M4 "dnl Plugins in the $pname / $f framework and their corresponding subdirectories
m4_define([plugins_${pname}_${f}_m4_config_plugin_list], [$m4_config_plugin_list])
m4_define([plugins_${pname}_${f}_no_config_plugin_list], [$no_config_plugin_list])
PLUGINS_${pname}_${f}_ALL_PLUGINS=\"$plugins\"
AC_SUBST([PLUGINS_${pname}_${f}_ALL_PLUGINS])
PLUGINS_${pname}_${f}_ALL_SUBDIRS=\"$subdirs\"
AC_SUBST([PLUGINS_${pname}_${f}_ALL_SUBDIRS])

";
            }
        }
    }

    # List out all the m4_include
    print M4 "dnl ---------------------------------------------------------------------------

dnl List of configure.m4 files to include\n";
    foreach my $i (@includes) {
        print M4 "m4_include([$i])\n";
    }

    # List out all the AC_OUTPUT files
    print M4 "
dnl ---------------------------------------------------------------------------

dnl List files to output\n";
    foreach my $f (@ac_output_files) {
        print M4 "AC_CONFIG_FILES([$f])\n";
    }

    close(M4);
}

##############################################################################
#
# main - do the real work...
#
##############################################################################

print "CCI autogen
1. Searching for projects, frameworks, and plugins...\n";

my $ret;

# Sanity check
if (! -d ".svn" && ! -d ".hg" && ! -d ".git") {
    print("

This doesn't look like a developer copy of CCI.  You probably do not
want to run autogen.pl - it is normally not needed for a release
source tree.  Giving you 5 seconds to reconsider and kill me.\n\n");
    sleep(5);
}

# figure out if we're at the top level of the OMPI tree, a plugin's
# top-level directory, or somewhere else.
if (! (-f "VERSION" && -f "configure.ac" && -f $topdir_file)) {
    print("\n\nYou must run this script from the top-level directory of the CCI tree.\n\n");
    exit(1);
}

# Locations to look for plugins frameworks
my $projects;
push(@{$projects}, { name => "cci", dir => "src", need_base => 1 });
&run_global($projects);

# If we got here, all was good.  Run the auto tools.
print "2. Running GNU Autotools...\n";
$ret = system("autoreconf -ivf");
$ret >>= 8;

# Done!
exit($ret);
