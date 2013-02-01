#!/usr/bin/perl

use strict;
use warnings;
use File::Basename; # basename
use Net::SSH::Perl; # SSH
use Net::SSH::Perl::Constants qw( :msg ); # register handler
use Getopt::Std; # parse input
use IO::Handle; # pipes

sub print_usage;
sub run_single;
sub run_pair;

my %opt;
my @hosts;
my @sessions;
my ($stdout, $stderr, $exit);
  
my $base_dir    = "/tmp/cci";
my $config_file = "$base_dir/cci.conf";
my $test_dir    = "$base_dir/src/tests";
my $export_cci  = "export CCI_CONFIG=$config_file";

# parse input
$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts('f:v', \%opt) or print_usage;

my $host_file = $opt{'f'};
my $verbose   = $opt{'v'};

if (defined $host_file) {
  open(FILE, "<$host_file") || die "open $host_file: $!";
  while (<FILE>) {
    chomp;
    push @hosts, $_ if (/(\S+)/);
  }
} else {
  die "missing host arguments" if (scalar(@ARGV) < 1);
  while (scalar(@ARGV) > 0) {
    my $host = shift;
    push @hosts, $host;
  }
}

# start SSH sessions
foreach my $host (@hosts) {
  my $ssh = Net::SSH::Perl->new($host, interactive => 1);
  $ssh->login();
  ($stdout, $stderr, $exit) = $ssh->cmd("echo `whoami`@`hostname`");
  chomp $stdout;
  print "$stdout: login successful\n";
  push @sessions, $ssh;
}

# define tests
my @tests = (
  {
    label => "",
    desc => "",
    server => {
      cmd => "$test_dir/cci_data_integrity -s",
     exp => sub {
        return 1; 
      },
    },
    client => {
      cmd => "$test_dir/cci_data_integrity -h URI",
      exp => sub {
        return 1;
      },
    },
  },
#  {
#    label => "",
#    desc => "",
#    server => {
#      cmd => "$test_dir/cci_err_return -s",
#      exp => sub {
#        return 1; 
#      },
#    },
#    client => {
#      cmd => "$test_dir/cci_err_return -h URI",
#      exp => sub {
#        return 1;
#      },
#    },
#  },
#  {
#    label => "",
#    desc => "",
#    server => {
#      cmd => "$test_dir/cci_connect -s",
#     exp => sub {
#        return 1; 
#      },
#    },
#    client => {
#      cmd => "$test_dir/cci_connect -h URI",
#      exp => sub {
#        return 1;
#      },
#    },
#  },
);

# run tests
my $test_num;
my ($passes, $fails) = (0)x2;
foreach my $t (@tests) {
  $test_num++;
  print "\nStart Test #$test_num\n";
  print "$t->{desc}\n" if $t->{desc};

  my @rslts;
  my $rc;
  if (defined $t->{server}{cmd}) {
    if (defined $t->{client}{cmd}) {
      $rc = run_pair(\@sessions, $t->{server}{cmd}, $t->{client}{cmd}, \@rslts);
    } else {
      $rc = run_single(\$sessions[0], $t->{server}{cmd}, \@rslts);
    }

    if ($rc) {
      print "ERROR: non-zero return code $rc\n";
      $fails++;
    } else {
      if (defined $t->{server}{exp}) {
        if (&{$t->{server}{exp}}(\@rslts)) {
          print "End Test: PASS\n";
          $passes++;
        } else {
          print "End Test: FAIL\n";
          $fails++;
        }
      }
    }
  } else {
    $test_num--;
  }

  sleep 1;
}

print "\nRun Summary:\n";
print "$passes/$test_num tests passed\n";
print "$fails/$test_num tests failed\n";

##########
sub print_usage {
  print "Usage: " . basename($0) . " [-options <args>] [host1 .. hostN]\n";
  print "     -f <file>   specify list of hosts to use (overrides command line input)\n";
  print "                 one host should be declared per line\n";
  print "     -v          print verbose output\n";

  exit;
}

sub run_single {
  my $session = shift;
  my $server_cmd = shift;
  my $rslts = shift;
  my @out;

  $$session->register_handler("stdout", sub { 
    push @$rslts, ($_[1])->bytes;
  });

  @out = $$session->cmd("$export_cci; $server_cmd 2>&1");

  return $out[2];
}

sub run_pair {
  my $session_ref = shift;
  my $server_cmd = shift;
  my $client_cmd = shift;
  my $rslts = shift;
  my @out;

  pipe(READER, WRITER);
  WRITER->autoflush(1);
    
  ($session_ref->[0])->register_handler("stdout", sub {
    my ($channel, $buffer) = @_;
    my $tmp_output = $buffer->bytes;
    # print to pipe for child
    print WRITER "$tmp_output\n";
  });

  my $pid = fork;
  if ($pid) {
    print "Server command: $server_cmd\n";
    @out = ($session_ref->[0])->cmd("$export_cci; $server_cmd 2>&1");
  } else {
    sleep 2;
    close WRITER;
    while (<READER>) {
      chomp;
      if (/Opened (\S+)/) {
        my $uri = $1;
        $client_cmd =~ s/URI/$uri/;
	print "Client command: $client_cmd\n";
        ($session_ref->[1])->cmd("$export_cci; $client_cmd 2>&1");
        last;
      }
    }
    close READER;
    exit;
  }

  print "Processing output...\n";
  
  # signal end of pipe
  print WRITER "EOF\n";
  
  # save output
  while (<READER>) {
    chomp;
    last if ($_ eq "EOF");
    push @$rslts, $_;
  }
  
  close WRITER;
  close READER;

  # return exit code from server
  return $out[2];
}
