#!/usr/bin/perl
#
# Transform a mapi.conf for DAG into a mapi.conf for non-DAG
use strict;

use Cwd;
print STDERR getcwd(),"\n";
my $conffile = shift @ARGV;;
my $dagentfile = shift @ARGV;;
print STDERR $conffile,"\n";
print STDERR $dagentfile,"\n";
my $dagentstr;
my $confstr;
{
    local $/;
    open SLURP, $conffile or die "can't open $conffile: $!";
    $confstr = <SLURP>;
    close SLURP;
    open SLURP, $dagentfile or die "can't open $dagentfile: $!";
    $dagentstr = <SLURP>;
    close SLURP;
}
$confstr =~ s/dagflib.so//;
$confstr =~ s/::/:/;
my $matchstart = index($confstr,$dagentstr);
my $matchend   = $matchstart + length ($dagentstr);
print substr($confstr, 0, $matchstart);
print substr($confstr, $matchend)
