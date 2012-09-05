#!/usr/bin/perl

#Run this script in the same directory as MAPI functions are located to 
#generate source code for a library that includes all the functions
#Usage: createlib.pl <name of library> <name of library file>

use strict;

my @functions;

if($#ARGV!=1) {
    print "Usage: createlib.pl <name of library> <name of library file>\n";
    exit(0);
}

my $libname=$ARGV[0];
my $libfile=$ARGV[1];

#Find all *c files in directory
opendir(DIR,".") || die("Could not open current directory\n");

while (defined(my $file = readdir(DIR)) ) {
 if (-T $file && $file=~/\.c$/ && $file ne $libfile) {
  print "Processing: $file\n";
  open(FILE,"$file");
  
  #Search for get_funct_info
  while(<FILE>) {
      if(/^\s*mapidflib_function.*\s([^\s]*_get_funct_info\(\))[^;]/) {
	  print "   $1\n";
	  push @functions,$1;
      }
  }

  close(FILE);
 }
}

close(DIR);


#Write library file

open(LIBFILE,">$libfile") || die("Could not open $libfile for writing\n");

my $time=localtime(time());
my $c=$#functions+1;
print LIBFILE <<HEADER;
//$time
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="$libname";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[$c];

HEADER

#Write MAPI function definitions
for my $f (sort @functions) {
    print LIBFILE "extern mapidflib_function_def_t * $f;\n";
}

print LIBFILE <<BODY;

mapidflib_functionlist_t* mapidflib_get_function_list()
{
BODY

#Write entries for each MAPI function
my $c=0;
my $c2;

for my $f (sort @functions) {
    print LIBFILE "  functions[$c].def=$f;\n";
    print LIBFILE "  functions[$c].def->libname=libname;\n";  
    if($c==$#functions) {
	print LIBFILE "  functions[$c].next=NULL;\n";
    } else {
	$c2=$c+1;
	print LIBFILE "  functions[$c].next=&functions[$c2];\n\n";
	$c++;
    }
}


print LIBFILE <<FOOT;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    DEBUG_CMD(printf ("Library $libname loaded\\n"));
}

__attribute__ ((destructor))
     void fini ()
{
    DEBUG_CMD(printf ("Library $libname unloaded\\n"));
}

FOOT

close(LIBFILE);


print "Library created in $libfile\n";
