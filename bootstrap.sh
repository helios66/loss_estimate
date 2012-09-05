#!/bin/sh
# Use this script to create generated files from the SVN distribution

libtoolize --automake --copy
aclocal -I .
autoheader 
automake --add-missing --copy
autoconf

