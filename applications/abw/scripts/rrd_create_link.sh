#!/bin/bash 
#
# Copyright (c) 2006, CESNET
# All rights reserved.
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the company nor the names of its contributors 
#       may be used to endorse or promote products derived from this 
#       software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
# THE COMPANY OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# $Id$
#

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

if [ $# != 1 ]; then
	echo "Usage: $0 <file.rrd>"
	exit
fi

# Keep 1 second averages for 3 hours
#     10 second              1 day
#     60 second              1 week
#    600 second              1 month
#      1 hour                2 years

if test ! -f $1 ; then

rrdtool create $1 --start now --step 1 \
	DS:packets:GAUGE:5:U:U \
	DS:bytes:GAUGE:5:U:U \
	DS:mbps:GAUGE:5:U:U \
	RRA:AVERAGE:0:1:10800 \
	RRA:AVERAGE:0.5:10:8640 \
	RRA:AVERAGE:0.5:60:10080 \
	RRA:AVERAGE:0.5:600:4464 \
	RRA:AVERAGE:0.5:3600:17544 \
   RRA:MIN:0.5:10:8640 \
   RRA:MIN:0.5:60:10080 \
	RRA:MIN:0.5:600:4464 \
	RRA:MIN:0.5:3600:17544 \
   RRA:MAX:0.5:10:8640 \
   RRA:MAX:0.5:60:10080 \
	RRA:MAX:0.5:600:4464 \
	RRA:MAX:0.5:3600:17544

fi
