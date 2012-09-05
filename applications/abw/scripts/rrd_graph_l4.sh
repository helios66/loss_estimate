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
# $Id: rrd_graph_l4.sh,v 1.1 2006/11/23 10:32:13 ubik Exp $
#

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

usage() {
  echo "Usage: $0 <prefix_in> <prefix_out> <filename_graph> <start_time> <end_time> <resolution 1> <resolution 2> <title>"
  echo "One of <prefix_in> or <prefix_out> can be empty string \"\""
  echo "Example:"
  echo "$0 \\"
  echo "   /var/lib/abw/rrd/perfmon-plzen.cesnet.cz-eth1-0-1 \\"
  echo "   /var/lib/abw/rrd/perfmon-plzen.cesnet.cz-eth2-0-1 \\"
  echo "   graph-Plzen_PoP-l4.png \\"
  echo "   \"14:33 20060504\" \"15:00 20060504\""
  echo "   1 60"
  echo "   \"CESNET - GN2\""
}

if [ $# -ne 8 ]; then
  usage
  exit -1
fi

PREFIX_IN=$1
PREFIX_OUT=$2
FILENAME_GRAPH=$3
START_TIME=$4
END_TIME=$5
R1=$6
R2=$7
TITLE=$8

if [ "x$PREFIX_OUT" != "x" -a "x$PREFIX_IN" != "x" ]; then

rrdtool graph ${FILENAME_GRAPH} --width 600 --height 450 \
	--start "${START_TIME}" --end "${END_TIME}" \
	--slope-mode --interlaced --vertical-label "out    Mb/s    in" \
	--title "${TITLE}: L3/L4 protocols, interval $R1 second(s), avg/max $R2 seconds" -X 0 \
	DEF:all_in=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_in_avg_r2=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:all_in_max_r2=${PREFIX_IN}-all.rrd:mbps:MAX:step=$R2 \
	DEF:tcp_in=${PREFIX_IN}-tcp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:udp_in=${PREFIX_IN}-udp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:icmp_in=${PREFIX_IN}-icmp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:multicast_in=${PREFIX_IN}-multicast.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ip6_in=${PREFIX_IN}-ip6.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out_avg_r2=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:all_out_max_r2=${PREFIX_OUT}-all.rrd:mbps:MAX:step=$R2 \
	DEF:tcp_out=${PREFIX_OUT}-tcp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:udp_out=${PREFIX_OUT}-udp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:icmp_out=${PREFIX_OUT}-icmp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:multicast_out=${PREFIX_OUT}-multicast.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ip6_out=${PREFIX_OUT}-ip6.rrd:mbps:AVERAGE:step=$R1 \
	CDEF:other_in=all_in,tcp_in,-,udp_in,-,icmp_in,- \
	CDEF:other_out=all_out,tcp_out,-,udp_out,-,icmp_out,- \
	CDEF:all_out_neg=all_out,-1,* \
	CDEF:all_out_neg_avg_r2=all_out_avg_r2,-1,* \
	CDEF:all_out_neg_max_r2=all_out_max_r2,-1,* \
	CDEF:tcp_out_neg=tcp_out,-1,* \
	CDEF:udp_out_neg=udp_out,-1,* \
	CDEF:icmp_out_neg=icmp_out,-1,* \
	CDEF:multicast_out_neg=multicast_out,-1,* \
	CDEF:ip6_out_neg=ip6_out,-1,* \
	CDEF:other_out_neg=other_out,-1,* \
	AREA:all_in#FF0000:"Other" \
	LINE:0 \
	AREA:udp_in#FFFF00:"UDP":STACK \
	AREA:icmp_in#AF5000:"ICMP":STACK \
	AREA:tcp_in#00FF00:"TCP":STACK \
	AREA:all_out_neg#FF0000 \
	LINE:0 \
	AREA:udp_out_neg#FFFF00::STACK \
	AREA:icmp_out_neg#AF5000::STACK \
	AREA:tcp_out_neg#00FF00::STACK \
	LINE2:multicast_in#FF00FF:"Multicast" \
	LINE2:multicast_out_neg#FF00FF \
	LINE2:ip6_in#000000D0:"IPv6" \
	LINE2:ip6_out_neg#000000D0 \
	LINE2:all_in_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE2:all_out_neg_avg_r2#00FFFF \
	LINE2:all_in_max_r2#0000FF:"Maximum ($R2 seconds)" \
	LINE2:all_out_neg_max_r2#0000FF \
	LINE:0#000000

elif [ "x$PREFIX_IN" != "x" ]; then

rrdtool graph ${FILENAME_GRAPH} --width 600 --height 450 \
	--start "${START_TIME}" --end "${END_TIME}" \
	--slope-mode --interlaced --vertical-label "    Mb/s    in" \
	--title "${TITLE}: L3/L4 protocols, interval $R1 second(s), avg/max $R2 seconds" -X 0 \
	DEF:all_in=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_in_avg_r2=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:all_in_max_r2=${PREFIX_IN}-all.rrd:mbps:MAX:step=$R2 \
	DEF:tcp_in=${PREFIX_IN}-tcp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:udp_in=${PREFIX_IN}-udp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:icmp_in=${PREFIX_IN}-icmp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:multicast_in=${PREFIX_IN}-multicast.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ip6_in=${PREFIX_IN}-ip6.rrd:mbps:AVERAGE:step=$R1 \
	CDEF:other_in=all_in,tcp_in,-,udp_in,-,icmp_in,- \
	AREA:all_in#FF0000:"Other" \
	LINE:0 \
	AREA:udp_in#FFFF00:"UDP":STACK \
	AREA:tcp_in#00FF00:"TCP":STACK \
	AREA:icmp_in#FF00FF:"ICMP":STACK \
	LINE2:multicast_in#FF00FF:"Multicast" \
	LINE2:ip6_in#000000D0:"IPv6" \
	LINE2:all_in_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE2:all_in_max_r2#0000FF:"Maximum ($R2 seconds)" \
	LINE:0#000000

elif [ "x$PREFIX_OUT" != "x" ]; then

rrdtool graph ${FILENAME_GRAPH} --width 600 --height 450 \
	--start "${START_TIME}" --end "${END_TIME}" \
	--slope-mode --interlaced --vertical-label "out    Mb/s    " \
	--title "${TITLE}: L3/L4 protocols, interval $R1 second(s), avg/max $R2 seconds" -X 0 \
	DEF:all_out=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out_avg_r2=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:all_out_max_r2=${PREFIX_OUT}-all.rrd:mbps:MAX:step=$R2 \
	DEF:tcp_out=${PREFIX_OUT}-tcp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:udp_out=${PREFIX_OUT}-udp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:icmp_out=${PREFIX_OUT}-icmp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:multicast_out=${PREFIX_OUT}-multicast.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ip6_out=${PREFIX_OUT}-ip6.rrd:mbps:AVERAGE:step=$R1 \
	CDEF:other_out=all_out,tcp_out,-,udp_out,-,icmp_out,- \
	CDEF:all_out_neg=all_out,-1,* \
	CDEF:all_out_neg_avg_r2=all_out_avg_r2,-1,* \
	CDEF:all_out_neg_max_r2=all_out_max_r2,-1,* \
	CDEF:tcp_out_neg=tcp_out,-1,* \
	CDEF:udp_out_neg=udp_out,-1,* \
	CDEF:icmp_out_neg=icmp_out,-1,* \
	CDEF:multicast_out_neg=multicast_out,-1,* \
	CDEF:ip6_out_neg=ip6_out,-1,* \
	CDEF:other_out_neg=other_out,-1,* \
	AREA:all_out_neg#FF0000:"Other" \
	LINE:0 \
	AREA:udp_out_neg#FFFF00:"UDP":STACK \
	AREA:tcp_out_neg#00FF00:"TCP":STACK \
	AREA:icmp_out_neg#FF00FF:"ICMP":STACK \
	LINE2:multicast_out_neg#FF00FF:"Multicast" \
	LINE2:ip6_out_neg#000000D0:"IPv6" \
	LINE2:all_out_neg_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE2:all_out_neg_max_r2#0000FF:"Maximum ($R2 seconds)" \
	LINE:0#000000

else

	echo "At least one of <prefix_in> or <prefix_out> must be non-empty"
	echo ""
	usage
	exit -1

fi
