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
# $Id: rrd_graph_apps.sh,v 1.1 2006/11/23 10:32:13 ubik Exp $
#

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

usage() {
  echo "Usage: $0 <prefix_in> <prefix_out> <filename_graph> <start_time> <end_time> <resolution 1> <resolution 2> <title>"
  echo "One of <prefix_in> or <prefix_out> can be empty string \"\""
  echo "Example:"
  echo "$0 \\"
  echo "   /var/lib/abw/rrd/perfmon-plzen.cesnet.cz-eth1-0-1 \\"
  echo "   /var/lib/abw/rrd/perfmon-plzen.cesnet.cz-eth2-0-1 \\"
  echo "   perfmon-plzen_apps.png \\"
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
	--title "${TITLE}: applications, interval $R1 second(s), avg $R2 seconds" -X 0 \
	DEF:all_in=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_in_avg_r2=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:http_in=${PREFIX_IN}-http.rrd:mbps:AVERAGE:step=$R1 \
	DEF:https_in=${PREFIX_IN}-https.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ssh_in=${PREFIX_IN}-ssh.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ftp_in=${PREFIX_IN}-ftp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:gnutella_in=${PREFIX_IN}-gnutella.rrd:mbps:AVERAGE:step=$R1 \
	DEF:torrent_in=${PREFIX_IN}-torrent.rrd:mbps:AVERAGE:step=$R1 \
	DEF:dc_in=${PREFIX_IN}-dc.rrd:mbps:AVERAGE:step=$R1 \
	DEF:edonkey_in=${PREFIX_IN}-edonkey.rrd:mbps:AVERAGE:step=$R1 \
	DEF:skype_in=${PREFIX_IN}-skype.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out_avg_r2=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:http_out=${PREFIX_OUT}-http.rrd:mbps:AVERAGE:step=$R1 \
	DEF:https_out=${PREFIX_OUT}-https.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ssh_out=${PREFIX_OUT}-ssh.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ftp_out=${PREFIX_OUT}-ftp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:gnutella_out=${PREFIX_OUT}-gnutella.rrd:mbps:AVERAGE:step=$R1 \
	DEF:torrent_out=${PREFIX_OUT}-torrent.rrd:mbps:AVERAGE:step=$R1 \
	DEF:dc_out=${PREFIX_OUT}-dc.rrd:mbps:AVERAGE:step=$R1 \
	DEF:edonkey_out=${PREFIX_OUT}-edonkey.rrd:mbps:AVERAGE:step=$R1 \
	DEF:skype_out=${PREFIX_OUT}-skype.rrd:mbps:AVERAGE:step=$R1 \
	CDEF:all_out_neg=all_out,-1,* \
	CDEF:all_out_neg_avg_r2=all_out_avg_r2,-1,* \
	CDEF:http_out_neg=http_out,-1,* \
	CDEF:https_out_neg=https_out,-1,* \
	CDEF:ssh_out_neg=ssh_out,-1,* \
	CDEF:ftp_out_neg=ftp_out,-1,* \
	CDEF:gnutella_out_neg=gnutella_out,-1,* \
	CDEF:torrent_out_neg=torrent_out,-1,* \
	CDEF:dc_out_neg=dc_out,-1,* \
	CDEF:edonkey_out_neg=edonkey_out,-1,* \
	CDEF:skype_out_neg=skype_out,-1,* \
	AREA:all_in#C0C0C0:"Other" \
	LINE:0 \
	AREA:http_in#00FF00:"HTTP":STACK \
	AREA:https_in#FF0000:"HTTPS":STACK \
	AREA:ssh_in#FADADD:"SSH":STACK \
	AREA:ftp_in#FF00FF:"FTP":STACK \
	AREA:gnutella_in#50AF00:"Gnutella":STACK \
	AREA:torrent_in#AF5000:"BitTorrent":STACK \
	AREA:dc_in#FFFF00:"DC":STACK \
	AREA:edonkey_in#5050AF:"eDonkey":STACK \
	AREA:skype_in#CC9900:"Skype":STACK \
	AREA:all_out_neg#C0C0C0 \
	LINE:0 \
	AREA:http_out_neg#00FF00::STACK \
	AREA:https_out_neg#FF0000::STACK \
	AREA:ssh_out_neg#FADADD::STACK \
	AREA:ftp_out_neg#FF00FF::STACK \
	AREA:gnutella_out_neg#50AF00::STACK \
	AREA:torrent_out_neg#AF5000::STACK \
	AREA:dc_out_neg#FFFF00::STACK \
	AREA:edonkey_out_neg#5050FF::STACK \
	AREA:skype_out_neg#CC9900::STACK \
	LINE2:all_in_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE2:all_out_neg_avg_r2#00FFFF \
	LINE:0#000000

elif [ "x$PREFIX_IN" != "x" ]; then

rrdtool graph ${FILENAME_GRAPH} --width 600 --height 450 \
	--start "${START_TIME}" --end "${END_TIME}" \
	--slope-mode --interlaced --vertical-label "    Mb/s    in" \
	--title "${TITLE}: applications, interval $R1 second(s), avg $R2 seconds" -X 0 \
	DEF:all_in=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_in_avg_r2=${PREFIX_IN}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:http_in=${PREFIX_IN}-http.rrd:mbps:AVERAGE:step=$R1 \
	DEF:https_in=${PREFIX_IN}-https.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ssh_in=${PREFIX_IN}-ssh.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ftp_in=${PREFIX_IN}-ftp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:gnutella_in=${PREFIX_IN}-gnutella.rrd:mbps:AVERAGE:step=$R1 \
	DEF:torrent_in=${PREFIX_IN}-torrent.rrd:mbps:AVERAGE:step=$R1 \
	DEF:dc_in=${PREFIX_IN}-dc.rrd:mbps:AVERAGE:step=$R1 \
	DEF:edonkey_in=${PREFIX_IN}-edonkey.rrd:mbps:AVERAGE:step=$R1 \
	DEF:skype_in=${PREFIX_IN}-skype.rrd:mbps:AVERAGE:step=$R1 \
	AREA:all_in#C0C0C0:"Other" \
	LINE:0 \
	AREA:http_in#00FF00:"HTTP":STACK \
	AREA:https_in#FF0000:"HTTPS":STACK \
	AREA:ssh_in#FADADD:"SSH":STACK \
	AREA:ftp_in#FF00FF:"FTP":STACK \
	AREA:gnutella_in#50AF00:"Gnutella":STACK \
	AREA:torrent_in#AF5000:"BitTorrent":STACK \
	AREA:dc_in#FFFF00:"DC":STACK \
	AREA:edonkey_in#5050AF:"eDonkey":STACK \
	AREA:skype_in#CC9900:"Skype":STACK \
	LINE2:all_in_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE:0#000000

elif [ "x$PREFIX_OUT" != "x" ]; then

rrdtool graph ${FILENAME_GRAPH} --width 600 --height 450 \
	--start "${START_TIME}" --end "${END_TIME}" \
	--slope-mode --interlaced --vertical-label "out    Mb/s    " \
	--title "${TITLE}: applications, interval $R1 second(s), avg $R2 seconds" -X 0 \
	DEF:all_out=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R1 \
	DEF:all_out_avg_r2=${PREFIX_OUT}-all.rrd:mbps:AVERAGE:step=$R2 \
	DEF:http_out=${PREFIX_OUT}-http.rrd:mbps:AVERAGE:step=$R1 \
	DEF:https_out=${PREFIX_OUT}-https.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ssh_out=${PREFIX_OUT}-ssh.rrd:mbps:AVERAGE:step=$R1 \
	DEF:ftp_out=${PREFIX_OUT}-ftp.rrd:mbps:AVERAGE:step=$R1 \
	DEF:gnutella_out=${PREFIX_OUT}-gnutella.rrd:mbps:AVERAGE:step=$R1 \
	DEF:torrent_out=${PREFIX_OUT}-torrent.rrd:mbps:AVERAGE:step=$R1 \
	DEF:dc_out=${PREFIX_OUT}-dc.rrd:mbps:AVERAGE:step=$R1 \
	DEF:edonkey_out=${PREFIX_OUT}-edonkey.rrd:mbps:AVERAGE:step=$R1 \
	DEF:skype_out=${PREFIX_OUT}-skype.rrd:mbps:AVERAGE:step=$R1 \
	CDEF:all_out_neg=all_out,-1,* \
	CDEF:all_out_neg_avg_r2=all_out_avg_r2,-1,* \
	CDEF:http_out_neg=http_out,-1,* \
	CDEF:https_out_neg=https_out,-1,* \
	CDEF:ssh_out_neg=ssh_out,-1,* \
	CDEF:ftp_out_neg=ftp_out,-1,* \
	CDEF:gnutella_out_neg=gnutella_out,-1,* \
	CDEF:torrent_out_neg=torrent_out,-1,* \
	CDEF:dc_out_neg=dc_out,-1,* \
	CDEF:edonkey_out_neg=edonkey_out,-1,* \
	CDEF:skype_out_neg=skype_out,-1,* \
	AREA:all_out_neg#C0C0C0:"Other" \
	LINE:0 \
	AREA:http_out_neg#00FF00:"HTTP":STACK \
	AREA:https_out_neg#FF0000:"HTTPS":STACK \
	AREA:ssh_out_neg#FADADD:"SSH":STACK \
	AREA:ftp_out_neg#FF00FF:"FTP":STACK \
	AREA:gnutella_out_neg#50AF00:"Gnutella":STACK \
	AREA:torrent_out_neg#AF5000:"BitTorrent":STACK \
	AREA:dc_out_neg#FFFF00:"DC":STACK \
	AREA:edonkey_out_neg#5050FF:"eDonkey":STACK \
	AREA:skype_out_neg#CC9900:"Skype":STACK \
	LINE2:all_out_neg_avg_r2#00FFFF:"Average ($R2 seconds)" \
	LINE:0#000000

else

	echo "At least one of <prefix_in> or <prefix_out> must be non-empty"
	echo ""
	usage
	exit -1

fi
