#!/bin/bash

ear_conf="/usr/local/etc/ear_monitor.conf"
ear_parser="/usr/local/etc/ear_out_parser.awk"
pid_file="/var/run/ear_monitor.pid"

state="UNKNOWN"

# load ear configuration
if [ -r $ear_conf ] ; then
	. $ear_conf
	echo "loaded configuration from $ear_conf"
else
	echo "Conf file $ear_conf cannot be read"
	exit 43
fi

# change directory to earlive dor
pushd $earlivedir &> /dev/null

#check argc
if [ $# != 1 ] ; then
	echo "usage: $0 [start|stop|check]"
	exit 13
fi

############### functions #################################

function check() {
	if [ -r $pid_file ]; then
		if [ "x`ps -p \`cat $pid_file\` -o comm=`" = "xearmonitor" ]; then
			echo "earmonitor is running with pid `cat $pid_file`"
			state="RUNNING"
		else
			echo "$pid_file contains wrong pid. removing it."
			rm -f $pid_file
			echo "earmonitor is not running"
			state="STOPED"
		fi
	else
		echo "earmonitor is not running"
		state="STOPED"
	fi

	if [ -d alerts ]; then
		echo "alerts directory contains `ls alerts|wc -w` files"
	else
		echo "there is no alerts directory. creating it"
		mkdir -p alerts
	fi

	if [ -p comm ]; then
		echo "comm fifo exists"
	else
		echo "comm fifo does not exist. creating it"
		mkfifo -m 777 comm
	fi

	if [ -r data ]; then
		echo "data file has `cat data|wc -l` lines"
	else
		echo "no data file"
	fi
}

function start() {

	if [ $state = "RUNNING" ]; then 
		echo "earmonitor is already runnig."
	else
		if [ -s data ]; then 
			echo "found previous data file. deleting it"
			rm -f data
		fi

		if [ ${trace_file-"none"} == "none" ]; then
			first_arg="-i ${mon_if}"
		else
			first_arg="-r ${trace_file}"
		fi

		earmonitor 			$first_arg \
			--offset 		${stream_offset} \
			--period 		${time_thres} \
			--select-mask 	${sample_mask-"0x0"} \
			--targets 		${target_thres} \
			--length 		${sub_length} \
			| gawk -f $ear_parser  \
			-v "ALERTID=`ls alerts|wc -w`" \
			-v "EARDIR=$earlivedir" \
			-v "SUBLEN=$sub_length" \
			-v "DESTTHR=$target_thres" \
			-v "TIMETHR=$time_thres" &
		echo $(( $! - 1 ))  >> $pid_file
		echo "earmonitor started"
	fi
}

function stop() {
	if [ $state = "RUNNING" ]; then
		kill -9 `cat $pid_file`
		rm -f $pid_file
		echo "earmonitor stopped."
	fi
}

case $1 in
	start )
			echo "Checking Ear Monitor's state"
			check
			echo "Starting Ear Monitor"
			start
			;;
	stop ) 
			echo "Checking Ear Monitor's state"
			check
			echo "Stoping Ear Monitor"
			stop
			;;
	check ) 
			echo "Checking Ear Monitor's state"
			check
			;;
	* )
			echo "Usage: $0 [start|stop|check]"
			;;
esac

