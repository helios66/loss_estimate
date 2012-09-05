#!/bin/bash 

must_replay="no"
mapi_conf="/usr/local/etc/mapi/mapi.conf"

############ Functions ###################

## function check_iface(inf) ##
# Checks if the specified interface exist
# and it creates/configures it.
function check_iface() {
	local desc;

#	check if interface exists
	echo -n "Checking for interface $1 ..."
	ifconfig $1 &> /dev/null
	if [ $? -ne 0 ] ; then
		tunctl -t $1 &> /dev/null
		ifconfig $1 up
		echo -n " (created) "
	fi
	echo "OK"

#	check if exists in mapi_conf
	echo -n "Checking for entry in mapi.conf ..."
	grep "device=$1" $mapi_conf &> /dev/null
	if [ $? -ne 0 ]; then
#		find the desciption
		echo -n " (adding) "
		if [ -e .desc ] && [ `cat .desc | wc -l` -eq 1 ]; then
			desc=`cat .desc`
		else
			echo -n "[no .desc] "
			desc="Auto-generated interface for trace replay"
		fi
		
		echo >> $mapi_conf
		echo "[driver]" >> $mapi_conf
		echo "device=$1" >> $mapi_conf
		echo "driver=mapinicdrv.so" >> $mapi_conf
		echo "description=$desc" >> $mapi_conf
	fi
	echo "OK"

#	loads device in mapid (if necessery)
	#mapi_helper -l $1 $desc;

}

## function prepare_traces() ##
# gunzips all the traces in the down_dir directory
# and converts the tsh formate ones  in ethernet.
function prepare_traces() {
	local suf="";

	echo "Preparing traces"
	for trace in `ls *.gz *.bz2 2> /dev/null` ; do
		echo -n "Gunziping $trace ..."
		
		case $trace in
		*gz		)
			gunzip $trace
			suf=".gz"
			;;
		*bz2	)
			tar -xj $trace
			suf=".bz2"
			;;
		esac
		
		if [ $? -eq 0 ]; then
			echo "OK"
		else
			echo "FAIL"
		fi
		
		cur_file=${trace%%$suf}
		
		case $cur_file in
		*tsh    )
			echo -n "Converting $cur_file (tsh to pcap) ..."
			tsh2eth /etc/template.pcap $cur_file &> /dev/null
			if [ $? -ne 0 ]; then
				echo "FAIL"
			else
				echo "OK"
				rm -f $cur_file
			fi
			;;
		*erf    )
			echo -n "Converting $cur_file (erf to pcap) ..."
			tshark -r ${cur_file} -s 68 -w ${cur_file%%".erf"} &> /dev/null
			if [ $? -ne 0 ]; then
				echo "FAIL"
			else
				echo "OK"
				rm -f ${cur_file}
			fi
			;;
		*       )
			;;
		esac
		must_replay="yes";
	done
	
# there should be no erf tsh or gz left here
	if [ -n "`ls *.tsh *.gz *.bz2 *.erf 2> /dev/null`" ] ; then
		echo "Error: Problems occured with these files : "
		ls *.gz *.erf *.tsh
		exit 21
	fi
}

## function replay_traces() ##
# Replays the traces if necessary
function replay_traces() {

	echo -n "Checking replay status ..."

	if [ ! -e .replay-pid ]; then 
		must_replay="yes"
	else
		pid=`cat .replay-pid`;
		if [ -z `ps -p $pid -o pid=` ]; then 
			must_replay="yes"
		fi
	fi

	if [ $must_replay == "yes" ]; then
		rm -f .replay-pid
		tcpreplay -i $1 -m 0.01 -l 100000 * &> .replay-log || (echo "Error: tcpreplay stopped...($1)" && rm -f .replay-pid) &
		echo $! >> .replay-pid
		must_replay="no"
		echo "STARTED"
	else
		echo "RUNNING"
	fi
	
}

## function process_dir(dir) ##
# Processes a single directory
function process_dir() {
	echo "Processing directory $1"
	check_iface $1;
	prepare_traces
	replay_traces $1
	read -p "Continue [y/n]? " ans
	if [ $ans == "n" ] ; then
		exit 33;
	fi
}

## function traverse(dir) ##
# Performs directory traversal.
function traverse() {
	local non_dir=0;
	local all_conts=0;

	pushd $1 &> /dev/null
	echo "Entering directory $1"

	for f in `ls` ; do
		if [ -d $f ] ; then
			traverse $f;
		else
			((non_dir += 1));
		fi
		((all_conts += 1));
	done

	if [ $non_dir -eq $all_conts ] && 
		[ $non_dir -ne 0 ]; then
		process_dir `basename $1`;
	fi

	echo
	popd &> /dev/null
}


if [ $# != 1 ] ; then
	echo "usage: $0 directory"
	exit 1
fi

if [ $UID != 0 ] ; then 
	echo "Only root should run this"
	exit 2
fi

if [ ! -w $mapi_conf ] ; then
	echo "Cannot open $mapi_conf file for writting."
	exit 55
fi

if [ ! -r /etc/template.pcap ] ; then
    echo "Error: cannot read /etc/template.pcap"
    exit 23;
fi

if [ ! -x /usr/local/bin/tsh2eth ] ; then
    echo "Error: cannot exec /usr/local/bin/tsh2eth"
	exit 24;
fi

traverse $1

