#!/bin/bash

# Run this script (only as root user), in order to check reconnection of 
# client - application after connection to mapid or mapicommd breaks down

# In order to enable reconnection, MAPI should be configured as follows:
#	./configure --enable-reconnect
#			OR
#	./configure --enable-dimapi --enable-reconnect (in case that you want DiMAPI)

# Copyright (C) 2007 Makridakis Andreas (amakrid@ics.forth.gr)

mapid=`ps -A | grep mapid | awk ' { print $4 } '`
mapicommd=`ps -A | grep mapicommd | awk ' { print $4 } '`
flag=0

if [ $mapid ]		# mapid is running or not ???
then
	echo -e "\n\t *** mapid is running ***\n"
	flag=1
else
	echo -e "\n\t *** mapid is out of execution ***\n"
	/usr/local/sbin/mapid > /dev/null &
fi

if [ $mapicommd ]	# mapicommd is running or not ???
then
	if [ $flag -eq 1 ]
	then
		echo -e "\t *** mapicommd is running ***\n"
	else
		echo -e "\n\t *** mapicommd is running ***\n"
	fi
else
	if [ $flag -eq 1 ]
	then
		echo -e "\t *** mapicommd is out of execution ***\n"
	else
		echo -e "\n\t *** mapicommd is out of execution ***\n"
	fi

	/usr/local/sbin/mapicommd > /dev/null &
	echo
fi

sleep 1

./test_reconnection eth0 & 		# run sample monitoring application, using local MAPI
sleep 10

killall mapid				# kill mapid, in order to check reconnection
echo -e "\n\t ---> Kill mapid - Use local MAPI\n"
sleep 7

/usr/local/sbin/mapid > /dev/null &	# mapid is now up and running
echo -e "\n\n\t ---> mapid is running - Use local MAPI"
sleep 10

killall mapid
echo -e "\n\t ---> Kill mapid - Use local MAPI\n"
sleep 7

/usr/local/sbin/mapid > /dev/null &
echo -e "\n\n\t ---> mapid is running - Use local MAPI"
sleep 10

echo
killall test_reconnection
sleep 1
./test_reconnection localhost:eth0 & 		# run sample monitoring application, using DiMAPI
echo -e "\n\t ---> Restart application\n"

sleep 10

killall mapicommd				# kill mapicommd, in order to check reconnection
echo -e "\n\t ---> Kill mapicommd - Use DiMAPI"
sleep 7

/usr/local/sbin/mapicommd > /dev/null &		# mapicommd is now up and running
echo -e "\n\n\t ---> mapicommd is running - Use DiMAPI"
sleep 10

killall mapicommd
echo -e "\n\t ---> Kill mapicommd - Use DiMAPI"
sleep 7

/usr/local/sbin/mapicommd > /dev/null &
echo -e "\n\n\t ---> mapicommd is running - Use DiMAPI"

sleep 10

echo
killall test_reconnection
sleep 1
./test_reconnection localhost:eth0 & 	# run sample monitoring application, using DiMAPI
echo -e "\n\t ---> Restart application\n"

sleep 10

killall mapid				# kill mapid, in order to check reconnection
echo -e "\n\t ---> Kill mapid - Use DiMAPI\n"
sleep 7

/usr/local/sbin/mapid > /dev/null &	# mapid is now up and running
echo -e "\t ---> mapid is running - Use DiMAPI\n"
sleep 10

killall mapid
echo -e "\n\t ---> Kill mapid - Use DiMAPI\n"
sleep 7

/usr/local/sbin/mapid > /dev/null &
echo -e "\t ---> mapid is running - Use DiMAPI\n"
sleep 10

echo
killall test_reconnection
sleep 1
./test_reconnection localhost:eth0 & 	# run sample monitoring application, using DiMAPI
echo -e "\n\t ---> Restart application\n"

sleep 10

killall mapicommd ; killall mapid	# kill mapid & mapicommd, in order to check reconnection
echo -e "\n\t ---> Kill mapid & mapicommd - Use DiMAPI"
sleep 7

/usr/local/sbin/mapid > /dev/null &	# mapid & mapicommd are now up and running
/usr/local/sbin/mapicommd > /dev/null &
echo -e "\n\n\t ---> mapid & mapicommd are running - Use DiMAPI"
sleep 10

killall mapicommd ; killall mapid
echo -e "\n\t ---> Kill mapid & mapicommd - Use DiMAPI"
sleep 7

/usr/local/sbin/mapid > /dev/null &
/usr/local/sbin/mapicommd > /dev/null &
echo -e "\n\n\t ---> mapid & mapicommd are running - Use DiMAPI"
sleep 20

echo
killall test_reconnection
killall mapicommd ; killall mapid
