#!/bin/bash

# For reconnection purposes, just append the following line
# */1 * * * * root /usr/local/etc/mapi/reconnection.sh >> a_possible_file_for_output_messages
# to file: /etc/crontab

# Cron daemon (crond) will run reconnection.sh script, every one minute, checking
# for execution of daemons mapid and mapicommd. If mapid and/or mapicommd, stops its
# execution, it will be executed automatically, from the script.
# When the connection with mapi daemons is restored, the monitoring applications
# will continue automatically their execution.

mapid=`ps -A | grep mapid | awk ' { print $4 } '`
mapicommd=`ps -A | grep mapicommd | awk ' { print $4 } '`

if [ -n "$mapid" ]			# mapid is running or not ???
then
	date=`/bin/date`
	echo -e "\n\t *** mapid is running *** ($date)\n"
else
	date=`/bin/date`
	echo -e "\n\t *** mapid is out of execution *** ($date)\n"
	/usr/local/sbin/mapid -d	# run mapid as daemon
fi

if [ -n "$mapicommd" ]			# mapicommd is running or not ???
then
	date=`/bin/date`
	echo -e "\n\t *** mapicommd is running *** ($date)\n"
else
	date=`/bin/date`
	echo -e "\n\t *** mapicommd is out of execution *** ($date)\n"
	/usr/local/sbin/mapicommd -d	# run mapicommd as daemon
fi
