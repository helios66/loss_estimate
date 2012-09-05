#!/bin/sh -x

buf=`./randstr.pl 300`
echo string: $buf

for ((a=22; a <= 144; a++))
do
	echo $buf | netcat -w 1 139.91.70.$a 22 >& /dev/null &
done
