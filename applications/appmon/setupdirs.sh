#!/bin/sh
if [ $# -ne 1 ]; then
	echo 1>&2 "Usage: $0 <path to web server's root directory>"
	exit 1
fi

mkdir $1/appmon
mkdir $1/appmon/cgi-bin
mkdir $1/appmon/private
mkdir $1/appmon/img

# awful
chmod 777 $1/appmon
chmod +r $1/appmon/private
chmod +rx $1/appmon/img


cp `pwd`/lobster-logo.jpg $1/appmon/img/lobster-logo.jpg
chmod +x $1/appmon/img/lobster-logo.jpg

cp index.html $1/appmon


ln -fs `pwd`/appmon_form.html $1/appmon/appmon_form.html
ln -fs `pwd`/appmon_top.html $1/appmon/appmon_top.html
ln -fs `pwd`/appmon.cgi $1/appmon/cgi-bin/appmon.cgi
ln -fs `pwd`/appmon3.cgi $1/appmon/cgi-bin/appmon3.cgi
ln -fs `pwd`/appmon24.cgi $1/appmon/cgi-bin/appmon24.cgi
ln -fs `pwd`/appmonWeek.cgi $1/appmon/cgi-bin/appmonWeek.cgi
ln -fs `pwd`/appmonMonth.cgi $1/appmon/cgi-bin/appmonMonth.cgi
ln -fs `pwd`/appmonYear.cgi $1/appmon/cgi-bin/appmonYear.cgi
ln -fs `pwd`/appmon_top_private.html $1/appmon/private/appmon_top_private.html

echo -e "\nDONE - created the following files in $1/appmon\n"

ls -Rl $1/appmon

echo -e "\nDon't forget to enable script execution for $1/appmon/cgi-bin \
in your web server's configuration"

exit 0
