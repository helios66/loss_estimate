#ifndef __CGI_HEADERS_H__
	#define __CGI_HEADERS_H__


#define BASENAME "appmon"  //change only this one
#define RRD_FILENAME BASENAME".rrd"
#define CGI_FILENAME BASENAME".cgi"
#define FORM_FILENAME BASENAME"_form.html"
#define TOP_FILENAME BASENAME"_top.html"
#define PTOP_FILENAME BASENAME"_top_private.html"

#define APPMON_DIR "/var/lib/appmon"

static char cgiHead[] = "\
#!/usr/bin/rrdcgi\n\
<HTML>\n<HEAD>\n\
<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">\n\
<META Http-Equiv=\"Expires\" Content=\"10\">\n\
<META Http-Equiv=\"Refresh\" Content=\"10;url=./appmon.cgi\">\
<script language=\"JavaScript\">\n\
<!--var time = null\n\
function move() {\n\
window.location = '"CGI_FILENAME"';\n\
} //-->\n\
</script>\n\
</HEAD>\n<BODY vlink=\"blue\">\n<center>\n\
<table><tr><td width=25\%>\n\
<a href=\"http://www.ist-lobster.org\" style=\"color: white\"><img src=../img/lobster-logo.jpg></a></td>\n\
<td width=75\%><h2>Application Traffic Breakdown</h2></td></tr></table><br><h2>";

static char cgiHead2[] = "\
</h2>\
<table align=\"center\"><tr>\
<td><a href=\"appmon.cgi\">1 hour</a></td>\n\
<td><a href=\"appmon3.cgi\">3 hour</a></td>\n\
<td><a href=\"appmon24.cgi\">1 day</a></td>\n\
<td><a href=\"appmonWeek.cgi\">1 Week</a></td>\n\
<td><a href=\"appmonMonth.cgi\">1 Month</a></td>\n\
<td><a href=\"appmonYear.cgi\">1 Year</a></td>\n\
</tr>\n\
<tr><td colspan=6>\n\
<p align=center>\n\
</p></td></tr>\n\
</table>\n\
<P>\n<RRD::GRAPH\n";

#define IMAGE_NAME "../%s \n %s "

#define RRD_ATRS	"--width 500 --height 300\n\--imginfo '<IMG SRC=../%s WIDTH=%lu HEIGHT=%lu >'\n"

#define cgiHead3 "--end now --start end-%s --lazy\n\ --slope-mode --interlaced --vertical-label \"outbound      Mbit/s      inbound\"\n"

#endif
