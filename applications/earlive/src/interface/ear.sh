#!/bin/sh

MONITOR=/home/akritid/MyData/EAR/src/monitor/monitor
TRACE=/home/akritid/forth.trace2

# Must change to the dir that has detect.data for mod_detect's decoder
cd `dirname $MONITOR`

sudo $MONITOR -r $TRACE $*
