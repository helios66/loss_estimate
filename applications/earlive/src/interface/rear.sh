#!/bin/sh
# Remote EAR

EAR_COMMAND="sudo /spare/near/src/ear -i eth1"
REMOTE_HOST=almagest

trap "ssh $REMOTE_HOST sudo killall /spare/near/src/ear" EXIT
ssh $REMOTE_HOST $EAR_COMMAND $*
