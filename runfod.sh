#!/bin/sh

if [ -f "./runfod.conf" ]; then
  . "./runfod.conf"
fi

#

if [ "$FOD_RUNMODE" = "via_supervisord" ]; then
  echo "$0: using runmode via_supervisord" 1>&2
  exec ./runfod-supervisord.sh "$@"
else
  echo "$0: using runmod fg" 1>&2
  exec ./runfod-fg.sh "$@"
fi

