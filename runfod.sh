#!/bin/sh

if [ -f "./runfod.conf" ]; then
  . "./runfod.conf"
fi

#

if [ "$FOD_RUNMODE" = "via_systemd" ]; then
  echo "$0: using runmode via_systemd, nothing todo" 1>&2

  SYSTEMD_COLORS=1 systemctl status "fod-gunicorn" | cat
  echo

  SYSTEMD_COLORS=1 systemctl status "fod-celeryd" | cat
  echo

  SYSTEMD_COLORS=1 systemctl status "redis" | cat
  echo

  SYSTEMD_COLORS=1 systemctl status "exabgpForFod" | cat
  echo

elif [ "$FOD_RUNMODE" = "via_supervisord" ]; then
  echo "$0: using runmode via_supervisord" 1>&2
  exec ./runfod-supervisord.sh "$@"
else
  echo "$0: using runmod fg" 1>&2
  exec ./runfod-fg.sh "$@"
fi

