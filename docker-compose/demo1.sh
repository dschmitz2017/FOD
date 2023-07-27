#!/bin/bash

# to be run from FoD main dir

# ./docker-compose/README.txt

set -e

##

count_up="$(docker-compose ps | grep Up | wc -l)"

if [ "$1" = "rebuild" -o "$count_up" != 4 ]; then
  echo "$0: docker-compose set not fully setup, trying to do so" 1>&2

  echo "$0: tearing down docker-compse set completly" 1>&2
  docker-compose down

  echo "$0: (re-)building docker-compose set" 1&>2
  docker-compose build

  echo "$0: bringing docker-compose set up" 1>&2
  docker-compose up -d

  reinit_done=1

else
  echo "$0: docker-compose seems to be ready" 1>&2
  reinit_done=0
fi

#

echo "$0: running freertr_disable_offload hack" 1>&2
./docker-compose/freertr_disable_offload.sh || true

echo "$0: making sure bind-mounted FoD dir is setup from within container" 1>&2
while ! docker exec -ti fod ls /opt/setup_ok &>/dev/null; do
  echo "docker container has not yet fully completed setup of FoD dir from inside container, so waiting 1 sec" 1>&2
  sleep 1  
done

#

clear
echo 1>&2
echo "$0: beginning with demo proper: part1: initial ping between host1 and host2; disabling any left-over rules:" 1>&2

docker exec -ti fod ./inst/helpers/enable_rule.sh 10.1.10.11/32 10.2.10.12/32 1 -1

#

clear
echo 1>&2
echo "$0: beginning with demo proper: part1: initial ping between host1 and host2" 1>&2

sleep 2

echo "$0: ping not to be blocked:" 1>&2
docker exec -d -ti host1 ping -c 1 10.2.10.12
docker exec -ti host1 ping -c 7 10.2.10.12

wait1=5
echo "waiting $wait1 seconds" 1>&2
sleep "$wait1"

echo "$0: exabgp current exported rules/routes:" 1>&2
docker exec -ti freertr sh -c '{ echo "show ipv4 bgp 1 flowspec database"; echo "show policy-map flowspec CORE ipv4"; echo exit; } | netcat 127.1 2323'

#

clear
echo 1>&2
echo "$0: beginning with demo proper: part2: blocked ping between host1 and host2; adding block rule:" 1>&2

#docker exec -ti fod ./inst/helpers/add_rule.sh 10.1.10.11 10.2.10.12 1
docker exec -ti fod ./inst/helpers/enable_rule.sh 10.1.10.11/32 10.2.10.12/32 1
#docker exec -ti fod ./inst/helpers/list_rules_db.sh

clear
echo 1>&2
echo "$0: beginning with demo proper: part2: blocked ping between host1 and host2:" 1>&2

sleep 2

echo "$0: exabgp current exported rules/routes:" 1>&2
docker exec -ti fod sh -c '. /opt/venv/bin/activate && exabgpcli show adj-rib out extensive'

echo "$0: freertr block counters:" 1>&2
docker exec -ti freertr sh -c '{ echo "show ipv4 bgp 1 flowspec database"; echo "show policy-map flowspec CORE ipv4"; echo exit; } | netcat 127.1 2323'

echo "$0: ping to block:" 1>&2
docker exec -ti host1 ping -c 7 10.2.10.12 || true

echo "$0: freertr block counters:" 1>&2
docker exec -ti freertr sh -c '{ echo "show ipv4 bgp 1 flowspec database"; echo "show policy-map flowspec CORE ipv4"; echo exit; } | netcat 127.1 2323'


