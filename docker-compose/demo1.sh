#!/bin/bash

# to be run from FoD main dir

# ./docker-compose/README.txt

set -e

##

count_up="$(docker-compose ps | grep Up | wc -l)"

if [ "$count_up" != 4 ]; then
  echo "$0: docker-compose set not fully setup, trying to do so" 1>&2

  docker-compose down

  docker-compose build
  docker-compose up -d
else
  echo "$0: docker-compose seems to be ready" 1>&2
fi

#

./docker-compose/freertr_disable_offload.sh || true

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

echo "waiting 10 seconds" 1>&2
sleep 10

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


