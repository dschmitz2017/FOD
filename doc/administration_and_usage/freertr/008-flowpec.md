# **Configuring and Using FlowSpec**

### Freertr and FlowSpec

#### enabling FlowSpec in bgp server config:

```
router bgp4 1
 vrf CORE
 !vrf OOB
 local-as 1
 router-id 4.4.4.1
 no safe-ebgp
 address-family unicast flowspec
 flowspec-install
 flowspec-advert flowspec-v4
 !
 neighbor 10.197.36.2 remote-as 1001
 neighbor 10.197.36.2 local-as 2001
 neighbor 10.197.36.2 address-family unicast flowspec
 neighbor 10.197.36.2 distance 30
 neighbor 10.197.36.2 send-community standard extended
 !
 !
 !
 redistribute connected
 redistribute uni2flow4 1
 exit
!
```

#### local example rules to install in Flowspec Database

```
access-list rule1
 sequence 10 deny 6 15.10.10.1 255.255.255.255 123-129 20.20.20.1 255.255.255.255 200-400
 sequence 20 deny 6 16.10.10.1 255.255.255.255 123-129 20.20.20.1 255.255.255.255 200-400
 sequence 30 deny 7 16.10.10.1 255.255.255.255 123-129 20.20.20.1 255.255.255.255 200-400
 sequence 80 deny 7 16.10.10.2 255.255.255.255 123-129 20.20.20.1 255.255.255.255 200-400
 exit
!
policy-map flowspec-v4
 sequence 1 action drop
 sequence 1 match access-group rule1
 !
 exit
!
```

#### introspection and status

```
show policy-map flowspec-v4 # dump local rules defined in policy-map flowspec-v4

show ipv4 bgp 1 flowspec summary 

show ipv4 bgp 1 flowspec database # show FlowSpec rules defined locally or received 

show policy-map flowspec CORE ipv4 # replace CORE by vrf name # dump FlowSpec statistics
```

## Freertr used with Firewall-On-Demand (FoD)

https://github.com/GEANT/FOD/blob/feature/exabgp_support2/docker-compose/demo1.sh

prerequistes: docker, docker-compose

clone repo: git clone https://github.com/GEANT/FOD && cd ./FOD

switch to correct branch: git checkout feature/exabgp_support2

run demo script: ./docker-compose/demo1.sh # from main dir

### example output of a blocking rule src=10.1.10.11 dst=10.2.10.12 proto=icmp

... (after rule was installed by FoD on FreeRtr via FlowSpec)

```
./docker-compose/demo1.sh: status and freertr policy-map and block counters before the ping to be blocked:
line ready
15802c338fa3#show ipv4 bgp 1 flowspec summary                                 
neighbor     as    learn  accept  will  done  uptime
10.197.36.2  1001  1      1       1     1     03:47:25

15802c338fa3#show ipv4 bgp 1 flowspec database                                
prefix                                     hop          metric      aspath
f01:200a:20a:c02:200a:10a:b03:8101#:: 0:0  10.197.36.2  30/100/0/0  1001

15802c338fa3#show ipv4 bgp 1 flowspec database                                
prefix                                     hop          metric      aspath
f01:200a:20a:c02:200a:10a:b03:8101#:: 0:0  10.197.36.2  30/100/0/0  1001

15802c338fa3#show policy-map flowspec CORE ipv4                               
seq  chld  queue  intrvl  byt/int  rxb  rxp  trnsmt                      ace
1    0     0/128  100     0        0    0    tx=0(0) rx=0(0) drp=0(0)    1-1 10.1.10.11 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff all 10.2.10.12 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff all
2    0     0/128  100     0        378  7    tx=378(7) rx=0(0) drp=0(0)

15802c338fa3#exit                                                             
see you later


./docker-compose/demo1.sh: ping to block:
PING 10.2.10.12 (10.2.10.12) 56(84) bytes of data.

--- 10.2.10.12 ping statistics ---
7 packets transmitted, 0 received, 100% packet loss, time 6137ms


./docker-compose/demo1.sh: freertr policy-map and block counters after blocking the ping:
line ready
15802c338fa3#show ipv4 bgp 1 flowspec summary                                 
neighbor     as    learn  accept  will  done  uptime
10.197.36.2  1001  1      1       1     1     03:47:42

15802c338fa3#show ipv4 bgp 1 flowspec database                                
prefix                                     hop          metric      aspath
f01:200a:20a:c02:200a:10a:b03:8101#:: 0:0  10.197.36.2  30/100/0/0  1001

15802c338fa3#show policy-map flowspec CORE ipv4                               
seq  chld  queue  intrvl  byt/int  rxb  rxp  trnsmt                       ace
1    0     0/128  100     0        588  7    tx=0(0) rx=0(0) drp=588(7)   1-1 10.1.10.11 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff all 10.2.10.12 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff all
2    0     0/128  100     0        517  10   tx=517(10) rx=0(0) drp=0(0)

15802c338fa3#exit                                                             
see you later
```

