# **Configuring and Using FlowSpec**

### Freertr and FlowSpec

#### Freertr Config: Enabling FlowSpec in bgp server config

FlowSpec support via BGP is enabled within the respective router bgp[46] config:
First of all, the flowspec has to be added as an supported addres family for the router itself, as well as all respective peers.
This enables the receiving of FlowSpec rules via such BGP peers and
populating these rules into the FlowSpec database of that router.
Local mitigation rules specified by a manually defined policy-map can be imported into the flowspec database for the router by flowspec-advert config parameter and this also will enable the sending of these rules via BGP by the router to all configured peers which support this.
Processing of these FlowSpec rules in the FlowSpec database of the router, i.e. installation of these rules in the special FlowSpec-specific policy-map for the vrf of the router is enabled by bgp config option flowspec-install.

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

#### Freertr Config: Local example rules to install in Flowspec Database

Here is an example of a manually defined policy-map. It can be used with Flowspec by applying the flowspec-advert (see above).

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

#### Freertr CLI: introspection and status interrogation for Flowspec

Example Freertr CLI commands:


show locally defined rules (via manually defined policy-map), which can be imported in the router by flowspec-advert config,
```
show policy-map flowspec-v4 # dump local rules defined in policy-map flowspec-v4
```

show the flowspec connection summary for a specific bgp router,
```
show ipv4 bgp 1 flowspec summary 
```

show the flowspec database of a specific bgp router (locally or received via BGP),
```
show ipv4 bgp 1 flowspec database # show FlowSpec rules defined locally or received 
```

show the special, flowspec-specific policy-map (including mitigation counters) for a specific vrf (for all flowspec rules in flowspec databases for each every router which is assigned to that vrf ???)
```
show policy-map flowspec CORE ipv4 # replace CORE by vrf name # dump FlowSpec statistics
```

## Freertr used with Firewall-On-Demand (FoD)

### FoD in general

Firewall-On-Demand (FoD) is a server application for multi-tenant DDoS mitigation in a core network.
FoD allow the specification of FlowSpec rules
and their apllication on connected routers of a core network,
restricted according on the users access rights based traffic's target IP prefix.
The applied rules are to be propagated via BGP.
With FoD users are enabled to apply FlowSpec rules in the core network only 
for the network traffic targeted to/from their organization, 
i.e., network traffic traversing the core network towards/from their network
access points.

### FoD installation and FoD with Freertr in general

FoD installation in general:
https://github.com/GEANT/FOD/tree/python3/doc/installation


FoD with Freertr in general:
https://github.com/GEANT/FOD/blob/python3/doc/administration_and_usage/testing_and_using_fod_with_freertr.md

FoD version with exabgp support (https://github.com/GEANT/FOD/tree/feature/exabgp_support2)
can be used for peering with Freertr for distributing FlowSpec rules.
On side of FoD, required is only the exabgp peering configuration (peer AS, peer node id, peer ipv4 address).
Correspondingly, regarding the Freertr side, an example configuration
is available at https://github.com/GEANT/FOD/blob/feature/exabgp_support2/docker-compose/freertr.cfg
(especially the 'router bgp4 1' config part)
assuming the FoD ip address used for BGP peering is 10.197.36.2.


Docker-compose set with FoD and Freertr and attacker/victim host containers:
https://github.com/GEANT/FOD/blob/python3/docker-compose/README.txt

### Demo for using Freertr with FoD

FoD has support for running inside a Docker container and, especially for testing and demonstration purposes,
can be coupled with Freertr running in another container
(https://github.com/GEANT/FOD/blob/python3/docker-compose/README.txt).
Based on this, a script is provided to allow for an integrated, simple demonstration of mitigation via FoD:
In this demo example traffic between an attacker host container towards and victim host container inter-connected via the Freertr container is mitigated by Freertr with the respective FlowSpec rule controlled by FoD.


Script for setting up and running the demo:
```
https://github.com/GEANT/FOD/blob/feature/exabgp_support2/docker-compose/demo1.sh
```

Steps to run the demo:
```
# prerequistes: docker, docker-compose

#clone repo: 
git clone https://github.com/GEANT/FOD && cd ./FOD

#switch to correct branch: 
git checkout feature/exabgp_support2

#run demo script: 
./docker-compose/demo1.sh # from main dir

```

#### Demo: Diagram of docker containers 

```
host1 (attacker) - freertr - host2 (victim)
                      |
                     fod
```

#### Demo: Example output of a blocking rule src=10.1.10.11 dst=10.2.10.12 proto=icmp

Here an excerpt of the output of a run of the demo script,
illustrating the blocking rule in action, is given.
It consists of the output of the various Freertr CLI command for status interrogation
utilized by the demo script, run before and after the installation of the blocking rule:

... (after the blocking rule rule was installed by FoD on FreeRtr via FlowSpec)

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

### FoD and Freertr in Containerlab - Demo for using Freertr with FoD in Containerlab

containerlab in general: https://containerlab.dev/

FoD+Freertr example containerlab specification: https://github.com/rare-freertr/freeRtr-containerlab/blob/main/lab/005-rare-hello-fod/rtr005.clab.yml

recipe how to use this example containerlab: https://github.com/rare-freertr/freeRtr-containerlab/blob/main/lab/005-rare-hello-fod/containerlab-fod-freertr.txt

recipe/demo script based on this example containerlab: https://github.com/rare-freertr/freeRtr-containerlab/blob/main/lab/005-rare-hello-fod/containerlab-fod-freertr.sh





