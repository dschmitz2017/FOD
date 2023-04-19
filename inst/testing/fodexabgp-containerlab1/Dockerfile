
FROM ubuntu:latest

#RUN apt-get update -y -y && DEBIAN_FRONTEND="noninteractive" apt-get install -y -y systemd-sysv systemd # minimal set
RUN apt-get update -y -y && DEBIAN_FRONTEND="noninteractive" apt-get install -y -y systemd-sysv systemd git less man make gcc strace ltrace lsof file vim tshark tcpdump curl wget net-tools sudo psutils procps iptables iputils-ping iputils-tracepath hping3 iproute2 # with typically useful tools for investigation

WORKDIR /root
COPY ./prep_fod_exabgp2_on_ubuntu.sh /root/

RUN ./prep_fod_exabgp2_on_ubuntu.sh --setup_admin_user5 admin adminpwd admin@localhost.local testpeer 0.0.0.0/0 --exabgp "172.17.0.2" "172.17.0.2" 1001 "172.17.0.3" "172.17.0.3" 2001 

CMD [ "/sbin/init" ]

