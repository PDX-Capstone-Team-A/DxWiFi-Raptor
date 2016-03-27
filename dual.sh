#!/bin/bash

devname=$1
ipaddr=$3

if [ $# -le 1 ]
then
	echo "usage: sh dual.sh wifi_device_name physical_device_name ip_address"
	echo "eg: sudo sh dual.sh wlan0 phy0 10.0.0.8"
	exit 1
fi

if [ "$(whoami)" != "root" ]
then
	echo "script must be run as root"
	exit 1
fi

if [ -f /usr/bin/systemctl ] #systemd
then
	systemctl stop NetworkManager.service
fi

if [ -f /usr/sbin/service ] #upstart
then
	service network-manager stop
fi


ip link set $devname down && sleep 1 #set device down
iw dev $devname set type ibss && sleep 1 #ad hoc mode
ip addr flush dev $devname && sleep 1 #flush previous config
ip addr add $ipaddr/24 dev $devname && sleep 1 #assign static ip
ip link set $devname up && sleep 1 #set device up
iw $devname ibss leave 2> /dev/null && sleep 1
iw $devname ibss join rockets 2412 fixed-freq basic-rates 1 && sleep 1
iw $devname set bitrates legacy-2.4 1 && sleep 1
iw phy $2 set rts -1

#this line is new vvv 
ip route add 224.0.0.0/4 dev wlp4s0 #set the route for multicasting

