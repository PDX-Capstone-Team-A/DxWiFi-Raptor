#!/bin/bash

devname=$1

if [ $# -eq 0 ]
then
	echo "usage: sh wifi_back_on wifi_device_name"
	exit 1
fi

if [ "$(whoami)" != "root" ]
then
	echo "script must be run as root"
	exit 1
fi

if [ -f /usr/bin/systemctl ] #systemd
then
	systemctl start NetworkManager.service
	systemctl start NetworkManager.service
fi

if [ -f /usr/sbin/service ] #upstart
then
	service network-manager start
fi

ip link set $devname down && sleep 1
iw dev $devname set type managed && sleep 1 #ibss = Ad-hoc
ip addr flush dev $devname && sleep 1
ip link set $devname up && sleep 1

