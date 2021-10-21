#!/bin/sh

ip addr add 192.168.111.2/24 dev eth0
ip addr add 127.0.0.1/24 dev lo
ip link set eth0 up
ip link set lo up
ip route add default via 192.168.111.1 dev eth0
