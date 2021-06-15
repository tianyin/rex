#!/bin/bash
TAP=tap100
KERNEL=$1
ROOTFS=$2

# clean up old tap
sudo ip link del $TAP
# create new tap
if ! ip link show $TAP &> /dev/null; then
    sudo ip tuntap add mode tap $TAP
    sudo ip addr add 192.168.100.1/24 dev $TAP
    sudo ip link set $TAP up
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
    sudo iptables -t nat -A POSTROUTING -o bond1 -j MASQUERADE
    sudo iptables -I FORWARD 1 -i $TAP -j ACCEPT
    sudo iptables -I FORWARD 1 -o $TAP -m state --state RELATED,ESTABLISHED -j ACCEPT
fi


fc-bin/firectl --firecracker-binary=$(pwd)/fc-bin/firecracker \
--kernel $KERNEL \
--root-drive=$ROOTFS \
--tap-device=$TAP/AA:FC:00:00:00:01 \
--vmm-log-fifo=firelog \
--ncpus=1 \
--memory=8192 \
-d \
--kernel-opts="console=ttyS0 panic=1 init=/sbin/init"
