#!/bin/bash
QEMU=/usr/bin/qemu-system-x86_64
TAP=tap100
KERNEL=$1
ROOTFS=$2

# clean up old tap
sudo ip link del $TAP
# create new tap
if ! ip link show $TAP &> /dev/null; then
    sudo ip tuntap add mode tap $TAP
    sudo ip addr add 192.168.111.1/24 dev $TAP
    sudo ip link set $TAP up
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
    sudo iptables -t nat -A POSTROUTING -o bond1 -j MASQUERADE
    sudo iptables -I FORWARD 1 -i $TAP -j ACCEPT
    sudo iptables -I FORWARD 1 -o $TAP -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

sudo $QEMU -M microvm,rtc=on \
    -enable-kvm -cpu host -m 256m -smp 1 \
    -kernel ${KERNEL} -append "earlyprintk=ttyS0 console=ttyS0 reboot=k nomodules panic=1 root=/dev/vda init=/sbin/init" \
    -nodefaults -no-user-config -nographic \
    -serial stdio \
    -drive id=drive0,file=${ROOTFS},format=raw,if=none \
    -device virtio-blk-device,drive=drive0 \
    -device virtio-net-device,netdev=n0,mac=AA:FC:00:00:00:01 \
    -netdev tap,id=n0,ifname=$TAP,script=no,downscript=no \
    -no-reboot \
    -no-acpi \
#    -s -S
#2>&1 > /dev/null &

# sleep 5
# ssh -t root@192.168.111.2 "cd /guest; /bin/bash --login"


