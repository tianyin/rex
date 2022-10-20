#!/bin/bash
QEMU=/usr/bin/qemu-system-x86_64
TAP=tap100
KERNEL=$1
ROOTFS=$2

INNER_UNIKERNELS_PATH=`pwd`
LINUX_PATH=`readlink -f ~/linux`
LIBBPF_BOOTSTRAP_PATH=`readlink -f ~/libbpf-bootstrap`

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

nohup sudo $QEMU \
     -machine accel=kvm:tcg \
     -enable-kvm -cpu host -m 256m -smp 1 \
     -kernel ${KERNEL} -append "earlyprintk=ttyS0 console=ttyS0 reboot=k nomodules panic=1 root=/dev/vda init=/sbin/init" \
    -nodefaults -no-user-config -nographic \
    -serial stdio \
    -drive file=${ROOTFS},format=raw,if=virtio,media=disk \
    -device virtio-net-pci,netdev=n0,mac=AA:FC:00:00:00:01 \
    -netdev tap,id=n0,ifname=$TAP,script=no,downscript=no \
	-fsdev local,multidevs=remap,id=iu,path=$INNER_UNIKERNELS_PATH,security_model=none \
    -device virtio-9p-pci,fsdev=iu,mount_tag=inner_unikernels \
	-fsdev local,multidevs=remap,id=linux,path=$LINUX_PATH,security_model=none \
    -device virtio-9p-pci,fsdev=linux,mount_tag=linux \
	-fsdev local,multidevs=remap,id=libbpf-bootstrap,path=$LIBBPF_BOOTSTRAP_PATH,security_model=none \
    -device virtio-9p-pci,fsdev=libbpf-bootstrap,mount_tag=libbpf-bootstrap \
    -no-reboot \
    -no-acpi \
    &>/dev/null & 
    #    2>&1 > /dev/null & 
#    -s -S \


reset
echo -n "waiting for VM"
until ssh root@192.168.111.2 true >/dev/null 2>&1; do
    echo -n "."
    sleep 1
done
echo
ssh -t root@192.168.111.2 "cd /host/inner_unikernels/rootfs/guest; /bin/bash --login"
