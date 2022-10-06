FROM linux-builder

RUN apt-get update

RUN apt-get install -y iputils-ping
RUN apt-get install -y iproute2
RUN apt-get install -y openssh-server

COPY rootfs/vm-net-setup.sh /sbin/vm-net-setup.sh
COPY rootfs/vm-net-setup.service /etc/systemd/system/vm-net-setup.service
COPY rootfs/authorized_keys /root/.ssh/authorized_keys
COPY rootfs/fstab /etc/fstab

RUN systemctl enable vm-net-setup.service

RUN apt-get install -y strace
