FROM ubuntu:groovy

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev binutils-dev cmake
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcap-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y llvm-11-dev llvm-11-tools
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libelf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang-11
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bpfcc-tools libbpfcc-dev libbpfcc

RUN apt-get install -y iputils-ping
RUN apt-get install -y iproute2
RUN apt-get install -y openssh-server
RUN ln -s /usr/lib/systemd/system/getty@.service /etc/systemd/system/getty.target.wants/getty@ttyS0.service
RUN echo "root:root" | chpasswd

COPY rootfs/vm-net-setup.sh /sbin/vm-net-setup.sh
COPY rootfs/vm-net-setup.service /etc/systemd/system/vm-net-setup.service

RUN systemctl enable vm-net-setup.service

RUN apt-get install -y strace