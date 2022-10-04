FROM debian:bookworm-20211201

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential gcc-11 g++-11 fakeroot libncurses5-dev libssl-dev ccache dwarves
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libelf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libdw-dev libdwarf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bpfcc-tools libbpfcc-dev libbpfcc
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-generic
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libtinfo-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libstdc++-10-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bc
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y flex bison

RUN DEBIAN_FRONTEND=noninteractive update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 11

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcap-dev llvm-dev libdisasm-dev binutils-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y pkg-config

WORKDIR /linux

