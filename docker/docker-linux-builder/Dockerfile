FROM debian:bookworm-20211201

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential fakeroot libncurses5-dev libssl-dev ccache dwarves
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libelf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libdw-dev libdwarf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bpfcc-tools libbpfcc-dev libbpfcc
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-generic
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libtinfo-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libstdc++-10-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bc
#RUN git clone https://github.com/acmel/dwarves.git
#RUN cd dwarves && git checkout tags/v1.18 && mkdir build && cd build && cmake -D__LIB=lib -DBUILD_SHARED_LIBS=OFF .. && make install
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y flex bison

RUN DEBIAN_FRONTEND=noninteractive update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 11
RUN DEBIAN_FRONTEND=noninteractive update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 11

WORKDIR /linux

