FROM debian:stable-20220822

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev zlib1g 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bpfcc-tools libbpfcc-dev libbpfcc
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libdw-dev libdwarf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcap-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libelf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libdisasm-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y binutils-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y llvm-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang clang-tools

WORKDIR /linux/tools/bpf/bpftool