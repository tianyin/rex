FROM ubuntu:groovy

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev binutils-dev cmake
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcap-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y llvm-11-dev llvm-11-tools
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libelf-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang-11
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y bpfcc-tools libbpfcc-dev libbpfcc

WORKDIR /linux/tools/bpf/bpftool