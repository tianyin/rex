FROM ubuntu:22.04 as Linux-builder

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/linux/rust/dist/bin:$PATH \
    LD_LIBRARY_PATH=/inner_unikernels/libiu:$LD_LIBRARY_PATH \
    LINUX=/linux 

# adding clang
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -y git build-essential gcc g++ fakeroot libncurses5-dev libssl-dev ccache dwarves libelf-dev \
 cmake \
 libdw-dev libdwarf-dev \
 bpfcc-tools libbpfcc-dev libbpfcc \
 linux-headers-generic \
 libtinfo-dev \
 libstdc++-11-dev libstdc++-12-dev \
 bc \
 flex bison \
 rsync \
 libcap-dev libdisasm-dev binutils-dev unzip \
 pkg-config lsb-release wget software-properties-common gnupg zlib1g 

RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 16
RUN ln -s /usr/bin/clang-16 /usr/bin/clang
RUN ln -s /usr/bin/clang++-16 /usr/bin/clang++
RUN ln -s /usr/bin/ld.lld-16 /usr/bin/ld.lld 
RUN ln -s /usr/bin/llvm-ar-16 /usr/bin/llvm-ar
RUN ln -s /usr/bin/llvm-strip-16 /usr/bin/llvm-strip
RUN ln -s /usr/bin/llvm-objdump-16 /usr/bin/llvm-objdump
RUN ln -s /usr/bin/llc-16 /usr/bin/llc
RUN ln -s /usr/bin/llvm-readelf-16 /usr/bin/llvm-readelf
RUN ln -s /usr/bin/llvm-dis-16 /usr/bin/llvm-dis
RUN ln -s /usr/bin/opt-16 /usr/bin/opt

# Rust 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3-toml bindgen libssl-dev pkg-config curl ninja-build git
RUN DEBIAN_FRONTEND=noninteractive git clone --recursive -j32 --depth=1 --shallow-submodules https://github.com/xlab-uiuc/rust 
WORKDIR "/rust"
RUN cp inner-unikernels-config.toml config.toml
RUN python3 x.py build; \
	python3 x.py install;
RUN python3 x.py install cargo

ENV PATH=/usr/local/cargo/bin:/rust/dist/bin:$PATH 
RUN cargo install --version 0.62.0 bindgen-cli
RUN chmod -R 777 $CARGO_HOME

# Qemu
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils virtinst libvirt-daemon xterm attr busybox openssh-server

