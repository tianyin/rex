FROM debian:bookworm-20211201

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/inner_unikernels/libiu

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

# Rust samples
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3-toml bindgen
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    \
    url="https://static.rust-lang.org/rustup/dist/${rustArch}/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

WORKDIR /linux

