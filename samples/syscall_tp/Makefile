LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = $(abspath ${LINUX}/tools/lib/bpf)
LIBREX_DIR := $(shell if [ -d "/rex-kernel/librex" ]; then echo "/rex-kernel/librex"; else echo `realpath ../../librex`; fi)

RUST_FLAGS = -Funsafe_code -Clink-arg=-nostartfiles -Cenable_rex
CARGO_FLAGS = -Zbuild-std=core --target x86_64-unknown-linux-gnu

CC = gcc

CFLAGS += -O2 -march=native -pipe -std=gnu11
CFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
LDFLAGS += -fuse-ld=mold -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections

LOADER_INC += -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBREX_DIR}
LOADER_LDFLAGS = -L${LIBBPF_DIR} -L${LIBREX_DIR} -lbpf -lrex -Wl,-rpath=${LIBBPF_DIR} -Wl,-rpath=${LIBREX_DIR}

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

all: target/x86_64-unknown-linux-gnu/release/syscall_tp syscall_tp

target/x86_64-unknown-linux-gnu/debug/syscall_tp: Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

target/x86_64-unknown-linux-gnu/release/syscall_tp: Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

syscall_tp: syscall_tp_user.c
	${CC} ${LOADER_INC} ${CFLAGS} ${LDFLAGS} -o $@ $< ${LOADER_LDFLAGS}

clean:
	cargo clean
	rm -rf syscall_tp ./src/linux ./src/stub.rs
