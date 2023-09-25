LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

RUST_FLAGS = -Funsafe_code -Clink-arg=-nostartfiles -Ciu-playground
CARGO_FLAGS = -Zbuild-std=core --target x86_64-unknown-linux-gnu

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

all: target/x86_64-unknown-linux-gnu/release/syscall_tp syscall_tp

target/x86_64-unknown-linux-gnu/debug/syscall_tp: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

target/x86_64-unknown-linux-gnu/release/syscall_tp: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

syscall_tp: syscall_tp_user.c
	clang -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR} -g -Wl,--as-needed $< -L${LIBBPF_DIR} -L${LIBIU_DIR}\
		-lbpf -lelf -liu -lz -o $@

clean:
	cargo clean
	rm -rf syscall_tp ./src/linux ./src/stub.rs
