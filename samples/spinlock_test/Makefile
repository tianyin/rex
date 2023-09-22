LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

RUST_FLAGS = -Funsafe_code -Clink-arg=-nostartfiles -Ciu-playground

all: target/release/spinlock_test loader event-trigger

target/debug/spinlock_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS}

mir:
	cargo rustc -vv -- ${RUST_FLAGS} --emit=mir

llvm-ir:
	cargo rustc -vv -- ${RUST_FLAGS} --emit=llvm-ir

target/release/spinlock_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv --release -- ${RUST_FLAGS}

loader: loader.c
	clang -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR} -g -Wl,--as-needed $< -L${LIBBPF_DIR} -L${LIBIU_DIR}\
		-lbpf -lelf -liu -lz -o $@

event-trigger: event-trigger.c
	clang -I${LINUX_INC} -g $< -o $@

clean:
	rm -rf loader event-trigger ./src/linux ./src/stub.rs
	cargo clean

vmcopy: target/debug/spinlock_test loader
	cp target/debug/spinlock_test loader ../../rootfs/guest/
