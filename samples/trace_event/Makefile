LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

RUST_FLAGS = -Funsafe_code -Clink-arg=-nostartfiles -Ciu-playground


all: target/release/trace_event_kern trace_event

target/debug/trace_event_kern: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS}

target/release/trace_event_kern: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv --release -- ${RUST_FLAGS}

trace_helpers.o: trace_helpers.c
	clang -I${LINUX_INC} -g -c $^ -o $@

trace_event: trace_event_user.c trace_helpers.o
	clang -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR} -g -Wl,--as-needed $^ -L${LIBBPF_DIR} -L${LIBIU_DIR}\
		-lbpf -lelf -liu -lz -o $@

clean:
	cargo clean
	rm -rf bpf.o trace_helpers.o trace_event ./src/linux ./src/stub.rs
