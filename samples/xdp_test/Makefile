LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -F unsafe_code -A non_snake_case ${NO_OPT} -C iu-playground

all: target/release/xdp_test entry

target/debug/xdp_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS}

ir: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit=llvm-ir

target/release/xdp_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv --release -- ${RUST_FLAGS}

entry: entry.c
	clang -g -Wl,--as-needed -I. -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR}  -o $@ $< ${LIBBPF_DIR}/bpf/libbpf.a  -L${LIBBPF_DIR} -l:libbpf.a -L${LIBIU_DIR} -lelf -liu -lz

clean:
	cargo clean
	rm -rf entry ./src/linux/*.rs ./src/stub.rs
