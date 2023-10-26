LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -F unsafe_code -A non_snake_case ${NO_OPT} -C iu-playground
CARGO_FLAGS = -Zbuild-std=core --target x86_64-unknown-linux-gnu

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

all: target/x86_64-unknown-linux-gnu/release/map_test entry

target/x86_64-unknown-linux-gnu/debug/map_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

target/x86_64-unknown-linux-gnu/release/map_test: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

llvm-ir: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS} --emit llvm-ir

entry: entry.c
	clang -g -Wl,--as-needed -I. -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR}  -o $@ $< ${LIBBPF_DIR}/bpf/libbpf.a  \
		-L${LIBBPF_DIR} -l:libbpf.a -L${LIBIU_DIR} -lelf -liu -lz

clean:
	cargo clean
	rm -rf entry ./src/linux/*.rs ./src/stub.rs
