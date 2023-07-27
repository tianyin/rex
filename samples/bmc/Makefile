LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR := $(shell if [ -d "/inner_unikernels/libiu" ]; then echo "/inner_unikernels/libiu"; else echo "../../libiu"; fi)

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case ${NO_OPT} -C iu-playground

all: target/debug/bmc

target/debug/bmc: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS}

target/release/bmc: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv --release -- ${RUST_FLAGS}


bmc_user: bmc_user.c
	clang -g -Wl,--as-needed -I. -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR}  -o $@ $< ${LIBBPF_DIR}/libbpf.a  -L${LIBBPF_DIR} -l:libbpf.a -L${LIBIU_DIR} -lelf -liu -lz

event-trigger: event-trigger.c
	clang -I${LINUX_INC} -g $< -o $@

clean:
	cargo clean
	rm -rf bmc ./src/linux/*.rs ./src/stub.rs
