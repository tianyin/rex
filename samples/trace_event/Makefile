LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR = "../../libiu"

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case ${NO_OPT} -C iu-playground

all: target/debug/trace_event_kern trace_event

target/debug/trace_event_kern: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS}

trace_helpers.o: trace_helpers.c
	clang -I${LINUX_INC} -g -c $^ -o $@

trace_event: trace_event_user.c trace_helpers.o
	clang -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR} -g -Wl,--as-needed $^ -L${LIBBPF_DIR} -L${LIBIU_DIR}\
		-lbpf -lelf -liu -o $@

clean:
	cargo clean
	rm -rf bpf.o trace_helpers.o trace_event ./src/linux ./src/stub.rs
