LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBIU_DIR = "../../libiu"

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case

all: target/debug/trace_event_kern trace_event

target/debug/trace_event_kern: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv -- ${RUST_FLAGS}

trace_helpers.o: trace_helpers.c
	clang -I${LINUX_INC} -g -c $^ -o $@

bpf.o: bpf.c
	clang -I${LINUX_INC} -g -c $^ -o $@

trace_event: trace_event_user.c trace_helpers.o bpf.o
	clang -I${LINUX_INC} -I${LIBIU_DIR} -g -Wl,--as-needed $^ -L${LIBIU_DIR}\
		-liu -o $@

clean:
	cargo clean
	rm -rf bpf.o trace_helpers.o trace_event ./src/linux ./src/stub.rs
