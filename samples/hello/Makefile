LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = ${LINUX}/tools/lib/bpf
LIBIU_DIR = "../../libiu"

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case ${NO_OPT} -C iu-playground

all: target/debug/hello loader event-trigger llvm-ir mir

target/debug/hello: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv -- ${RUST_FLAGS}

mir:
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv -- ${RUST_FLAGS} --emit=mir

llvm-ir:
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
        `realpath .`
	cargo rustc -vv -- ${RUST_FLAGS} --emit=llvm-ir

target/release/hello: Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv --release -- ${RUST_FLAGS}

loader: loader.c
	clang -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBIU_DIR} -g -Wl,--as-needed $< -L${LIBBPF_DIR} -L${LIBIU_DIR}\
		-lbpf -lelf -liu -o $@

event-trigger: event-trigger.c
	clang -I${LINUX_INC} -g $< -o $@

clean:
	rm -rf loader event-trigger ./src/linux ./src/stub.rs
	cargo clean

vmcopy: target/debug/hello loader
	cp target/debug/hello loader ../../rootfs/guest/
