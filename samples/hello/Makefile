LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBIU_DIR = "../../libiu"

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case

all: target/debug/hello loader event-trigger

target/debug/hello: Cargo.toml src/*.rs
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv -- ${RUST_FLAGS}

loader: loader.c
	clang -I${LINUX_INC} -I${LIBIU_DIR} -g -Wl,--as-needed $< -L${LIBIU_DIR}\
		-liu -o $@

event-trigger: event-trigger.c
	clang -I${LINUX_INC} -g $< -o $@

clean:
	rm -rf loader event-trigger ./src/linux ./src/stub.rs
	cargo clean

vmcopy: target/debug/hello loader
	cp target/debug/hello loader ../../rootfs/guest/
