# The purpose here is to define `hello', `trace_event', whatever, in only
# _one_ place (in this case, in Cargo.toml). The `toml-cli' solution may
# be very ad-hoc and not optimal. But let it be...

ifeq (, $(shell which toml))
    $(info  )
    $(info  Command `toml' not found.)
    $(info  )
    $(info  This is only a stop-gap, but at this stage please install the dependency with the following command:)
    $(info  )
    $(info  $$ pip install toml-cli)
    $(info  )
    $(error )
endif

SAMPLE_NAME = $(shell toml get --toml-path Cargo.toml package.name)

LINUX ?= $(HOME)/linux

LINUX_INC = ${LINUX}/usr/include
LIBIU_DIR = "../../libiu"

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0\
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types\
		-A non_upper_case_globals -A non_snake_case

all: target/debug/$(SAMPLE_NAME) trace_event

target/debug/$(SAMPLE_NAME): Cargo.toml ./src/*.rs ${LINUX}/vmlinux
	PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/prep_interface.py ${LINUX}\
		`realpath .`
	cargo rustc -vv -- ${RUST_FLAGS}

llvm-ir: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit llvm-ir

mir: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit mir

asm: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit asm

trace_event: trace_event.c
	clang -I${LINUX_INC} -I${LIBIU_DIR} -D SAMPLE_NAME=\"$(SAMPLE_NAME)\" -g -Wl,--as-needed $< -L${LIBIU_DIR}\
		-liu -o $@


clean:
	cargo clean
	rm -rf trace_event ./src/linux ./src/stub.rs
