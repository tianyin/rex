LINUX ?= $(HOME)/linux

INC = ${LINUX}/usr/include

RUST_FLAGS = -Z macro-backtrace -C debuginfo=0 -C opt-level=0 \
		-C link-arg=-nostartfiles -A unused -A non_camel_case_types \
		-A non_upper_case_globals -A non_snake_case

all: target/debug/rust loader event-trigger

target/debug/rust: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	python3 prep_interface.py  ${LINUX}
	cargo rustc -vv -- ${RUST_FLAGS}

llvm-ir: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit llvm-ir

mir: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit mir

asm: ./src/*.rs prep_interface.py ${LINUX}/vmlinux
	cargo rustc -vv -- ${RUST_FLAGS} --emit asm

loader: loader.cpp
	clang++ -I${INC} -g $< -o $@ -lelf

event-trigger: event-trigger.c
	clang -I${INC} -g $< -o $@

clean:
	cargo clean
	rm -rf loader even-trigger
