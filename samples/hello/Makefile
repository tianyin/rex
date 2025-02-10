LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = $(abspath ${LINUX}/tools/lib/bpf)
LIBREX_DIR := $(abspath ../../librex)

RUST_FLAGS = -Funsafe_code -Finternal_features -Fincomplete_features -Funstable_features -Clink-arg=-nostartfiles -Cenable_rex

CC = clang

CFLAGS += -O2 -march=native -pipe -std=gnu11
CFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
LDFLAGS += -fuse-ld=mold -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections

LOADER_INC += -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBREX_DIR}/include
LOADER_LDFLAGS = -L${LIBBPF_DIR} -L${LIBREX_DIR} -lbpf -lrex -Wl,-rpath=${LIBBPF_DIR} -Wl,-rpath=${LIBREX_DIR}

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

.PHONY: clean clippy

all: target/x86_64-unknown-linux-gnu/release/hello loader event-trigger

clippy: Cargo.toml clippy.toml ./src/*.rs
	cargo clippy -r -- -Fclippy::disallowed-methods -Fclippy::disallowed-types

target/x86_64-unknown-linux-gnu/debug/hello: clippy clippy Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

mir:
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS} --emit=mir

llvm-ir:
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS} --emit=llvm-ir

target/x86_64-unknown-linux-gnu/release/hello: clippy clippy Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

loader: loader.c
	${CC} ${LOADER_INC} ${CFLAGS} ${LDFLAGS} -o $@ $< ${LOADER_LDFLAGS}

event-trigger: event-trigger.c
	${CC} -I${LINUX_INC} ${CFLAGS} ${LDFLAGS} -o $@ $<

clean:
	rm -rf loader event-trigger ./src/linux ./src/stub.rs
	cargo clean
