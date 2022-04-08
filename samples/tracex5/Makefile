LINUX ?= $(HOME)/linux

all: target/debug/tracex5 tracex5

target/debug/tracex5: prep_interface.py ./src/*.rs ${LINUX}/vmlinux
	python3 prep_interface.py  ${LINUX}
	cargo rustc -vv -- -C opt-level=0 -C link-arg=-nostartfiles -A unused -A non_camel_case_types -A non_upper_case_globals -A non_snake_case

tracex5: tracex5.c
	clang -I `realpath ${LINUX}/usr/include` -g $< -o $@

clean:
	cargo clean
	rm -rf ./src/linux/*.rs ./src/stub.rs tracex5
