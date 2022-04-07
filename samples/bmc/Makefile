LINUX ?= /home/jinghao/inner-kernel-linux

all: target/debug/bmc

target/debug/bmc: prep_interface.py ./src/*.rs ${LINUX}/vmlinux
	python prep_interface.py  ${LINUX}
	cargo rustc -vv -- -C opt-level=0 -C link-arg=-nostartfiles -A unused -A non_camel_case_types -A non_upper_case_globals -A non_snake_case

clean:
	cargo clean
	rm -rf ./src/linux/*.rs ./src/stub.rs
