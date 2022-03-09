LINUX ?= /home/jinghao/inner-kernel-linux/

all: target/debug/tracex5

target/debug/tracex5:
	python prep_interface.py  ${LINUX}
	cargo rustc -vv -- -C link-arg=-nostartfiles -A unused -A non_camel_case_types -A non_upper_case_globals -A non_snake_case

clean:
	cargo clean
	rm -rf ./src/linux/*.rs ./src/stub.rs
