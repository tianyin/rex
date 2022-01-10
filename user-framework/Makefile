all: prog-run bpf-load test/hello rust_test/target/debug/rust_test event-trigger

test/hello: test/hello.c test/link.lds Makefile interface-kernel.h
	clang -static --target=x86_64-none-elf -march=x86-64 -fPIC -static -fno-asynchronous-unwind-tables -ffreestanding -fno-builtin -nostdlib -nostdinc -Wl,-pie -Wl,-Ttest/link.lds,-N,-static,-ebpf_main test/hello.c -o test/hello

rust_test/target/debug/rust_test: rust_test/Cargo.toml rust_test/src/main.rs rust_test/src/interface.rs
	(cd rust_test && cargo rustc -vv -- -C link-arg=-nostartfiles)

# this rule assumes a linux symlink in the project rootdir
FORCE:
	python ./fixup_addrs.py `realpath ../linux/vmlinux`

interface-kernel.h: FORCE

rust_test/src/interface.rs: FORCE

prog-run: prog-run.c elf.c elf.h Makefile
	clang -g $< elf.c -o $@

bpf-load: bpf-load.c elf.c elf.h Makefile
	clang -g $< elf.c -o $@

event-trigger: event-trigger.c
	clang -g $< -o $@

clean:
	rm -f prog-run test/hello bpf-load event-trigger interface-kernel.h rust_test/src/interface.rs
	rm -f test/*.o
	(cd rust_test && cargo clean)

run: prog-run test/hello
	./prog-run test/hello

rust: prog-run rust_test/target/debug/rust_test
	./prog-run rust_test/target/debug/rust_test

vm: bpf-load test/hello
	cp bpf-load test/hello ../rootfs/guest/
