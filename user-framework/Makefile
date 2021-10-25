all: prog-run test/hello rust_test/target/debug/rust_test

test/hello: test/hello.c test/link.lds Makefile interface.h
	clang -static --target=x86_64-none-elf -march=x86-64 -fPIC -static -fno-asynchronous-unwind-tables -ffreestanding -fno-builtin -nostdlib -nostdinc -Wl,-pie -Wl,-Ttest/link.lds,-N,-static,-ebpf_main test/hello.c -o test/hello

rust_test/target/debug/rust_test: rust_test/Cargo.toml rust_test/src/main.rs
	(cd rust_test && cargo rustc -- -C link-arg=-nostartfiles)

interface.h: fixup_addrs.bash prog-run
	./fixup_addrs.bash

prog-run: prog-run.c elf.c elf.h Makefile
	clang -g $< elf.c -o $@

clean:
	rm -f interface.h prog-run test/hello
	rm -f test/*.o

run: prog-run test/hello
	./prog-run test/hello
