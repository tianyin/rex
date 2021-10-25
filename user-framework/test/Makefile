
hello: hello.c Makefile link.lds
	clang -fPIC -static -fno-asynchronous-unwind-tables --target=i686-pc-none-elf -march=i686 -ffreestanding -fno-builtin -nostdlib -nostdinc -Wl,-pie -Wl,-Tlink.lds,-N,-static,-no-dynamic-linker hello.c -o hello

clean:
	rm -rf hello
