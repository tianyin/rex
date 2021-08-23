
hello: hello.c Makefile link.lds
	clang -fPIC -static -fno-asynchronous-unwind-tables -nostdlib -Wl,-pie -Wl,-Tlink.lds,-N,-static hello.c -o hello

clean:
	rm -rf hello
