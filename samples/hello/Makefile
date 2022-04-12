all: rusthello helloc

rusthello: src/*
	cargo rustc -vv -- -C link-arg=-nostartfiles

helloc: helloc.c
	clang -I $(HOME)/linux/usr/include -g $< -o $@

clean:
	rm -f helloc
	cargo clean

vmcopy: rusthello helloc
	cp target/debug/hello helloc ../../rootfs/guest/
