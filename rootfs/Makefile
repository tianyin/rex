

ubuntu-ebpf-build.ext4: Makefile Dockerfile $(shell find guest) eth0.network
	rm -f ubuntu-ebpf.ext4
	docker build -t ubuntu-ebpf .
	@echo "preparing rootfs"
	./image2rootfs.sh ubuntu-ebpf latest ext4 2>&1 > /dev/null
	touch ubuntu-ebpf-build.ext4
