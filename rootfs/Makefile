

ubuntu-ebpf.ext4: Dockerfile
	rm -f ubuntu-ebpf.ext4
	docker build -t ubuntu-ebpf .
	./image2rootfs.sh ubuntu-ebpf latest ext4
