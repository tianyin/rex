
.ALWAYS:

rootfs/ubuntu-ebpf.ext4: .ALWAYS
	make -C rootfs

vmlinux:
	docker run -v ~/linux:/linux linux-builder make -j32 bzImage
	./get_linux.sh

run: rootfs/ubuntu-ebpf.ext4
	./firecracker-run.sh vmlinux rootfs/ubuntu-ebpf.ext4 /sbin/init


