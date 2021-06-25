
.ALWAYS:

all: vmlinux fs

bpftool: ~/linux/tools/bpf/bpftool/bpftool
	docker run -v ~/linux:/linux bpftool-builder make bpftool
	./get_bpftool.sh

vmlinux: .ALWAYS
	docker run -v ~/linux:/linux linux-builder make -j32 bzImage
	./get_linux.sh

DOCKERCONTEXT=\
	rootfs/Dockerfile \
	rootfs/vm-net-setup.service \
	rootfs/vm-net-setup.sh

rootfs/.build-base: rootfs/Dockerfile rootfs/vm-net-setup.service rootfs/vm-net-setup.sh
	rm -f ubuntu-ebpf.ext4
	tar zc ${DOCKERCONTEXT} | docker build -f rootfs/Dockerfile -t ubuntu-ebpf -
	@echo "preparing rootfs"
	rootfs/image2rootfs.sh ubuntu-ebpf latest ext4 2>&1 > /dev/null
	touch rootfs/.build-base

rootfs/.build-guest: $(shell find rootfs/guest) rootfs/.build-base
	rootfs/update_guest_files.sh ubuntu-ebpf.ext4

fs: rootfs/.build-guest

run: rootfs/.build-guest
	./firecracker-run-new.sh vmlinux ubuntu-ebpf.ext4

clean:
	rm -f ubuntu-ebpf.ext4 rootfs/.build-base
