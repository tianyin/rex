
.ALWAYS:

all: vmlinux fs examples

docker: .ALWAYS
	make -C docker/docker-linux-builder docker
	make -C docker/docker-bpftool-builder docker
	make -C docker/docker-example-builder docker

bpftool: ~/linux/tools/bpf/bpftool/bpftool docker
	docker run --rm -v ~/linux:/linux bpftool-builder make bpftool
	scripts/get_bpftool.sh

vmlinux: .ALWAYS docker
	docker run --rm -v ~/linux:/linux linux-builder make -j32 bzImage
	scripts/get_linux.sh

examples: .ALWAYS docker
	docker run --rm -v ~/libbpf-bootstrap:/libbpf-bootstrap libbpf-bootstrap-example-builder make
	scripts/get_examples.sh

DOCKERCONTEXT=\
	rootfs/Dockerfile \
	rootfs/vm-net-setup.service \
	rootfs/vm-net-setup.sh \
	rootfs/authorized_keys

rootfs/.build-base: rootfs/Dockerfile rootfs/vm-net-setup.service rootfs/vm-net-setup.sh
	rm -f ubuntu-ebpf.ext4
	cp ~/.ssh/id_rsa.pub rootfs/authorized_keys
	tar zc ${DOCKERCONTEXT} | docker build -f rootfs/Dockerfile -t ubuntu-ebpf -
	@echo "preparing rootfs"
	rootfs/image2rootfs.sh ubuntu-ebpf latest ext4 2>&1 > /dev/null
	touch rootfs/.build-base

rootfs/.build-guest: $(shell find rootfs/guest) rootfs/.build-base
	rootfs/update_guest_files.sh ubuntu-ebpf.ext4

fs: rootfs/.build-guest

run:
	make -C user-framework vm
	rootfs/update_guest_files.sh ubuntu-ebpf.ext4
	./firecracker-run-new.sh vmlinux ubuntu-ebpf.ext4

runq: rootfs/.build-guest
	./qemu-run.sh bzImage ubuntu-ebpf.ext4

clean:
	rm -f ubuntu-ebpf.ext4 rootfs/.build-base

linux-clean:
	docker run -v ~/linux:/linux linux-builder make clean

shell:
	ssh -t root@192.168.111.2 "cd /guest; /bin/bash --login"
