
.ALWAYS:

all: vmlinux fs examples

docker: .ALWAYS
	make -C docker/docker-linux-builder docker

bpftool: .ALWAYS docker
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -w /linux/tools/bpf/bpftool linux-builder make bpftool
	scripts/get_bpftool.sh

vmlinux-config: .ALWAYS docker
	cp epf_tests.config ~/linux/.config
	docker run --user $(shell id -u) --rm -v ~/linux:/linux linux-builder make olddefconfig

vmlinux: .ALWAYS docker
	docker run --user $(shell id -u) --rm -v ~/linux:/linux linux-builder make -j32 bzImage
	docker run --user $(shell id -u) --rm -v ~/linux:/linux linux-builder make headers
	scripts/get_linux.sh

samples: .ALWAYS docker vmlinux
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -w /linux/samples/bpf linux-builder make

linux-clean:
	docker run --user $(shell id -u) --rm -v ~/linux:/linux linux-builder make distclean

iu: .ALWAYS docker 
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -w /linux/tools/lib/bpf linux-builder make libbpf.a
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -v ~/inner_unikernels:/inner_unikernels -w /inner_unikernels/libiu linux-builder make -j32

iu-clean: 
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -v ~/inner_unikernels:/inner_unikernels -w /inner_unikernels/libiu linux-builder make clean

iu-examples: .ALWAYS docker iu
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -v ~/inner_unikernels:/inner_unikernels -w /inner_unikernels/samples/hello linux-builder make
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -v ~/inner_unikernels:/inner_unikernels -w /inner_unikernels/samples/map_test linux-builder make
	docker run --user $(shell id -u) --rm -v ~/linux:/linux -v ~/inner_unikernels:/inner_unikernels -w /inner_unikernels/samples/syscall_tp linux-builder make

examples: .ALWAYS docker
	docker run --user $(shell id -u) --rm -v ~/libbpf-bootstrap:/libbpf-bootstrap -w /libbpf-bootstrap/examples/c linux-builder make
	scripts/get_examples.sh

DOCKERCONTEXT=\
	rootfs/Dockerfile \
	rootfs/vm-net-setup.service \
	rootfs/vm-net-setup.sh \
	rootfs/authorized_keys \
	rootfs/fstab

rootfs/.build-base: $(DOCKERCONTEXT)
	rm -f ubuntu-ebpf.ext4
	cp ~/.ssh/id_rsa.pub rootfs/authorized_keys
	tar zc ${DOCKERCONTEXT} | docker build -f rootfs/Dockerfile -t ubuntu-ebpf -
	@echo "preparing rootfs"
	rootfs/image2rootfs.sh ubuntu-ebpf latest ext4 2>&1 > /dev/null
	touch rootfs/.build-base

run:
	make -C user-framework vm
	rootfs/update_guest_files.sh ubuntu-ebpf.ext4
	./firecracker-run-new.sh vmlinux ubuntu-ebpf.ext4

runq: rootfs/.build-base
	./qemu-run.sh bzImage ubuntu-ebpf.ext4

THISDIR=$(shell pwd)
qscript: .ALWAYS
	(cd $(HOME)/linux && $(THISDIR)/q-script/yifei-q)

hello: .ALWAYS
	make -C samples/hello/ vmcopy

map: .ALWAYS
	make -C user-framework/ vm

tracex5: .ALWAYS
	make -C samples/tracex5/

cpustat: .ALWAYS
	make -C samples/cpustat/

clean:
	rm -f ubuntu-ebpf.ext4 rootfs/.build-base

shell:
	ssh -t root@192.168.111.2 "cd /host/inner_unikernels/rootfs/guest; /bin/bash --login"
