BASE_PROJ ?= $(shell pwd)
LINUX ?= ${BASE_PROJ}/linux
.ALWAYS:

all: vmlinux fs samples

docker: .ALWAYS
	make -C docker/docker-linux-builder docker

qemu-run: 
	docker run --privileged --rm \
	--device=/dev/kvm:/dev/kvm --device=/dev/net/tun:/dev/net/tun \
	-v ${BASE_PROJ}:/inner_unikernels -v ${LINUX}:/linux \
	-w /linux \
	-it runtime:latest \
	/inner_unikernels/q-script/yifei-q

bpftool: 
	docker run --rm -v ${LINUX}:/linux -w /linux/tools/bpf/bpftool runtime make -j`nproc` bpftool

vmlinux: 
	docker run --rm -v ${LINUX}:/linux -w /linux runtime  make -j`nproc` bzImage

linux-clean:
	docker run --rm -v ${LINUX}:/linux runtime make distclean

# Might not be needed anymore
iu: 
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/libiu runtime make -j32 LLVM=1

iu-clean: 
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/libiu runtime make clean

iu-examples: 
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/hello runtime make -j32 LLVM=1
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/map_test runtime make -j32 LLVM=1
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/syscall_tp runtime make -j32 LLVM=1
	docker run --rm -v ${LINUX}:/linux -v ${BASE_PROJ}:/inner_unikernels -w /inner_unikernels/samples/trace_event runtime make -j32 LLVM=1

DOCKERCONTEXT=\
	rootfs/Dockerfile \
	rootfs/vm-net-setup.service \
	rootfs/vm-net-setup.sh \
	rootfs/authorized_keys \
	rootfs/fstab \
	rootfs/bash_profile

rootfs/.build-base: $(DOCKERCONTEXT)
	rm -f ubuntu-ebpf.ext4
	cp ~/.ssh/id_rsa.pub rootfs/authorized_keys
	tar zc ${DOCKERCONTEXT} | docker build -f rootfs/Dockerfile -t ubuntu-ebpf -
	@echo "preparing rootfs"
	rootfs/image2rootfs.sh ubuntu-ebpf latest ext4 2>&1 > /dev/null
	touch rootfs/.build-base

fs: rootfs/.build-base

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
