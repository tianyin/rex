### VMM

We are using firecracker as our VMM, which we have obtained via
Firecracker's binary distribution.  

    curl -Lo firecracker https://github.com/firecracker-microvm/firecracker/releases/download/v0.16.0/firecracker-v0.16.0
    curl -Lo firectl https://firectl-release.s3.amazonaws.com/firectl-v0.1.0

### kernel

We are using a small kernel config based off the firecracker microvm
config with `make olddefconfig`.  We have added some kernel features
relevant to eBPF.  Importantly some of the BTF stuff requires really
recent versions of tools (e.g., `pahole`) for the kernel build.  So,
it's easiest to use a container.  To get our `linux-builder`
container, build it like this:

    cd docker-linux-builder
    make docker

Then, back out in the top-level directory, assuming your linux tree is
at `~/linux` run:

    make vmlinux

That will just run the following two commands:

    docker run -v ~/linux:/linux linux-builder make -j32 bzImage
    ./getlinux.sh
    
The `getlinux.sh` script simply copies over the kernel vmlinx file and
its config so that everything matches.

### bpftool

The Linux kernel comes with a tool called bpftool, which can be useful
but should be built from the same kernel source that we are dealing
with.  We have a builder container for that too, which you can build
with:

    cd docker-bpftool-builder
    make docker

Then, back out in the top-level directory, assuming your linux tree is
at `~/linux` run:

    make bpftool

That will just run the following two commands:

    docker run -v ~/linux:/linux bpftool-builder make bpftool
    ./getbpftool.sh
    
### rootfs

We are using a very small distro so that everything stays fast and
manageable (e.g., kernel build, building the rootfs, etc.).  The
distro we are using is from some scripts adapted from Lupine Linux.
Lupine's scripts create a rootfs from a Docker image.  We put our
stuff in there (based on ubuntu at this point because we needed a
glibc-based system).  The `rootfs/Dockerfile` contains the build-time
stuff to go in the rootfs.

The root filesystem is best built from the top level with:

    make fs

This can be rerun whenever you want to boot with a new script in the
guest (put it in `rootfs/guest/`).  But you don't have to run it
directly because it's a dependency of `make run`.

### running it

We modified some of the Lupine scripts for a single point of
invocation into a guest shell.

    ./firecracker-run-new.sh vmlinux rootfs/ubuntu-ebpf.ext4

or

    make run

At this point it gives us a root SSH shell.  To get more, type:

    make shell

### status

So far, we have run the sock_example from the bundled Linux samples.
See `linux/samples/bpf/README.rst`.  Also, the minimal example from
libbpf-bootstrap.

### Next steps

- check out some of the debugging features from https://prototype-kernel.readthedocs.io/en/latest/bpf/troubleshooting.html
