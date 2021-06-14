

### rootfs

We are using a very small distro so that everything stays fast and
manageable (e.g., kernel build, building the rootfs, etc.).  The
distro we are using is from some scripts adapted from Lupine Linux.
Lupine's scripts create a rootfs from a Docker image.  We put our
stuff in there (based on ubuntu at this point because we needed a
glibc-based system).  The `rootfs/Dockerfile` contains the build-time
stuff to go in the rootfs.

The root filesystem is best built from the top level with:

    make -C rootfs

This can be rerun whenever you want to boot with a new script in the
guest (put it in `rootfs/guest/`).

### kernel

We are using a small kernel config based off the firecracker microvm
config with `make olddefconfig`.  We have added some kernel features
relevant to eBPF.  Importantly some of the BTF stuff requires really
recent versions of tools (e.g., `pahole`) for the kernel build.  So,
it's easiest to use a container:

    docker run -v ~/linux:/linux linux-builder make -j32 bzImage

The `getlinux.sh` script ensures we have a matching
kernel vmlinx file and its config.  

### VMM

We are using firecracker as our VMM, which we have obtained via
Firecracker's binary distribution.  

    curl -Lo firecracker https://github.com/firecracker-microvm/firecracker/releases/download/v0.16.0/firecracker-v0.16.0
    curl -Lo firectl https://firectl-release.s3.amazonaws.com/firectl-v0.1.0

### running it

We modified some of the Lupine scripts for a single point of
invocation into a guest shell.

    ./firecracker-run.sh vmlinux rootfs/ubuntu-ebpf.ext4 /bin/bash

### status

So far, we have run the sock_example from the bundled Linux samples.
See `linux/samples/bpf/README.rst`.

### Next steps

- make `/guest/init.sh` run on boot then give us a shell
- check out some of the debugging features from https://prototype-kernel.readthedocs.io/en/latest/bpf/troubleshooting.html
