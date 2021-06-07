

### Test setup

Got rootfs from Lupine Linux

    scripts/image2rootfs.sh alpine latest ext4

Got firecracker from binary release on github

Got kernel config from microvm (Lupine) then make olddefconfig

Run vm with `firecracker-run.sh`

    ./firecracker-run.sh vmlinux alpine.ext4 /bin/sh

