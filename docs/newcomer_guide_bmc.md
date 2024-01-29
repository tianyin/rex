This is a guide to running eBPF BMC and Rust BMC for newcomers, with potential challenges encountered during installation.

Instructions will be mostly similar to this repo's README and `inner_unikernels/docs/evaluation_readme.md`, with some added caveats.

## Dependencies: 
All dependencies from the README.

## Set up Rust BMC:

### Setup repo: 
Same as README, except we will clone from `https://github.com/xlab-uiuc/inner_unikernels.git` 

### Build the kernel, build libbpf: 
Same as README

### Bootstrap Rust:
Before doing this step, check if you have gcc 12+ installed:
```bash
gcc --version
```
If you don't, update gcc. Alternatively, remove the mold linker by commenting out the line `use-linker = "mold"` in `inner_unikernels/rust/inner-unikernels-config.toml`.

Then follow the README.

### Set up environment and build libiu: Same as README

### Build sample hello:
First, `cd samples/hello`. At this point, you should have `bindgen` installed. If not you can install it with:
```bash
cargo install bindgen-cli
```

If that fails, download binary from source:
```bash
wget https://github.com/rust-lang/rust-bindgen/releases/download/v0.68.1/bindgen-cli-x86_64-unknown-linux-gnu.tar.xz
tar xf bindgen-cli-x86_64-unknown-linux-gnu.tar.xz
```
Then copy `bindgen-cli-x86_64-unknown-linux-gnu/bindgen` to `~/bin/`.

Then follow the README.

If Clang throws an error while `make`ing, simply update it or alternately, download binary:
```bash
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04.tar.xz
tar xf clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04.tar.xz
```
Then add `export PATH="~/path/to/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin:$PATH"` at the end of `~/.profile`

To run QEMU, you may also need to add your user to the `KVM` group, using:
```bash
sudo usermod -a -G groupName userName
```
If that fails, contact your administrator.

Then follow the rest of the instruction.

### Build Rust BMC:
Make sure the BPF filesystem is mounted:
```bash
ls /sys/fs
```
If not, simply mount it:
```bash
mount -t bpf none /sys/fs/bpf/
```
The follow the instructions for `Rust extension` in `evaluation_readme.md`.

## Set up BPF BMC:
Follow the instructions for `Run BMC` in `evaluation_readme.md`. For the linux folder, we will use `/path/to/inner_unikernels/linux`. Then `make` inside QEMU.

Then follow the rest of the instructions.
