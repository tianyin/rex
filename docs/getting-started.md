# Getting started (p20250206)

## Nix flake
Using Nix, a package manager, allows you to bypass these dependency
requirements below.

Check out the https://nixos.org/download/ for installation instructions,
the single-user installation should be sufficient.

## Dependencies:
The following tools/libraries are required. Older versions are not
guaranteed to (or guaranteed not to) work. This list does not include
standard kernel build dependencies.
- `binutils (>= 2.38)`
- `c++23`-compatible toolchain
- `cmake`
- `elfutils`
- `LLVM`
- `mold`
- `ninja`
- `python (>= 3.11)`
- `QEMU`
- `rust-bindgen`

## Repo setup and build
Clone this repo and its submodules:
```bash
git clone https://github.com/rex-rs/rex.git
cd rex-kernel
git submodule update --init --recursive --progress
```

If you are using Nix, the following additional step is required.
```bash
nix develop --extra-experimental-features nix-command --extra-experimental-features flakes
```
It will launch a Nix shell with all necessary dependencies installed.
All subsequent steps should be carried out within this shell.

The Linux directory now hosts the kernel repo, checked out at the pre-set
commit. To build the kernel, do:
```bash
cd linux
cp ../scripts/q-script/.config .config
make oldconfig LLVM=1
make -j`nproc` LLVM=1
cd -
```
Note: The default configuration in this repo
([`q-script/.config`](q-script/.config)) uses the LLVM toolchain (i.e.
`clang`, `llvm-ar`, `lld`, etc). If desired, the GNU toolchain (i.e. `gcc`,
`ld.bfd`) can be used by removing the `LLVM=1` environment variable setup.

Since `librex` loader library depends on the `libbpf` shipped with the
kernel, `libbpf` needs to be built first:
```bash
cd linux/tools/lib/bpf
make -j`nproc`
cd -
```

Rex uses custom LLVM passes in the Rust compiler to generate additional
code and instruments the extension programs, therefore,
[bootstraping](https://en.wikipedia.org/wiki/Bootstrapping_(compilers)) the
Rust compiler is required:
```bash
cd rust
./x.py install --config=rex-config.toml
cd -
```
This will bootstrap a Rust compiler and build the relevant tools (e.g.,
`cargo`, `clippy`, etc).  The Rust artifacts will be installed under
`rust/dist`.

With the linux and Rust setup, add them to the environment (skip if using
Nix):
```bash
source ./scripts/env.sh
```

Finally build `librex`:
```bash
cd librex
make -j`nproc`
cd -
```

## Run `hello` example
First build the source
```bash
cd samples/hello
make
cd -
```

Then boot the VM:
```bash
cd linux
../scripts/q-script/yifei-q # use ../scripts/q-script/nix-q instead if you are using Nix
```

Inside the VM:
```bash
cd ..
cd samples/hello
./loader &
./event_trigger
```

The following output should be printed out:
```console
<...>-245     [002] d...1    18.417331: bpf_trace_printk: Rust triggered from PID 245.
```
