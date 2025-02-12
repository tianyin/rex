# Rex kernel extensions

```
____  _______  __  _____      _                 _
|  _ \| ____\ \/ / | ____|_  _| |_ ___ _ __  ___(_) ___  _ __  ___
| |_) |  _|  \  /  |  _| \ \/ / __/ _ \ '_ \/ __| |/ _ \| '_ \/ __|
|  _ <| |___ /  \  | |___ >  <| ||  __/ | | \__ \ | (_) | | | \__ \
|_| \_\_____/_/\_\ |_____/_/\_\\__\___|_| |_|___/_|\___/|_| |_|___/

```

Rex is a safe and usable kernel extension framework that allows loading and
executing Rust kernel extension programs in the place of eBPF. Unlike
eBPF-based frameworks such as [Aya](https://aya-rs.dev), Rex programs does
not go through the in-kernel verifier, instead, the programs are
implemented in the safe subset of Rust, on which the Rust compiler performs
the needed safety checks and generates native code directly. This approach
avoids the overly restricted verification requirements (e.g., program
complexity contraints) and the resulting arcane verification errors, while
at the same time potentially provides a better optimization opportunity in
the native compiler backend (i.e., LLVM) than the eBPF backend + in-kernel
JIT approach.

Rex currently supports the following features:

- 5 eBPF program types: `kprobe`, `perf_event`, `tracepoint`, `xdp`, and
  `tc`.
- invocation of eBPF helper functions that are commonly used by these
  programs
- interaction with eBPF maps
- RAII-style management of kernel resources obtainable by programs
- cleanup and in-kernel exception handling of Rust runtime panics with call
  stack traces
- kernel stack (only when CFG cannot be computed statically) and
  termination safety from a thin in-kernel runtime
- bindings and abstractions of kernel data types commonly needed by eBPF
  programs

## Getting started

You can find the detailed guide [here](docs/getting-started.md).

## Example program

The following example implements a kprobe program that attaches to a
selected system call and injects an error (specified by `errno`) to the
system call on a process (specified by its `pid`). The full example,
including the loader program, can be found under
[samples/error_injector](samples/error_injector).

```Rust
#![no_std]
#![no_main]

use rex::kprobe::kprobe;
use rex::map::RexHashMap;
use rex::pt_regs::PtRegs;
use rex::rex_kprobe;
use rex::rex_map;
use rex::Result;

#[allow(non_upper_case_globals)]
#[rex_map]
static pid_to_errno: RexHashMap<i32, u64> = RexHashMap::new(1, 0);

#[rex_kprobe]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    obj.bpf_get_current_task()
        .map(|t| t.get_pid())
        .and_then(|p| obj.bpf_map_lookup_elem(&pid_to_errno, &p).cloned())
        .map(|e| obj.bpf_override_return(ctx, e))
        .ok_or(0)
}
```

## Documentations

TODO: add rustdoc of Rex

Additional design documentations can be found under [docs](docs).

## License

Rex is licensed under the GPLv2 license. The submodules (Linux, Rust, LLVM)
in this repo are licensed under their own terms. Please see the
corresponding license file in for more details. Additionally, the memcached
benchmark is licensed under the MIT license.
