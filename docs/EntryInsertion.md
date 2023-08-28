# Entry point code Insertion

## Motivation

To allow Rust extension code to be called from the kernel, an FFI entry-point
function is needed to wrap around the user-defined extension function. This
wrapper function needs to handle certain unsafe operations, for example,
context conversion for XDP and perf event programs. Because of this, it should
never be implemented by the user. For example, interpreting an XDP context as
perf event context and perform the context conversion specific to perf-event
clearly violates memory and type safety and could result in undefined behavior.

Therefore, we choose to automatically generate the entry point code during
compilation for the Rust extension programs. Since Rust by default uses LLVM as
its code generation backend. We performs the generation of entry code in the
middle-end on LLVM IR.

## Implementation

The entry point insertion is implemented as an LLVM pass (`IUEntryInsertion`)
that operates on the compilation unit that contains the Rust extension
programs. This LLVM pass can be enabled via the `iu-playground` codegen option
in rustc (we should make this option more self-explanatory sometime), which
sets the corresponding pass for the LLVM backend.

Under this new scheme, all user needs to do besides implementing the actual
program function is to define a "program object". Take the [hello
sample](../samples/hello/src/main.rs) as an example:
```Rust
#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::tracepoint::*;

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let option_task = obj.bpf_get_current_task();
    if let Some(task) = option_task {
        let pid = task.get_pid();
        bpf_printk!(obj, "Rust triggered from PID %u.\n", pid as u64);
    }
    0
}

#[link_section = "inner_unikernel/tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);
```
Here, the user defines the `PROG` object of type `tracepoint` using
`tracepoint::new`, a
[`const`](https://doc.rust-lang.org/std/keyword.const.html#compile-time-evaluable-functions)
function takes the program function (this function has a required signature,
but it is out of the scope of this document) and the program name. The
`link_section` attribute specifies the attachment type of the program. This is
the same as how eBPF works.

Under the hood, the `tracepoint` is defined as the following:
```Rust
#[repr(C)]
pub struct tracepoint<'a> {
    rtti: u64,
    prog: fn(&Self, &tp_ctx) -> u32,
    name: &'a str,
    tp_type: tp_ctx,
}
```
The first three fields are relevant here. The `rtti` field, which always equal
to the corresponding
[`bpf_prog_type`](https://elixir.bootlin.com/linux/v5.15.128/source/include/uapi/linux/bpf.h#L919)
enum. Next, `prog` is a function pointer that points to the user-defined
extension program function. And lastly, `name` holds the user-intended name of
the program, in a string literal form.

At LLVM IR level, the `IUEntryInsertion` will iterate over all global variables
and look for variables with the special `link_section`. For the found program
objects, it will then generate the entry point based on the object contents.
Because the `tracepoint::new` function is a `const` function. The `PROG` object
is initialized with a constant expression that can be parsed by the
`IUEntryInsertion` pass. This effectively allows the pass to obtain the program
type (via `rtti`), the actual extension function (via `prog`), and the
user-specified name (via `name`).

The pass will construct a new `fn (*const()) -> u32` function with the
specified name and link section, which will be used as the entry point function
the kernel can invoke. This function takes in the context pointer (as
`*const()`) and invokes the special program-type-specific entry function in the
runtime crate. The code of the aforementioned example would be modified as (the
process happens at LLVM-IR stage, but here Rust is used for clarity):
```Rust
#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::tracepoint::*;

fn iu_prog1_fn(obj: &tracepoint, ctx: &tp_ctx) -> u32 {
    let option_task = obj.bpf_get_current_task();
    if let Some(task) = option_task {
        let pid = task.get_pid();
        bpf_printk!(obj, "Rust triggered from PID %u.\n", pid as u64);
    }
    0
}

#[link_section = "inner_unikernel/tracepoint/syscalls/sys_enter_dup"]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_ctx::Void);

#[link_section = "inner_unikernel/tracepoint/syscalls/sys_enter_dup"]
#[no_mangle]
fn iu_prog1(ctx: *const()) -> u32 {
    inner_unikernel_rt::__iu_entry_tracepoint(&PROG, ctx)
}
```
`__iu_entry_tracepoint` is the tracepoint specific entry function defined in
the runtime crate (not to be confused with the generated kernel entry point).
The function essentially calls `tracepoint::prog_run` that converts the context
and invokes the `prog` function. In this way the program context conversion and
other preparation for execution is safe abstracted away from the users.

### Add new program type support

The only file needs to be updated is
[llvm/include/llvm/Transforms/InnerUnikernels/IUProgType.def](https://github.com/xlab-uiuc/llvm-rust/blob/inner-unikernel-dev/llvm/include/llvm/Transforms/InnerUnikernels/IUProgType.def).
The basic syntex is:
```C
IU_PROG_TYPE_1(<BPF_PROG_TYPE_ENUM>, <program_type in RT crate>, <sec name>)
```
If the program type has more than 1 section names, use `IU_PROG_TYPE_2`
instead, which will support 2 names (and we probably don't need anything more
than that).  Therefore, for `tracepoint` this is:
```C
IU_PROG_TYPE_2(BPF_PROG_TYPE_TRACEPOINT, tracepoint, "tracepoint", "tp")
```

Relevant files:
- LLVM pass:
  - [llvm/lib/Transforms/InnerUnikernels/IUInsertEntry.cpp](https://github.com/xlab-uiuc/llvm-rust/blob/inner-unikernel-dev/llvm/lib/Transforms/InnerUnikernels/IUInsertEntry.cpp)
  - [llvm/include/llvm/Transforms/InnerUnikernels/IUInsertEntry.h](https://github.com/xlab-uiuc/llvm-rust/blob/inner-unikernel-dev/llvm/include/llvm/Transforms/InnerUnikernels/IUInsertEntry.h)
  - [llvm/include/llvm/Transforms/InnerUnikernels/IUProgType.def](https://github.com/xlab-uiuc/llvm-rust/blob/inner-unikernel-dev/llvm/include/llvm/Transforms/InnerUnikernels/IUProgType.def)
- Program-type-specific entry function (defined using the `define_prog_entry`
  macro):
  - [inner_unikernel_rt/src/lib.rs](https://github.com/djwillia/inner_unikernels/blob/main/inner_unikernel_rt/src/lib.rs)
- Tracepoint implementation (can be generalized to other programs):
  - [inner_unikernel_rt/src/tracepoint/tp_impl.rs](https://github.com/djwillia/inner_unikernels/blob/main/inner_unikernel_rt/src/tracepoint/tp_impl.rs)
