# Exception handling and runtime mechanism

This document will cover the following:
- [Handling of Rust panics (language exceptions)](#handling-of-rust-panics-in-kernel-space)
  - [Kernel dispatch and landingpad](#kernel-stack-unwinding)
  - [Rust panic handler and cleanup mechanism](#resource-cleanup-in-rust)
- Handling of kernel events triggered by extension programs
  - Kernel stack overflow
  - Program termination

## Handling of Rust panics in kernel space

In userspace, Rust panics are essentially the same as C++ exceptions and
are handled based on [Itanium
ABI](https://llvm.org/docs/ExceptionHandling.html#itanium-abi-zero-cost-exception-handling).
That is, when a panic is triggered, the control flow will be redirect to
the unwind library (e.g. `libgcc` or `llvm-libunwind`). The unwind library
will then unwind the program stack. For each function call frame, it will
invoke the `personality` routine to look for feasible landingpads which
contains cleaup and (possibly) exception handling code. The unwind process
ends when either the exception is handled (e.g. by a C++ catch) or no
handler is found.

P.S. The actual Itanium ABI is more complicated than described here, e.g.
the unwind library runs two passes on the stack, once for searching
landingpads, and another time for executing landingpads code.

However, the Itanium EH ABI is not suitable in our case for the following
reasons:
- It adds too much complexity, as the userspace unwind libraries are not
  direcly usable.
- It usually requries dynamic allocation for certain exception contexts,
  which may not be available to kernel extensions (e.g. kprobe executes in
  interrupt contexts and is therefore not sleepable).
- It allows failures during the unwinding which cannot be tolerated in
  kernel space. Incomplete cleanup means leaking kernel resources.
- It generally executes destructors for all existing objects on the stack,
  but executing untrusted, user-defined destructors (via the `Drop` trait
  in Rust) may not be safe.

Therefore, in our framework we implement our exception handling mechanism.
It can be divided into two parts: stack unwinding in the kernel and
resource cleanup in the runtime crate.

### Kernel stack unwinding

This component consists the `iu_dispatcher_func` to dispatch
inner-unikernel programs so that rust panics can be handled. The dispatcher
have a prototype of:

```C
extern asmlinkage unsigned int iu_dispatcher_func(
        const void *ctx,
        const struct bpf_insn *insnsi,
        unsigned int (*bpf_func)(const void *,
                                 const struct bpf_insn *));
```

which shares the same signature as `bpf_dispatcher_nop_func` but differs
in linkage, as it is implemented directly in assembly.

The function saves the stack pointer and frame pointer to designated
per-cpu variables before calling into the program.

If the execution is successful (i.e. no exceptions), the function will
just return normally.

```
   +-----------------------+
   | iu_dispatcher_func:   |
   | movq %rsp %gs:iu_sp   |
   | movq %rbp %gs:iu_fp   |                +-----------+
   | call *%rdx            |--------------->| iu_prog1: |
   |                       |                | ...       |
   | iu_exit:              |<---------------| ret       |
   | ret                   |                +-----------+
   | ...                   |
   +-----------------------+
```

Under exceptional cases (where a rust panic is fired), `rust_begin_unwind`
(i.e. panic handler) will transfer the control flow to the `iu_landingpad`
function, which, after dumping some information to the kernel ring buffer,
will issue a direct jump to `iu_panic_trampoline`, a global label in the
middle of `iu_dispatcher_func`. The trampoline code restores the old stack
pointer and frame pointer value, effectively unwinding the stack.  It
then sets a return value of `-EINVAL` and jumps to `iu_exit` to return from
`iu_dispatcher_func`.

```
         +-----------------------+
         | iu_dispatcher_func:   |
         | movq %rsp, %gs:iu_sp  |
         | movq %rbp, %gs:iu_fp  |                +-----------+
         | call *%rdx            |--------------->| iu_prog1: |
         |                       |         +------| ...       |
   +---->| iu_exit:              |         |      | ret       |
   |     | ret                   |         |      +-----------+
   |     |                       |         |
   |     | iu_panic_trampoline:  |<-----+  | panic!()
   |     | movq %gs:iu_sp, %rsp  |      |  |
   |     | movq %gs:iu_fp, %rbp  |      |  |      +-------------------------+
   |     | movq $(-EINVAL), %rax |      |  +----->| iu_landingpad:          |
   +-----| jmp iu_exit           |      |         | ...                     |
         +-----------------------+      +---------| jmp iu_panic_trampoline |
                                                  +-------------------------+
```

This right now only works for program invocations where
`bpf_dispatcher_nop_func` is used originally. It does cover all tracing
programs (i.e. these invoked via `trace_call_bpf`). Other program types
(e.g. XDP) are not supported.

For further information please refer to the actual commits:
- <https://github.com/djwillia/linux/commit/348c9a1ef8a92172e9c9a1f724f363d4a9dbf749>
- <https://github.com/djwillia/linux/commit/11d3a5fd12872dd47da54a41483c567419a80fd3>

### Resource cleanup in Rust

Not using the existing ABI-based exception handling / stack unwinding scheme
means we need to handle resource cleanup in our own way. We make the observation
that the only resources that requires cleanup are the resources obtained from
kernel helper functions. This is because of the restricted programing interface
exposed to these extension programs, which disallow direct kernel resource
alloation (e.g. allocate memory, directly access a lock, etc).

This brings us chance to create a light-weight resource clean up scheme. We
can record allocated kernel resources and their destructors on-the-fly
during program execution. When termination is needed, the destructors of
allocated resources are invoked to release the resources. Since only the
trusted kernel crate that interfaces with the kernel resources is
responsible for implementing the aforementioned destructors, all the
cleanup code is trusted and guaranteed not to fail.

The PoC implemention uses `CleanupEntry` to represent an allocated resource:
```Rust
pub(crate) type CleanupFn = fn(*const ()) -> ();

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub(crate) struct CleanupEntry {
    pub(crate) valid: u64,
    pub(crate) cleanup_fn: Option<CleanupFn>,
    pub(crate) cleanup_arg: *const (),
}
```
An instance of the struct is supposed to be instantiated in the constructor
of the kernel resource binding types in the runtime crate:
- `valid` should be set to 1
- `cleanup_fn` should point to a function provided in `impl` of the binding
  type, which takes in a pointer to the object and runs `drop` on it. The
  `drop` handler is also responsible for setting `valid` to 0.
- `cleanup_arg` should point to the newly created object. It is used as the
  argument to `cleanup_fn`.

Note:
1. `valid` field is of type `u64`. This may not seem space effcient at a
   glance, but since both `cleanup_fn` and `cleanup_arg` are 64 bit large.
   The alignment of the struct is 64 bit anyway.
2. According to
   [Rustonomicon](https://doc.rust-lang.org/nomicon/repr-rust.html) and
   [Rust doc](https://doc.rust-lang.org/std/option/#representation),
   `Option<CleanupFn>` has the same size and bit-level representation as
   `CleanupFn` as long as it is a `Some`. This is important because on the
   kernel side it can be treated as a `void (*)(void *)`.

The created struct is then stored in a per-CPU array `iu_cleanup_entries`
in the kernel. Since for non-sleepable BPF programs, no two programs can
execute on the same CPU at the same time, there is no race condition
possible ([this](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/trace/bpf_trace.c#n109) is an example, though it is questionable whether this assumption can be generalized to all program types).
This also implies that a C binding for `CleanupEntry` is needed in the kernel:
```C
struct iu_cleanup_entry {
    u64 valid;
    void *cleanup_fn;
    void *cleanup_arg;
};
```
Note:
1. Using `void *` to store function pointer is not standard compliant,
  though at ABI level it is always a 64-bit value and should work correctly.
  We should change it to a real function pointer: `void (*)(void *)`.
2. Currently, the array is statically allocated with a capacity
  of 64. This **may not** be sustainable.

During normal execution, the `drop` handlers are executed normally so the
kernel resource will be released and the `CleanupEntry` will be invalidated.

Upon a panic, the control flow will transfer to `rust_begin_unwind` (i.e.
the Rust panic handler). `rust_begin_unwind` will traverse the array on current
CPU and free any resources allocated by invoking `(cleanup_fn)(cleanup_arg)`.
It then invalidate these entries.

Code references:
1. [Rust side `CleanupEntry` and panic handler implementation](https://github.com/djwillia/inner_unikernels/blob/main/inner_unikernel_rt/src/panic.rs)
2. [Kernel side binding type and per-CPU array](https://github.com/djwillia/linux/blob/inner_unikernels/kernel/bpf/core.c#L2465)