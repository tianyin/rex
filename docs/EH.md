# Exception handling and runtime mechanism

This document will cover the following:
- Handling of Rust panics (language exceptions)
  - Kernel dispatch and landingpad
  - Rust panic handler and cleanup mechanism
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
<https://github.com/djwillia/linux/commit/348c9a1ef8a92172e9c9a1f724f363d4a9dbf749>
<https://github.com/djwillia/linux/commit/11d3a5fd12872dd47da54a41483c567419a80fd3>
