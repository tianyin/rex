### How it works:

Taken from the commit message:

Add a new `iu_dispatcher_func` to dispatch inner-unikernel programs so
that rust panics can be handled. The dispatch have a prototype of:

```C
extern asmlinkage unsigned int iu_dispatcher_func(
        const void *ctx,
        const struct bpf_insn *insnsi,
        unsigned int (*bpf_func)(const void *,
                                 const struct bpf_insn *));
```

which shares the same signature as `bpf_dispatcher_nop_func` but differs
in linkage, as it is implemented directly in assembly.

The function will save the stack pointer and frame pointer to designated
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
https://github.com/djwillia/linux/commit/348c9a1ef8a92172e9c9a1f724f363d4a9dbf749

https://github.com/djwillia/linux/commit/348c9a1ef8a92172e9c9a1f724f363d4a9dbf749
