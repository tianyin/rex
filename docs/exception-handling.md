# Exception handling and runtime mechanism

This document will cover the following:

- [Handling of Rust panics (language exceptions)](#handling-of-rust-panics-in-kernel-space)
  - [Kernel dispatch and landingpad](#kernel-stack-unwinding)
  - [Rust panic handler and cleanup mechanism](#resource-cleanup-in-rust)

## Handling of Rust panics in kernel space

In userspace, Rust panics are essentially the same as C++ exceptions and
are handled based on [Itanium
ABI](https://llvm.org/docs/ExceptionHandling.html#itanium-abi-zero-cost-exception-handling).
That is, when a panic is triggered, the control flow will be redirect to
the unwind library (e.g. `libgcc` or `llvm-libunwind`). The unwind library
will then unwind the program stack. For each function call frame, it will
invoke the `personality` routine to look for feasible landingpads which
contains cleaup and (possibly) exception handling code. The unwind process
ends when either the exception is handled (e.g. by a C++ `catch`) or no
handler is found.

P.S. The actual Itanium ABI is more complicated than described here, e.g.
the unwind library runs two passes on the stack, once for searching
landingpads, and another time for executing landingpads code.

However, the Itanium EH ABI is not suitable in our case for the following
reasons:

- It adds too much complexity, as the userspace unwind libraries are not
  directly usable.
- It usually requires dynamic allocation for certain exception contexts,
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

We need to be able support graceful exception handling in kernel space,
i.e.  the extension program should be terminated without bringing down the
kernel.  The idea is to transfer the exceptional control flow back to the
return address of the extension program and reset the stack and frame
pointer to ensure the context remains valid. In this way, the program would
act as if it just returned normally.

The implementation consists the `rex_dispatcher_func` to dispatch Rex
programs so that rust panics can be handled. The dispatcher have a
prototype of:

```C
extern asmlinkage unsigned int rex_dispatcher_func(
        const void *ctx,
        const struct bpf_prog *prog,
        unsigned int (*bpf_func)(const void *,
                                 const struct bpf_insn *));
```

which shares a similar signature as `bpf_dispatcher_nop_func` but with the
`struct bpf_insn` array argument replaced by a pointer to the program
struct, as Rex does not work with eBPF bytecode.

The function first saves the current stack pointer to the top of the
per-CPU Rex-specific stack, and then switches the stack before calling into
the program.

If the execution is successful (i.e. no exceptions), the function will just
return normally and the old stack pointer will be restored with a `pop`.

```
   +-----------------------+
   | rex_dispatcher_func:  |
   | ...                   |
   | movq %gs:rex_sp, %rbp |
   | movq %rsp, (%rbp)     |
   | movq %rbp, %rsp       |                +-----------+
   | call *%rdx            |--------------->| rex_prog: |
   |                       |                | ...       |
   | rex_exit:             |<---------------| ret       |
   | popq %rsp             |                +-----------+
   | ...                   |
   | ret                   |
   +-----------------------+
```

Under exceptional cases (where a rust panic is fired), `rust_begin_unwind`
(i.e. panic handler) will transfer the control flow to the `rex_landingpad`
C function in the kernel, which, after dumping some information to the
kernel ring buffer, will call `rex_landingpad_asm`. `rex_landingpad_asm`
sets a default reutrn value, restores the stack pointer to the top of the
Rex stack, i.e. the same address when program returns without an exception,
and issues an direct jump to the `rex_exit` label in the middle of
`rex_dispatcher_func`.

```
         +-----------------------+
         | rex_dispatcher_func:  |
         | ...                   |
         | movq %gs:rex_sp, %rbp |
         | movq %rsp, (%rbp)     |
         | movq %rbp, %rsp       |                +-----------+
         | call *%rdx            |--------------->| rex_prog: |
         |                       |         +------| ...       |
   +---->| rex_exit:             |         |      | ret       |
   |     | popq %rsp             |         |      +-----------+
   |     | ...                   |         |
   |     | ret                   |         | panic!()
   |     |                       |         |
   |     | rex_landingpad_asm:   |<-----+  |      +-------------------------+
   |     | ...                   |      |  +----->| rex_landingpad:         |
   |     | movq %gs:rex_sp, %rsp |      |         | ...                     |
   +-----| jmp rex_exit          |      +---------| call rex_landingpad_asm |
         +-----------------------+                +-------------------------+
```

The Rex stack uses the same layout as other kernel stacks -- the pointer to
the previous stack is stored in the top-most entry of the Rex stack. This,
combined with `bpf-ksyms`, allows smooth integration with the ORC unwinder
and provides meaningful stack traces:

```console
[   12.568364][  T208] rex: Panic from Rex prog: called `Option::unwrap()` on a `None` value
[   12.568622][  T208] CPU: 3 UID: 0 PID: 208 Comm: userapp Not tainted 6.13.0-rex+ #226
[   12.568854][  T208] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-20240910_120124-localhost 04/01/2014
[   12.569236][  T208] Call Trace:
[   12.569345][  T208]  <REX>
[   12.569428][  T208]  dump_stack_lvl+0x6e/0xa8
[   12.569559][  T208]  rex_landingpad+0x64/0xb0
[   12.569704][  T208]  rex_prog_4168211f00000000::rust_begin_unwind+0x15a/0x1a0
[   12.569944][  T208]  rex_prog_4168211f00000000::core::panicking::panic_fmt+0x9/0x10
[   12.570188][  T208]  rex_prog_4168211f00000000::core::panicking::panic+0x53/0x60
[   12.570423][  T208]  rex_prog_4168211f00000000::core::option::unwrap_failed+0x9/0x10
[   12.570668][  T208]  rex_prog_4168211f00000000::err_injector+0x8f/0xa0
[   12.570879][  T208]  rex_dispatcher_func+0x32/0x32
[   12.571045][  T208]  </REX>
[   12.571137][  T208]  <TASK>
[   12.571229][  T208]  trace_call_bpf+0x1a1/0x1f0
[   12.571363][  T208]  ? __x64_sys_dup+0x1/0xd0
[   12.571468][  T208]  kprobe_perf_func+0x4e/0x260
[   12.571582][  T208]  ? kmem_cache_free+0x29/0x290
[   12.571718][  T208]  ? __cfi___x64_sys_dup+0x10/0x10
[   12.571879][  T208]  kprobe_ftrace_handler+0x115/0x1a0
[   12.572046][  T208]  ? __x64_sys_dup+0x5/0xd0
[   12.572189][  T208]  0xffffffffa02010c8
[   12.572310][  T208]  ? __x64_sys_dup+0x1/0xd0
[   12.572452][  T208]  __x64_sys_dup+0x5/0xd0
[   12.572582][  T208]  do_syscall_64+0x42/0xb0
[   12.572722][  T208]  entry_SYSCALL_64_after_hwframe+0x4b/0x53
[   12.572910][  T208] RIP: 0033:0x7f6039f0ee9d
[   12.573050][  T208] Code: ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 33 bf 0b 00 f7 d8 64 89 01 48
[   12.573579][  T208] RSP: 002b:00007ffd562cee08 EFLAGS: 00000246 ORIG_RAX: 0000000000000020
[   12.573779][  T208] RAX: ffffffffffffffda RBX: 00007ffd562cef28 RCX: 00007f6039f0ee9d
[   12.573967][  T208] RDX: 000055cc27f9b988 RSI: 00007ffd562cef38 RDI: 0000000000000000
[   12.574150][  T208] RBP: 0000000000000001 R08: 00007f6039ffada0 R09: 000055cc27f9a730
[   12.574348][  T208] R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
[   12.574600][  T208] R13: 00007ffd562cef38 R14: 00007f603a02a000 R15: 000055cc27f9b988
[   12.574810][  T208]  </TASK>
```

For further information please refer to the [actual
code](https://github.com/rex-rs/linux/blob/rex-linux/arch/x86/net/rex_64.S).

### Resource cleanup in Rust

Not using the existing ABI-based exception handling / stack unwinding
scheme means we need to handle resource cleanup in our own way. We make the
observation that the only resources that requires cleanup are the resources
obtained from kernel helper functions. This is because of the restricted
programing interface exposed to these extension programs, which disallow
direct kernel resource alloation (e.g. allocate memory, directly access a
lock, etc).

This brings us chance to create a light-weight resource clean up scheme. We
can record allocated kernel resources and their destructors on-the-fly
during program execution. When termination is needed, the destructors of
allocated resources are invoked to release the resources. Since only the
trusted kernel crate that interfaces with the kernel resources is
responsible for implementing the aforementioned destructors, all the
cleanup code is trusted and guaranteed not to fail.

The PoC implemention uses `CleanupEntry` to represent an allocated
resource:

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
   The alignment of the struct is 64 bits anyway.
2. According to
   [Rustonomicon](https://doc.rust-lang.org/nomicon/repr-rust.html) and
   [Rust doc](https://doc.rust-lang.org/std/option/#representation),
   `Option<CleanupFn>` has the same size and bit-level representation as
   `CleanupFn` as long as it is a `Some`. This is important because on the
   kernel side it can be treated as a `void (*)(void *)`.

The created struct is then stored in a per-CPU array `rex_cleanup_entries`
in the kernel. This also implies that a C binding for `CleanupEntry` is
needed in the kernel:

```C
struct rex_cleanup_entry {
    u64 valid;
    void *cleanup_fn;
    void *cleanup_arg;
};
```

Note:

1. Using `void *` to store function pointer is not standard compliant,
   though at ABI level it is always a 64-bit value and should work
   correctly.  We should change it to a real function pointer: `void
   (*)(void *)`.
2. Currently, the array is statically allocated with a capacity of 64. This
   **may not** be sustainable.

During normal execution, the `drop` handlers are executed normally so the
kernel resource will be released and the `CleanupEntry` will be
invalidated.

Upon a panic, the control flow will transfer to `rust_begin_unwind` (i.e.
the Rust panic handler). `rust_begin_unwind` will traverse the array on
current CPU and free any resources allocated by invoking
`(cleanup_fn)(cleanup_arg)`.  It then invalidate these entries.

Code references:

1. [Rust side `CleanupEntry` and panic handler
   implementation](https://github.com/rex-rs/rex/blob/main/rex/src/panic.rs)
2. [Kernel side binding type and per-CPU
   array](https://github.com/rex-rs/linux/blob/cd07f685c08b6087da0b1468a97d75c3de51e296/kernel/bpf/core.c#L3146)
