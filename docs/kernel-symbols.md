# Handling of kernel symbols

This document covers dynamic kernel symbol resolution.

The `rex` crate serves as an interface for the extension programs to
interact with the kernel. To accomplish this, the crate will need to access
kernel symbols. For example, invoking kernel helper functions requires
knowing the kernel address of the target helper function symbol.  These
kernel symbols includes not only BPF helper functions, but also certain
per-cpu variables and other kernel functions (these comes partly from our
previous effort on rewriting kernel helpers, but it is also used by the
stack unwind/protection and panic cleanup mechanism).

Before [`36b91e1aab92: ("libiu: support dynamic symbol
relocation")`](https://github.com/rex-rs/rex/commit/36b91e1aab92a28cf341852c1ffd187597736d60),
the `rex` crate directly compiles the address of the kernel symbols in. The
build script uses `nm` to resolve addresses of the needed kernel symbols
(specified in a special section of `Cargo.toml`) and generates the
`stub.rs` file. The rest of the crate can use the generated `xxx_addr`
function to get the address of kernel symbol `xxx` as an `u64`. The code
can then transmute the value into the appropriate type (e.g. a function
pointer for helper functions). This way of kernel symbol resolution causes
several problems:

1. The compiled executable will contain kernel addresses, which should not
   be leaked to userspace.
2. It requires KASLR to be turned off (because addresses from
   `nm`/`System.map` are static), which is not portable on KASLR-enabled
   kernels.
3. When ever kernel image layout changes (e.g. changes in function offset),
   the extension program needs to be re-compiled.
4. The transmuted stub becomes a function pointer for helper functions,
   which, after inlining, hinders further optimization on stack
   instrumentation (the instrumentation can only be omitted if there are no
   indirect calls / recursions).

Therefore, it is reasonable to defer the kernel symbol resolution to load
time.  At this point, the kernel always knows where the symbols are located
(even with KASLR), which solves problems 2 and 3. At the same time, the
final executable will not contain any actual kernel address, addressing
problem 1. In order to avoid the need of an indirect call (problem 4), we
choose to implement the kernel symbol resolution the same way dynamic
linking works in userspace -- declare the needed kernel symbols as external
symbols and let the compiler generate relocation entries for these symbols.

The new implementation involves the following:

1. Declare the needed kernel symbols as `extern "C"` and with appropriate
   type.  For example `bpf_probe_read_kernel` is declared as:

   ```Rust
   extern "C" {
       /// `long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)`
       pub(crate) fn bpf_probe_read_kernel(
           dst: *mut (),
           size: u32,
           unsafe_ptr: *const (),
       ) -> i64;
   }
   ```

   `extern "C"` specifies that the symbol uses the C ABI, which matches
   that of the actual in-kernel object/function (check the
   [Rustonomicon](https://doc.rust-lang.org/nomicon/other-reprs.html) for
   more information). The declarations can be found in
   [`src/stub.rs`](https://github.com/rex-rs/rex/blob/main/rex/src/stub.rs).

2. To make it easy to generate the relocations, we add a dummy library,
   [`librexstub`](https://github.com/rex-rs/rex/tree/main/rex/librexstub),
   that provides "fake" definitions of the symbols. The extension programs
   will link against this library dynamically so that a dynamic relocation
   entry is generated for each kernel symbol and the linker will not
   complain about undefined symbols. For example, dumping relocations for
   the
   [`error_injector`](https://github.com/rex-rs/rex/tree/main/samples/error_injector)
   sample gives the following:

   ```console
   $ objdump -R target/x86_64-unknown-linux-gnu/release/error_injector

   target/x86_64-unknown-linux-gnu/release/error_injector:     file format elf64-x86-64

   DYNAMIC RELOCATION RECORDS
   OFFSET           TYPE              VALUE
   0000000000003e58 R_X86_64_RELATIVE  *ABS*+0x0000000000002029
   0000000000003e68 R_X86_64_RELATIVE  *ABS*+0x0000000000002000
   0000000000003fc0 R_X86_64_RELATIVE  *ABS*+0x0000000000001210
   0000000000003ff8 R_X86_64_RELATIVE  *ABS*+0x0000000000001020
   0000000000003fb8 R_X86_64_GLOB_DAT  this_cpu_off
   0000000000003fc8 R_X86_64_GLOB_DAT  pcpu_hot
   0000000000003fd0 R_X86_64_GLOB_DAT  rex_cleanup_entries
   0000000000003fd8 R_X86_64_GLOB_DAT  rex_landingpad
   0000000000003fe0 R_X86_64_GLOB_DAT  just_return_func
   0000000000003fe8 R_X86_64_GLOB_DAT  rex_termination_state
   0000000000003ff0 R_X86_64_GLOB_DAT  bpf_map_lookup_elem
   ```

   The relocations with type `R_X86_64_GLOB_DAT` are the kernel symbol
   relocations generated from dynamic linking, where the `OFFSET` denotes the
   address offset within the binary and the `VALUE` specifies the actual symbol
   name.

   Other relocations with type `R_X86_64_RELATIVE` are a result from
   position-independent executables (PIE).  In PIE, function invocations
   involve a IP-relative call that indexes into the global offset table
   (GOT) that stores the absolute address of the function. The GOT entries
   are generated as relocations that are patched at the program load time.
   For example, `3fc0 R_X86_64_RELATIVE  *ABS*+0x1270` specifies that the
   value at offset `3fc0` of the binary needs to be patched to the absolute
   start address of the binary (after it is mapped into memory) plus
   `0x1270`.

   The library exists solely for the generation of relocations, it is never
   mapped into the kernel with the program and the symbols defined in the
   library are therefore never accessed. At the same time, because the
   symbols are not accessed, their types are not relevant, only the name
   matters. The build script of the `rex` crate automatically builds the
   library and adds the needed linker flags so that users can just use
   `cargo` to build the programs.

3. At load time, librex parses the relocation entries to find out the
   offsets and symbol names (accessible by symbol table index), and send
   them to the kernel. The decision to let the loader library parse the
   relocation entries is to reduce the complexity of code in the kernel and
   take advantage of the existing userspace ELF libraries (we use
   `elfutils`, the same library used by `libbpf`).  Each dynamic symbol
   relocation is the stored in an
   [`rex_dyn_sym`](https://github.com/rex-rs/linux/blob/cd07f685c08b6087da0b1468a97d75c3de51e296/include/uapi/linux/bpf.h#L1472-L1475)

   struct:

   ```C
   struct rex_dyn_sym {
       __u64	offset; // symbol offset
       __u64	symbol; // symbol name string (actually a char *)
   };
   ```

   When invoking the `bpf(2)` syscall to load the program, the library will
   pass an array of `struct rex_dyn_sym` to the kernel (by setting pointer
   to the start address and the size in the
   [`bpf_attr`](https://github.com/rex-rs/linux/blob/cd07f685c08b6087da0b1468a97d75c3de51e296/include/uapi/linux/bpf.h#L1591-L1592)
   union).

   The kernel copies the array into kernel space and queries each symbol
   name against `kallsyms` to lookup the in-kernel address of the symbol,
   it then patches the value at the specified offset to that address.

The same symbol resolution mechanism is applied to maps as well.
