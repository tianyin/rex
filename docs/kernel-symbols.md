# Handling of kernel symbols

This document covers dynamic kernel symbol resolution.

The `inner_unikernel_rt` crate serves as an interface for the extension
programs to interact with the kernel. To accomplish this, the crate will need
to access kernel symbols. For example, invoking kernel helper functions
requires knowing the kernel address of the target helper function symbol.

Before [36b91e1aab92: ("libiu: support dynamic symbol
relocation")](https://github.com/rosalab/inner_unikernels/commit/36b91e1aab92a28cf341852c1ffd187597736d60),
the `inner_unikernel_rt` crate directly compiles the address of the kernel
symbols in. The build script uses `nm` to resolve addresses of the needed
kernel symbols (specified in a special section of `Cargo.toml`) and generates
the `stub.rs` file. The rest of the crate can use the generated `xxx_addr`
function to get the address of kernel symbol `xxx` as an `u64`. The code can
then transmute the value into the appropriate type (e.g. a function pointer for
helper functions). This way of kernel symbol resolution causes several
problems:

1. The compiled executable will contain kernel addresses, which should not be
   leaked to userspace.
2. It requires KASLR to be turned off (because address from `nm`/`System.map`
   are static), which is not portable on KASLR-enabled kernels.
3. When ever kernel image layout changes (e.g. changes in function offset), the
   extension program needs to be re-compiled.
4. The transmuted stub becomes a function pointer for helper functions, which,
   after inlining, hinders further optimization on stack instrumentation (the
   instrumentation can only be omitted if there are no indirect calls /
   recursions).

Therefore, it is reasonable to defer the kernel symbol resolution to load time.
At this point, the kernel always knows where the symbols are located (even with
KASLR), which solves problems 2 and 3. At the same time, the final executable
will not contain any actual kernel address, addressing problem 1. In order to
avoid the need of an indirect call (problem 4), we choose to implement the
kernel symbol resolution the same way dynamic linking works in userspace --
declare the needed kernel symbols as external symbols and let the compiler
generate relocation entries for these symbols.

The new implementation involves the following:

1. Declare the needed kernel symbols as `extern "C"` and with appropriate type.
   For example `bpf_probe_read_kernel` is declared as:

   ```Rust
   extern "C" {
       /// `long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)`
       pub(crate) fn bpf_probe_read_kernel(
           dst: *mut (),
           size: u32,
           unsafe_ptr: *const (),
       ) -> i64;
       ...
   }
   ```

   `extern "C"` specifies that the symbol uses the C ABI, which matches that of
   the actual in-kernel object/function (check the
   [Rustonomicon](https://doc.rust-lang.org/nomicon/other-reprs.html) for more
   information). The declarations can found in
   [`src/stub.rs`](https://github.com/rosalab/inner_unikernels/blob/main/inner_unikernel_rt/src/stub.rs).

2. To make it easy to generate the relocations, we add a dummy library,
   [`libiustub`](https://github.com/rosalab/inner_unikernels/tree/main/inner_unikernel_rt/libiustub),
   that provides "fake" definitions of the symbols. The extension programs will
   link against this library dynamically so that a dynamic relocation entry is
   generated for each kernel symbol and the linker will not complain about
   undefined symbols. For example, dumping relocations for the
   [trace\_event](https://github.com/rosalab/inner_unikernels/tree/main/samples/trace_event)
   sample gives the following:

   ```console
   $ objdump -R target/x86_64-unknown-linux-gnu/release/trace_event_kern

   target/x86_64-unknown-linux-gnu/release/trace_event_kern:     file format elf64-x86-64

   DYNAMIC RELOCATION RECORDS
   OFFSET           TYPE              VALUE
   0000000000003fc0 R_X86_64_RELATIVE  *ABS*+0x0000000000001270
   0000000000003fc8 R_X86_64_RELATIVE  *ABS*+0x00000000000011f0
   0000000000004008 R_X86_64_RELATIVE  *ABS*+0x0000000000001000
   0000000000004010 R_X86_64_RELATIVE  *ABS*+0x0000000000002028
   0000000000003fb8 R_X86_64_GLOB_DAT  bpf_trace_printk_iu
   0000000000003fd0 R_X86_64_GLOB_DAT  bpf_get_stackid_pe
   0000000000003fd8 R_X86_64_GLOB_DAT  current_task
   0000000000003fe0 R_X86_64_GLOB_DAT  bpf_map_update_elem
   0000000000003fe8 R_X86_64_GLOB_DAT  cpu_number
   0000000000003ff0 R_X86_64_GLOB_DAT  bpf_perf_prog_read_value
   0000000000003ff8 R_X86_64_GLOB_DAT  bpf_map_lookup_elem
   ```

   The library exists solely for the generate of relocations, it is never map
   into the kernel with the program and the symbols defined in the library are
   therefore never accessed. At the same time, because the symbols are not
   accessed, their types are not relevant, only the name matters. The build
   script automatically builds the library and adds the needed linker flags so
   that users can still use `cargo` to build the programs.

3. At load time, libiu parses the relocation entries to find out the offsets
   and symbol names (accessible by symbol table index), and send them to the
   kernel.  The kernel queries the symbol name against `kallsyms` to lookup the
   in-kernel address of the symbol, it then patches the value at the specified
   offset to that address.

The whole set of commits can be found here:
<https://github.com/rosalab/inner_unikernels/pull/61>

The same way of symbol resolution can potentially be applied to maps as well.
